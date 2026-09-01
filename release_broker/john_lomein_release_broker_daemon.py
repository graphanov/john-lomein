#!/usr/bin/env python3
"""Kernel-authenticated Unix-socket transport for the release broker."""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import os
import signal
import socket
import stat
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .john_lomein_release_broker_protocol import (
    ReleaseBrokerProtocolError,
    canonical_json,
    load_config,
    parse_json_bytes,
    validate_requester_uid,
)


RESPONSE_SCHEMA = "john-lomein.protected-release-broker-response.v1"
MAX_RESPONSE_BYTES = 1024 * 1024 + 64 * 1024
FRAME_HEADER_BYTES = 4
SOCKET_BACKLOG = 8
SENSITIVE_ENV_KEYS = frozenset(
    {
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "NPM_TOKEN",
        "NODE_AUTH_TOKEN",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "GH_CONFIG_DIR",
        "GIT_ASKPASS",
        "GIT_SSH_COMMAND",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "SSLKEYLOGFILE",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "NODE_EXTRA_CA_CERTS",
        "OPENSSL_CONF",
        "OPENSSL_MODULES",
        "OPENSSL_ENGINES",
        "AWS_PROFILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "KUBECONFIG",
        "DOCKER_CONFIG",
        "NETRC",
    }
)
SENSITIVE_ENV_SUFFIXES = (
    "_API_KEY",
    "_PASSWORD",
    "_PRIVATE_KEY",
    "_SECRET",
    "_TOKEN",
)


class ReleaseBrokerDaemonError(RuntimeError):
    """The authenticated release transport cannot operate safely."""


@dataclass(frozen=True)
class PeerCredentials:
    uid: int
    gid: int
    pid: int | None


class _ReleaseBrokerServerSocket(socket.socket):
    """Server socket retaining its exclusion lock until close."""

    _release_broker_lock_fd: int | None = None
    _release_broker_bound_identity: tuple[int, int] | None = None

    def close(self) -> None:
        lock_fd = self._release_broker_lock_fd
        self._release_broker_lock_fd = None
        try:
            super().close()
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)


def sanitize_process_environment() -> None:
    """Remove ambient caller credentials and proxy/TLS overrides."""

    for key in tuple(os.environ):
        if (
            key in SENSITIVE_ENV_KEYS
            or key.upper().endswith(SENSITIVE_ENV_SUFFIXES)
        ):
            os.environ.pop(key, None)


def peer_credentials(sock: socket.socket) -> PeerCredentials:
    """Read immutable peer identity from the connected Unix socket."""

    if sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"):
        size = struct.calcsize("3i")
        try:
            raw = sock.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, size
            )
        except OSError as exc:
            raise ReleaseBrokerDaemonError(
                "release socket peer credentials are unavailable"
            ) from exc
        pid, uid, gid = struct.unpack("3i", raw)
        if pid <= 0 or uid < 0 or gid < 0:
            raise ReleaseBrokerDaemonError(
                "release socket peer credentials are invalid"
            )
        return PeerCredentials(uid=uid, gid=gid, pid=pid)
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        function = getattr(libc, "getpeereid", None)
        if function is None:
            raise ReleaseBrokerDaemonError(
                "release socket peer credentials are unavailable"
            )
        function.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(ctypes.c_uint),
        ]
        function.restype = ctypes.c_int
        uid = ctypes.c_uint()
        gid = ctypes.c_uint()
        if function(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            error = ctypes.get_errno()
            raise ReleaseBrokerDaemonError(
                "release socket peer credentials are unavailable"
            ) from OSError(error, os.strerror(error))
        return PeerCredentials(uid=uid.value, gid=gid.value, pid=None)
    raise ReleaseBrokerDaemonError(
        "platform has no supported Unix peer-credential adapter"
    )


def _set_deadline_timeout(
    sock: socket.socket,
    deadline: float | None,
) -> None:
    if deadline is None:
        return
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ReleaseBrokerDaemonError(
            "release socket request timed out"
        )
    sock.settimeout(remaining)


def _read_exact(
    sock: socket.socket,
    count: int,
    *,
    deadline: float | None,
) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        _set_deadline_timeout(sock, deadline)
        try:
            chunk = sock.recv(remaining)
        except socket.timeout as exc:
            raise ReleaseBrokerDaemonError(
                "release socket request timed out"
            ) from exc
        except OSError as exc:
            raise ReleaseBrokerDaemonError(
                "release socket request read failed"
            ) from exc
        if not chunk:
            raise ReleaseBrokerDaemonError(
                "release socket request ended prematurely"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _deadline(
    timeout_seconds: float | None,
    sock: socket.socket,
) -> float | None:
    value = timeout_seconds
    if value is None:
        value = sock.gettimeout()
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or value <= 0
    ):
        raise ReleaseBrokerDaemonError(
            "release socket request timeout is invalid"
        )
    return time.monotonic() + float(value)


def read_frame(
    sock: socket.socket,
    *,
    maximum_bytes: int,
    timeout_seconds: float | None = None,
) -> bytes:
    """Read one bounded frame (without asserting stream termination)."""

    deadline = _deadline(timeout_seconds, sock)
    header = _read_exact(
        sock, FRAME_HEADER_BYTES, deadline=deadline
    )
    (length,) = struct.unpack("!I", header)
    if length <= 0 or length > maximum_bytes:
        raise ReleaseBrokerDaemonError(
            "release socket frame length is outside policy"
        )
    return _read_exact(sock, length, deadline=deadline)


def read_single_frame(
    sock: socket.socket,
    *,
    maximum_bytes: int,
    timeout_seconds: float,
) -> bytes:
    """Read exactly one frame and require client write-side EOF."""

    deadline = _deadline(timeout_seconds, sock)
    header = _read_exact(
        sock, FRAME_HEADER_BYTES, deadline=deadline
    )
    (length,) = struct.unpack("!I", header)
    if length <= 0 or length > maximum_bytes:
        raise ReleaseBrokerDaemonError(
            "release socket frame length is outside policy"
        )
    payload = _read_exact(sock, length, deadline=deadline)
    _set_deadline_timeout(sock, deadline)
    try:
        trailing = sock.recv(1)
    except socket.timeout as exc:
        raise ReleaseBrokerDaemonError(
            "release socket request did not terminate"
        ) from exc
    except OSError as exc:
        raise ReleaseBrokerDaemonError(
            "release socket request termination failed"
        ) from exc
    if trailing:
        raise ReleaseBrokerDaemonError(
            "release socket request contains trailing data"
        )
    return payload


def write_frame(
    sock: socket.socket,
    payload: bytes,
    *,
    maximum_bytes: int = MAX_RESPONSE_BYTES,
) -> None:
    if not payload or len(payload) > maximum_bytes:
        raise ReleaseBrokerDaemonError(
            "release socket response length is outside policy"
        )
    try:
        sock.sendall(struct.pack("!I", len(payload)) + payload)
    except (socket.timeout, OSError) as exc:
        raise ReleaseBrokerDaemonError(
            "release socket response write failed"
        ) from exc


def _safe_socket_parent(path: Path, *, broker_uid: int) -> None:
    current = path.parent
    while True:
        try:
            info = current.lstat()
        except OSError as exc:
            raise ReleaseBrokerDaemonError(
                "release broker socket directory is unavailable"
            ) from exc
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid not in {0, broker_uid}
            or info.st_mode & 0o022
        ):
            raise ReleaseBrokerDaemonError(
                "release broker socket directory is unsafe"
            )
        if current.parent == current:
            return
        current = current.parent


def _acquire_socket_lock(path: Path, *, broker_uid: int) -> int:
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ReleaseBrokerDaemonError(
            "release broker socket lock cannot be opened safely"
        ) from exc
    try:
        info = os.fstat(descriptor)
        named = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != broker_uid
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or (info.st_dev, info.st_ino)
            != (named.st_dev, named.st_ino)
        ):
            raise ReleaseBrokerDaemonError(
                "release broker socket lock is unsafe"
            )
        try:
            fcntl.flock(
                descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB
            )
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise ReleaseBrokerDaemonError(
                    "another release broker holds the socket lock"
                ) from exc
            raise ReleaseBrokerDaemonError(
                "release broker socket lock cannot be acquired"
            ) from exc
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _existing_socket_is_active(path: Path) -> bool:
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(0.25)
        probe.connect(str(path))
        return True
    except OSError as exc:
        if exc.errno in {errno.ECONNREFUSED, errno.ENOENT}:
            return False
        raise ReleaseBrokerDaemonError(
            "existing release socket cannot be proven stale"
        ) from exc
    finally:
        probe.close()


def _unlink_owned_socket(
    path: Path,
    *,
    broker_uid: int,
    expected_identity: tuple[int, int] | None,
) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ReleaseBrokerDaemonError(
            "release broker socket path cannot be inspected"
        ) from exc
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != broker_uid
        or (
            expected_identity is not None
            and (info.st_dev, info.st_ino) != expected_identity
        )
    ):
        raise ReleaseBrokerDaemonError(
            "release broker socket path changed unsafely"
        )
    try:
        path.unlink()
    except OSError as exc:
        raise ReleaseBrokerDaemonError(
            "release broker socket cannot be removed"
        ) from exc


def _validate_process_identity(config: Mapping[str, Any]) -> None:
    broker_uid = int(config["broker_uid"])
    if (
        os.getuid() != broker_uid
        or (hasattr(os, "geteuid") and os.geteuid() != broker_uid)
    ):
        raise ReleaseBrokerDaemonError(
            "release broker is not running as its configured OS identity"
        )
    private_gid = config.get("broker_private_gid")
    if private_gid is not None and (
        os.getgid() != int(private_gid)
        or (
            hasattr(os, "getegid")
            and os.getegid() != int(private_gid)
        )
    ):
        raise ReleaseBrokerDaemonError(
            "release broker private-key group does not match config"
        )


def bind_server_socket(config: Mapping[str, Any]) -> socket.socket:
    broker_uid = int(config["broker_uid"])
    _validate_process_identity(config)
    transport = config["transport"]
    path = Path(transport["socket_path"])
    _safe_socket_parent(path, broker_uid=broker_uid)
    lock_fd = _acquire_socket_lock(
        path.with_name(path.name + ".lock"),
        broker_uid=broker_uid,
    )
    server: _ReleaseBrokerServerSocket | None = None
    bound_identity: tuple[int, int] | None = None
    try:
        try:
            existing = path.lstat()
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise ReleaseBrokerDaemonError(
                "release broker socket path cannot be inspected"
            ) from exc
        if existing is not None:
            if (
                not stat.S_ISSOCK(existing.st_mode)
                or existing.st_uid != broker_uid
            ):
                raise ReleaseBrokerDaemonError(
                    "release broker socket path is occupied unsafely"
                )
            if _existing_socket_is_active(path):
                raise ReleaseBrokerDaemonError(
                    "release broker socket is already active"
                )
            _unlink_owned_socket(
                path,
                broker_uid=broker_uid,
                expected_identity=(existing.st_dev, existing.st_ino),
            )
        server = _ReleaseBrokerServerSocket(
            socket.AF_UNIX, socket.SOCK_STREAM
        )
        server._release_broker_lock_fd = lock_fd
        lock_fd = -1
        server.bind(str(path))
        bound = path.lstat()
        if (
            not stat.S_ISSOCK(bound.st_mode)
            or bound.st_uid != broker_uid
        ):
            raise ReleaseBrokerDaemonError(
                "bound release broker socket is unsafe"
            )
        bound_identity = (bound.st_dev, bound.st_ino)
        server._release_broker_bound_identity = bound_identity
        os.chown(
            path, broker_uid, int(transport["submit_gid"])
        )
        os.chmod(path, 0o660)
        final = path.lstat()
        if (
            not stat.S_ISSOCK(final.st_mode)
            or (final.st_dev, final.st_ino) != bound_identity
            or final.st_uid != broker_uid
            or final.st_gid != int(transport["submit_gid"])
            or stat.S_IMODE(final.st_mode) != 0o660
        ):
            raise ReleaseBrokerDaemonError(
                "release broker socket permissions changed unsafely"
            )
        server.listen(SOCKET_BACKLOG)
        server.settimeout(1.0)
        return server
    except BaseException:
        if bound_identity is not None:
            try:
                _unlink_owned_socket(
                    path,
                    broker_uid=broker_uid,
                    expected_identity=bound_identity,
                )
            except ReleaseBrokerDaemonError:
                pass
        if server is not None:
            server.close()
        elif lock_fd >= 0:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        raise


def error_response(code: str) -> bytes:
    if code not in {
        "request_rejected",
        "transport_rejected",
        "broker_failure",
    }:
        raise ReleaseBrokerDaemonError(
            "release daemon error code is invalid"
        )
    return canonical_json(
        {
            "schema_version": RESPONSE_SCHEMA,
            "ok": False,
            "error": {"code": code},
        }
    )


def success_response(receipt: Mapping[str, Any]) -> bytes:
    return canonical_json(
        {
            "schema_version": RESPONSE_SCHEMA,
            "ok": True,
            "receipt": dict(receipt),
        }
    )


class ReleaseBrokerDaemon:
    def __init__(
        self,
        *,
        config: Mapping[str, Any],
        handler: Callable[
            [Mapping[str, Any], PeerCredentials], Mapping[str, Any]
        ],
    ) -> None:
        self.config = config
        self.handler = handler
        self._stopping = False

    def stop(self, *_: Any) -> None:
        self._stopping = True

    @staticmethod
    def _finish_response(connection: socket.socket) -> None:
        try:
            connection.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def handle_connection(self, connection: socket.socket) -> None:
        timeout = float(
            self.config["transport"]["request_timeout_seconds"]
        )
        connection.settimeout(timeout)
        try:
            peer = peer_credentials(connection)
            validate_requester_uid(self.config, peer.uid)
            raw = read_single_frame(
                connection,
                maximum_bytes=int(
                    self.config["transport"]["max_request_bytes"]
                ),
                timeout_seconds=timeout,
            )
            value = parse_json_bytes(
                raw,
                field="release broker submission",
                maximum_bytes=int(
                    self.config["transport"]["max_request_bytes"]
                ),
            )
            if not isinstance(value, Mapping):
                raise ReleaseBrokerProtocolError(
                    "release broker submission must be an object"
                )
            receipt = self.handler(value, peer)
            write_frame(connection, success_response(receipt))
            self._finish_response(connection)
        except ReleaseBrokerProtocolError:
            try:
                write_frame(
                    connection, error_response("request_rejected")
                )
                self._finish_response(connection)
            except ReleaseBrokerDaemonError:
                pass
        except ReleaseBrokerDaemonError:
            try:
                write_frame(
                    connection, error_response("transport_rejected")
                )
                self._finish_response(connection)
            except ReleaseBrokerDaemonError:
                pass
        except Exception:
            try:
                write_frame(
                    connection, error_response("broker_failure")
                )
                self._finish_response(connection)
            except ReleaseBrokerDaemonError:
                pass

    def serve_forever(self) -> None:
        if self.config.get("enabled") is not True:
            raise ReleaseBrokerDaemonError(
                "protected release broker is disabled by config"
            )
        sanitize_process_environment()
        server = bind_server_socket(self.config)
        path = Path(self.config["transport"]["socket_path"])
        previous_handlers: dict[int, Any] = {}
        try:
            for number in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[number] = signal.signal(
                    number, self.stop
                )
            while not self._stopping:
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError as exc:
                    if exc.errno == errno.EINTR:
                        continue
                    raise ReleaseBrokerDaemonError(
                        "release broker socket accept failed"
                    ) from exc
                with connection:
                    self.handle_connection(connection)
        finally:
            for number, handler in previous_handlers.items():
                signal.signal(number, handler)
            try:
                _unlink_owned_socket(
                    path,
                    broker_uid=int(self.config["broker_uid"]),
                    expected_identity=getattr(
                        server,
                        "_release_broker_bound_identity",
                        None,
                    ),
                )
            except ReleaseBrokerDaemonError:
                pass
            finally:
                server.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the isolated John Lomein protected release broker"
        )
    )
    parser.add_argument("--config", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    sanitize_process_environment()
    service: Any = None
    try:
        if (
            hasattr(os, "geteuid") and os.getuid() != os.geteuid()
        ) or (
            hasattr(os, "getegid") and os.getgid() != os.getegid()
        ):
            raise ReleaseBrokerDaemonError(
                "release broker refuses a set-ID execution context"
            )
        config = load_config(
            args.config,
            expected_owner_uids=(0,),
            parent_owner_uids=(0,),
        )
        if config["enabled"] is not True:
            raise ReleaseBrokerDaemonError(
                "protected release broker is disabled by config"
            )
        _validate_process_identity(config)
        from .john_lomein_release_broker_service import build_service

        service = build_service(config)
        service.recover_pending()
        ReleaseBrokerDaemon(
            config=config, handler=service.handle
        ).serve_forever()
        return 0
    except (
        ReleaseBrokerProtocolError,
        ReleaseBrokerDaemonError,
    ) as exc:
        print(
            f"protected release broker refused startup: {exc}",
            file=sys.stderr,
        )
        return 2
    except Exception:
        print(
            "protected release broker refused startup: "
            "initialization failed",
            file=sys.stderr,
        )
        return 2
    finally:
        if service is not None:
            service.close()


# Concise compatibility aliases inside the isolated package.
BrokerDaemon = ReleaseBrokerDaemon
BrokerDaemonError = ReleaseBrokerDaemonError


if __name__ == "__main__":
    raise SystemExit(main())
