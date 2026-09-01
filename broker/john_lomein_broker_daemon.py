"""Authenticated Unix-socket transport for the protected broker."""

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import json
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

from .john_lomein_broker_protocol import (
    BrokerProtocolError,
    canonical_json,
    load_config,
    validate_requester_uid,
)


RESPONSE_SCHEMA = "john-lomein.protected-broker-response.v1"
MAX_RESPONSE_BYTES = 512 * 1024
FRAME_HEADER_BYTES = 4
SOCKET_BACKLOG = 16
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


class BrokerDaemonError(RuntimeError):
    """The authenticated broker transport cannot operate safely."""


@dataclass(frozen=True)
class PeerCredentials:
    uid: int
    gid: int
    pid: int | None


class _BrokerServerSocket(socket.socket):
    """Server socket that holds the daemon exclusion lock until close."""

    _broker_lock_fd: int | None = None
    _broker_bound_identity: tuple[int, int] | None = None

    def close(self) -> None:
        lock_fd = self._broker_lock_fd
        self._broker_lock_fd = None
        try:
            super().close()
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(lock_fd)


def sanitize_process_environment() -> None:
    for key in tuple(os.environ):
        if (
            key in SENSITIVE_ENV_KEYS
            or key.upper().endswith(SENSITIVE_ENV_SUFFIXES)
        ):
            os.environ.pop(key, None)


def peer_credentials(sock: socket.socket) -> PeerCredentials:
    if sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"):
        size = struct.calcsize("3i")
        try:
            raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
        except OSError as exc:
            raise BrokerDaemonError(
                "socket peer credentials are unavailable"
            ) from exc
        pid, uid, gid = struct.unpack("3i", raw)
        if pid <= 0 or uid < 0 or gid < 0:
            raise BrokerDaemonError("socket peer credentials are invalid")
        return PeerCredentials(uid=uid, gid=gid, pid=pid)
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        function = getattr(libc, "getpeereid", None)
        if function is None:
            raise BrokerDaemonError(
                "socket peer credentials are unavailable"
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
            raise BrokerDaemonError(
                "socket peer credentials are unavailable"
            ) from OSError(error, os.strerror(error))
        return PeerCredentials(uid=uid.value, gid=gid.value, pid=None)
    raise BrokerDaemonError(
        "this platform has no supported socket peer-credential adapter"
    )


def _read_exact(
    sock: socket.socket,
    count: int,
    *,
    deadline: float | None = None,
) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        if deadline is not None:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                raise BrokerDaemonError("socket request timed out")
            sock.settimeout(timeout)
        try:
            chunk = sock.recv(remaining)
        except socket.timeout as exc:
            raise BrokerDaemonError("socket request timed out") from exc
        except OSError as exc:
            raise BrokerDaemonError("socket request read failed") from exc
        if not chunk:
            raise BrokerDaemonError("socket request ended prematurely")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_frame(
    sock: socket.socket,
    *,
    maximum_bytes: int,
    timeout_seconds: float | None = None,
) -> bytes:
    if timeout_seconds is None:
        timeout_seconds = sock.gettimeout()
    if timeout_seconds is not None and (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds <= 0
    ):
        raise BrokerDaemonError("socket request timeout is invalid")
    deadline = (
        time.monotonic() + float(timeout_seconds)
        if timeout_seconds is not None
        else None
    )
    header = _read_exact(
        sock,
        FRAME_HEADER_BYTES,
        deadline=deadline,
    )
    (length,) = struct.unpack("!I", header)
    if length <= 0 or length > maximum_bytes:
        raise BrokerDaemonError("socket frame length is outside policy")
    return _read_exact(sock, length, deadline=deadline)


def write_frame(
    sock: socket.socket,
    payload: bytes,
    *,
    maximum_bytes: int = MAX_RESPONSE_BYTES,
) -> None:
    if not payload or len(payload) > maximum_bytes:
        raise BrokerDaemonError("socket response length is outside policy")
    framed = struct.pack("!I", len(payload)) + payload
    try:
        sock.sendall(framed)
    except (socket.timeout, OSError) as exc:
        raise BrokerDaemonError("socket response write failed") from exc


def _safe_socket_parent(
    path: Path,
    *,
    broker_uid: int,
) -> None:
    try:
        info = path.parent.lstat()
    except OSError as exc:
        raise BrokerDaemonError("broker socket directory is unavailable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid not in {0, broker_uid}
        or info.st_mode & 0o022
    ):
        raise BrokerDaemonError("broker socket directory is unsafe")


def _acquire_socket_lock(path: Path, *, broker_uid: int) -> int:
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise BrokerDaemonError(
            "broker socket lock cannot be opened safely"
        ) from exc
    try:
        info = os.fstat(fd)
        named = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != broker_uid
            or info.st_mode & 0o077
            or info.st_nlink != 1
            or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise BrokerDaemonError("broker socket lock is unsafe")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise BrokerDaemonError(
                    "another broker daemon already holds the socket lock"
                ) from exc
            raise BrokerDaemonError(
                "broker socket lock cannot be acquired"
            ) from exc
        return fd
    except BaseException:
        os.close(fd)
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
        raise BrokerDaemonError(
            "existing broker socket cannot be proven stale"
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
        raise BrokerDaemonError(
            "broker socket path cannot be inspected"
        ) from exc
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != broker_uid
        or (
            expected_identity is not None
            and (info.st_dev, info.st_ino) != expected_identity
        )
    ):
        raise BrokerDaemonError("broker socket path changed unsafely")
    try:
        path.unlink()
    except OSError as exc:
        raise BrokerDaemonError("broker socket cannot be removed") from exc


def bind_server_socket(config: Mapping[str, Any]) -> socket.socket:
    broker_uid = int(config["broker_uid"])
    if (
        os.getuid() != broker_uid
        or (
            hasattr(os, "geteuid")
            and os.geteuid() != broker_uid
        )
    ):
        raise BrokerDaemonError(
            "broker daemon is not running as the configured OS identity"
        )
    transport = config["transport"]
    path = Path(transport["socket_path"])
    _safe_socket_parent(path, broker_uid=broker_uid)
    lock_fd = _acquire_socket_lock(
        path.with_name(path.name + ".lock"),
        broker_uid=broker_uid,
    )
    server: _BrokerServerSocket | None = None
    bound_identity: tuple[int, int] | None = None
    try:
        try:
            existing = path.lstat()
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise BrokerDaemonError(
                "broker socket path cannot be inspected"
            ) from exc
        if existing is not None:
            if (
                not stat.S_ISSOCK(existing.st_mode)
                or existing.st_uid != broker_uid
            ):
                raise BrokerDaemonError(
                    "broker socket path is occupied unsafely"
                )
            if _existing_socket_is_active(path):
                raise BrokerDaemonError("broker socket is already active")
            _unlink_owned_socket(
                path,
                broker_uid=broker_uid,
                expected_identity=(existing.st_dev, existing.st_ino),
            )
        server = _BrokerServerSocket(socket.AF_UNIX, socket.SOCK_STREAM)
        server._broker_lock_fd = lock_fd
        lock_fd = -1
        server.bind(str(path))
        bound = path.lstat()
        if (
            not stat.S_ISSOCK(bound.st_mode)
            or bound.st_uid != broker_uid
        ):
            raise BrokerDaemonError("bound broker socket is unsafe")
        bound_identity = (bound.st_dev, bound.st_ino)
        server._broker_bound_identity = bound_identity
        submit_gid = int(transport["submit_gid"])
        os.chown(path, broker_uid, submit_gid)
        os.chmod(path, 0o660)
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
            except BrokerDaemonError:
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


class BrokerDaemon:
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

    def handle_connection(self, connection: socket.socket) -> None:
        timeout = float(self.config["transport"]["request_timeout_seconds"])
        connection.settimeout(timeout)
        try:
            peer = peer_credentials(connection)
            validate_requester_uid(self.config, peer.uid)
            raw = read_frame(
                connection,
                maximum_bytes=int(
                    self.config["transport"]["max_request_bytes"]
                ),
                timeout_seconds=timeout,
            )
            try:
                value = json.loads(
                    raw,
                    object_pairs_hook=_reject_duplicate_keys,
                    parse_constant=_reject_nonfinite,
                )
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise BrokerProtocolError(
                    "broker submission is invalid JSON"
                ) from exc
            receipt = self.handler(value, peer)
            write_frame(connection, success_response(receipt))
        except BrokerProtocolError:
            try:
                write_frame(connection, error_response("request_rejected"))
            except BrokerDaemonError:
                pass
        except BrokerDaemonError:
            try:
                write_frame(connection, error_response("transport_rejected"))
            except BrokerDaemonError:
                pass
        except Exception:
            try:
                write_frame(connection, error_response("broker_failure"))
            except BrokerDaemonError:
                pass

    def serve_forever(self) -> None:
        if self.config.get("enabled") is not True:
            raise BrokerDaemonError("protected broker is disabled by config")
        sanitize_process_environment()
        server = bind_server_socket(self.config)
        path = Path(self.config["transport"]["socket_path"])
        previous_handlers: dict[int, Any] = {}
        try:
            for number in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[number] = signal.signal(number, self.stop)
            while not self._stopping:
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError as exc:
                    if exc.errno == errno.EINTR:
                        continue
                    raise BrokerDaemonError(
                        "broker socket accept failed"
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
                        server, "_broker_bound_identity", None
                    ),
                )
            except BrokerDaemonError:
                pass
            finally:
                server.close()


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BrokerProtocolError(
                "broker submission contains duplicate JSON fields"
            )
        result[key] = value
    return result


def _reject_nonfinite(_: str) -> None:
    raise BrokerProtocolError(
        "broker submission contains a non-finite number"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the isolated John Lomein protected-action broker"
    )
    parser.add_argument("--config", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    sanitize_process_environment()
    try:
        if (
            hasattr(os, "geteuid")
            and os.getuid() != os.geteuid()
        ) or (
            hasattr(os, "getegid")
            and os.getgid() != os.getegid()
        ):
            raise BrokerDaemonError(
                "broker daemon refuses a set-ID execution context"
            )
        config = load_config(
            args.config,
            expected_broker_uid=(
                os.geteuid() if hasattr(os, "geteuid") else os.getuid()
            ),
        )
        from .john_lomein_broker_service import build_service

        service = build_service(config)
        BrokerDaemon(config=config, handler=service.handle).serve_forever()
        return 0
    except (BrokerProtocolError, BrokerDaemonError) as exc:
        print(f"protected broker refused startup: {exc}", file=sys.stderr)
        return 2
    except Exception:
        print(
            "protected broker refused startup: initialization failed",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
