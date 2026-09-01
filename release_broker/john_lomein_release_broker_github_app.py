"""Credential-isolated GitHub App transport for the release broker.

This module deliberately shares no code or credentials with the routine
maintainer broker.  The installation token is repository-scoped, retained only
in memory, and usable for read-only GraphQL plus exactly one REST mutation:
an exact-head squash merge.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import ssl
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


API_HOST = "api.github.com"
API_PORT = 443
API_VERSION = "2026-03-10"
USER_AGENT = "john-lomein-release-broker/1"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_PRIVATE_KEY_BYTES = 128 * 1024
MAX_TOKEN_LIFETIME_SECONDS = 3700
OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
MERGE_PATH_RE = re.compile(
    r"^/repos/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"pulls/[1-9][0-9]*/merge$"
)

# Keep the requested and returned permission set identical.  In particular,
# metadata is named explicitly instead of being left to an API default.
REQUIRED_PERMISSIONS = {
    "checks": "read",
    "contents": "write",
    "issues": "read",
    "metadata": "read",
    "pull_requests": "read",
    "statuses": "read",
}
TOKEN_REQUEST_PERMISSIONS = REQUIRED_PERMISSIONS
REQUESTED_PERMISSIONS = REQUIRED_PERMISSIONS

UNTRUSTED_NETWORK_ENV_KEYS = frozenset(
    {
        "ALL_PROXY",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "NO_PROXY",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SSLKEYLOGFILE",
        "all_proxy",
        "https_proxy",
        "http_proxy",
        "no_proxy",
    }
)


class ReleaseGitHubAppError(RuntimeError):
    """A fail-closed release GitHub App or transport failure."""


@dataclass(frozen=True)
class ReleaseHTTPResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class ReleaseHTTPTransport(Protocol):
    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> ReleaseHTTPResponse:
        """Perform one request against the fixed GitHub API origin."""


class FixedReleaseGitHubTransport:
    """Direct TLS transport with no proxy or caller-selected trust roots."""

    def __init__(self, *, ssl_context: ssl.SSLContext | None = None) -> None:
        if any(os.environ.get(key) for key in UNTRUSTED_NETWORK_ENV_KEYS):
            raise ReleaseGitHubAppError(
                "network or TLS environment overrides are not permitted"
            )
        context = ssl_context or ssl.create_default_context()
        if (
            context.verify_mode != ssl.CERT_REQUIRED
            or not context.check_hostname
        ):
            raise ReleaseGitHubAppError(
                "GitHub TLS context must verify certificates and hostnames"
            )
        if hasattr(ssl, "TLSVersion"):
            if context.minimum_version < ssl.TLSVersion.TLSv1_2:
                context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._ssl_context = context

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> ReleaseHTTPResponse:
        normalized_method = str(method).upper()
        if normalized_method not in {"GET", "POST", "PUT"}:
            raise ReleaseGitHubAppError("GitHub API method is invalid")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path.startswith("//")
            or "://" in path
            or "\r" in path
            or "\n" in path
            or "#" in path
        ):
            raise ReleaseGitHubAppError("GitHub API path is invalid")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
            or timeout_seconds > 120
        ):
            raise ReleaseGitHubAppError("GitHub API timeout is invalid")
        _validate_transport_authority(normalized_method, path, body)
        if any(
            isinstance(key, str)
            and key.lower() in {"host", "proxy-authorization"}
            for key in headers
        ):
            raise ReleaseGitHubAppError(
                "caller-selected authority headers are not permitted"
            )
        connection = http.client.HTTPSConnection(
            API_HOST,
            API_PORT,
            timeout=float(timeout_seconds),
            context=self._ssl_context,
        )
        try:
            connection.request(
                normalized_method,
                path,
                body=body,
                headers=dict(headers),
            )
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ReleaseGitHubAppError(
                    "GitHub API response exceeds size limit"
                )
            response_headers: dict[str, str] = {}
            for key, value in response.getheaders():
                normalized_key = key.lower()
                if normalized_key in response_headers:
                    raise ReleaseGitHubAppError(
                        "GitHub API returned duplicate response headers"
                    )
                response_headers[normalized_key] = value
            return ReleaseHTTPResponse(
                status=response.status,
                headers=response_headers,
                body=raw,
            )
        except ReleaseGitHubAppError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise ReleaseGitHubAppError("GitHub API transport failed") from exc
        finally:
            connection.close()


@dataclass(frozen=True)
class ReleaseInstallationCredential:
    token: str
    expires_at: datetime
    repository_id: int
    installation_id: int
    app_slug: str
    permissions: Mapping[str, str]


def _duplicate_rejecting_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ReleaseGitHubAppError(
                "GitHub API returned duplicate JSON fields"
            )
        output[key] = value
    return output


def _reject_nonfinite(_: str) -> None:
    raise ReleaseGitHubAppError(
        "GitHub API returned a non-finite JSON number"
    )


def _json_loads(raw: bytes) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_nonfinite,
        )
    except ReleaseGitHubAppError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseGitHubAppError(
            "GitHub API returned invalid JSON"
        ) from exc


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ReleaseGitHubAppError(
            "GitHub request payload is not canonical JSON"
        ) from exc


def _base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _validate_rate_header(headers: Mapping[str, str]) -> int:
    values = [
        value
        for key, value in headers.items()
        if isinstance(key, str) and key.lower() == "x-ratelimit-remaining"
    ]
    if len(values) != 1:
        raise ReleaseGitHubAppError(
            "GitHub REST rate-limit header is missing or duplicated"
        )
    try:
        remaining = int(values[0])
    except (TypeError, ValueError) as exc:
        raise ReleaseGitHubAppError(
            "GitHub REST rate-limit header is invalid"
        ) from exc
    if remaining < 0:
        raise ReleaseGitHubAppError(
            "GitHub REST rate-limit header is invalid"
        )
    return remaining


def _validate_full_oid(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise ReleaseGitHubAppError(f"{field} is invalid")
    normalized = value.lower()
    if value != normalized or not OID_RE.fullmatch(normalized):
        raise ReleaseGitHubAppError(f"{field} must be a full lowercase OID")
    return normalized


def _validate_transport_authority(
    method: str,
    path: str,
    body: bytes | None,
) -> None:
    """Apply the release HTTP allowlist even to direct transport callers."""

    if method == "GET":
        if body is not None or not (
            path == "/app"
            or path == "/installation/repositories?per_page=100"
            or re.fullmatch(r"/app/installations/[1-9][0-9]*", path)
        ):
            raise ReleaseGitHubAppError(
                "GitHub transport request is outside the release allowlist"
            )
        return
    if method == "POST" and re.fullmatch(
        r"/app/installations/[1-9][0-9]*/access_tokens",
        path,
    ):
        if body is None:
            raise ReleaseGitHubAppError(
                "installation-token request body is missing"
            )
        payload = _json_loads(body)
        if (
            not isinstance(payload, dict)
            or set(payload) != {"repository_ids", "permissions"}
            or not isinstance(payload.get("repository_ids"), list)
            or len(payload["repository_ids"]) != 1
            or isinstance(payload["repository_ids"][0], bool)
            or not isinstance(payload["repository_ids"][0], int)
            or payload["repository_ids"][0] <= 0
            or payload.get("permissions") != TOKEN_REQUEST_PERMISSIONS
        ):
            raise ReleaseGitHubAppError(
                "installation-token request authority is invalid"
            )
        return
    if method == "POST" and path == "/graphql":
        if body is None:
            raise ReleaseGitHubAppError("GraphQL request body is missing")
        payload = _json_loads(body)
        if (
            not isinstance(payload, dict)
            or set(payload) != {"query", "variables"}
            or not isinstance(payload.get("query"), str)
            or not payload["query"].lstrip().startswith("query ")
            or re.search(
                r"\b(?:mutation|subscription)\b",
                payload["query"],
                re.I,
            )
            or not isinstance(payload.get("variables"), dict)
        ):
            raise ReleaseGitHubAppError(
                "release GraphQL authority is read-only"
            )
        return
    if method == "PUT" and MERGE_PATH_RE.fullmatch(path):
        if body is None:
            raise ReleaseGitHubAppError("release merge body is missing")
        payload = _json_loads(body)
        if (
            not isinstance(payload, dict)
            or set(payload) != {"sha", "merge_method"}
            or payload.get("merge_method") != "squash"
        ):
            raise ReleaseGitHubAppError(
                "release merge payload is invalid"
            )
        _validate_full_oid(
            payload.get("sha"), field="release merge head OID"
        )
        return
    raise ReleaseGitHubAppError(
        "GitHub transport request is outside the release allowlist"
    )


def _trusted_id(value: Any, *, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > 2**31 - 1
    ):
        raise ReleaseGitHubAppError(f"{field} is invalid")
    return value


def _private_key_mode(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value not in {0o600, 0o640}
    ):
        raise ReleaseGitHubAppError(
            "release GitHub App private key mode must be 0600 or 0640"
        )
    return value


def _key_snapshot(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_uid),
        int(info.st_gid),
        int(info.st_nlink),
        int(info.st_size),
        int(
            getattr(
                info,
                "st_mtime_ns",
                round(float(info.st_mtime) * 1_000_000_000),
            )
        ),
        int(
            getattr(
                info,
                "st_ctime_ns",
                round(float(info.st_ctime) * 1_000_000_000),
            )
        ),
    )


def read_private_key_snapshot(
    path: Path,
    *,
    expected_owner_uid: int,
    expected_gid: int,
    expected_mode: int,
) -> bytes:
    path = Path(path)
    text = str(path)
    if (
        not path.is_absolute()
        or "\x00" in text
        or ".." in path.parts
        or "." in path.parts
        or text != str(Path(text))
    ):
        raise ReleaseGitHubAppError(
            "release GitHub App private key path must be normalized "
            "and absolute"
        )
    owner_uid = _trusted_id(
        expected_owner_uid,
        field="release GitHub App private key owner UID",
    )
    group_id = _trusted_id(
        expected_gid,
        field="release GitHub App private key GID",
    )
    mode = _private_key_mode(expected_mode)
    if not hasattr(os, "O_NOFOLLOW"):
        raise ReleaseGitHubAppError(
            "release GitHub App private key cannot be opened safely"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReleaseGitHubAppError(
            "release GitHub App private key is unreadable"
        ) from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ReleaseGitHubAppError(
                "release GitHub App private key must be a regular file"
            )
        if before.st_nlink != 1:
            raise ReleaseGitHubAppError(
                "release GitHub App private key must not have hard links"
            )
        if before.st_uid != owner_uid:
            raise ReleaseGitHubAppError(
                "release GitHub App private key owner is untrusted"
            )
        if before.st_gid != group_id:
            raise ReleaseGitHubAppError(
                "release GitHub App private key group is untrusted"
            )
        if stat.S_IMODE(before.st_mode) != mode:
            raise ReleaseGitHubAppError(
                "release GitHub App private key mode must be exactly "
                f"{mode:04o}"
            )
        if before.st_size <= 0 or before.st_size > MAX_PRIVATE_KEY_BYTES:
            raise ReleaseGitHubAppError(
                "release GitHub App private key size is invalid"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                fd,
                min(64 * 1024, MAX_PRIVATE_KEY_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_PRIVATE_KEY_BYTES:
                raise ReleaseGitHubAppError(
                    "release GitHub App private key exceeds size limit"
                )
        raw = b"".join(chunks)
        try:
            after = os.fstat(fd)
            named = os.lstat(path)
        except OSError as exc:
            raise ReleaseGitHubAppError(
                "release GitHub App private key changed while being read"
            ) from exc
        if (
            _key_snapshot(before) != _key_snapshot(after)
            or _key_snapshot(after) != _key_snapshot(named)
            or len(raw) != before.st_size
        ):
            raise ReleaseGitHubAppError(
                "release GitHub App private key changed while being read"
            )
        if b"PRIVATE KEY" not in raw:
            raise ReleaseGitHubAppError(
                "release GitHub App private key is not PEM encoded"
            )
        return raw
    finally:
        os.close(fd)


def generate_release_app_jwt(
    *,
    app_id: int,
    private_key_path: Path,
    private_key_owner_uid: int,
    private_key_gid: int,
    private_key_mode: int,
    now: datetime | None = None,
    lifetime_seconds: int = 540,
) -> str:
    if isinstance(app_id, bool) or not isinstance(app_id, int) or app_id <= 0:
        raise ReleaseGitHubAppError("release GitHub App id is invalid")
    if (
        isinstance(lifetime_seconds, bool)
        or not isinstance(lifetime_seconds, int)
        or lifetime_seconds < 60
        or lifetime_seconds > 540
    ):
        raise ReleaseGitHubAppError(
            "release GitHub App JWT lifetime is invalid"
        )
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    issued_at = int(current.timestamp()) - 30
    expires_at = int(current.timestamp()) + lifetime_seconds
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"exp": expires_at, "iat": issued_at, "iss": str(app_id)}
    signing_input = (
        f"{_base64url(_canonical_json(header))}."
        f"{_base64url(_canonical_json(payload))}"
    ).encode("ascii")
    key_bytes = read_private_key_snapshot(
        private_key_path,
        expected_owner_uid=private_key_owner_uid,
        expected_gid=private_key_gid,
        expected_mode=private_key_mode,
    )
    try:
        private_key = serialization.load_pem_private_key(
            key_bytes,
            password=None,
        )
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise ReleaseGitHubAppError(
            "release GitHub App private key is invalid"
        ) from exc
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ReleaseGitHubAppError(
            "release GitHub App private key must be RSA"
        )
    if private_key.key_size < 2048:
        raise ReleaseGitHubAppError(
            "release GitHub App RSA private key is too small"
        )
    try:
        signature = private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise ReleaseGitHubAppError(
            "release GitHub App JWT signing failed"
        ) from exc
    return f"{signing_input.decode('ascii')}.{_base64url(signature)}"


class ReleaseGitHubAppClient:
    """Narrow GitHub App client with a transport-level authority allowlist."""

    def __init__(
        self,
        *,
        app_id: int,
        installation_id: int,
        app_slug: str,
        private_key_path: Path,
        private_key_owner_uid: int,
        private_key_gid: int,
        private_key_mode: int,
        repository_id: int,
        transport: ReleaseHTTPTransport | None = None,
        timeout_seconds: float = 20,
    ) -> None:
        if (
            isinstance(app_id, bool)
            or not isinstance(app_id, int)
            or app_id <= 0
        ):
            raise ReleaseGitHubAppError("release GitHub App id is invalid")
        if (
            isinstance(installation_id, bool)
            or not isinstance(installation_id, int)
            or installation_id <= 0
        ):
            raise ReleaseGitHubAppError(
                "release GitHub App installation id is invalid"
            )
        if (
            isinstance(repository_id, bool)
            or not isinstance(repository_id, int)
            or repository_id <= 0
        ):
            raise ReleaseGitHubAppError("GitHub repository id is invalid")
        if (
            not isinstance(app_slug, str)
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?",
                app_slug,
            )
        ):
            raise ReleaseGitHubAppError(
                "release GitHub App slug is invalid"
            )
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
            or timeout_seconds > 120
        ):
            raise ReleaseGitHubAppError("GitHub API timeout is invalid")
        self.app_id = app_id
        self.installation_id = installation_id
        self.app_slug = app_slug
        self.private_key_path = Path(private_key_path)
        self.private_key_owner_uid = _trusted_id(
            private_key_owner_uid,
            field="release GitHub App private key owner UID",
        )
        self.private_key_gid = _trusted_id(
            private_key_gid,
            field="release GitHub App private key GID",
        )
        self.private_key_mode = _private_key_mode(private_key_mode)
        self.repository_id = repository_id
        self.transport = transport or FixedReleaseGitHubTransport()
        self.timeout_seconds = float(timeout_seconds)

    @staticmethod
    def _headers(token: str) -> dict[str, str]:
        if (
            not isinstance(token, str)
            or not token
            or "\r" in token
            or "\n" in token
        ):
            raise ReleaseGitHubAppError("GitHub credential is invalid")
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        }

    def _perform_json(
        self,
        method: str,
        path: str,
        *,
        token: str,
        payload: Any | None,
        expected_statuses: frozenset[int],
    ) -> tuple[Any, Mapping[str, str]]:
        body = _canonical_json(payload) if payload is not None else None
        headers = self._headers(token)
        if body is not None:
            headers["Content-Type"] = "application/json"
        response = self.transport.request(
            method,
            path,
            headers=headers,
            body=body,
            timeout_seconds=self.timeout_seconds,
        )
        # Raw transport never follows redirects.  Any redirect is just an
        # unexpected status, and neither response bodies nor tokens enter the
        # exception.
        if response.status not in expected_statuses:
            raise ReleaseGitHubAppError(
                f"GitHub API request failed with status {response.status}"
            )
        _validate_rate_header(response.headers)
        return _json_loads(response.body), response.headers

    def _app_request_json(
        self,
        method: str,
        path: str,
        *,
        app_jwt: str,
        payload: Any | None = None,
        expected_statuses: frozenset[int] = frozenset({200}),
    ) -> tuple[Any, Mapping[str, str]]:
        normalized_method = method.upper()
        allowed = {
            ("GET", "/app"),
            (
                "GET",
                f"/app/installations/{self.installation_id}",
            ),
            (
                "POST",
                f"/app/installations/{self.installation_id}/access_tokens",
            ),
        }
        if (normalized_method, path) not in allowed:
            raise ReleaseGitHubAppError(
                "release App credential request is outside the allowlist"
            )
        if normalized_method == "POST":
            expected = {
                "repository_ids": [self.repository_id],
                "permissions": TOKEN_REQUEST_PERMISSIONS,
            }
            if payload != expected:
                raise ReleaseGitHubAppError(
                    "installation-token request authority is invalid"
                )
        elif payload is not None:
            raise ReleaseGitHubAppError(
                "release App read request must not carry a body"
            )
        return self._perform_json(
            normalized_method,
            path,
            token=app_jwt,
            payload=payload,
            expected_statuses=expected_statuses,
        )

    def installation_request_json(
        self,
        method: str,
        path: str,
        *,
        token: str,
        payload: Any | None = None,
        expected_statuses: frozenset[int] = frozenset({200}),
    ) -> tuple[Any, Mapping[str, str]]:
        """Use an installation token inside the exact release allowlist."""

        normalized_method = method.upper()
        if (
            normalized_method == "GET"
            and path == "/installation/repositories?per_page=100"
            and payload is None
        ):
            pass
        elif normalized_method == "POST" and path == "/graphql":
            if not isinstance(payload, dict) or set(payload) != {
                "query",
                "variables",
            }:
                raise ReleaseGitHubAppError(
                    "GraphQL request payload is invalid"
                )
            query = payload.get("query")
            variables = payload.get("variables")
            if (
                not isinstance(query, str)
                or not query.lstrip().startswith("query ")
                or re.search(r"\b(?:mutation|subscription)\b", query, re.I)
                or not isinstance(variables, dict)
            ):
                raise ReleaseGitHubAppError(
                    "release GraphQL authority is read-only"
                )
        elif normalized_method == "PUT" and MERGE_PATH_RE.fullmatch(path):
            if (
                not isinstance(payload, dict)
                or set(payload) != {"sha", "merge_method"}
                or payload.get("merge_method") != "squash"
            ):
                raise ReleaseGitHubAppError(
                    "release merge payload is invalid"
                )
            _validate_full_oid(
                payload.get("sha"), field="release merge head OID"
            )
        else:
            raise ReleaseGitHubAppError(
                "installation-token request is outside the release allowlist"
            )
        return self._perform_json(
            normalized_method,
            path,
            token=token,
            payload=payload,
            expected_statuses=expected_statuses,
        )

    def graphql(
        self,
        *,
        token: str,
        query: str,
        variables: Mapping[str, Any],
    ) -> tuple[dict[str, Any], Mapping[str, str]]:
        data, headers = self.installation_request_json(
            "POST",
            "/graphql",
            token=token,
            payload={"query": query, "variables": dict(variables)},
        )
        if not isinstance(data, dict):
            raise ReleaseGitHubAppError(
                "GitHub GraphQL response must be an object"
            )
        errors = data.get("errors")
        if errors:
            raise ReleaseGitHubAppError(
                "GitHub GraphQL request returned errors"
            )
        result = data.get("data")
        if not isinstance(result, dict):
            raise ReleaseGitHubAppError(
                "GitHub GraphQL response is missing data"
            )
        return result, headers

    def authenticate_installation(
        self,
        *,
        now: datetime | None = None,
    ) -> ReleaseInstallationCredential:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        app_jwt = generate_release_app_jwt(
            app_id=self.app_id,
            private_key_path=self.private_key_path,
            private_key_owner_uid=self.private_key_owner_uid,
            private_key_gid=self.private_key_gid,
            private_key_mode=self.private_key_mode,
            now=current,
        )
        app, _ = self._app_request_json("GET", "/app", app_jwt=app_jwt)
        if (
            not isinstance(app, dict)
            or app.get("id") != self.app_id
            or app.get("slug") != self.app_slug
        ):
            raise ReleaseGitHubAppError(
                "release GitHub App identity does not match config"
            )

        installation, _ = self._app_request_json(
            "GET",
            f"/app/installations/{self.installation_id}",
            app_jwt=app_jwt,
        )
        if (
            not isinstance(installation, dict)
            or installation.get("id") != self.installation_id
            or installation.get("app_id") != self.app_id
        ):
            raise ReleaseGitHubAppError(
                "release GitHub App installation does not match config"
            )
        installation_permissions = installation.get("permissions")
        if (
            not isinstance(installation_permissions, dict)
            or {
                str(key): str(value)
                for key, value in installation_permissions.items()
            }
            != REQUIRED_PERMISSIONS
        ):
            raise ReleaseGitHubAppError(
                "release GitHub App installation permissions do not exactly "
                "match release authority"
            )
        if installation.get("suspended_at") is not None:
            raise ReleaseGitHubAppError(
                "release GitHub App installation is suspended"
            )

        token_data, _ = self._app_request_json(
            "POST",
            f"/app/installations/{self.installation_id}/access_tokens",
            app_jwt=app_jwt,
            payload={
                "repository_ids": [self.repository_id],
                "permissions": TOKEN_REQUEST_PERMISSIONS,
            },
            expected_statuses=frozenset({201}),
        )
        if not isinstance(token_data, dict):
            raise ReleaseGitHubAppError(
                "installation-token response must be an object"
            )
        token = token_data.get("token")
        expires_text = token_data.get("expires_at")
        permissions = token_data.get("permissions")
        if (
            not isinstance(token, str)
            or not token
            or "\r" in token
            or "\n" in token
        ):
            raise ReleaseGitHubAppError("installation token is invalid")
        if not isinstance(expires_text, str):
            raise ReleaseGitHubAppError(
                "installation token expiry is invalid"
            )
        try:
            expires_at = datetime.strptime(
                expires_text, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise ReleaseGitHubAppError(
                "installation token expiry is invalid"
            ) from exc
        remaining = (expires_at - current).total_seconds()
        if remaining < 60 or remaining > MAX_TOKEN_LIFETIME_SECONDS:
            raise ReleaseGitHubAppError(
                "installation token lifetime is invalid"
            )
        if not isinstance(permissions, dict):
            raise ReleaseGitHubAppError(
                "installation token permissions are missing"
            )
        normalized_permissions = {
            str(key): str(value) for key, value in permissions.items()
        }
        if normalized_permissions != REQUIRED_PERMISSIONS:
            raise ReleaseGitHubAppError(
                "installation token permissions do not exactly match "
                "release authority"
            )

        repositories, _ = self.installation_request_json(
            "GET",
            "/installation/repositories?per_page=100",
            token=token,
        )
        if not isinstance(repositories, dict):
            raise ReleaseGitHubAppError(
                "installation repository response is invalid"
            )
        items = repositories.get("repositories")
        total_count = repositories.get("total_count")
        if (
            isinstance(total_count, bool)
            or not isinstance(total_count, int)
            or total_count != 1
            or not isinstance(items, list)
            or len(items) != 1
            or not isinstance(items[0], dict)
            or items[0].get("id") != self.repository_id
        ):
            raise ReleaseGitHubAppError(
                "installation token is not restricted to the configured "
                "repository"
            )
        return ReleaseInstallationCredential(
            token=token,
            expires_at=expires_at,
            repository_id=self.repository_id,
            installation_id=self.installation_id,
            app_slug=self.app_slug,
            permissions=normalized_permissions,
        )


def key_sha256(
    path: Path,
    *,
    expected_owner_uid: int,
    expected_gid: int,
    expected_mode: int,
) -> str:
    """Return the digest of the stable release-App key snapshot."""

    return hashlib.sha256(
        read_private_key_snapshot(
            path,
            expected_owner_uid=expected_owner_uid,
            expected_gid=expected_gid,
            expected_mode=expected_mode,
        )
    ).hexdigest()


# Concise aliases make the module convenient without obscuring the separate
# package/identity boundary.
GitHubAppClient = ReleaseGitHubAppClient
GitHubAppError = ReleaseGitHubAppError
HTTPResponse = ReleaseHTTPResponse
InstallationCredential = ReleaseInstallationCredential
FixedGitHubTransport = FixedReleaseGitHubTransport
generate_app_jwt = generate_release_app_jwt
