"""Credential-isolated GitHub App authentication for the protected broker.

This module deliberately does not use ``gh``, caller environment tokens, proxy
configuration, or repository code.  The broker owns the App private key and
keeps installation tokens in memory only.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import ssl
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


API_HOST = "api.github.com"
API_PORT = 443
API_VERSION = "2022-11-28"
USER_AGENT = "john-lomein-protected-broker/1"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_PRIVATE_KEY_BYTES = 128 * 1024
MAX_TOKEN_LIFETIME_SECONDS = 3700
REQUESTED_PERMISSIONS = {
    "checks": "read",
    "issues": "read",
    "pull_requests": "write",
    "statuses": "read",
}
ALLOWED_RETURNED_PERMISSIONS = {
    **REQUESTED_PERMISSIONS,
    "metadata": "read",
}
TLS_TRUST_ENV_KEYS = frozenset(
    {
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "NODE_EXTRA_CA_CERTS",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SSLKEYLOGFILE",
    }
)


class GitHubAppError(RuntimeError):
    """A fail-closed GitHub App authentication or transport failure."""


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class HTTPTransport(Protocol):
    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> HTTPResponse:
        """Perform one request against the fixed GitHub API origin."""


class FixedGitHubTransport:
    """Direct TLS transport that ignores all proxy-related environment state."""

    def __init__(self, *, ssl_context: ssl.SSLContext | None = None) -> None:
        if any(os.environ.get(key) for key in TLS_TRUST_ENV_KEYS):
            raise GitHubAppError(
                "TLS trust environment overrides are not permitted"
            )
        self._ssl_context = ssl_context or ssl.create_default_context()

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> HTTPResponse:
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path.startswith("//")
            or "://" in path
            or "\r" in path
            or "\n" in path
        ):
            raise GitHubAppError("GitHub API path is invalid")
        connection = http.client.HTTPSConnection(
            API_HOST,
            API_PORT,
            timeout=timeout_seconds,
            context=self._ssl_context,
        )
        try:
            connection.request(
                method.upper(),
                path,
                body=body,
                headers=dict(headers),
            )
            response = connection.getresponse()
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise GitHubAppError("GitHub API response exceeds size limit")
            return HTTPResponse(
                status=response.status,
                headers={key.lower(): value for key, value in response.getheaders()},
                body=raw,
            )
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise GitHubAppError("GitHub API transport failed") from exc
        finally:
            connection.close()


@dataclass(frozen=True)
class InstallationCredential:
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
            raise GitHubAppError("GitHub API returned duplicate JSON fields")
        output[key] = value
    return output


def _reject_nonfinite(_: str) -> None:
    raise GitHubAppError("GitHub API returned a non-finite JSON number")


def _json_loads(raw: bytes) -> Any:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_nonfinite,
        )
    except GitHubAppError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise GitHubAppError("GitHub API returned invalid JSON") from exc


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def read_private_key_snapshot(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise GitHubAppError("GitHub App private key is unreadable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise GitHubAppError("GitHub App private key must be a regular file")
        if info.st_size <= 0 or info.st_size > MAX_PRIVATE_KEY_BYTES:
            raise GitHubAppError("GitHub App private key size is invalid")
        if info.st_mode & 0o077:
            raise GitHubAppError(
                "GitHub App private key must not be accessible by group or others"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, MAX_PRIVATE_KEY_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_PRIVATE_KEY_BYTES:
                raise GitHubAppError("GitHub App private key exceeds size limit")
        raw = b"".join(chunks)
        if b"PRIVATE KEY" not in raw:
            raise GitHubAppError("GitHub App private key is not PEM encoded")
        return raw
    finally:
        os.close(fd)


def generate_app_jwt(
    *,
    app_id: int,
    private_key_path: Path,
    now: datetime | None = None,
    lifetime_seconds: int = 540,
) -> str:
    if isinstance(app_id, bool) or not isinstance(app_id, int) or app_id <= 0:
        raise GitHubAppError("GitHub App id is invalid")
    if (
        isinstance(lifetime_seconds, bool)
        or not isinstance(lifetime_seconds, int)
        or lifetime_seconds < 60
        or lifetime_seconds > 540
    ):
        raise GitHubAppError("GitHub App JWT lifetime is invalid")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    issued_at = int(current.timestamp()) - 30
    expires_at = int(current.timestamp()) + lifetime_seconds
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"exp": expires_at, "iat": issued_at, "iss": str(app_id)}
    signing_input = (
        f"{_base64url(_canonical_json(header))}."
        f"{_base64url(_canonical_json(payload))}"
    ).encode("ascii")
    key_bytes = read_private_key_snapshot(private_key_path)
    try:
        private_key = serialization.load_pem_private_key(
            key_bytes,
            password=None,
        )
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise GitHubAppError("GitHub App private key is invalid") from exc
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise GitHubAppError("GitHub App private key must be RSA")
    if private_key.key_size < 2048:
        raise GitHubAppError("GitHub App RSA private key is too small")
    try:
        signature = private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise GitHubAppError("GitHub App JWT signing failed") from exc
    return f"{signing_input.decode('ascii')}.{_base64url(signature)}"


class GitHubAppClient:
    def __init__(
        self,
        *,
        app_id: int,
        installation_id: int,
        app_slug: str,
        private_key_path: Path,
        repository_id: int,
        transport: HTTPTransport | None = None,
        timeout_seconds: float = 20,
    ) -> None:
        if (
            isinstance(installation_id, bool)
            or not isinstance(installation_id, int)
            or installation_id <= 0
        ):
            raise GitHubAppError("GitHub App installation id is invalid")
        if (
            isinstance(repository_id, bool)
            or not isinstance(repository_id, int)
            or repository_id <= 0
        ):
            raise GitHubAppError("GitHub repository id is invalid")
        if not isinstance(app_slug, str) or not app_slug:
            raise GitHubAppError("GitHub App slug is invalid")
        self.app_id = app_id
        self.installation_id = installation_id
        self.app_slug = app_slug
        self.private_key_path = Path(private_key_path)
        self.repository_id = repository_id
        self.transport = transport or FixedGitHubTransport()
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _headers(token: str | None = None) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def request_json(
        self,
        method: str,
        path: str,
        *,
        token: str,
        payload: Any | None = None,
        expected_statuses: frozenset[int] = frozenset({200}),
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
        if response.status not in expected_statuses:
            raise GitHubAppError(
                f"GitHub API request failed with status {response.status}"
            )
        return _json_loads(response.body), response.headers

    def graphql(
        self,
        *,
        token: str,
        query: str,
        variables: Mapping[str, Any],
    ) -> tuple[dict[str, Any], Mapping[str, str]]:
        data, headers = self.request_json(
            "POST",
            "/graphql",
            token=token,
            payload={"query": query, "variables": dict(variables)},
        )
        if not isinstance(data, dict):
            raise GitHubAppError("GitHub GraphQL response must be an object")
        errors = data.get("errors")
        if errors:
            raise GitHubAppError("GitHub GraphQL request returned errors")
        result = data.get("data")
        if not isinstance(result, dict):
            raise GitHubAppError("GitHub GraphQL response is missing data")
        return result, headers

    def authenticate_installation(
        self,
        *,
        now: datetime | None = None,
    ) -> InstallationCredential:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        app_jwt = generate_app_jwt(
            app_id=self.app_id,
            private_key_path=self.private_key_path,
            now=current,
        )
        app, _ = self.request_json("GET", "/app", token=app_jwt)
        if (
            not isinstance(app, dict)
            or app.get("id") != self.app_id
            or app.get("slug") != self.app_slug
        ):
            raise GitHubAppError("GitHub App identity does not match broker config")

        installation, _ = self.request_json(
            "GET",
            f"/app/installations/{self.installation_id}",
            token=app_jwt,
        )
        if (
            not isinstance(installation, dict)
            or installation.get("id") != self.installation_id
            or installation.get("app_id") != self.app_id
        ):
            raise GitHubAppError(
                "GitHub App installation does not match broker config"
            )

        token_data, _ = self.request_json(
            "POST",
            f"/app/installations/{self.installation_id}/access_tokens",
            token=app_jwt,
            payload={
                "repository_ids": [self.repository_id],
                "permissions": REQUESTED_PERMISSIONS,
            },
            expected_statuses=frozenset({201}),
        )
        if not isinstance(token_data, dict):
            raise GitHubAppError("installation-token response must be an object")
        token = token_data.get("token")
        expires_text = token_data.get("expires_at")
        permissions = token_data.get("permissions")
        if (
            not isinstance(token, str)
            or not token
            or "\r" in token
            or "\n" in token
        ):
            raise GitHubAppError("installation token is invalid")
        if not isinstance(expires_text, str):
            raise GitHubAppError("installation token expiry is invalid")
        try:
            expires_at = datetime.strptime(
                expires_text, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise GitHubAppError("installation token expiry is invalid") from exc
        remaining = (expires_at - current).total_seconds()
        if remaining < 60 or remaining > MAX_TOKEN_LIFETIME_SECONDS:
            raise GitHubAppError("installation token lifetime is invalid")
        if not isinstance(permissions, dict):
            raise GitHubAppError("installation token permissions are missing")
        normalized_permissions = {
            str(key): str(value) for key, value in permissions.items()
        }
        for name, level in REQUESTED_PERMISSIONS.items():
            if normalized_permissions.get(name) != level:
                raise GitHubAppError(
                    "installation token lacks the broker permission subset"
                )
        for name, level in normalized_permissions.items():
            if ALLOWED_RETURNED_PERMISSIONS.get(name) != level:
                raise GitHubAppError(
                    "installation token carries an unexpected permission"
                )

        repositories, _ = self.request_json(
            "GET",
            "/installation/repositories?per_page=100",
            token=token,
        )
        if not isinstance(repositories, dict):
            raise GitHubAppError("installation repository response is invalid")
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
            raise GitHubAppError(
                "installation token is not restricted to the configured repository"
            )
        return InstallationCredential(
            token=token,
            expires_at=expires_at,
            repository_id=self.repository_id,
            installation_id=self.installation_id,
            app_slug=self.app_slug,
            permissions=normalized_permissions,
        )


def key_sha256(path: Path) -> str:
    """Return a digest of the stable key snapshot for diagnostics/tests."""

    return hashlib.sha256(read_private_key_snapshot(path)).hexdigest()
