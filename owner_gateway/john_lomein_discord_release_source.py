"""Independently verify a Discord owner approval before release signing.

Hermes is intentionally treated as an untrusted requester here.  It may name
an already-authorized channel and a message ID, but it cannot provide the
message body, actor identity, guild identity, or observation timestamp that
the release-owner signer trusts.  This module retrieves those facts directly
from Discord over a fixed TLS origin using a read-only bot credential.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from owner_gateway import john_lomein_release_owner_signer as signer
from release_broker import john_lomein_release_broker_protocol as protocol


SOURCE_CONFIG_SCHEMA = "john-lomein.release-owner-discord-source-config.v1"
API_BASE_URL = "https://discord.com/api/v10"
API_HOST = "discord.com"
API_PORT = 443
API_PREFIX = "/api/v10"
USER_AGENT = "john-lomein-release-owner-gateway/1"

MAX_SOURCE_CONFIG_BYTES = 128 * 1024
MAX_BOT_TOKEN_BYTES = 512
MIN_RESPONSE_BYTES = 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 30
ALLOWED_CHANNEL_TYPES = frozenset({0, 5, 10, 11, 12})

BOT_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]{20,511}$")
ALLOWED_PATH_RE = re.compile(
    r"^/api/v10/(?:"
    r"applications/@me|"
    r"users/@me|"
    r"channels/[0-9]{17,20}|"
    r"channels/[0-9]{17,20}/messages/[0-9]{17,20}"
    r")$"
)

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


class DiscordReleaseSourceError(signer.ReleaseOwnerSignerError):
    """A fail-closed Discord source configuration or verification failure."""


@dataclass(frozen=True)
class DiscordHTTPResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class DiscordHTTPTransport(Protocol):
    def request(
        self,
        path: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
        maximum_response_bytes: int,
    ) -> DiscordHTTPResponse:
        """Perform one GET against the fixed Discord API origin."""


class FixedDiscordTransport:
    """Direct Discord TLS transport with no proxy or caller-selected CA roots."""

    def __init__(self, *, ssl_context: ssl.SSLContext | None = None) -> None:
        if any(os.environ.get(key) for key in UNTRUSTED_NETWORK_ENV_KEYS):
            raise DiscordReleaseSourceError(
                "network or TLS environment overrides are not permitted"
            )
        context = ssl_context or ssl.create_default_context()
        if (
            context.verify_mode != ssl.CERT_REQUIRED
            or not context.check_hostname
        ):
            raise DiscordReleaseSourceError(
                "Discord TLS context must verify certificates and hostnames"
            )
        if hasattr(ssl, "TLSVersion"):
            if context.minimum_version < ssl.TLSVersion.TLSv1_2:
                context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._ssl_context = context

    def request(
        self,
        path: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
        maximum_response_bytes: int,
    ) -> DiscordHTTPResponse:
        _validate_request(path, timeout_seconds, maximum_response_bytes)
        if any(
            isinstance(key, str)
            and key.lower() in {"host", "proxy-authorization"}
            for key in headers
        ):
            raise DiscordReleaseSourceError(
                "caller-selected authority headers are not permitted"
            )
        connection = http.client.HTTPSConnection(
            API_HOST,
            API_PORT,
            timeout=float(timeout_seconds),
            context=self._ssl_context,
        )
        try:
            connection.request("GET", path, body=None, headers=dict(headers))
            response = connection.getresponse()
            raw = response.read(maximum_response_bytes + 1)
            if len(raw) > maximum_response_bytes:
                raise DiscordReleaseSourceError(
                    "Discord API response exceeds size limit"
                )
            response_headers: dict[str, str] = {}
            for key, value in response.getheaders():
                normalized_key = key.lower()
                if normalized_key in response_headers:
                    raise DiscordReleaseSourceError(
                        "Discord API returned duplicate response headers"
                    )
                response_headers[normalized_key] = value
            return DiscordHTTPResponse(
                status=response.status,
                headers=response_headers,
                body=raw,
            )
        except DiscordReleaseSourceError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise DiscordReleaseSourceError(
                "Discord API transport failed"
            ) from exc
        finally:
            connection.close()


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DiscordReleaseSourceError(f"{field} must be an object")
    return value


def _strict_keys(
    value: dict[str, Any],
    *,
    field: str,
    required: set[str],
) -> None:
    if set(value) != required:
        raise DiscordReleaseSourceError(
            f"{field} fields do not match the required schema"
        )


def _bounded_int(
    value: Any,
    *,
    field: str,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise DiscordReleaseSourceError(f"{field} is outside the allowed range")
    return value


def _snowflake(value: Any, *, field: str) -> str:
    text = str(value or "")
    if not signer.SNOWFLAKE_RE.fullmatch(text):
        raise DiscordReleaseSourceError(f"{field} must be a Discord snowflake")
    return text


def _digest(value: Any, *, field: str) -> str:
    text = str(value or "")
    if not protocol.SHA256_RE.fullmatch(text):
        raise DiscordReleaseSourceError(f"{field} must be a SHA-256 digest")
    return text


def _absolute_path(value: Any, *, field: str) -> str:
    try:
        return signer._absolute_path(value, field=field)
    except signer.ReleaseOwnerSignerError as exc:
        raise DiscordReleaseSourceError(str(exc)) from exc


def normalize_source_config(raw: Any, signer_config: Any) -> dict[str, Any]:
    normalized_signer = signer.normalize_signer_config(signer_config)
    config = _mapping(raw, field="Discord release source config")
    _strict_keys(
        config,
        field="Discord release source config",
        required={
            "schema_version",
            "enabled",
            "signer_id",
            "signer_config_sha256",
            "api_base_url",
            "bot_user_id",
            "bot_token_path",
            "request_timeout_seconds",
            "maximum_response_bytes",
        },
    )
    if config.get("schema_version") != SOURCE_CONFIG_SCHEMA:
        raise DiscordReleaseSourceError(
            "Discord release source config schema is unsupported"
        )
    if type(config.get("enabled")) is not bool:
        raise DiscordReleaseSourceError(
            "Discord release source enabled must be boolean"
        )
    signer_id = str(config.get("signer_id") or "")
    if signer_id != normalized_signer["signer_id"]:
        raise DiscordReleaseSourceError(
            "Discord release source signer binding does not match"
        )
    signer_config_sha256 = _digest(
        config.get("signer_config_sha256"),
        field="Discord release source signer-config fingerprint",
    )
    if signer_config_sha256 != protocol.sha256_json(normalized_signer):
        raise DiscordReleaseSourceError(
            "Discord release source signer-config fingerprint does not match"
        )
    if config.get("api_base_url") != API_BASE_URL:
        raise DiscordReleaseSourceError(
            "Discord release source API origin or version is unsupported"
        )
    bot_user_id = _snowflake(
        config.get("bot_user_id"), field="Discord observer bot user ID"
    )
    bot_token_path = _absolute_path(
        config.get("bot_token_path"), field="Discord observer bot-token path"
    )
    timeout = _bounded_int(
        config.get("request_timeout_seconds"),
        field="Discord API request timeout",
        minimum=MIN_TIMEOUT_SECONDS,
        maximum=MAX_TIMEOUT_SECONDS,
    )
    maximum_response_bytes = _bounded_int(
        config.get("maximum_response_bytes"),
        field="Discord API response limit",
        minimum=MIN_RESPONSE_BYTES,
        maximum=MAX_RESPONSE_BYTES,
    )
    return {
        "schema_version": SOURCE_CONFIG_SCHEMA,
        "enabled": config["enabled"],
        "signer_id": signer_id,
        "signer_config_sha256": signer_config_sha256,
        "api_base_url": API_BASE_URL,
        "bot_user_id": bot_user_id,
        "bot_token_path": bot_token_path,
        "request_timeout_seconds": timeout,
        "maximum_response_bytes": maximum_response_bytes,
    }


def load_source_config(
    path: Path,
    signer_config: Any,
    *,
    expected_owner_uid: int = 0,
    expected_group_gid: int | None = None,
    trusted_root: Path = Path("/"),
) -> dict[str, Any]:
    group_gid = os.getegid() if expected_group_gid is None else expected_group_gid
    try:
        raw = signer.read_secure_file(
            path,
            field="Discord release source config",
            maximum_bytes=MAX_SOURCE_CONFIG_BYTES,
            expected_owner_uid=expected_owner_uid,
            expected_group_gid=group_gid,
            exact_mode=0o440,
            trusted_root=trusted_root,
        )
        parsed = protocol.parse_json_bytes(
            raw,
            field="Discord release source config",
            maximum_bytes=MAX_SOURCE_CONFIG_BYTES,
        )
        return normalize_source_config(parsed, signer_config)
    except (signer.ReleaseOwnerSignerError, protocol.ReleaseBrokerProtocolError) as exc:
        raise DiscordReleaseSourceError(str(exc)) from exc


def load_bot_token(
    source_config: Any,
    signer_config: Any,
    *,
    expected_owner_uid: int = 0,
    trusted_root: Path = Path("/"),
) -> str:
    normalized_signer = signer.normalize_signer_config(signer_config)
    normalized_source = normalize_source_config(source_config, normalized_signer)
    try:
        raw = signer.read_secure_file(
            Path(normalized_source["bot_token_path"]),
            field="Discord observer bot token",
            maximum_bytes=MAX_BOT_TOKEN_BYTES,
            expected_owner_uid=expected_owner_uid,
            expected_group_gid=normalized_signer["signer_gid"],
            exact_mode=0o640,
            trusted_root=trusted_root,
        )
    except signer.ReleaseOwnerSignerError as exc:
        raise DiscordReleaseSourceError(str(exc)) from exc
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if b"\n" in raw or b"\r" in raw:
        raise DiscordReleaseSourceError("Discord observer bot token is invalid")
    try:
        token = raw.decode("ascii", errors="strict")
    except UnicodeError as exc:
        raise DiscordReleaseSourceError(
            "Discord observer bot token is invalid"
        ) from exc
    if not BOT_TOKEN_RE.fullmatch(token):
        raise DiscordReleaseSourceError("Discord observer bot token is invalid")
    return token


def _validate_request(
    path: str,
    timeout_seconds: float,
    maximum_response_bytes: int,
) -> None:
    if not isinstance(path, str) or not ALLOWED_PATH_RE.fullmatch(path):
        raise DiscordReleaseSourceError("Discord API path is not authorized")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or timeout_seconds < MIN_TIMEOUT_SECONDS
        or timeout_seconds > MAX_TIMEOUT_SECONDS
    ):
        raise DiscordReleaseSourceError("Discord API timeout is invalid")
    if (
        isinstance(maximum_response_bytes, bool)
        or not isinstance(maximum_response_bytes, int)
        or maximum_response_bytes < MIN_RESPONSE_BYTES
        or maximum_response_bytes > MAX_RESPONSE_BYTES
    ):
        raise DiscordReleaseSourceError("Discord API response limit is invalid")


def _duplicate_rejecting_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise DiscordReleaseSourceError(
                "Discord API returned duplicate JSON fields"
            )
        output[key] = value
    return output


def _reject_nonfinite(_: str) -> None:
    raise DiscordReleaseSourceError(
        "Discord API returned a non-finite JSON number"
    )


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_nonfinite,
        )
    except DiscordReleaseSourceError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DiscordReleaseSourceError(
            "Discord API returned invalid JSON"
        ) from exc
    return _mapping(parsed, field="Discord API response")


def _normalized_headers(raw: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        raise DiscordReleaseSourceError("Discord API response headers are invalid")
    output: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise DiscordReleaseSourceError(
                "Discord API response headers are invalid"
            )
        name = key.lower()
        if name in output:
            raise DiscordReleaseSourceError(
                "Discord API returned duplicate response headers"
            )
        output[name] = value
    return output


def _request_json(
    transport: DiscordHTTPTransport,
    path: str,
    *,
    token: str,
    source_config: dict[str, Any],
) -> dict[str, Any]:
    _validate_request(
        path,
        source_config["request_timeout_seconds"],
        source_config["maximum_response_bytes"],
    )
    response = transport.request(
        path,
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Authorization": f"Bot {token}",
            "User-Agent": USER_AGENT,
        },
        timeout_seconds=source_config["request_timeout_seconds"],
        maximum_response_bytes=source_config["maximum_response_bytes"],
    )
    if (
        isinstance(response.status, bool)
        or not isinstance(response.status, int)
        or response.status < 100
        or response.status > 599
    ):
        raise DiscordReleaseSourceError("Discord API status is invalid")
    headers = _normalized_headers(response.headers)
    if 300 <= response.status <= 399:
        raise DiscordReleaseSourceError("Discord API redirect was refused")
    if response.status == 429:
        raise DiscordReleaseSourceError("Discord API rate limit was refused")
    if response.status != 200:
        raise DiscordReleaseSourceError(
            f"Discord API request failed with HTTP {response.status}"
        )
    content_type = headers.get("content-type", "")
    if content_type.split(";", 1)[0].strip().lower() != "application/json":
        raise DiscordReleaseSourceError(
            "Discord API response content type is invalid"
        )
    content_encoding = headers.get("content-encoding", "identity").strip().lower()
    if content_encoding not in {"", "identity"}:
        raise DiscordReleaseSourceError(
            "Discord API response content encoding is unsupported"
        )
    if (
        not isinstance(response.body, bytes)
        or not response.body
        or len(response.body) > source_config["maximum_response_bytes"]
    ):
        raise DiscordReleaseSourceError("Discord API response size is invalid")
    return _json_object(response.body)


def _discord_timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise DiscordReleaseSourceError(f"{field} is invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise DiscordReleaseSourceError(f"{field} is invalid") from exc
    if parsed.tzinfo is None:
        raise DiscordReleaseSourceError(f"{field} is invalid")
    return parsed.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _verify_application(
    raw: Any,
    *,
    signer_config: dict[str, Any],
    source_config: dict[str, Any],
) -> None:
    application = _mapping(raw, field="Discord current application")
    application_id = _snowflake(
        application.get("id"), field="Discord current application ID"
    )
    if application_id != signer_config["discord"]["application_id"]:
        raise DiscordReleaseSourceError(
            "Discord current application does not match signer policy"
        )
    bot = _mapping(
        application.get("bot"), field="Discord current application bot"
    )
    bot_id = _snowflake(bot.get("id"), field="Discord application bot user ID")
    if bot_id != source_config["bot_user_id"]:
        raise DiscordReleaseSourceError(
            "Discord application bot identity does not match"
        )
    if "bot" in bot and bot.get("bot") is not True:
        raise DiscordReleaseSourceError(
            "Discord application bot identity does not match"
        )


def _verify_current_user(
    raw: Any,
    *,
    source_config: dict[str, Any],
) -> None:
    user = _mapping(raw, field="Discord current user")
    user_id = _snowflake(user.get("id"), field="Discord current bot user ID")
    if user_id != source_config["bot_user_id"] or user.get("bot") is not True:
        raise DiscordReleaseSourceError(
            "Discord current bot user identity does not match"
        )


def _verify_channel(
    raw: Any,
    *,
    channel_id: str,
    signer_config: dict[str, Any],
) -> None:
    channel = _mapping(raw, field="Discord approval channel")
    returned_id = _snowflake(
        channel.get("id"), field="Discord returned channel ID"
    )
    guild_id = _snowflake(
        channel.get("guild_id"), field="Discord returned channel guild ID"
    )
    channel_type = channel.get("type")
    if returned_id != channel_id:
        raise DiscordReleaseSourceError("Discord returned channel does not match")
    if guild_id != signer_config["discord"]["guild_id"]:
        raise DiscordReleaseSourceError(
            "Discord returned channel guild does not match"
        )
    if (
        isinstance(channel_type, bool)
        or not isinstance(channel_type, int)
        or channel_type not in ALLOWED_CHANNEL_TYPES
    ):
        raise DiscordReleaseSourceError(
            "Discord approval channel type is not authorized"
        )


def _empty_collection(message: dict[str, Any], field: str) -> None:
    value = message.get(field, [])
    if not isinstance(value, list) or value:
        raise DiscordReleaseSourceError(
            f"Discord approval message {field} are not permitted"
        )


def _normalized_message_event(
    raw: Any,
    *,
    channel_id: str,
    message_id: str,
    signer_config: dict[str, Any],
    observed_at: datetime,
) -> dict[str, Any]:
    message = _mapping(raw, field="Discord approval message")
    returned_id = _snowflake(
        message.get("id"), field="Discord returned message ID"
    )
    returned_channel_id = _snowflake(
        message.get("channel_id"), field="Discord returned message channel ID"
    )
    if returned_id != message_id or returned_channel_id != channel_id:
        raise DiscordReleaseSourceError(
            "Discord returned approval message does not match"
        )
    if "guild_id" in message:
        returned_guild_id = _snowflake(
            message.get("guild_id"), field="Discord returned message guild ID"
        )
        if returned_guild_id != signer_config["discord"]["guild_id"]:
            raise DiscordReleaseSourceError(
                "Discord returned message guild does not match"
            )
    message_type = message.get("type")
    if (
        isinstance(message_type, bool)
        or not isinstance(message_type, int)
        or message_type != 0
    ):
        raise DiscordReleaseSourceError(
            "Discord approval must be a standalone default message"
        )
    if message.get("edited_timestamp") is not None:
        raise DiscordReleaseSourceError(
            "edited Discord approval messages are not accepted"
        )
    if message.get("webhook_id") is not None:
        raise DiscordReleaseSourceError(
            "Discord webhook messages may not approve releases"
        )
    if message.get("application_id") is not None:
        raise DiscordReleaseSourceError(
            "Discord application messages may not approve releases"
        )
    for field in ("attachments", "embeds", "components", "sticker_items"):
        _empty_collection(message, field)
    if message.get("poll") is not None:
        raise DiscordReleaseSourceError(
            "Discord approval message polls are not permitted"
        )
    author = _mapping(message.get("author"), field="Discord message author")
    actor_user_id = _snowflake(
        author.get("id"), field="Discord message author ID"
    )
    if author.get("bot", False) is not False:
        raise DiscordReleaseSourceError(
            "Discord bot actors may not approve releases"
        )
    if author.get("system", False) is not False:
        raise DiscordReleaseSourceError(
            "Discord system actors may not approve releases"
        )
    if actor_user_id not in {
        actor["user_id"] for actor in signer_config["discord"]["owner_actors"]
    }:
        raise DiscordReleaseSourceError(
            "Discord message author is not an authorized owner"
        )
    content = message.get("content")
    if not isinstance(content, str):
        raise DiscordReleaseSourceError(
            "Discord approval message content is unavailable"
        )
    created_at = _discord_timestamp(
        message.get("timestamp"), field="Discord message timestamp"
    )
    event = {
        "schema_version": signer.EVENT_SCHEMA,
        "platform": signer.PLATFORM,
        "application_id": signer_config["discord"]["application_id"],
        "guild_id": signer_config["discord"]["guild_id"],
        "channel_id": channel_id,
        "message_id": message_id,
        "actor_user_id": actor_user_id,
        "actor_is_bot": False,
        "created_at": _utc_text(created_at),
        "observed_at": _utc_text(observed_at),
        "text": content,
    }
    try:
        return signer.normalize_discord_event(
            event,
            signer_config,
            now=observed_at,
        )
    except signer.ReleaseOwnerSignerError as exc:
        raise DiscordReleaseSourceError(str(exc)) from exc


def fetch_normalized_event(
    *,
    signer_config: Any,
    source_config: Any,
    channel_id: Any,
    message_id: Any,
    bot_token: str,
    now: datetime | None = None,
    transport: DiscordHTTPTransport | None = None,
) -> dict[str, Any]:
    normalized_signer = signer.normalize_signer_config(signer_config)
    normalized_source = normalize_source_config(source_config, normalized_signer)
    if not normalized_signer["enabled"]:
        raise DiscordReleaseSourceError("release owner signer is disabled")
    if not normalized_source["enabled"]:
        raise DiscordReleaseSourceError("Discord release source is disabled")
    normalized_channel_id = _snowflake(
        channel_id, field="Discord requested approval channel ID"
    )
    normalized_message_id = _snowflake(
        message_id, field="Discord requested approval message ID"
    )
    if normalized_channel_id not in normalized_signer["discord"][
        "approval_channel_ids"
    ]:
        raise DiscordReleaseSourceError(
            "Discord requested approval channel is not authorized"
        )
    if not isinstance(bot_token, str) or not BOT_TOKEN_RE.fullmatch(bot_token):
        raise DiscordReleaseSourceError("Discord observer bot token is invalid")
    fixed_observed_at = None if now is None else now
    if fixed_observed_at is not None and (
        not isinstance(fixed_observed_at, datetime)
        or fixed_observed_at.tzinfo is None
    ):
        raise DiscordReleaseSourceError(
            "Discord source observation clock must be timezone-aware"
        )
    if fixed_observed_at is not None:
        fixed_observed_at = fixed_observed_at.astimezone(timezone.utc)
    client = FixedDiscordTransport() if transport is None else transport
    application = _request_json(
        client,
        f"{API_PREFIX}/applications/@me",
        token=bot_token,
        source_config=normalized_source,
    )
    _verify_application(
        application,
        signer_config=normalized_signer,
        source_config=normalized_source,
    )
    current_user = _request_json(
        client,
        f"{API_PREFIX}/users/@me",
        token=bot_token,
        source_config=normalized_source,
    )
    _verify_current_user(current_user, source_config=normalized_source)
    channel = _request_json(
        client,
        f"{API_PREFIX}/channels/{normalized_channel_id}",
        token=bot_token,
        source_config=normalized_source,
    )
    _verify_channel(
        channel,
        channel_id=normalized_channel_id,
        signer_config=normalized_signer,
    )
    message = _request_json(
        client,
        (
            f"{API_PREFIX}/channels/{normalized_channel_id}/messages/"
            f"{normalized_message_id}"
        ),
        token=bot_token,
        source_config=normalized_source,
    )
    observed_at = (
        datetime.now(timezone.utc)
        if fixed_observed_at is None
        else fixed_observed_at
    )
    return _normalized_message_event(
        message,
        channel_id=normalized_channel_id,
        message_id=normalized_message_id,
        signer_config=normalized_signer,
        observed_at=observed_at,
    )
