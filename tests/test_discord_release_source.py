#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import os
import ssl
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from owner_gateway import john_lomein_discord_release_source as source
from owner_gateway import john_lomein_release_owner_signer as signer
from release_broker import john_lomein_release_broker_protocol as protocol
from tests.test_release_broker_protocol import release_bundle


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
TOKEN = "discord.observer.token_0123456789"
JSON_HEADERS = {"content-type": "application/json"}


def snowflake(at: datetime, increment: int) -> str:
    milliseconds = int(at.timestamp() * 1000)
    return str(
        ((milliseconds - signer.DISCORD_EPOCH_MS) << 22)
        | (increment & ((1 << 22) - 1))
    )


def response(value: object, *, status: int = 200) -> source.DiscordHTTPResponse:
    return source.DiscordHTTPResponse(
        status=status,
        headers=JSON_HEADERS,
        body=json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii"),
    )


class FakeTransport:
    def __init__(self, responses: dict[str, source.DiscordHTTPResponse]) -> None:
        self.responses = responses
        self.calls: list[dict[str, object]] = []

    def request(
        self,
        path: str,
        *,
        headers: dict[str, str],
        timeout_seconds: float,
        maximum_response_bytes: int,
    ) -> source.DiscordHTTPResponse:
        self.calls.append(
            {
                "path": path,
                "headers": dict(headers),
                "timeout_seconds": timeout_seconds,
                "maximum_response_bytes": maximum_response_bytes,
            }
        )
        return self.responses[path]


class DiscordReleaseSourceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.key_root = self.root / "keys"
        self.key_root.mkdir(mode=0o700)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.application_id = snowflake(NOW - timedelta(days=300), 1)
        self.bot_user_id = snowflake(NOW - timedelta(days=290), 2)
        self.guild_id = snowflake(NOW - timedelta(days=250), 3)
        self.channel_id = snowflake(NOW - timedelta(days=200), 4)
        self.actor_id = snowflake(NOW - timedelta(days=150), 5)
        self.message_created = NOW - timedelta(seconds=10)
        self.message_id = snowflake(self.message_created, 6)
        self.bundle = release_bundle()
        self.approval = signer.expected_release_approval_text(self.bundle)
        self.token_path = self.key_root / "discord-observer.token"
        self.signer_config = {
            "schema_version": signer.CONFIG_SCHEMA,
            "enabled": True,
            "signer_id": "owner-gateway-widget",
            "signer_uid": self.uid or 1,
            "signer_gid": self.gid or 1,
            "runtime_uid": (self.uid or 1) + 100,
            "issuer": "trusted-owner-gateway",
            "key_id": "owner-2026-01",
            "private_key_path": str(self.key_root / "owner.pem"),
            "public_key_path": str(self.key_root / "owner.pub.pem"),
            "public_key_sha256": "sha256:" + "a" * 64,
            "state_directory": str(self.state),
            "assertion_ttl_seconds": 300,
            "maximum_event_age_seconds": 120,
            "maximum_observation_delay_seconds": 30,
            "maximum_clock_skew_seconds": 5,
            "instance": {
                "slug": "widget-production",
                "repository": {
                    "id": 987654,
                    "full_name": "acme/widget",
                    "default_branch": "main",
                },
            },
            "discord": {
                "application_id": self.application_id,
                "guild_id": self.guild_id,
                "approval_channel_ids": [self.channel_id],
                "owner_actors": [
                    {
                        "user_id": self.actor_id,
                        "actor_login": "maintainer",
                    }
                ],
            },
        }
        normalized_signer = signer.normalize_signer_config(self.signer_config)
        self.source_config = {
            "schema_version": source.SOURCE_CONFIG_SCHEMA,
            "enabled": True,
            "signer_id": normalized_signer["signer_id"],
            "signer_config_sha256": protocol.sha256_json(normalized_signer),
            "api_base_url": source.API_BASE_URL,
            "bot_user_id": self.bot_user_id,
            "bot_token_path": str(self.token_path),
            "request_timeout_seconds": 5,
            "maximum_response_bytes": 64 * 1024,
        }
        self.paths = {
            "application": f"{source.API_PREFIX}/applications/@me",
            "user": f"{source.API_PREFIX}/users/@me",
            "channel": f"{source.API_PREFIX}/channels/{self.channel_id}",
            "message": (
                f"{source.API_PREFIX}/channels/{self.channel_id}/messages/"
                f"{self.message_id}"
            ),
        }
        self.application = {
            "id": self.application_id,
            "bot": {"id": self.bot_user_id, "bot": True},
        }
        self.current_user = {"id": self.bot_user_id, "bot": True}
        self.channel = {
            "id": self.channel_id,
            "guild_id": self.guild_id,
            "type": 0,
        }
        self.message = {
            "id": self.message_id,
            "channel_id": self.channel_id,
            "guild_id": self.guild_id,
            "author": {
                "id": self.actor_id,
                "bot": False,
                "system": False,
            },
            "content": self.approval,
            "timestamp": self.message_created.isoformat(),
            "edited_timestamp": None,
            "type": 0,
            "attachments": [],
            "embeds": [],
            "components": [],
            "sticker_items": [],
        }

    def transport(
        self,
        *,
        application: object | None = None,
        current_user: object | None = None,
        channel: object | None = None,
        message: object | None = None,
    ) -> FakeTransport:
        return FakeTransport(
            {
                self.paths["application"]: response(
                    self.application if application is None else application
                ),
                self.paths["user"]: response(
                    self.current_user if current_user is None else current_user
                ),
                self.paths["channel"]: response(
                    self.channel if channel is None else channel
                ),
                self.paths["message"]: response(
                    self.message if message is None else message
                ),
            }
        )

    def fetch(self, transport: FakeTransport | None = None) -> dict:
        return source.fetch_normalized_event(
            signer_config=self.signer_config,
            source_config=self.source_config,
            channel_id=self.channel_id,
            message_id=self.message_id,
            bot_token=TOKEN,
            now=NOW,
            transport=self.transport() if transport is None else transport,
        )

    def test_fetches_exact_remote_identity_channel_and_message(self):
        transport = self.transport()
        event = self.fetch(transport)
        self.assertEqual(
            [call["path"] for call in transport.calls],
            [
                self.paths["application"],
                self.paths["user"],
                self.paths["channel"],
                self.paths["message"],
            ],
        )
        for call in transport.calls:
            self.assertEqual(
                call["headers"],
                {
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Authorization": f"Bot {TOKEN}",
                    "User-Agent": source.USER_AGENT,
                },
            )
            self.assertEqual(call["timeout_seconds"], 5)
            self.assertEqual(call["maximum_response_bytes"], 64 * 1024)
        self.assertEqual(event["application_id"], self.application_id)
        self.assertEqual(event["guild_id"], self.guild_id)
        self.assertEqual(event["channel_id"], self.channel_id)
        self.assertEqual(event["message_id"], self.message_id)
        self.assertEqual(event["actor_user_id"], self.actor_id)
        self.assertEqual(event["text"], self.approval)
        self.assertEqual(event["observed_at"], "2026-07-16T12:00:00Z")

    def test_source_config_is_exact_and_bound_to_complete_signer_policy(self):
        normalized = source.normalize_source_config(
            self.source_config, self.signer_config
        )
        self.assertEqual(normalized, self.source_config)
        mutations = {
            "schema_version": "unsupported",
            "signer_id": "other-signer",
            "signer_config_sha256": "sha256:" + "f" * 64,
            "api_base_url": "https://example.invalid/api/v10",
            "bot_user_id": "not-a-snowflake",
            "request_timeout_seconds": 31,
            "maximum_response_bytes": source.MAX_RESPONSE_BYTES + 1,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                config = copy.deepcopy(self.source_config)
                config[field] = value
                with self.assertRaises(source.DiscordReleaseSourceError):
                    source.normalize_source_config(config, self.signer_config)
        signer_policy = copy.deepcopy(self.signer_config)
        signer_policy["maximum_event_age_seconds"] = 60
        with self.assertRaisesRegex(
            source.DiscordReleaseSourceError, "fingerprint"
        ):
            source.normalize_source_config(self.source_config, signer_policy)

    def test_disabled_or_unapproved_requests_never_reach_network(self):
        transport = self.transport()
        disabled = copy.deepcopy(self.source_config)
        disabled["enabled"] = False
        with self.assertRaisesRegex(
            source.DiscordReleaseSourceError, "disabled"
        ):
            source.fetch_normalized_event(
                signer_config=self.signer_config,
                source_config=disabled,
                channel_id=self.channel_id,
                message_id=self.message_id,
                bot_token=TOKEN,
                now=NOW,
                transport=transport,
            )
        self.assertEqual(transport.calls, [])

        other_channel = snowflake(NOW - timedelta(days=180), 7)
        with self.assertRaisesRegex(
            source.DiscordReleaseSourceError, "not authorized"
        ):
            source.fetch_normalized_event(
                signer_config=self.signer_config,
                source_config=self.source_config,
                channel_id=other_channel,
                message_id=self.message_id,
                bot_token=TOKEN,
                now=NOW,
                transport=transport,
            )
        self.assertEqual(transport.calls, [])

    def test_application_user_and_channel_identity_fail_closed(self):
        cases: list[tuple[str, FakeTransport, str]] = []
        wrong_application = copy.deepcopy(self.application)
        wrong_application["id"] = snowflake(NOW - timedelta(days=280), 8)
        cases.append(
            ("application", self.transport(application=wrong_application), "application")
        )
        wrong_application_bot = copy.deepcopy(self.application)
        wrong_application_bot["bot"]["id"] = snowflake(
            NOW - timedelta(days=270), 9
        )
        cases.append(
            (
                "application_bot",
                self.transport(application=wrong_application_bot),
                "bot identity",
            )
        )
        non_bot_application = copy.deepcopy(self.application)
        non_bot_application["bot"]["bot"] = False
        cases.append(
            (
                "application_non_bot",
                self.transport(application=non_bot_application),
                "bot identity",
            )
        )
        wrong_user = copy.deepcopy(self.current_user)
        wrong_user["id"] = snowflake(NOW - timedelta(days=260), 10)
        cases.append(("current_user", self.transport(current_user=wrong_user), "bot user"))
        wrong_guild = copy.deepcopy(self.channel)
        wrong_guild["guild_id"] = snowflake(NOW - timedelta(days=240), 11)
        cases.append(("channel_guild", self.transport(channel=wrong_guild), "guild"))
        wrong_type = copy.deepcopy(self.channel)
        wrong_type["type"] = 1
        cases.append(("channel_type", self.transport(channel=wrong_type), "type"))
        for name, transport, message in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    source.DiscordReleaseSourceError, message
                ):
                    self.fetch(transport)

    def test_message_authorship_mutability_and_shape_fail_closed(self):
        other_actor = snowflake(NOW - timedelta(days=140), 12)
        cases: dict[str, tuple[object, str]] = {
            "edited": (
                "2026-07-16T11:59:55.000000+00:00",
                "edited",
            ),
            "webhook": (
                snowflake(NOW - timedelta(days=100), 13),
                "webhook",
            ),
            "application_message": (
                self.application_id,
                "application messages",
            ),
            "reply": (19, "standalone"),
            "attachment": ([{"id": "1"}], "attachments"),
            "poll": ({"question": {}}, "polls"),
            "content_unavailable": (None, "content"),
            "wrong_actor": (other_actor, "authorized owner"),
            "bot_actor": (True, "bot actors"),
            "system_actor": (True, "system actors"),
        }
        for name, (value, error) in cases.items():
            with self.subTest(name=name):
                message = copy.deepcopy(self.message)
                if name == "edited":
                    message["edited_timestamp"] = value
                elif name == "webhook":
                    message["webhook_id"] = value
                elif name == "application_message":
                    message["application_id"] = value
                elif name == "reply":
                    message["type"] = value
                elif name == "attachment":
                    message["attachments"] = value
                elif name == "poll":
                    message["poll"] = value
                elif name == "content_unavailable":
                    message["content"] = value
                elif name == "wrong_actor":
                    message["author"]["id"] = value
                elif name == "bot_actor":
                    message["author"]["bot"] = value
                elif name == "system_actor":
                    message["author"]["system"] = value
                with self.assertRaisesRegex(
                    source.DiscordReleaseSourceError, error
                ):
                    self.fetch(self.transport(message=message))

    def test_remote_message_time_must_match_message_snowflake(self):
        message = copy.deepcopy(self.message)
        message["timestamp"] = (
            self.message_created - timedelta(seconds=2)
        ).isoformat()
        with self.assertRaisesRegex(
            source.DiscordReleaseSourceError, "snowflake"
        ):
            self.fetch(self.transport(message=message))

    def test_http_redirect_rate_limit_encoding_size_and_json_are_refused(self):
        base = self.transport()
        hostile_responses = {
            "redirect": source.DiscordHTTPResponse(
                status=302,
                headers={"content-type": "application/json", "location": "https://x"},
                body=b"{}",
            ),
            "rate_limit": source.DiscordHTTPResponse(
                status=429,
                headers=JSON_HEADERS,
                body=b'{"retry_after":1}',
            ),
            "status": source.DiscordHTTPResponse(
                status=500,
                headers=JSON_HEADERS,
                body=b"{}",
            ),
            "content_type": source.DiscordHTTPResponse(
                status=200,
                headers={"content-type": "text/html"},
                body=b"{}",
            ),
            "encoding": source.DiscordHTTPResponse(
                status=200,
                headers={
                    "content-type": "application/json",
                    "content-encoding": "gzip",
                },
                body=b"{}",
            ),
            "oversized": source.DiscordHTTPResponse(
                status=200,
                headers=JSON_HEADERS,
                body=b"x" * (64 * 1024 + 1),
            ),
            "duplicate_json": source.DiscordHTTPResponse(
                status=200,
                headers=JSON_HEADERS,
                body=b'{"id":"1","id":"2"}',
            ),
            "nonfinite_json": source.DiscordHTTPResponse(
                status=200,
                headers=JSON_HEADERS,
                body=b'{"id":NaN}',
            ),
        }
        for name, hostile in hostile_responses.items():
            with self.subTest(name=name):
                transport = FakeTransport(dict(base.responses))
                transport.responses[self.paths["application"]] = hostile
                with self.assertRaises(source.DiscordReleaseSourceError) as caught:
                    self.fetch(transport)
                self.assertNotIn(TOKEN, str(caught.exception))

    def test_secure_source_config_and_token_files_are_required(self):
        config_path = self.root / "source.json"
        config_path.write_text(
            json.dumps(self.source_config, sort_keys=True),
            encoding="utf-8",
        )
        config_path.chmod(0o440)
        loaded = source.load_source_config(
            config_path,
            self.signer_config,
            expected_owner_uid=self.uid,
            expected_group_gid=self.gid,
            trusted_root=self.root,
        )
        self.assertEqual(loaded, self.source_config)

        self.token_path.write_text(TOKEN + "\n", encoding="ascii")
        self.token_path.chmod(0o640)
        self.assertEqual(
            source.load_bot_token(
                self.source_config,
                self.signer_config,
                expected_owner_uid=self.uid,
                trusted_root=self.root,
            ),
            TOKEN,
        )
        self.token_path.chmod(0o600)
        with self.assertRaisesRegex(source.DiscordReleaseSourceError, "mode"):
            source.load_bot_token(
                self.source_config,
                self.signer_config,
                expected_owner_uid=self.uid,
                trusted_root=self.root,
            )
        self.token_path.chmod(0o640)
        hardlink = self.key_root / "discord-observer-copy.token"
        os.link(self.token_path, hardlink)
        with self.assertRaisesRegex(
            source.DiscordReleaseSourceError, "hard links"
        ):
            source.load_bot_token(
                self.source_config,
                self.signer_config,
                expected_owner_uid=self.uid,
                trusted_root=self.root,
            )

    def test_fixed_transport_rejects_environment_overrides_and_other_routes(self):
        cleared = {key: "" for key in source.UNTRUSTED_NETWORK_ENV_KEYS}
        with mock.patch.dict(os.environ, cleared, clear=False):
            transport = source.FixedDiscordTransport()
            with self.assertRaisesRegex(
                source.DiscordReleaseSourceError, "not authorized"
            ):
                transport.request(
                    "/api/v10/guilds/" + "1234567890123456" + "7",
                    headers={},
                    timeout_seconds=5,
                    maximum_response_bytes=64 * 1024,
                )
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "https://proxy.invalid"}):
            with self.assertRaisesRegex(
                source.DiscordReleaseSourceError, "overrides"
            ):
                source.FixedDiscordTransport()
        insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        with mock.patch.dict(os.environ, cleared, clear=False):
            with self.assertRaisesRegex(
                source.DiscordReleaseSourceError, "verify"
            ):
                source.FixedDiscordTransport(ssl_context=insecure)


if __name__ == "__main__":
    unittest.main()
