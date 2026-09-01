#!/usr/bin/env python3
"""Fail-closed John Lomein role-collaboration contracts.

Hermes Bot Mode and Hermes Peer are transport capabilities. This module keeps
them disabled until a product-owned broker exists, while allowing a versioned,
advisory-only route policy and message envelope to be prepared and tested.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from john_lomein_public_safety import assert_public_safe_text

COLLABORATION_SCHEMA = "john-lomein.collaboration.v1"
ROLE_MESSAGE_SCHEMA = "john-lomein.role-message.v1"
ROLE_NAMES = frozenset(
    {"guide", "forge", "overwatch", "maintainer", "learning_steward"}
)
PURPOSES = frozenset(
    {
        "proposal_refinement",
        "design_consultation",
        "review_finding",
        "repair_request",
        "lesson_share",
        "operational_notice",
    }
)
SECTION_KEYS = frozenset(
    {
        "schema_version",
        "mode",
        "authority",
        "bot_chat_protocol_enabled",
        "peer_messaging_enabled",
        "max_message_chars",
        "allowed_routes",
        "peer_targets",
    }
)
MESSAGE_REQUIRED_KEYS = frozenset(
    {
        "schema_version",
        "sender_role",
        "recipient_role",
        "purpose",
        "correlation_id",
        "body",
        "authority",
    }
)
MESSAGE_OPTIONAL_KEYS = frozenset(
    {"message_id", "may_mark_ready", "may_merge", "may_publish"}
)
PEER_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
CORRELATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,127}$")
MESSAGE_ID_RE = re.compile(r"^jlrm-[0-9a-f]{24}$")


def _mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be a YAML mapping")
    return value


def _strict_bool(value: Any, *, field: str, default: bool) -> bool:
    if value is None:
        return default
    if type(value) is not bool:
        raise ValueError(f"{field} must be true or false")
    return value


def _strict_positive_int(value: Any, *, field: str, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 16000:
        raise ValueError(f"{field} must be an integer from 1 to 16000")
    return value


def _routes(value: Any) -> dict[str, list[str]]:
    data = _mapping(value, field="collaboration.allowed_routes")
    routes: dict[str, list[str]] = {}
    for raw_sender, raw_recipients in data.items():
        sender = str(raw_sender or "").strip()
        if sender not in ROLE_NAMES:
            raise ValueError("collaboration.allowed_routes has an unknown sender role")
        if not isinstance(raw_recipients, list):
            raise ValueError(
                f"collaboration.allowed_routes.{sender} must be a YAML list"
            )
        recipients: list[str] = []
        seen: set[str] = set()
        for item in raw_recipients:
            if not isinstance(item, str):
                raise ValueError(
                    f"collaboration.allowed_routes.{sender} must contain role names"
                )
            recipient = item.strip()
            if recipient not in ROLE_NAMES or recipient == sender:
                raise ValueError(
                    f"collaboration.allowed_routes.{sender} has an invalid recipient"
                )
            if recipient in seen:
                raise ValueError(
                    f"collaboration.allowed_routes.{sender} contains duplicates"
                )
            seen.add(recipient)
            recipients.append(recipient)
        if recipients:
            routes[sender] = sorted(recipients)
    return dict(sorted(routes.items()))


def _peer_targets(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("collaboration.peer_targets must be a YAML list")
    targets: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not PEER_RE.fullmatch(item.strip()):
            raise ValueError("collaboration.peer_targets contains an invalid peer handle")
        target = item.strip()
        if target in seen:
            raise ValueError("collaboration.peer_targets contains duplicates")
        seen.add(target)
        targets.append(target)
    return sorted(targets)


def collaboration_policy(manifest: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, Mapping):
        raise ValueError("collaboration manifest must be a YAML mapping")
    section = _mapping(manifest.get("collaboration"), field="collaboration")
    unknown = set(section) - SECTION_KEYS
    if unknown:
        raise ValueError(
            "collaboration contains unsupported fields: " + ", ".join(sorted(unknown))
        )
    schema = str(section.get("schema_version") or COLLABORATION_SCHEMA)
    if schema != COLLABORATION_SCHEMA:
        raise ValueError("collaboration.schema_version is unsupported")
    mode = str(section.get("mode") or "disabled")
    if mode not in {"disabled", "prepared"}:
        raise ValueError("collaboration.mode must be disabled or prepared")
    authority = str(section.get("authority") or "advisory_only")
    if authority != "advisory_only":
        raise ValueError("collaboration.authority must remain advisory_only")
    bot_chat_enabled = _strict_bool(
        section.get("bot_chat_protocol_enabled"),
        field="collaboration.bot_chat_protocol_enabled",
        default=False,
    )
    peer_enabled = _strict_bool(
        section.get("peer_messaging_enabled"),
        field="collaboration.peer_messaging_enabled",
        default=False,
    )
    if bot_chat_enabled or peer_enabled:
        raise ValueError(
            "collaboration transport cannot be enabled before a product-owned broker exists"
        )
    routes = _routes(section.get("allowed_routes"))
    peers = _peer_targets(section.get("peer_targets"))
    if mode == "disabled" and (routes or peers):
        raise ValueError(
            "collaboration disabled mode cannot declare routes or peer targets"
        )
    return {
        "schema_version": COLLABORATION_SCHEMA,
        "mode": mode,
        "authority": "advisory_only",
        "bot_chat_protocol_enabled": False,
        "peer_messaging_enabled": False,
        "max_message_chars": _strict_positive_int(
            section.get("max_message_chars"),
            field="collaboration.max_message_chars",
            default=4000,
        ),
        "allowed_routes": routes,
        "peer_targets": peers,
    }


def _message_digest(value: Mapping[str, Any]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def normalize_role_message(
    raw: Mapping[str, Any],
    *,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ValueError("role message must be a JSON object")
    missing = MESSAGE_REQUIRED_KEYS - set(raw)
    unknown = set(raw) - MESSAGE_REQUIRED_KEYS - MESSAGE_OPTIONAL_KEYS
    if missing or unknown:
        raise ValueError(
            f"role message fields invalid: missing={sorted(missing)} extra={sorted(unknown)}"
        )
    if raw.get("schema_version") != ROLE_MESSAGE_SCHEMA:
        raise ValueError("role message schema_version is unsupported")
    sender = str(raw.get("sender_role") or "").strip()
    recipient = str(raw.get("recipient_role") or "").strip()
    if sender not in ROLE_NAMES or recipient not in ROLE_NAMES or sender == recipient:
        raise ValueError("role message route has invalid roles")
    allowed_routes = policy.get("allowed_routes") or {}
    if recipient not in set(allowed_routes.get(sender) or []):
        raise ValueError("role message route is not allowed by collaboration policy")
    purpose = str(raw.get("purpose") or "").strip()
    if purpose not in PURPOSES:
        raise ValueError("role message purpose is unsupported")
    correlation_id = str(raw.get("correlation_id") or "").strip()
    if not CORRELATION_RE.fullmatch(correlation_id):
        raise ValueError("role message correlation_id is invalid")
    authority = str(raw.get("authority") or "").strip()
    if authority != "advisory_only":
        raise ValueError("role message authority must remain advisory_only")
    for field in ("may_mark_ready", "may_merge", "may_publish"):
        if field in raw and raw[field] is not False:
            raise ValueError(f"role message {field} must remain false")
    body = assert_public_safe_text(raw.get("body"), field="role message body").strip()
    maximum = int(policy.get("max_message_chars") or 4000)
    if not body or len(body) > maximum:
        raise ValueError("role message body is empty or exceeds the policy limit")
    normalized = {
        "schema_version": ROLE_MESSAGE_SCHEMA,
        "sender_role": sender,
        "recipient_role": recipient,
        "purpose": purpose,
        "correlation_id": correlation_id,
        "body": body,
        "authority": "advisory_only",
        "may_mark_ready": False,
        "may_merge": False,
        "may_publish": False,
    }
    message_id = f"jlrm-{_message_digest(normalized)[:24]}"
    supplied_id = str(raw.get("message_id") or "")
    if supplied_id and (
        not MESSAGE_ID_RE.fullmatch(supplied_id) or supplied_id != message_id
    ):
        raise ValueError("role message message_id does not match normalized content")
    return {"message_id": message_id, **normalized}
