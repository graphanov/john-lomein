"""Exact-message protected release approval hook for the public Guide."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

PLUGIN_NAME = "john-lomein-release-approval"
GUIDE_PROFILE = "john-lomein-guide"
RESULT_SCHEMA = "john-lomein.current-release-approval-result.v1"
MAX_HELPER_OUTPUT_BYTES = 256 * 1024
SNOWFLAKE_RE = re.compile(r"^[0-9]{17,20}$")
APPROVAL_RE = re.compile(
    r"^APPROVE JOHN-LOMEIN BUNDLE "
    r"(?P<bundle_id>jlb-[0-9a-f]{24}) DIGEST "
    r"(?P<bundle_digest>sha256:[0-9a-f]{64}): "
    r"squash-merge the listed PR with the protected release broker; "
    r"DO NOT publish\. Post-merge repository verification and any "
    r"publication require separate gates\.$"
)
INSTANCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REASON_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
PACKET_LOCATOR_RE = re.compile(
    r"^state/protected-releases/outbox/(jlrp-[0-9a-f]{24})\.json$"
)
RECEIPT_LOCATOR_RE = re.compile(
    r"^state/protected-releases/receipts/jlrrc-[0-9a-f]{24}\.json$"
)


def _blocked(reason: str) -> dict[str, str]:
    return {
        "context": (
            "[John Lomein protected release approval]\n"
            f"Deterministic approval processing was blocked: {reason}.\n"
            "No merge authority was exercised. Do not claim success."
        )
    }


def _duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def _reject_number(_: str) -> None:
    raise ValueError("non-integer JSON number")


def _parse_helper_output(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_HELPER_OUTPUT_BYTES:
        raise ValueError("helper output size")
    value = json.loads(
        raw,
        object_pairs_hook=_duplicate_keys,
        parse_float=_reject_number,
        parse_constant=_reject_number,
    )
    if not isinstance(value, dict):
        raise ValueError("helper output object")
    required = {
        "schema_version",
        "instance_slug",
        "bundle_id",
        "bundle_digest",
        "record_id",
        "event_id",
        "packet_id",
        "packet_locator",
        "submission",
    }
    if set(value) != required or value.get("schema_version") != RESULT_SCHEMA:
        raise ValueError("helper output contract")
    if not INSTANCE_RE.fullmatch(str(value.get("instance_slug") or "")):
        raise ValueError("helper output instance")
    for key, pattern in (
        ("bundle_id", r"jlb-[0-9a-f]{24}"),
        ("bundle_digest", r"sha256:[0-9a-f]{64}"),
        ("record_id", r"jlros-[0-9a-f]{24}"),
        ("event_id", r"jlroe-[0-9a-f]{24}"),
        ("packet_id", r"jlrp-[0-9a-f]{24}"),
    ):
        if not re.fullmatch(pattern, str(value.get(key) or "")):
            raise ValueError("helper output identifier")
    packet_locator = str(value.get("packet_locator") or "")
    locator_match = PACKET_LOCATOR_RE.fullmatch(packet_locator)
    if locator_match is None or locator_match.group(1) != value["packet_id"]:
        raise ValueError("helper packet locator")
    submission = value.get("submission")
    if not isinstance(submission, dict) or set(submission) != {
        "schema_version",
        "packet_id",
        "bundle_id",
        "outcome",
        "reason_code",
        "receipt_locator",
    }:
        raise ValueError("helper submission contract")
    if submission.get("packet_id") != value["packet_id"]:
        raise ValueError("helper packet binding")
    if submission.get("bundle_id") != value["bundle_id"]:
        raise ValueError("helper bundle binding")
    if submission.get("outcome") not in {
        "succeeded",
        "rejected",
        "partial",
        "indeterminate",
    }:
        raise ValueError("helper outcome")
    if not REASON_RE.fullmatch(str(submission.get("reason_code") or "")):
        raise ValueError("helper reason")
    if RECEIPT_LOCATOR_RE.fullmatch(
        str(submission.get("receipt_locator") or "")
    ) is None:
        raise ValueError("helper receipt locator")
    return value


def _default_session_getter(name: str, default: str = "") -> str:
    from gateway.session_context import get_session_env

    return get_session_env(name, default)


def _default_runner(
    command: list[str],
    *,
    env: dict[str, str],
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        command,
        capture_output=True,
        check=False,
        timeout=120,
        env=env,
    )


def process_exact_release_approval(
    *,
    user_message: str,
    platform: str,
    session_getter: Callable[[str, str], str] = _default_session_getter,
    runner: Callable[..., subprocess.CompletedProcess[bytes]] = _default_runner,
    helper_path: Path | None = None,
    python_executable: str | None = None,
) -> dict[str, str] | None:
    """Run one fixed helper argv for one exact Guide/Discord approval."""
    text = str(user_message or "")
    approval_match = APPROVAL_RE.fullmatch(text)
    if approval_match is None:
        return None

    session_profile = session_getter("HERMES_SESSION_PROFILE", "")
    if session_profile != GUIDE_PROFILE:
        return None

    session_platform = session_getter("HERMES_SESSION_PLATFORM", "")
    if str(platform or "").casefold() != "discord" or (
        str(session_platform or "").casefold() != "discord"
    ):
        return _blocked("the current turn is not a Discord Guide turn")

    channel_id = session_getter("HERMES_SESSION_CHAT_ID", "")
    message_id = session_getter("HERMES_SESSION_MESSAGE_ID", "")
    if not SNOWFLAKE_RE.fullmatch(channel_id) or not SNOWFLAKE_RE.fullmatch(
        message_id
    ):
        return _blocked("the current Discord channel/message IDs are unavailable")
    if channel_id == message_id:
        return _blocked(
            "the current locator is an auto-thread starter; protected release "
            "approvals must be posted in a configured no-thread channel"
        )

    plugin_dir = Path(__file__).resolve().parent
    runtime_home = plugin_dir.parents[1]
    fixed_helper = (
        helper_path
        if helper_path is not None
        else runtime_home / "scripts" / "john-lomein-release-approve.py"
    )
    expected_helper = (
        runtime_home / "scripts" / "john-lomein-release-approve.py"
    )
    if fixed_helper != expected_helper:
        return _blocked("the fixed runtime helper binding differs")
    if (
        not fixed_helper.is_file()
        or fixed_helper.is_symlink()
    ):
        return _blocked("the fixed runtime helper is unavailable")

    command = [
        python_executable or sys.executable,
        str(fixed_helper),
        "approve",
        "--approval",
        text,
    ]
    child_env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C.UTF-8",
        "HERMES_SESSION_PLATFORM": "discord",
        "HERMES_SESSION_CHAT_ID": channel_id,
        "HERMES_SESSION_MESSAGE_ID": message_id,
    }
    try:
        result = runner(command, env=child_env)
    except Exception:
        return _blocked("the fixed runtime helper could not be invoked")

    if result.returncode == 6:
        return {
            "context": (
                "[John Lomein protected release approval]\n"
                "The single broker submission attempt is ambiguous. Inspect "
                "the signed receipt store before any retry. Do not retry "
                "automatically and do not claim merge success."
            )
        }
    if result.returncode not in {0, 3, 4, 5}:
        try:
            diagnostic = bytes(result.stderr).decode(
                "utf-8", errors="strict"
            ).strip()
        except Exception:
            diagnostic = ""
        specific = {
            (
                "john-lomein current release approval blocked: current "
                "Discord channel is not configured for protected release "
                "approvals"
            ): (
                "the current Discord channel is not configured for "
                "protected release approvals"
            ),
            (
                "john-lomein current release approval blocked: protected "
                "release approval channels must be allowed, free-response, "
                "and no-thread in the instance manifest"
            ): (
                "the protected release approval channel is not configured "
                "as allowed, free-response, and no-thread"
            ),
        }.get(diagnostic)
        if specific:
            return _blocked(specific)
        return _blocked("the isolated owner gateway or release broker refused it")
    if result.stderr:
        return _blocked("the fixed runtime helper returned unexpected diagnostics")
    try:
        parsed = _parse_helper_output(bytes(result.stdout))
    except Exception:
        return _blocked("the fixed runtime helper returned an invalid result")
    submission = parsed["submission"]
    if (
        parsed["bundle_id"] != approval_match.group("bundle_id")
        or parsed["bundle_digest"]
        != approval_match.group("bundle_digest")
    ):
        return _blocked("the fixed runtime helper returned a different bundle")
    expected_exit = {
        "succeeded": 0,
        "rejected": 3,
        "partial": 4,
        "indeterminate": 5,
    }[submission["outcome"]]
    if result.returncode != expected_exit:
        return _blocked("the fixed runtime helper outcome code was inconsistent")
    return {
        "context": "\n".join(
            [
                "[John Lomein protected release approval]",
                "The deterministic Guide hook processed this exact Discord "
                "message through the isolated owner gateway and made one "
                "protected release broker submission attempt.",
                f"Outcome: {submission['outcome']}.",
                f"Reason: {submission['reason_code']}.",
                f"Bundle: {parsed['bundle_id']}.",
                f"Packet: {parsed['packet_id']}.",
                f"Receipt: {submission['receipt_locator']}.",
                "This receipt proves only the protected merge outcome. "
                "Repository verification and publication remain separate.",
                "Treat this injected result as the only execution evidence "
                "for the current approval turn.",
            ]
        )
    }


def pre_llm_call(**kwargs: Any) -> dict[str, str] | None:
    try:
        return process_exact_release_approval(
            user_message=str(kwargs.get("user_message") or ""),
            platform=str(kwargs.get("platform") or ""),
        )
    except Exception:
        text = str(kwargs.get("user_message") or "")
        if APPROVAL_RE.fullmatch(text) is None:
            return None
        return _blocked("the deterministic approval hook failed closed")


def register(ctx: Any) -> None:
    ctx.register_hook("pre_llm_call", pre_llm_call)
