#!/usr/bin/env python3
"""Deterministic public-output validation and redaction.

This module is the final content boundary for GitHub writes and external
notifications. It deliberately rejects secret/private-path content at mutation
brokers and redacts it when an operational alert must still be delivered.
"""
from __future__ import annotations

import argparse
import re
import sys
from typing import Any

from john_lomein_factory_receipts import (
    FILE_URL_RE,
    SECRET_RE,
    UNSAFE_CONTROL_RE,
    UNC_PATH_RE,
    WINDOWS_ABSOLUTE_PATH_RE,
    redact_public,
)

MAX_PUBLIC_INPUT_BYTES = 1_048_576
CONTROL_RE = UNSAFE_CONTROL_RE
PRIVATE_POSIX_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"/(?:Users|home|root)/[^\s)\]}>`'\"]+|"
    r"/(?:private/)?(?:tmp|var)/[^\s)\]}>`'\"]+|"
    r"~/(?:\.hermes|\.john-lomein|mnemosyne)(?:/|\\b)|"
    r"[^\s)\]}>`'\"]*\.john-lomein/instances/"
    r"[^\s)\]}>`'\"]*"
    r")",
    flags=re.I,
)


class PublicSafetyError(ValueError):
    """Raised when content is unsafe for an external surface."""


def assert_public_safe_text(value: Any, *, field: str) -> str:
    text = str(value or "")
    if "\ufffd" in text:
        raise PublicSafetyError(f"{field} contains invalid text encoding")
    if CONTROL_RE.search(text):
        raise PublicSafetyError(f"{field} contains control characters")
    if (
        SECRET_RE.search(text)
        or FILE_URL_RE.search(text)
        or WINDOWS_ABSOLUTE_PATH_RE.search(text)
        or UNC_PATH_RE.search(text)
        or PRIVATE_POSIX_PATH_RE.search(text)
    ):
        raise PublicSafetyError(
            f"{field} contains secret-shaped content or a private path"
        )
    return text


def sanitize_public_text(value: Any, *, limit: int = 1800) -> str:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 64:
        raise ValueError("public text limit must be an integer >= 64")
    text = str(redact_public(str(value or "")))
    text = CONTROL_RE.sub(" ", text).replace("\ufffd", "?").strip()
    if len(text) <= limit:
        return text
    suffix = "… [truncated]"
    return text[: limit - len(suffix)] + suffix


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate or redact a bounded public message from stdin."
    )
    parser.add_argument(
        "action",
        choices={"check", "sanitize"},
    )
    parser.add_argument("--field", default="public message")
    parser.add_argument("--max-chars", type=int, default=1800)
    args = parser.parse_args(argv)
    raw = sys.stdin.buffer.read(MAX_PUBLIC_INPUT_BYTES + 1)
    if len(raw) > MAX_PUBLIC_INPUT_BYTES:
        print("public message exceeds inspection limit", file=sys.stderr)
        return 2
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        print("public message is not valid UTF-8", file=sys.stderr)
        return 2
    try:
        if args.action == "check":
            sys.stdout.write(
                assert_public_safe_text(text, field=args.field)
            )
        else:
            sys.stdout.write(
                sanitize_public_text(text, limit=args.max_chars)
            )
    except (PublicSafetyError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
