#!/usr/bin/env python3
"""Canonical John Lomein persona source contract."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from john_lomein_file_contract import StableFileError, read_stable_regular


PERSONA_MARKER_RE = re.compile(
    r"<!--\s*(john-lomein\.persona\.v[0-9]+)\s*-->"
)
MAX_PERSONA_CHARACTERS = 4_500
MAX_PERSONA_BYTES = 32 * 1024


def load_persona_core(path: str | Path) -> tuple[str, str, str]:
    """Return the exact persona text, version, and digest or fail closed."""

    source = Path(path)
    try:
        raw = read_stable_regular(
            source,
            maximum_bytes=MAX_PERSONA_BYTES,
            owner_only=False,
        )
        text = raw.decode("utf-8").strip()
    except (StableFileError, UnicodeError) as exc:
        raise ValueError("canonical persona source is unsafe or unreadable") from exc
    markers = PERSONA_MARKER_RE.findall(text)
    if len(markers) != 1:
        raise ValueError("canonical persona must contain one version marker")
    if len(text) > MAX_PERSONA_CHARACTERS:
        raise ValueError(
            f"canonical persona exceeds {MAX_PERSONA_CHARACTERS} characters"
        )
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return text, markers[0], digest
