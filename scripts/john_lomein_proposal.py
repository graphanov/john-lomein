#!/usr/bin/env python3
"""Strict structured-proposal contract for Guide and intake brokers."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "john-lomein.proposal.v1"
PROPOSAL_ID_RE = re.compile(r"^jl-proposal-[0-9a-f]{16}$")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
COMMAND_LINE_RE = re.compile(r"(?m)^\s*[/@]")
DIALOGUE_STATES = frozenset({"READY", "EXHAUSTED"})
EXHAUSTION_REASONS = frozenset(
    {
        "enough_information",
        "diminishing_returns",
        "repeated_exchange",
        "hard_cap",
        "participant_requested_shape",
    }
)
ROOT_FIELDS = frozenset(
    {
        "schema_version",
        "proposal_id",
        "title",
        "problem",
        "desired_outcome",
        "scope",
        "out_of_scope",
        "constraints",
        "success_signals",
        "evidence_plan",
        "risks",
        "open_questions",
        "dialogue",
        "authority",
    }
)


class ProposalError(ValueError):
    """Stable validation failure for a structured Guide proposal."""


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProposalError(f"{field} must be an object")
    return dict(value)


def _strict_keys(
    value: Mapping[str, Any],
    *,
    field: str,
    required: set[str] | frozenset[str],
    optional: set[str] | frozenset[str] = frozenset(),
) -> None:
    keys = set(value)
    missing = set(required) - keys
    extra = keys - set(required) - set(optional)
    if missing or extra:
        raise ProposalError(
            f"{field} fields invalid: missing={sorted(missing)} extra={sorted(extra)}"
        )


def _text(value: Any, *, field: str, maximum: int, command_safe: bool = False) -> str:
    if not isinstance(value, str):
        raise ProposalError(f"{field} must be text")
    text = value.strip()
    if not text:
        raise ProposalError(f"{field} must not be empty")
    if len(text) > maximum:
        raise ProposalError(f"{field} exceeds {maximum} characters")
    if CONTROL_RE.search(text):
        raise ProposalError(f"{field} contains control characters")
    if command_safe and COMMAND_LINE_RE.search(text):
        raise ProposalError(f"{field} contains command-like content")
    return text


def _items(
    value: Any,
    *,
    field: str,
    minimum: int,
    maximum: int = 12,
) -> list[str]:
    if not isinstance(value, list):
        raise ProposalError(f"{field} must be a list")
    if not minimum <= len(value) <= maximum:
        raise ProposalError(f"{field} must contain {minimum}..{maximum} items")
    output: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        item = _text(raw, field=f"{field}[{index}]", maximum=1000, command_safe=True)
        key = item.casefold()
        if key in seen:
            raise ProposalError(f"{field} contains a duplicate item")
        seen.add(key)
        output.append(item)
    return output


def _dialogue(value: Any) -> dict[str, Any]:
    data = _mapping(value, field="dialogue")
    _strict_keys(
        data,
        field="dialogue",
        required={"status", "clarification_turns", "exhaustion_reason"},
    )
    status = str(data.get("status") or "")
    if status not in DIALOGUE_STATES:
        raise ProposalError("dialogue.status is unsupported")
    turns = data.get("clarification_turns")
    if isinstance(turns, bool) or not isinstance(turns, int) or not 0 <= turns <= 12:
        raise ProposalError("dialogue.clarification_turns must be an integer from 0 to 12")
    reason = str(data.get("exhaustion_reason") or "")
    if reason not in EXHAUSTION_REASONS:
        raise ProposalError("dialogue.exhaustion_reason is unsupported")
    return {
        "status": status,
        "clarification_turns": turns,
        "exhaustion_reason": reason,
    }


def _authority(value: Any) -> dict[str, Any]:
    data = _mapping(value, field="authority")
    _strict_keys(
        data,
        field="authority",
        required={"posture", "owner_readiness_required", "owner_merge_required"},
    )
    if data.get("posture") != "proposal_only":
        raise ProposalError("authority.posture must remain proposal_only")
    if data.get("owner_readiness_required") is not True:
        raise ProposalError("authority.owner_readiness_required must remain true")
    if data.get("owner_merge_required") is not True:
        raise ProposalError("authority.owner_merge_required must remain true")
    return {
        "posture": "proposal_only",
        "owner_readiness_required": True,
        "owner_merge_required": True,
    }


def _content_digest(value: Mapping[str, Any]) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def normalize_proposal(raw: Any) -> dict[str, Any]:
    data = _mapping(raw, field="proposal")
    required = ROOT_FIELDS - {"proposal_id"}
    _strict_keys(data, field="proposal", required=required, optional={"proposal_id"})
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ProposalError("proposal.schema_version is unsupported")
    normalized: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "title": _text(data.get("title"), field="title", maximum=200),
        "problem": _text(data.get("problem"), field="problem", maximum=4000),
        "desired_outcome": _text(
            data.get("desired_outcome"), field="desired_outcome", maximum=4000
        ),
        "scope": _items(data.get("scope"), field="scope", minimum=1),
        "out_of_scope": _items(
            data.get("out_of_scope"), field="out_of_scope", minimum=0
        ),
        "constraints": _items(
            data.get("constraints"), field="constraints", minimum=0
        ),
        "success_signals": _items(
            data.get("success_signals"), field="success_signals", minimum=1
        ),
        "evidence_plan": _items(
            data.get("evidence_plan"), field="evidence_plan", minimum=1
        ),
        "risks": _items(data.get("risks"), field="risks", minimum=0),
        "open_questions": _items(
            data.get("open_questions"), field="open_questions", minimum=0, maximum=8
        ),
        "dialogue": _dialogue(data.get("dialogue")),
        "authority": _authority(data.get("authority")),
    }
    proposal_id = f"jl-proposal-{_content_digest(normalized)[:16]}"
    supplied_id = str(data.get("proposal_id") or "")
    if supplied_id and (
        not PROPOSAL_ID_RE.fullmatch(supplied_id) or supplied_id != proposal_id
    ):
        raise ProposalError("proposal.proposal_id does not match normalized content")
    return {"proposal_id": proposal_id, **normalized}


def _bullets(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items) if items else "_None stated._"


def render_proposal_markdown(proposal: Mapping[str, Any]) -> str:
    data = normalize_proposal(proposal)
    return "\n".join(
        [
            f"# {data['title']}",
            "",
            f"Proposal `{data['proposal_id']}`",
            "",
            "## Problem",
            "",
            data["problem"],
            "",
            "## Desired outcome",
            "",
            data["desired_outcome"],
            "",
            "## Scope",
            "",
            _bullets(data["scope"]),
            "",
            "## Out of scope",
            "",
            _bullets(data["out_of_scope"]),
            "",
            "## Constraints and compatibility",
            "",
            _bullets(data["constraints"]),
            "",
            "## Success signals",
            "",
            _bullets(data["success_signals"]),
            "",
            "## Evidence plan",
            "",
            _bullets(data["evidence_plan"]),
            "",
            "## Risks and open questions",
            "",
            _bullets(data["risks"] + data["open_questions"]),
            "",
            "## Authority",
            "",
            "This proposal shapes a candidate only. It does not mark the work ready, approve coding, or approve release. Forge creates the design and acceptance criteria after the authenticated owner readiness gate; the owner alone may merge.",
            "",
        ]
    )


def _load(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ProposalError("proposal input must be a regular file")
    if path.stat().st_size > 256 * 1024:
        raise ProposalError("proposal input is too large")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProposalError("proposal input is not valid UTF-8 JSON") from exc


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("validate", "render"))
    parser.add_argument("--input", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        proposal = normalize_proposal(_load(args.input))
        if args.action == "render":
            sys.stdout.write(render_proposal_markdown(proposal))
        else:
            print(
                json.dumps(
                    {
                        "ok": True,
                        "schema_version": proposal["schema_version"],
                        "proposal_id": proposal["proposal_id"],
                    },
                    sort_keys=True,
                )
            )
        return 0
    except ProposalError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
