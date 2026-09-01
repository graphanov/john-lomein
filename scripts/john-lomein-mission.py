#!/usr/bin/env python3
"""Prepare or confirm a dormant John Lomein repository mission."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from john_lomein_mission import (
    MissionWorkflowError,
    confirm,
    propose,
    render_confirmation_human,
    render_proposal_human,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "prepare an unconfirmed mission proposal or adopt its exact "
            "digest without deploying or activating John"
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)

    proposal = commands.add_parser(
        "propose",
        help="write one private, digest-bound, unconfirmed mission proposal",
    )
    proposal.add_argument("instance")
    proposal.add_argument("--statement", required=True)
    proposal.add_argument(
        "--roadmap-source",
        action="append",
        required=True,
        dest="roadmap_sources",
    )
    proposal.add_argument("--owner-signal-policy", required=True)
    proposal.add_argument(
        "--output",
        help=(
            "proposal JSON path inside INSTANCE/private; defaults to "
            "mission-candidate.json"
        ),
    )
    proposal.add_argument("--json", action="store_true")

    confirmation = commands.add_parser(
        "confirm",
        help=(
            "adopt one exact proposal and reset desired authority to "
            "dormant observer posture"
        ),
    )
    confirmation.add_argument("instance")
    confirmation.add_argument(
        "--proposal",
        help=(
            "proposal JSON path inside INSTANCE/private; defaults to "
            "mission-candidate.json"
        ),
    )
    confirmation.add_argument(
        "--owner-confirmation",
        required=True,
        help=(
            "exact full-digest adoption phrase printed by the propose command"
        ),
    )
    confirmation.add_argument("--json", action="store_true")
    return parser


def _json_requested(argv: Sequence[str]) -> bool:
    return "--json" in argv


def _error_report(code: str, message: str) -> dict[str, str]:
    return {
        "schema_version": "john_lomein_mission_error/v1",
        "status": "rejected",
        "error_code": code,
        "message": message,
    }


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    json_requested = _json_requested(arguments)
    args = _parser().parse_args(arguments)
    try:
        if args.command == "propose":
            report = propose(
                args.instance,
                statement=args.statement,
                roadmap_sources=args.roadmap_sources,
                owner_signal_policy=args.owner_signal_policy,
                output=args.output,
            )
            rendered = (
                json.dumps(report, ensure_ascii=False, sort_keys=True)
                if args.json
                else render_proposal_human(report)
            )
        else:
            report = confirm(
                args.instance,
                proposal_path=args.proposal,
                owner_confirmation=args.owner_confirmation,
            )
            rendered = (
                json.dumps(report, ensure_ascii=False, sort_keys=True)
                if args.json
                else render_confirmation_human(report)
            )
    except MissionWorkflowError as exc:
        if json_requested:
            print(
                json.dumps(
                    _error_report(exc.code, exc.public_message),
                    sort_keys=True,
                )
            )
        else:
            print(
                f"john-lomein mission rejected: {exc.code}: "
                f"{exc.public_message}",
                file=sys.stderr,
            )
        return 2
    except Exception:
        if json_requested:
            print(
                json.dumps(
                    _error_report(
                        "mission_internal_error",
                        "mission workflow could not complete safely",
                    ),
                    sort_keys=True,
                )
            )
        else:
            print(
                "john-lomein mission rejected: mission_internal_error: "
                "mission workflow could not complete safely",
                file=sys.stderr,
            )
        return 2
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
