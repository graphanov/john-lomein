#!/usr/bin/env python3
"""Render John Lomein's offline instance orientation."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from john_lomein_orientation import (
    OrientationError,
    broken_report,
    build_orientation,
    exit_code,
    render_human,
    render_json,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Show John Lomein's local mission and activation posture."
    )
    parser.add_argument("instance", type=Path)
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = build_orientation(args.instance)
    except OrientationError as exc:
        report = broken_report(exc)
    except Exception:
        report = broken_report(
            OrientationError(
                "orientation_internal_error",
                "instance orientation could not complete safely",
            )
        )
    print(render_json(report) if args.json else render_human(report))
    return exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
