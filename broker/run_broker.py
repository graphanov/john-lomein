#!/usr/bin/env python3
"""Root-owned isolated entrypoint used by service managers."""

from __future__ import annotations

import sys
from pathlib import Path


if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from broker.john_lomein_broker_daemon import main


if __name__ == "__main__":
    raise SystemExit(main())
