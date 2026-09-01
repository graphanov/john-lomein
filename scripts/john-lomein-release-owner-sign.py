#!/usr/bin/env python3
"""Operator/gateway entry point for the isolated release-owner signer."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from owner_gateway.john_lomein_release_owner_signer import main


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
