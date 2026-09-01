#!/usr/bin/env python3
"""Repository wrapper for the zero-argument offline public verifier."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VENDOR_ROOT = ROOT / "vendor"
for measured_root in (VENDOR_ROOT, ROOT):
    if (
        measured_root == ROOT
        or measured_root.is_dir()
    ) and str(measured_root) not in sys.path:
        sys.path.insert(0, str(measured_root))

from qualification_attestor import (  # noqa: E402
    john_lomein_persona_qualification_public_verifier as verifier,
)


if __name__ == "__main__":
    raise SystemExit(verifier.main())
