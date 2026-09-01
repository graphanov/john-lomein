#!/usr/bin/env python3
"""Initialize john-lomein gateway trust-assertion verifier state.

Actual per-message trust assertions must be minted by gateway-owned code outside
the model command surface. Model-accessible runtime code stores only the public
verification key and consumed-nonce ledger; it cannot self-mint authority.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_owner_actions import trust_public_key_path


def init_verifier(env: dict[str, str]) -> Path:
    path = trust_public_key_path(env)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        mode = path.stat().st_mode & 0o777
        if mode & 0o222:
            raise SystemExit(f"trust assertion public key is writable: {oct(mode)}")
    return path


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cmd", choices=["init-verifier"])
    args = parser.parse_args(argv)
    path = init_verifier(dict(os.environ))
    fingerprint = ""
    if path.exists() and not path.is_symlink():
        import hashlib
        fingerprint = hashlib.sha256(path.read_bytes()).hexdigest()
    print(json.dumps({"ok": True, "public_key": str(path), "public_key_present": path.exists(), "public_key_sha256": fingerprint, "signing": "external_gateway_only"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
