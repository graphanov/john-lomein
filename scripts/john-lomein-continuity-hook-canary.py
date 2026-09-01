#!/usr/bin/env python3
"""Prove an installed Hermes runtime injects ``pre_llm_call`` context.

The canary runs one isolated Hermes turn against a loopback-only fake
OpenAI-compatible endpoint.  Success means the endpoint observed a nonce that
existed only in the plugin hook return value.  Plugin discovery or hook
registration alone is not accepted as evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


RESULT_SCHEMA = "john-lomein.continuity-hook-canary.v1"
PRODUCT_RESULT_SCHEMA = "john-lomein.continuity-product-hook-canary.v1"
MAX_REQUEST_BYTES = 2 * 1024 * 1024
CANARY_PLUGIN = "john-lomein-hook-injection-canary"


class CanaryError(RuntimeError):
    pass


def _message_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        pieces: list[str] = []
        for item in value:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                pieces.append(item["text"])
        return "\n".join(pieces)
    return ""


class _CaptureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], nonce: str):
        super().__init__(address, _Handler)
        self.nonce = nonce
        self.observed = threading.Event()
        self.request_sha256 = ""
        self.failure = ""


class _Handler(BaseHTTPRequestHandler):
    server: _CaptureServer

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def _json(self, status: int, value: Any) -> None:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path.rstrip("/") == "/v1/models":
            self._json(
                200,
                {
                    "object": "list",
                    "data": [
                        {
                            "id": "john-continuity-canary",
                            "object": "model",
                            "owned_by": "john-lomein-product",
                        }
                    ],
                },
            )
            return
        self._json(404, {"error": {"message": "not found"}})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path.rstrip("/") != "/v1/chat/completions":
            self._json(404, {"error": {"message": "not found"}})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length < 1 or length > MAX_REQUEST_BYTES:
            self.server.failure = "request_size"
            self._json(400, {"error": {"message": "request size"}})
            return
        raw = self.rfile.read(length)
        self.server.request_sha256 = hashlib.sha256(raw).hexdigest()
        try:
            body = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError):
            self.server.failure = "request_json"
            self._json(400, {"error": {"message": "request json"}})
            return
        messages = body.get("messages") if isinstance(body, dict) else None
        observed = False
        if isinstance(messages, list):
            for message in messages:
                if not isinstance(message, dict) or message.get("role") != "user":
                    continue
                if self.server.nonce in _message_text(message.get("content")):
                    observed = True
                    break
        if not observed:
            self.server.failure = "context_not_in_model_request"
        else:
            self.server.observed.set()
        created = int(time.time())
        if isinstance(body, dict) and body.get("stream") is True:
            chunks = [
                {
                    "id": "chatcmpl-john-continuity-canary",
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": "john-continuity-canary",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "role": "assistant",
                                "content": "CANARY_OK",
                            },
                            "finish_reason": None,
                        }
                    ],
                },
                {
                    "id": "chatcmpl-john-continuity-canary",
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": "john-continuity-canary",
                    "choices": [
                        {
                            "index": 0,
                            "delta": {},
                            "finish_reason": "stop",
                        }
                    ],
                },
            ]
            wire = "".join(
                f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n"
                for chunk in chunks
            ) + "data: [DONE]\n\n"
            raw_response = wire.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(raw_response)))
            self.end_headers()
            self.wfile.write(raw_response)
            return
        self._json(
            200,
            {
                "id": "chatcmpl-john-continuity-canary",
                "object": "chat.completion",
                "created": created,
                "model": "john-continuity-canary",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "CANARY_OK",
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2,
                },
            },
        )


def _write_canary_home(root: Path, *, port: int, nonce: str) -> Path:
    home = root / "hermes"
    plugin = home / "plugins" / CANARY_PLUGIN
    plugin.mkdir(parents=True, mode=0o700)
    (plugin / "plugin.yaml").write_text(
        "\n".join(
            [
                f"name: {CANARY_PLUGIN}",
                'version: "1.0.0"',
                'description: "Ephemeral pre_llm_call injection canary."',
                "author: John Lomein product",
                "provides_hooks:",
                "  - pre_llm_call",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (plugin / "__init__.py").write_text(
        "\n".join(
            [
                "import os",
                "",
                "def _hook(**_kwargs):",
                "    nonce = os.environ.get('JOHN_CONTINUITY_CANARY_NONCE', '')",
                "    return {'context': nonce} if nonce else None",
                "",
                "def register(ctx):",
                "    ctx.register_hook('pre_llm_call', _hook)",
                "",
            ]
        ),
        encoding="utf-8",
    )
    config = "\n".join(
        [
            "model:",
            "  default: john-continuity-canary",
            "  provider: custom",
            f"  base_url: http://127.0.0.1:{port}/v1",
            "  api_key: local-canary-key",
            "  api_mode: chat_completions",
            "  context_length: 65536",
            "max_tokens: 32",
            "agent:",
            "  max_turns: 1",
            "  disabled_toolsets:",
            "    - memory",
            "    - session_search",
            "plugins:",
            "  enabled:",
            f"    - {CANARY_PLUGIN}",
            "  disabled: []",
            "memory:",
            "  memory_enabled: false",
            "  user_profile_enabled: false",
            "  provider: ''",
            "mcp_servers: {}",
            "",
        ]
    )
    (home / "config.yaml").write_text(config, encoding="utf-8")
    os.chmod(plugin / "plugin.yaml", 0o600)
    os.chmod(plugin / "__init__.py", 0o600)
    os.chmod(home / "config.yaml", 0o600)
    return home


def run_canary(
    hermes: str | Path,
    *,
    timeout: int = 30,
) -> dict[str, Any]:
    executable = Path(hermes).expanduser()
    if not executable.is_file():
        resolved = shutil.which(str(hermes))
        if not resolved:
            raise CanaryError("Hermes executable is unavailable")
        executable = Path(resolved)
    nonce = f"JOHN_PRE_LLM_CANARY_{os.urandom(16).hex()}"
    server = _CaptureServer(("127.0.0.1", 0), nonce)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="john-continuity-canary-") as tmp:
            temp_root = Path(tmp).resolve()
            home = _write_canary_home(
                temp_root,
                port=int(server.server_address[1]),
                nonce=nonce,
            )
            env = {
                "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
                "HOME": str(temp_root),
                "HERMES_HOME": str(home),
                "OPENAI_API_KEY": "local-canary-key",
                "JOHN_CONTINUITY_CANARY_NONCE": nonce,
                "HERMES_ACCEPT_HOOKS": "1",
                "HERMES_DISABLE_AUTO_UPDATE": "1",
                "NO_COLOR": "1",
                "LANG": "C.UTF-8",
            }
            try:
                process = subprocess.run(
                    [
                        str(executable),
                        "chat",
                        "-q",
                        "Return the literal text CANARY_OK.",
                        "-Q",
                        "--ignore-rules",
                        "--provider",
                        "custom",
                        "-m",
                        "john-continuity-canary",
                        "--max-turns",
                        "1",
                    ],
                    env=env,
                    cwd=temp_root,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired as exc:
                raise CanaryError("Hermes hook canary timed out") from exc
        if not server.observed.is_set():
            reason = server.failure or "no_model_request"
            diagnostic_lines = [
                line.strip()
                for line in (process.stderr or process.stdout).splitlines()
                if line.strip()
            ]
            diagnostic = diagnostic_lines[-1][:240] if diagnostic_lines else "none"
            raise CanaryError(
                "Hermes did not inject pre_llm_call context: "
                f"{reason}; exit={process.returncode}; diagnostic={diagnostic}"
            )
        if process.returncode != 0:
            raise CanaryError(
                "Hermes returned a failure after the canary model request"
            )
        if not server.request_sha256:
            raise CanaryError("Hermes canary request digest is unavailable")
        return {
            "schema_version": RESULT_SCHEMA,
            "status": "verified",
            "hermes_path_sha256": hashlib.sha256(
                str(executable.resolve()).encode("utf-8")
            ).hexdigest(),
            "model_request_sha256": server.request_sha256,
            "context_target": "current_user_message",
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _asset_paths(asset_root: Path) -> tuple[Path, Path]:
    product_plugin = (
        asset_root / "runtime_plugins" / "john-lomein-continuity"
    )
    runtime_plugin = asset_root / "plugins" / "john-lomein-continuity"
    if product_plugin.is_dir():
        return product_plugin, asset_root / "scripts"
    if runtime_plugin.is_dir():
        return runtime_plugin, asset_root / "scripts"
    raise CanaryError("John continuity plugin asset is unavailable")


def _write_product_canary_runtime(
    root: Path,
    *,
    asset_root: Path,
    port: int,
    nonce: str,
) -> tuple[Path, str]:
    plugin_source, script_source = _asset_paths(asset_root)
    runtime = root / "runtime"
    profile_name = "john-lomein-maintainer"
    profile = runtime / "profiles" / profile_name
    for directory in (
        runtime,
        runtime / "state",
        runtime / "scripts",
        runtime / "plugins",
        runtime / "profiles",
        profile,
        profile / "plugins",
    ):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
    plugin_destination = runtime / "plugins" / "john-lomein-continuity"
    shutil.copytree(
        plugin_source,
        plugin_destination,
        ignore=shutil.ignore_patterns("__pycache__", ".DS_Store"),
    )
    for name in (
        "john_lomein_continuity.py",
        "john_lomein_continuity_importer.py",
        "john_lomein_continuity_protocol.py",
        "john_lomein_public_safety.py",
        "john_lomein_factory_receipts.py",
    ):
        source = script_source / name
        if not source.is_file() or source.is_symlink():
            raise CanaryError(f"John continuity helper dependency is unsafe: {name}")
        destination = runtime / "scripts" / name
        shutil.copy2(source, destination)
        os.chmod(destination, 0o600)
    (profile / "plugins" / "john-lomein-continuity").symlink_to(
        plugin_destination,
        target_is_directory=True,
    )
    profiles = {
        "maintainer": "john-lomein-maintainer",
        "forge": "john-lomein-forge",
        "guide": "john-lomein-guide",
        "overwatch": "john-lomein-overwatch",
        "learning_steward": "john-lomein-learning-steward",
    }
    persona = {
        "schema_version": "john_lomein_persona_deployment/v1",
        "persona_version": "john-lomein.persona.v1",
        "sha256": hashlib.sha256(b"john-continuity-product-canary").hexdigest(),
        "source": "persona/JOHN_LOMEIN.md",
        "profiles": profiles,
    }
    (runtime / "state" / "john-lomein-persona.json").write_text(
        json.dumps(persona, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    os.chmod(runtime / "state" / "john-lomein-persona.json", 0o600)

    scripts_path = str(Path(__file__).resolve().parent)
    if scripts_path not in os.sys.path:
        os.sys.path.insert(0, scripts_path)
    from john_lomein_continuity import (
        WRITE_SCHEMA,
        append_entry,
        initialize_store,
    )

    continuity = runtime / "state" / "continuity"
    initialize_store(
        continuity,
        ledger_id="jlcl-111111111111111111111111",
    )
    entry = append_entry(
        continuity,
        {
            "schema_version": WRITE_SCHEMA,
            "entry_id": "jlce-222222222222222222222222",
            "kind": "decision",
            "subject": "Hook capability continuity decision",
            "summary": nonce,
            "payload": {"disposition": "accepted"},
            "source": {
                "kind": "automation",
                "trust": "product_observed",
                "actor": "continuity-canary",
                "locator": "canary:" + ("a" * 220),
                "sha256": hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
            },
            "scope": {
                "privacy": "private",
                "visible_to_roles": ["maintainer"],
                "repository": "john-lomein/continuity-canary",
            },
            "expires_at": None,
            "supersedes_entry_id": None,
        },
    )
    config = "\n".join(
        [
            "model:",
            "  default: john-continuity-canary",
            "  provider: custom",
            f"  base_url: http://127.0.0.1:{port}/v1",
            "  api_key: local-canary-key",
            "  api_mode: chat_completions",
            "  context_length: 65536",
            "max_tokens: 32",
            "agent:",
            "  max_turns: 1",
            "  disabled_toolsets:",
            "    - memory",
            "    - session_search",
            "plugins:",
            "  enabled:",
            "    - john-lomein-continuity",
            "  disabled:",
            "    - mnemosyne",
            "memory:",
            "  memory_enabled: false",
            "  user_profile_enabled: false",
            "  provider: ''",
            "mcp_servers: {}",
            "",
        ]
    )
    (profile / "config.yaml").write_text(config, encoding="utf-8")
    os.chmod(profile / "config.yaml", 0o600)
    return profile, str(entry["entry_id"])


def run_product_canary(
    hermes: str | Path,
    *,
    asset_root: str | Path,
    timeout: int = 30,
) -> dict[str, Any]:
    executable = Path(hermes).expanduser()
    if not executable.is_file():
        resolved = shutil.which(str(hermes))
        if not resolved:
            raise CanaryError("Hermes executable is unavailable")
        executable = Path(resolved)
    assets = Path(asset_root).expanduser()
    if not assets.is_absolute():
        raise CanaryError("John continuity asset root must be absolute")
    assets = assets.resolve()
    nonce = f"JOHN_PRODUCT_CONTINUITY_CANARY_{os.urandom(16).hex()}"
    server = _CaptureServer(("127.0.0.1", 0), nonce)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(
            prefix="john-continuity-product-canary-"
        ) as tmp:
            temp_root = Path(tmp).resolve()
            profile, entry_id = _write_product_canary_runtime(
                temp_root,
                asset_root=assets,
                port=int(server.server_address[1]),
                nonce=nonce,
            )
            env = {
                "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
                "HOME": str(temp_root),
                "HERMES_HOME": str(profile),
                "OPENAI_API_KEY": "local-canary-key",
                "HERMES_SESSION_PROFILE": "john-lomein-maintainer",
                "HERMES_SESSION_PLATFORM": "cli",
                "BOT_REPO": "john-lomein/continuity-canary",
                "HERMES_ACCEPT_HOOKS": "1",
                "HERMES_DISABLE_AUTO_UPDATE": "1",
                "NO_COLOR": "1",
                "LANG": "C.UTF-8",
            }
            try:
                process = subprocess.run(
                    [
                        str(executable),
                        "chat",
                        "-q",
                        "Return the literal text CANARY_OK.",
                        "-Q",
                        "--ignore-rules",
                        "--provider",
                        "custom",
                        "-m",
                        "john-continuity-canary",
                        "--max-turns",
                        "1",
                    ],
                    env=env,
                    cwd=temp_root,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=timeout,
                )
            except subprocess.TimeoutExpired as exc:
                raise CanaryError("John continuity product canary timed out") from exc
        if not server.observed.is_set():
            reason = server.failure or "no_model_request"
            diagnostic_lines = [
                line.strip()
                for line in (process.stderr or process.stdout).splitlines()
                if line.strip()
            ]
            diagnostic = diagnostic_lines[-1][:240] if diagnostic_lines else "none"
            raise CanaryError(
                "deployed John continuity capsule did not reach the model "
                f"request: {reason}; exit={process.returncode}; "
                f"diagnostic={diagnostic}"
            )
        if process.returncode != 0 or not server.request_sha256:
            raise CanaryError(
                "Hermes failed after observing the John continuity capsule"
            )
        return {
            "schema_version": PRODUCT_RESULT_SCHEMA,
            "status": "verified",
            "profile": "john-lomein-maintainer",
            "entry_id": entry_id,
            "model_request_sha256": server.request_sha256,
            "context_target": "current_user_message",
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify installed Hermes pre_llm_call context injection."
    )
    parser.add_argument("--hermes", default=shutil.which("hermes") or "hermes")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument(
        "--asset-root",
        help=(
            "Also exercise the actual John continuity plugin/helper in a "
            "temporary deployed-profile layout using this product or runtime root."
        ),
    )
    args = parser.parse_args(argv)
    if args.timeout < 5 or args.timeout > 120:
        print("invalid canary timeout", file=os.sys.stderr)
        return 2
    try:
        if args.asset_root:
            result = run_product_canary(
                args.hermes,
                asset_root=args.asset_root,
                timeout=args.timeout,
            )
        else:
            result = run_canary(args.hermes, timeout=args.timeout)
    except CanaryError as exc:
        print(f"john-lomein continuity hook canary failed: {exc}", file=os.sys.stderr)
        return 3
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
