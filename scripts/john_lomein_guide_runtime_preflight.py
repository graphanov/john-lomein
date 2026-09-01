#!/usr/bin/env python3
"""Fail-closed Guide plugin discovery and public-workspace preflight."""
from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from john_lomein_honcho_contract import (
    honcho_settings,
    profile_honcho_errors,
)

GUIDE_LIFECYCLE_PLUGIN = "john-lomein-guide-lifecycle"
REQUIRED_HOOKS = ("pre_llm_call", "transform_llm_output")


def _safe_regular(path: Path, *, private: bool = False) -> Path:
    info = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o022
        or (private and info.st_mode & 0o077)
    ):
        raise ValueError(f"unsafe Guide runtime file: {path.name}")
    return path


def verify_plugin_inventory(
    inventory: Any,
    *,
    plugin_name: str = GUIDE_LIFECYCLE_PLUGIN,
) -> dict[str, Any]:
    entries = inventory.get("plugins") if isinstance(inventory, Mapping) else inventory
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes, bytearray)):
        raise ValueError("Hermes plugin inventory is invalid")
    matches = [
        item
        for item in entries
        if isinstance(item, Mapping) and str(item.get("name") or "") == plugin_name
    ]
    if len(matches) != 1 or str(matches[0].get("status") or "").casefold() != "enabled":
        raise ValueError(f"required Guide lifecycle plugin is not enabled: {plugin_name}")
    return dict(matches[0])


def load_hermes_plugin_inventory(
    *,
    hermes: str,
    runtime_home: Path,
    guide_profile: str,
) -> Any:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(Path.home()),
        "HERMES_HOME": str(runtime_home),
        "JOHN_LOMEIN_INSTANCE_HERMES_HOME": str(runtime_home),
        "HERMES_MANAGED_DIR": str(runtime_home / "managed-policy" / guide_profile),
    }
    result = subprocess.run(
        [hermes, "-p", guide_profile, "plugins", "list", "--json"],
        capture_output=True,
        text=True,
        timeout=45,
        check=True,
        env=env,
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("Hermes plugin inventory is unreadable") from exc


def verify_guide_runtime(
    *,
    runtime_home: Path,
    manifest: Mapping[str, Any],
    guide_profile: str,
    expected_workspace: str,
    plugin_inventory_loader: Callable[[], Any],
) -> dict[str, Any]:
    home = Path(runtime_home).expanduser().resolve()
    profile = home / "profiles" / guide_profile
    if profile.is_symlink() or not profile.is_dir():
        raise ValueError("Guide profile is missing or unsafe")

    plugin_root = home / "plugins" / GUIDE_LIFECYCLE_PLUGIN
    binding = profile / "plugins" / GUIDE_LIFECYCLE_PLUGIN
    if (
        not binding.is_symlink()
        or binding.resolve(strict=True) != plugin_root.resolve(strict=True)
    ):
        raise ValueError("Guide lifecycle plugin binding is missing or stale")
    plugin_yaml = _safe_regular(plugin_root / "plugin.yaml")
    _safe_regular(plugin_root / "__init__.py")
    metadata = yaml.safe_load(plugin_yaml.read_text(encoding="utf-8")) or {}
    if not isinstance(metadata, Mapping):
        raise ValueError("Guide lifecycle plugin metadata is invalid")
    hooks = metadata.get("provides_hooks")
    if tuple(hooks or ()) != REQUIRED_HOOKS:
        raise ValueError("Guide lifecycle plugin hook contract is incomplete")

    config_path = _safe_regular(profile / "config.yaml", private=True)
    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    plugins = config.get("plugins") if isinstance(config, Mapping) else None
    enabled = set(plugins.get("enabled") or []) if isinstance(plugins, Mapping) else set()
    disabled = set(plugins.get("disabled") or []) if isinstance(plugins, Mapping) else set()
    if GUIDE_LIFECYCLE_PLUGIN not in enabled or GUIDE_LIFECYCLE_PLUGIN in disabled:
        raise ValueError("Guide lifecycle plugin config is not enabled")

    slug = str((manifest.get("instance") or {}).get("slug") or "").strip()
    settings = honcho_settings(manifest, instance_slug=slug)
    if settings["workspace"] != expected_workspace:
        raise ValueError("configured Guide public workspace does not match runtime input")
    honcho_path = _safe_regular(profile / "honcho.json", private=True)
    honcho = json.loads(honcho_path.read_text(encoding="utf-8"))
    errors = profile_honcho_errors(
        honcho,
        instance_slug=slug,
        role="guide",
        profile=guide_profile,
        manifest=manifest,
    )
    if errors:
        raise ValueError("Guide public workspace binding is not exact")
    hosts = honcho.get("hosts") if isinstance(honcho, Mapping) else None
    if not isinstance(hosts, Mapping) or not hosts or any(
        not isinstance(host, Mapping) or host.get("workspace") != expected_workspace
        for host in hosts.values()
    ):
        raise ValueError("Guide memory is not bound only to the configured public workspace")

    discovered = verify_plugin_inventory(plugin_inventory_loader())
    return {
        "verified": True,
        "plugin": GUIDE_LIFECYCLE_PLUGIN,
        "plugin_status": discovered["status"],
        "hooks": list(REQUIRED_HOOKS),
        "workspace": expected_workspace,
    }


def parser() -> argparse.ArgumentParser:
    out = argparse.ArgumentParser(description=__doc__)
    out.add_argument("--runtime-home", required=True)
    out.add_argument("--manifest", required=True)
    out.add_argument("--guide-profile", required=True)
    out.add_argument("--expected-workspace", required=True)
    out.add_argument("--hermes", required=True)
    return out


def main() -> int:
    args = parser().parse_args()
    manifest_path = Path(args.manifest).expanduser().resolve()
    _safe_regular(manifest_path)
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    if not isinstance(manifest, Mapping):
        raise ValueError("instance manifest is invalid")
    home = Path(args.runtime_home).expanduser().resolve()
    result = verify_guide_runtime(
        runtime_home=home,
        manifest=manifest,
        guide_profile=args.guide_profile,
        expected_workspace=args.expected_workspace,
        plugin_inventory_loader=lambda: load_hermes_plugin_inventory(
            hermes=args.hermes,
            runtime_home=home,
            guide_profile=args.guide_profile,
        ),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Guide runtime preflight failed: {exc}", file=os.sys.stderr)
        raise SystemExit(1)
