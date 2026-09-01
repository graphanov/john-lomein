#!/usr/bin/env python3
"""Fail closed when the local Honcho pilot is unhealthy."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from john_lomein_honcho_pilot import (
    collect_metrics,
    evaluate_health,
    inspect_honcho_model_config,
    write_pause_receipt,
    write_private_json,
)


def watchdog_decision(health: Mapping[str, Any], pause_exists: bool) -> str:
    if pause_exists:
        return "stay_paused"
    return "healthy" if health.get("healthy") is True else "pause"


def supervisor_status_fresh(status: Mapping[str, Any], *, maximum_age_seconds: int = 360) -> bool:
    try:
        observed = datetime.fromisoformat(
            str(status["observed_at"]).replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    except (KeyError, TypeError, ValueError):
        return False
    age = (datetime.now(timezone.utc) - observed).total_seconds()
    return 0 <= age <= maximum_age_seconds


def disable_guide_memory_writes(runtime_home: Path, guide_profile: str) -> Path:
    target = runtime_home / "profiles" / guide_profile / "honcho.json"
    if not target.is_file() or target.is_symlink():
        raise RuntimeError("Guide Honcho config is missing or unsafe")
    payload = json.loads(target.read_text(encoding="utf-8"))
    hosts = payload.get("hosts")
    if not isinstance(hosts, dict) or not hosts:
        raise RuntimeError("Guide Honcho hosts are missing")
    for host in hosts.values():
        if not isinstance(host, dict):
            raise RuntimeError("Guide Honcho host is invalid")
        host["saveMessages"] = False
    write_private_json(target, payload)
    readback = json.loads(target.read_text(encoding="utf-8"))
    if any(not isinstance(host, dict) or host.get("saveMessages") is not False for host in (readback.get("hosts") or {}).values()):
        raise RuntimeError("Guide Honcho writes were not disabled")
    return target


def stop_guide_service(
    *, manifest: Path, runtime_home: Path, guide_label: str
) -> None:
    command = [
        sys.executable,
        str(runtime_home / "scripts" / "john_lomein_service_registry.py"),
        "stop", "--manifest", str(manifest), "--runtime-home", str(runtime_home),
        "--service", f"guide={guide_label}",
    ]
    child_env={
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(Path.home()),
        "USER": os.environ.get("USER", ""),
    }
    subprocess.run(command, check=True, timeout=60, env=child_env)


def apply_watchdog(
    *,
    health: Mapping[str, Any],
    runtime_home: Path,
    manifest: Path,
    guide_profile: str,
    guide_label: str,
    supervisor_label: str,
    snapshot_path: Path,
) -> dict[str, Any]:
    pause_path = runtime_home / "state" / "honcho" / "INGESTION_PAUSED.json"
    decision = watchdog_decision(health, pause_path.exists())
    result = {"decision": decision, "health": dict(health), "pause_path": str(pause_path)}
    if decision == "pause":
        result["pause_receipt"] = write_pause_receipt(pause_path, health)
    if decision in {"pause", "stay_paused"}:
        if not supervisor_label.startswith("ai.john-lomein.") or not supervisor_label.endswith(
            ".public-honcho"
        ):
            raise ValueError("public Honcho supervisor label is invalid")
        disable_guide_memory_writes(runtime_home, guide_profile)
        stop_guide_service(manifest=manifest, runtime_home=runtime_home, guide_label=guide_label)
        result["pause_reasserted"] = True
        result["supervisor_resident"] = True
    write_private_json(snapshot_path, result)
    return result


def parser() -> argparse.ArgumentParser:
    out = argparse.ArgumentParser(description=__doc__)
    out.add_argument("--database", required=True)
    out.add_argument("--base-url", required=True)
    out.add_argument("--workspace", required=True)
    out.add_argument("--runtime-home", required=True)
    out.add_argument("--manifest", required=True)
    out.add_argument("--guide-profile", required=True)
    out.add_argument("--guide-label", required=True)
    out.add_argument("--supervisor-label", required=True)
    out.add_argument("--server-root", required=True)
    out.add_argument("--expected-memory-model", required=True)
    out.add_argument("--snapshot", required=True)
    return out


def main() -> int:
    args = parser().parse_args()
    thresholds = {
        "queue_pending_max": 25,
        "queue_oldest_seconds_max": 900,
        "embedding_pending_max": 10,
        "embedding_oldest_seconds_max": 900,
        "embedding_recent_failed_max": 0,
        "workspace_storage_bytes_max": 1_073_741_824,
        "model_error_rows_max": 0,
        "embedding_error_rows_max": 0,
        "derivation_latency_p95_seconds_max": 900,
        "embedding_latency_p95_seconds_max": 900,
    }
    try:
        supervisor_status_path = Path(args.runtime_home) / "state" / "honcho" / "supervisor.json"
        supervisor_status = json.loads(supervisor_status_path.read_text(encoding="utf-8"))
        status_fresh = supervisor_status_fresh(supervisor_status)
        if supervisor_status.get("state") == "retention_running" and status_fresh:
            health = {
                "healthy": True,
                "reasons": [],
                "maintenance": "retention_running",
                "supervisor_status": supervisor_status,
            }
        else:
            metrics = collect_metrics(args.database, args.base_url, args.workspace)
            health = {"metrics": metrics, "thresholds": thresholds, **evaluate_health(metrics, thresholds)}
            model_config = inspect_honcho_model_config(
                Path(args.server_root), args.expected_memory_model
            )
            health["model_config"] = model_config
            health["supervisor_status"] = supervisor_status
            if model_config["model_config_matches"] is not True:
                health["healthy"] = False
                health["reasons"] = sorted({*(health.get("reasons") or []), "memory_model_config_mismatch"})
            if supervisor_status.get("state") not in {
                "running",
                "starting_children",
                "retention_complete",
            }:
                health["healthy"] = False
                health["reasons"] = sorted(
                    {*(health.get("reasons") or []), "public_honcho_supervisor_not_running"}
                )
            if not status_fresh:
                health["healthy"] = False
                health["reasons"] = sorted(
                    {*(health.get("reasons") or []), "public_honcho_supervisor_status_stale"}
                )
    except Exception as exc:
        health = {"healthy": False, "reasons": ["health_collection_failed"], "error_class": type(exc).__name__}
    result = apply_watchdog(
        health=health,
        runtime_home=Path(args.runtime_home).resolve(),
        manifest=Path(args.manifest).resolve(),
        guide_profile=args.guide_profile,
        guide_label=args.guide_label,
        supervisor_label=args.supervisor_label,
        snapshot_path=Path(args.snapshot).resolve(),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["decision"] == "healthy" else 2


if __name__ == "__main__":
    raise SystemExit(main())
