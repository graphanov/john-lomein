from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "john-lomein-honcho-watchdog.py"


def load_watchdog() -> Any:
    spec = importlib.util.spec_from_file_location("john_lomein_honcho_watchdog", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_unhealthy_watchdog_pauses_public_children_stops_guide_and_keeps_supervisor(
    tmp_path,
):
    watchdog = load_watchdog()
    home = tmp_path / "runtime"
    config = home / "profiles" / "john-lomein-guide" / "honcho.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"hosts": {"hermes_john-lomein-guide": {"saveMessages": True}, "hermes": {"saveMessages": True}}}), encoding="utf-8")
    config.chmod(0o600)
    manifest = tmp_path / "instance.yaml"
    manifest.write_text("instance: {slug: test}\n", encoding="utf-8")
    stops = []
    supervisor_stops = []
    watchdog.stop_guide_service = lambda **kwargs: stops.append(kwargs)
    watchdog.stop_public_honcho_supervisor = lambda **kwargs: supervisor_stops.append(kwargs)
    snapshot = home / "state" / "honcho" / "snapshot.json"
    result = watchdog.apply_watchdog(
        health={"healthy": False, "reasons": ["queue_oldest_seconds_exceeded"]},
        runtime_home=home,
        manifest=manifest,
        guide_profile="john-lomein-guide",
        guide_label="ai.hermes.gateway-test-guide",
        supervisor_label="ai.john-lomein.test.public-honcho",
        snapshot_path=snapshot,
    )
    assert result["decision"] == "pause"
    assert all(host["saveMessages"] is False for host in json.loads(config.read_text())["hosts"].values())
    assert len(stops) == 1
    assert supervisor_stops == []
    assert result["supervisor_resident"] is True
    assert (home / "state" / "honcho" / "INGESTION_PAUSED.json").is_file()
    stops.clear()
    supervisor_stops.clear()
    again = watchdog.apply_watchdog(
        health={"healthy": True, "reasons": []},
        runtime_home=home,
        manifest=manifest,
        guide_profile="john-lomein-guide",
        guide_label="ai.hermes.gateway-test-guide",
        supervisor_label="ai.john-lomein.test.public-honcho",
        snapshot_path=snapshot,
    )
    assert again["decision"] == "stay_paused"
    assert len(stops) == 1
    assert supervisor_stops == []
    assert again["supervisor_resident"] is True
    assert again["pause_reasserted"] is True
    assert all(host["saveMessages"] is False for host in json.loads(config.read_text())["hosts"].values())
