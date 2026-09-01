from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def manifest(runtime: Path) -> dict:
    return {
        "instance": {"slug": "pilot"},
        "runtime": {"hermes_home": str(runtime)},
        "profiles": {"guide": "john-lomein-guide"},
        "memory": {
            "provider": "honcho",
            "honcho": {
                "workspace": "pilot-public",
            },
        },
    }


def test_runtime_preflight_requires_exact_profile_binding_discovery_and_workspace(tmp_path):
    from john_lomein_guide_runtime_preflight import verify_guide_runtime
    from john_lomein_honcho_contract import profile_honcho_config

    runtime = tmp_path / "runtime"
    profile = runtime / "profiles" / "john-lomein-guide"
    plugin = runtime / "plugins" / "john-lomein-guide-lifecycle"
    plugin.mkdir(parents=True)
    (plugin / "plugin.yaml").write_text(
        "name: john-lomein-guide-lifecycle\nprovides_hooks:\n  - pre_llm_call\n  - transform_llm_output\n",
        encoding="utf-8",
    )
    (plugin / "__init__.py").write_text("def register(ctx): pass\n", encoding="utf-8")
    (profile / "plugins").mkdir(parents=True)
    (profile / "plugins" / "john-lomein-guide-lifecycle").symlink_to(plugin)
    config_path = profile / "config.yaml"
    config_path.write_text("{}\n", encoding="utf-8")
    config_path.chmod(0o600)
    managed = runtime / "managed-policy" / "john-lomein-guide"
    managed.mkdir(parents=True)
    managed_config = managed / "config.yaml"
    managed_config.write_text(
        "plugins:\n  enabled:\n  - john-lomein-guide-lifecycle\n  disabled: []\n",
        encoding="utf-8",
    )
    managed_config.chmod(0o600)
    payload = profile_honcho_config(
        manifest(runtime),
        instance_slug="pilot",
        role="guide",
        profile="john-lomein-guide",
    )
    honcho_path = profile / "honcho.json"
    honcho_path.write_text(json.dumps(payload), encoding="utf-8")
    honcho_path.chmod(0o600)

    result = verify_guide_runtime(
        runtime_home=runtime,
        manifest=manifest(runtime),
        guide_profile="john-lomein-guide",
        expected_workspace="pilot-public",
        plugin_inventory_loader=lambda: [
            {"name": "john-lomein-guide-lifecycle", "status": "enabled"}
        ],
    )
    assert result["verified"] is True
    assert result["workspace"] == "pilot-public"
    assert result["hooks"] == ["pre_llm_call", "transform_llm_output"]

    payload["hosts"]["hermes"]["workspace"] = "personal"
    honcho_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="workspace"):
        verify_guide_runtime(
            runtime_home=runtime,
            manifest=manifest(runtime),
            guide_profile="john-lomein-guide",
            expected_workspace="pilot-public",
            plugin_inventory_loader=lambda: [
                {"name": "john-lomein-guide-lifecycle", "status": "enabled"}
            ],
        )


def test_runtime_preflight_fails_when_hermes_did_not_discover_plugin(tmp_path):
    from john_lomein_guide_runtime_preflight import verify_plugin_inventory

    with pytest.raises(ValueError, match="not enabled"):
        verify_plugin_inventory(
            [],
            plugin_name="john-lomein-guide-lifecycle",
        )
