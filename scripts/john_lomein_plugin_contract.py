#!/usr/bin/env python3
"""Deterministic product-owned plugin enable/disable boundary."""
from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import Any

CONTINUITY_PLUGIN = "john-lomein-continuity"
RELEASE_APPROVAL_PLUGIN = "john-lomein-release-approval"
GUIDE_LIFECYCLE_PLUGIN = "john-lomein-guide-lifecycle"
OMH_PLUGIN = "omh"


def _names(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _set_state(
    enabled: list[str],
    disabled: list[str],
    plugin: str,
    *,
    active: bool,
) -> tuple[list[str], list[str]]:
    enabled = [name for name in enabled if name != plugin]
    disabled = [name for name in disabled if name != plugin]
    if active:
        enabled.append(plugin)
    else:
        disabled.append(plugin)
    return enabled, disabled


def apply_product_plugin_boundary(
    config: MutableMapping[str, Any],
    role: str,
    *,
    omh_enabled: bool,
) -> MutableMapping[str, Any]:
    """Reassert product plugin scope after Hermes CLI config rewrites."""
    raw = config.get("plugins")
    plugins: MutableMapping[str, Any]
    if isinstance(raw, MutableMapping):
        plugins = raw
    elif isinstance(raw, Mapping):
        plugins = dict(raw)
        config["plugins"] = plugins
    else:
        plugins = {}
        config["plugins"] = plugins

    enabled = _names(plugins.get("enabled"))
    disabled = _names(plugins.get("disabled"))
    enabled, disabled = _set_state(
        enabled,
        disabled,
        CONTINUITY_PLUGIN,
        active=True,
    )
    guide = role == "guide"
    enabled, disabled = _set_state(
        enabled,
        disabled,
        RELEASE_APPROVAL_PLUGIN,
        active=guide,
    )
    enabled, disabled = _set_state(
        enabled,
        disabled,
        GUIDE_LIFECYCLE_PLUGIN,
        active=guide,
    )
    enabled, disabled = _set_state(
        enabled,
        disabled,
        OMH_PLUGIN,
        active=bool(omh_enabled),
    )
    plugins["enabled"] = list(dict.fromkeys(enabled))
    plugins["disabled"] = list(dict.fromkeys(disabled))
    return config


def product_plugin_boundary_errors(
    config: Mapping[str, Any],
    role: str,
    *,
    omh_enabled: bool,
) -> list[str]:
    expected: dict[str, Any] = {"plugins": {}}
    apply_product_plugin_boundary(expected, role, omh_enabled=omh_enabled)
    expected_plugins = expected["plugins"]
    raw = config.get("plugins")
    if not isinstance(raw, Mapping):
        return ["plugins_missing"]
    enabled = set(_names(raw.get("enabled")))
    disabled = set(_names(raw.get("disabled")))
    errors: list[str] = []
    for plugin in (
        CONTINUITY_PLUGIN,
        RELEASE_APPROVAL_PLUGIN,
        GUIDE_LIFECYCLE_PLUGIN,
        OMH_PLUGIN,
    ):
        should_enable = plugin in expected_plugins["enabled"]
        if should_enable and plugin not in enabled:
            errors.append(f"plugin_not_enabled:{plugin}")
        if not should_enable and plugin not in disabled:
            errors.append(f"plugin_not_disabled:{plugin}")
        if plugin in enabled and plugin in disabled:
            errors.append(f"plugin_conflicting_state:{plugin}")
    return errors
