#!/usr/bin/env python3
"""Fail-closed agent-memory boundary for deployed John Lomein profiles.

Mnemosyne remains available only to the deterministic learning-steward script.
Hermes built-in memory, model-facing memory tools, and session search remain
disabled. Local Honcho supplies bounded provider lifecycle context; autonomous
worker profiles never save scheduler or repository prompts into user memory.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from pathlib import Path
from typing import Any


OPERATIONAL_ROLES = frozenset(
    {"maintainer", "forge", "guide", "overwatch", "learning_steward"}
)
DISABLED_AGENT_MEMORY_TOOLSETS = frozenset({"memory", "session_search"})
MNEMOSYNE_PLUGIN = "mnemosyne"
CONTINUITY_PLUGIN = "john-lomein-continuity"
RELEASE_APPROVAL_PLUGIN = "john-lomein-release-approval"
GUIDE_LIFECYCLE_PLUGIN = "john-lomein-guide-lifecycle"
NO_MCP_SENTINEL = "no_mcp"
PROFILE_MANAGED_POLICY_DIRNAME = "managed-policy"

_PRIVATE_MODEL_TOOLSETS = ("file", "skills", "terminal", "todo", "web")
_GUIDE_MODEL_TOOLSETS: tuple[str, ...] = ()
_MEMORY_ALIASES = frozenset(
    {"memory", "session_search", "mnemosyne", "mcp-mnemosyne"}
)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def allowed_profile_plugins(role: str) -> list[str]:
    """Return the exact user-plugin allow-list for an operational role."""

    if role not in OPERATIONAL_ROLES:
        raise ValueError(f"unsupported operational role: {role}")
    enabled = [CONTINUITY_PLUGIN]
    if role == "guide":
        enabled.extend([RELEASE_APPROVAL_PLUGIN, GUIDE_LIFECYCLE_PLUGIN])
    return enabled


def managed_policy_directory(
    runtime_home: str | Path,
    profile: str,
) -> Path:
    """Return the explicit Hermes managed-scope directory for one profile."""

    return (
        Path(runtime_home)
        / PROFILE_MANAGED_POLICY_DIRNAME
        / str(profile)
    )


def _sanitize_platform_toolsets(
    config: MutableMapping[str, Any],
    role: str,
    stale_mcp_names: set[str],
) -> None:
    raw = config.get("platform_toolsets")
    platform_toolsets: dict[str, list[str]] = {}
    if isinstance(raw, Mapping):
        for platform, entries in raw.items():
            if not isinstance(entries, list):
                continue
            clean = [
                str(entry)
                for entry in entries
                if str(entry) not in stale_mcp_names
                and str(entry).casefold() not in _MEMORY_ALIASES
                and str(entry) != NO_MCP_SENTINEL
            ]
            platform_toolsets[str(platform)] = list(
                dict.fromkeys([*clean, NO_MCP_SENTINEL])
            )

    # Every model turn currently resolves through the CLI platform. The public
    # Guide has no model-facing tools; its trusted gateway process alone owns
    # Discord transport and the model remains behind filesystem/provider
    # boundaries.
    if role == "guide":
        platform_toolsets["cli"] = [NO_MCP_SENTINEL]
        platform_toolsets["discord"] = [NO_MCP_SENTINEL]
    else:
        cli = platform_toolsets.get("cli", [])
        platform_toolsets["cli"] = list(dict.fromkeys([*cli, NO_MCP_SENTINEL]))
    config["platform_toolsets"] = platform_toolsets


def agent_memory_managed_policy(role: str) -> dict[str, Any]:
    """Return the exact higher-precedence Hermes policy for one role.

    Hermes applies ``HERMES_MANAGED_DIR/config.yaml`` after profile YAML.  This
    compact role-specific policy pins the memory/provider/plugin leaves and
    replaces the whole MCP subtree with ``null``.  The raw profile remains
    independently validated; this layer prevents an unrelated host-wide
    ``/etc/hermes`` overlay from silently changing the effective agent.
    """

    if role not in OPERATIONAL_ROLES:
        raise ValueError(f"unsupported operational role: {role}")
    enabled = allowed_profile_plugins(role)
    disabled = [MNEMOSYNE_PLUGIN]
    if role != "guide":
        disabled.extend([RELEASE_APPROVAL_PLUGIN, GUIDE_LIFECYCLE_PLUGIN])
    cli_toolsets = (
        list(_GUIDE_MODEL_TOOLSETS)
        if role == "guide"
        else list(_PRIVATE_MODEL_TOOLSETS)
    )
    policy: dict[str, Any] = {
        "memory": {
            "memory_enabled": False,
            "user_profile_enabled": False,
            "provider": "honcho",
            "write_approval": True,
            "nudge_interval": 0,
            "flush_min_turns": 0,
        },
        "agent": {
            "disabled_toolsets": sorted(DISABLED_AGENT_MEMORY_TOOLSETS),
        },
        "plugins": {
            "enabled": enabled,
            "disabled": disabled,
        },
        # A null parent wins over any raw child entries during Hermes' deep
        # merge. Hermes consistently resolves this through ``... or {}``.
        "mcp_servers": None,
        "platform_toolsets": {
            "cli": [*cli_toolsets, NO_MCP_SENTINEL],
        },
    }
    if role == "guide":
        policy["platform_toolsets"]["discord"] = [
            *_GUIDE_MODEL_TOOLSETS,
            NO_MCP_SENTINEL,
        ]
    return policy


def agent_memory_managed_policy_errors(
    policy: Mapping[str, Any] | Any,
    role: str,
) -> list[str]:
    """Return drift from the exact role-specific managed policy."""

    if not isinstance(policy, Mapping):
        return ["managed memory policy is not a mapping"]
    expected = agent_memory_managed_policy(role)
    return (
        []
        if dict(policy) == expected
        else ["managed memory policy does not exactly match the product contract"]
    )


def apply_agent_memory_boundary(
    config: MutableMapping[str, Any],
    role: str,
) -> None:
    """Apply the exact no-agent-memory contract while preserving other config."""

    if role not in OPERATIONAL_ROLES:
        raise ValueError(f"unsupported operational role: {role}")

    # Replace rather than merge so stale provider-specific configuration cannot
    # silently survive a redeploy and reactivate provider lifecycle hooks.
    config["memory"] = {
        "memory_enabled": False,
        "user_profile_enabled": False,
        "provider": "honcho",
        "write_approval": True,
        "nudge_interval": 0,
        "flush_min_turns": 0,
    }

    agent = config.get("agent")
    if not isinstance(agent, MutableMapping):
        agent = {}
        config["agent"] = agent
    disabled_toolsets = _string_list(agent.get("disabled_toolsets"))
    agent["disabled_toolsets"] = list(
        dict.fromkeys([*disabled_toolsets, *sorted(DISABLED_AGENT_MEMORY_TOOLSETS)])
    )

    # User plugins are executable code and can register arbitrary toolset names.
    # Keep an exact allow-list: the product-owned read-only continuity hook on
    # every role, plus Guide's deterministic release-approval and bounded
    # proposal-lifecycle hooks.
    disabled_plugins = [MNEMOSYNE_PLUGIN]
    if role != "guide":
        disabled_plugins.extend([RELEASE_APPROVAL_PLUGIN, GUIDE_LIFECYCLE_PLUGIN])
    config["plugins"] = {
        "enabled": allowed_profile_plugins(role),
        "disabled": disabled_plugins,
    }

    stale_mcp = config.get("mcp_servers")
    stale_mcp_names = (
        {str(name) for name in stale_mcp}
        if isinstance(stale_mcp, Mapping)
        else set()
    )
    config["mcp_servers"] = {}
    _sanitize_platform_toolsets(config, role, stale_mcp_names)

    # Hermes 0.18.2 still uses this transient bookkeeping key internally, but
    # its public config schema rejects persisted copies. CLI tool migrations
    # may add it; deployment reassertion removes it before a gateway starts.
    config.pop("known_plugin_toolsets", None)

    # Operational skills are immutable product assets. Hermes' curator may
    # otherwise rewrite or archive them during gateway housekeeping.
    curator = config.get("curator")
    if not isinstance(curator, MutableMapping):
        curator = {}
        config["curator"] = curator
    curator["enabled"] = False


def agent_memory_boundary_errors(
    config: Mapping[str, Any] | Any,
    role: str,
    *,
    effective: bool = False,
) -> list[str]:
    """Return exact deployed-config violations for one operational profile."""

    if role not in OPERATIONAL_ROLES:
        return [f"unsupported operational role: {role}"]
    if not isinstance(config, Mapping):
        return ["profile config is not a mapping"]

    errors: list[str] = []
    memory = config.get("memory")
    if not isinstance(memory, Mapping):
        return ["memory config is not a mapping"]

    if memory.get("memory_enabled") is not False:
        errors.append("memory.memory_enabled must be exactly false")
    if memory.get("user_profile_enabled") is not False:
        errors.append("memory.user_profile_enabled must be exactly false")
    if memory.get("provider") != "honcho":
        errors.append("memory.provider must be exactly honcho")
    if memory.get("nudge_interval") != 0:
        errors.append("memory.nudge_interval must be exactly 0")
    if memory.get("flush_min_turns") != 0:
        errors.append("memory.flush_min_turns must be exactly 0")
    if memory.get("write_approval") is not True:
        errors.append("memory.write_approval must remain exactly true")
    allowed_memory_keys = {
        "memory_enabled",
        "user_profile_enabled",
        "provider",
        "write_approval",
        "nudge_interval",
        "flush_min_turns",
    }
    # Hermes' resolved config contributes inert size defaults even when agent
    # memory is off. Raw deployed YAML must remain exact; effective inspection
    # may accept only these two known non-provider defaults.
    if effective:
        allowed_memory_keys.update({"memory_char_limit", "user_char_limit"})
    provider_specific = sorted(
        str(key)
        for key in memory
        if key not in allowed_memory_keys
    )
    if provider_specific:
        errors.append(
            "memory config contains non-contract/provider-specific keys: "
            + ", ".join(provider_specific)
        )

    agent = config.get("agent")
    if not isinstance(agent, Mapping):
        errors.append("agent config is not a mapping")
    else:
        disabled = set(_string_list(agent.get("disabled_toolsets")))
        missing = sorted(DISABLED_AGENT_MEMORY_TOOLSETS - disabled)
        if missing:
            errors.append(
                "agent.disabled_toolsets must include: " + ", ".join(missing)
            )

    plugins = config.get("plugins")
    if not isinstance(plugins, Mapping):
        errors.append("plugins config is not a mapping")
    else:
        enabled = _string_list(plugins.get("enabled"))
        disabled = set(_string_list(plugins.get("disabled")))
        expected_enabled = allowed_profile_plugins(role)
        if enabled != expected_enabled:
            errors.append(
                "plugins.enabled must exactly match the role allow-list: "
                + repr(expected_enabled)
            )
        required_disabled = {MNEMOSYNE_PLUGIN}
        if role != "guide":
            required_disabled.add(RELEASE_APPROVAL_PLUGIN)
        missing_disabled = sorted(required_disabled - disabled)
        if missing_disabled:
            errors.append(
                "plugins.disabled must include: " + ", ".join(missing_disabled)
            )

    mcp_servers = config.get("mcp_servers")
    if effective and mcp_servers is None:
        pass
    elif not isinstance(mcp_servers, Mapping):
        errors.append("mcp_servers must be an empty mapping")
    elif mcp_servers:
        errors.append("mcp_servers must be empty for model-facing profiles")

    platform_toolsets = config.get("platform_toolsets")
    if not isinstance(platform_toolsets, Mapping):
        errors.append("platform_toolsets must be a mapping")
    else:
        required_platforms = {"cli"}
        if role == "guide":
            required_platforms.add("discord")
        for platform in sorted(required_platforms):
            entries = platform_toolsets.get(platform)
            if role == "guide" and entries != [NO_MCP_SENTINEL]:
                errors.append(
                    f"public Guide platform_toolsets.{platform} must contain no model tools"
                )
            elif not isinstance(entries, list) or NO_MCP_SENTINEL not in {
                str(entry) for entry in entries
            }:
                errors.append(
                    f"platform_toolsets.{platform} must include {NO_MCP_SENTINEL}"
                )
        for platform, entries in platform_toolsets.items():
            if not isinstance(entries, list):
                errors.append(
                    f"platform_toolsets.{platform} must be a list"
                )
                continue
            aliases = sorted(
                {
                    str(entry)
                    for entry in entries
                    if str(entry).casefold() in _MEMORY_ALIASES
                }
            )
            if aliases:
                errors.append(
                    f"platform_toolsets.{platform} contains memory/MCP aliases: "
                    + ", ".join(aliases)
                )

    if "known_plugin_toolsets" in config:
        errors.append(
            "known_plugin_toolsets must not be persisted in profile config"
        )

    if not effective:
        curator = config.get("curator")
        if (
            not isinstance(curator, Mapping)
            or curator.get("enabled") is not False
        ):
            errors.append(
                "curator.enabled must be exactly false for product-managed skills"
            )

    return errors
