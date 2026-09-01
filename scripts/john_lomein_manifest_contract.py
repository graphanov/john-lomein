#!/usr/bin/env python3
"""Fail-closed validation for instance-manifest execution and prompt inputs."""
from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from john_lomein_honcho_contract import honcho_settings
from john_lomein_autonomy import normalize_policy
from john_lomein_collaboration_contract import collaboration_policy
from john_lomein_factory_receipts import (
    MISSION_PERSONALITY_CREATIVE_POSTURE,
    MISSION_PERSONALITY_VOICE,
    prompt_data,
    public_metadata_text,
    safe_runtime_activation,
)
from john_lomein_guide_lifecycle import guide_dialogue_policy
from john_lomein_review_quorum import review_quorum_policy

ROLE_NAMES = frozenset({"maintainer", "forge", "guide", "overwatch", "learning_steward"})
SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
GITHUB_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
DISCORD_USER_ID_RE = re.compile(r"^[0-9]{17,20}$")
OWNER_OVERRIDE_POLICY_SCHEMA = "john-lomein.owner-override-policy.v1"
MODEL_MEMORY_ISOLATION_MODES = frozenset({"required", "disabled"})

MAX_OMH_SKILLS_PER_ROLE = 32
MAX_MISSION_STATEMENT_CHARS = 1200
MAX_MISSION_POLICY_CHARS = 1600
MAX_MISSION_PERSONALITY_CHARS = 800
MAX_PUBLIC_LIST_ITEMS = 96
MAX_ROADMAP_SOURCES = 24
MAX_FORBIDDEN_PATHS = 64
MAX_READINESS_LABELS = 32
MAX_AUTONOMOUS_SAFE_LABELS = 32
MAX_ROADMAP_SOURCE_CHARS = 240
MAX_FORBIDDEN_PATH_CHARS = 240
MAX_READINESS_LABEL_CHARS = 96
MAX_AUTONOMOUS_SAFE_LABEL_CHARS = 96
MAX_PUBLIC_PROMPT_BYTES = 8192

_BOOLEAN_FIELDS: tuple[tuple[tuple[str, str], bool], ...] = (
    (("mission", "owner_authored"), False),
    (("runtime", "mutation_enabled"), False),
    (("runtime", "discord_enabled"), False),
    (("runtime", "guide_gateway_enabled"), False),
    (("runtime", "keep_awake_on_ac"), False),
    (("runtime", "review_only_profiles_qualified"), False),
    (("discord", "enabled"), False),
    (("discord", "guide_gateway_enabled"), False),
    (("release", "protected_broker_enabled"), False),
    (("workflows", "omh_enabled"), False),
    (("workflows", "omh_required"), False),
    (("learning", "enabled"), True),
    (("open_scaffold_portfolio", "enabled"), False),
    (("open_scaffold_portfolio", "open_scaffold_instance_only"), True),
    (("open_scaffold_portfolio", "draft_prs"), True),
    (("osc_portfolio", "enabled"), False),
    (("osc_portfolio", "open_scaffold_instance_only"), True),
    (("osc_portfolio", "draft_prs"), True),
)


def _mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"unsafe instance manifest: {field} must be a mapping")
    return value


def strict_boolean(value: Any, *, field: str, default: bool) -> bool:
    """Accept YAML booleans only; strings and numeric aliases are rejected."""
    if value is None:
        return default
    if type(value) is not bool:
        raise ValueError(f"unsafe instance manifest boolean: {field} must be true or false")
    return value


def strict_manifest_boolean(
    manifest: Mapping[str, Any],
    section: str,
    key: str,
    *,
    default: bool,
) -> bool:
    parent = _mapping(manifest.get(section), field=section)
    return strict_boolean(parent.get(key), field=f"{section}.{key}", default=default)


def manifest_boolean_flags(manifest: Mapping[str, Any]) -> dict[str, bool]:
    if not isinstance(manifest, Mapping):
        raise ValueError("unsafe instance manifest: expected mapping")
    raw: dict[str, bool] = {}
    for (section, key), default in _BOOLEAN_FIELDS:
        raw[f"{section}.{key}"] = strict_manifest_boolean(
            manifest,
            section,
            key,
            default=default,
        )

    primary_portfolio = _mapping(
        manifest.get("open_scaffold_portfolio"),
        field="open_scaffold_portfolio",
    )
    legacy_portfolio = _mapping(manifest.get("osc_portfolio"), field="osc_portfolio")
    use_primary = bool(primary_portfolio)
    portfolio_prefix = "open_scaffold_portfolio" if use_primary else "osc_portfolio"
    return {
        "mission_owner_authored": raw["mission.owner_authored"],
        "runtime_mutation_enabled": raw["runtime.mutation_enabled"],
        "runtime_discord_enabled": raw["runtime.discord_enabled"],
        "runtime_guide_gateway_enabled": raw["runtime.guide_gateway_enabled"],
        "runtime_keep_awake_on_ac": raw["runtime.keep_awake_on_ac"],
        "review_only_profiles_qualified": raw[
            "runtime.review_only_profiles_qualified"
        ],
        "discord_enabled": raw["runtime.discord_enabled"] or raw["discord.enabled"],
        "guide_gateway_enabled": (
            raw["runtime.guide_gateway_enabled"]
            or raw["discord.guide_gateway_enabled"]
        ),
        "protected_release_broker_enabled": raw[
            "release.protected_broker_enabled"
        ],
        "omh_enabled": raw["workflows.omh_enabled"],
        "omh_required": raw["workflows.omh_required"],
        "learning_enabled": raw["learning.enabled"],
        "portfolio_enabled": raw[f"{portfolio_prefix}.enabled"],
        "portfolio_instance_only": raw[
            f"{portfolio_prefix}.open_scaffold_instance_only"
        ],
        "portfolio_draft_prs": raw[f"{portfolio_prefix}.draft_prs"],
    }


def model_memory_isolation_mode(manifest: Mapping[str, Any]) -> str:
    """Return the fail-closed model/steward filesystem boundary mode.

    Learning-enabled appliances always require the OS sandbox boundary.  The
    ``disabled`` spelling exists only for deliberately memory-less instances;
    it is not a compatibility escape hatch for an active steward.
    """

    if not isinstance(manifest, Mapping):
        raise ValueError("unsafe instance manifest: expected mapping")
    learning = _mapping(manifest.get("learning"), field="learning")
    raw = learning.get("model_memory_isolation", "required")
    if not isinstance(raw, str) or raw not in MODEL_MEMORY_ISOLATION_MODES:
        raise ValueError(
            "unsafe instance manifest: learning.model_memory_isolation "
            "must be required or disabled"
        )
    enabled = strict_boolean(
        learning.get("enabled"),
        field="learning.enabled",
        default=True,
    )
    if enabled and raw != "required":
        raise ValueError(
            "unsafe instance manifest: learning-enabled instances require "
            "learning.model_memory_isolation=required"
        )
    return raw


def safe_component(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"unsafe instance manifest component: {field}")
    component = value.strip()
    if (
        component != value
        or component in {".", ".."}
        or not SAFE_COMPONENT_RE.fullmatch(component)
    ):
        raise ValueError(f"unsafe instance manifest component: {field}")
    return component


def validated_omh_skills_by_role(manifest: Mapping[str, Any]) -> dict[str, list[str]]:
    workflows = _mapping(manifest.get("workflows"), field="workflows")
    configured = workflows.get("omh_skills_by_role")
    if configured is None:
        return {}
    configured = _mapping(configured, field="workflows.omh_skills_by_role")
    unknown = sorted(str(role) for role in configured if role not in ROLE_NAMES)
    if unknown:
        raise ValueError(
            "unsafe instance manifest: workflows.omh_skills_by_role contains unknown roles"
        )

    result: dict[str, list[str]] = {}
    for role, raw_skills in configured.items():
        field = f"workflows.omh_skills_by_role.{role}"
        if not isinstance(raw_skills, list):
            raise ValueError(f"unsafe instance manifest: {field} must be a list")
        if len(raw_skills) > MAX_OMH_SKILLS_PER_ROLE:
            raise ValueError(
                f"unsafe instance manifest: {field} exceeds {MAX_OMH_SKILLS_PER_ROLE} items"
            )
        skills = [
            safe_component(item, field=f"{field}[{index}]")
            for index, item in enumerate(raw_skills)
        ]
        if len(skills) != len(set(skills)):
            raise ValueError(f"unsafe instance manifest: {field} contains duplicates")
        result[str(role)] = skills
    return result


def _bounded_list(
    value: Any,
    *,
    field: str,
    max_items: int,
    max_item_chars: int,
) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"unsafe instance manifest: {field} must be a list")
    if len(value) > max_items:
        raise ValueError(
            f"unsafe instance manifest: {field} exceeds {max_items} items"
        )
    items: list[str] = []
    for index, item in enumerate(value):
        item_field = f"{field}[{index}]"
        try:
            items.append(
                public_metadata_text(
                    item,
                    item_field,
                    max_length=max_item_chars,
                )
            )
        except ValueError as exc:
            raise ValueError(f"unsafe public prompt field: {item_field}") from exc
    return items


def _bounded_public_text(
    value: Any,
    *,
    field: str,
    default: str,
    max_chars: int,
) -> str:
    try:
        return public_metadata_text(
            value,
            field,
            default,
            max_length=max_chars,
        )
    except ValueError as exc:
        raise ValueError(f"unsafe mission public field: {field}") from exc


def validated_public_prompt_fields(
    manifest: Mapping[str, Any],
    *,
    flags: Mapping[str, bool] | None = None,
) -> dict[str, Any]:
    flags = dict(flags or manifest_boolean_flags(manifest))
    mission = _mapping(manifest.get("mission"), field="mission")
    personality = _mapping(mission.get("personality"), field="mission.personality")
    gates = _mapping(manifest.get("gates"), field="gates")

    statement = _bounded_public_text(
        mission.get("statement"),
        field="mission.statement",
        default="Maintain the target repository through evidence-bound, owner-gated work.",
        max_chars=MAX_MISSION_STATEMENT_CHARS,
    )
    roadmap_sources = _bounded_list(
        mission.get("roadmap_sources"),
        field="mission.roadmap_sources",
        max_items=MAX_ROADMAP_SOURCES,
        max_item_chars=MAX_ROADMAP_SOURCE_CHARS,
    )
    owner_signal_policy = _bounded_public_text(
        mission.get("owner_signal_policy"),
        field="mission.owner_signal_policy",
        default=(
            "Only authenticated owner signals may set or revise mission priorities; "
            "trusted collaborators may propose or narrow scoped candidates, and "
            "public suggestions remain untrusted candidate data."
        ),
        max_chars=MAX_MISSION_POLICY_CHARS,
    )
    supplied_personality: dict[str, str] = {}
    for key in ("voice", "creative_posture"):
        if personality.get(key) not in (None, ""):
            supplied_personality[key] = _bounded_public_text(
                personality.get(key),
                field=f"mission.personality.{key}",
                default="",
                max_chars=MAX_MISSION_PERSONALITY_CHARS,
            )

    forbidden_paths = _bounded_list(
        gates.get("forbidden_paths"),
        field="gates.forbidden_paths",
        max_items=MAX_FORBIDDEN_PATHS,
        max_item_chars=MAX_FORBIDDEN_PATH_CHARS,
    )
    readiness_labels = _bounded_list(
        gates.get("readiness_labels"),
        field="gates.readiness_labels",
        max_items=MAX_READINESS_LABELS,
        max_item_chars=MAX_READINESS_LABEL_CHARS,
    )
    autonomous_safe_labels = _bounded_list(
        gates.get("autonomous_safe_labels"),
        field="gates.autonomous_safe_labels",
        max_items=MAX_AUTONOMOUS_SAFE_LABELS,
        max_item_chars=MAX_AUTONOMOUS_SAFE_LABEL_CHARS,
    )
    normalized_safe_labels = [label.casefold() for label in autonomous_safe_labels]
    if len(normalized_safe_labels) != len(set(normalized_safe_labels)):
        raise ValueError(
            "unsafe instance manifest: gates.autonomous_safe_labels "
            "contains duplicates"
        )
    if any("," in label for label in autonomous_safe_labels):
        raise ValueError(
            "unsafe instance manifest: gates.autonomous_safe_labels "
            "cannot contain commas"
        )
    if set(normalized_safe_labels) & {
        label.casefold() for label in readiness_labels
    }:
        raise ValueError(
            "unsafe instance manifest: autonomous safe labels cannot also "
            "be readiness labels"
        )
    list_item_count = (
        len(roadmap_sources)
        + len(forbidden_paths)
        + len(readiness_labels)
        + len(autonomous_safe_labels)
    )
    if list_item_count > MAX_PUBLIC_LIST_ITEMS:
        raise ValueError(
            "unsafe instance manifest: public prompt lists exceed aggregate item limit"
        )

    prompt_parts = [
        prompt_data(flags["mission_owner_authored"]),
        prompt_data(statement),
        prompt_data(owner_signal_policy),
        prompt_data(MISSION_PERSONALITY_VOICE),
        prompt_data(MISSION_PERSONALITY_CREATIVE_POSTURE),
    ]
    for items in (roadmap_sources, forbidden_paths, readiness_labels):
        prompt_parts.extend(f"- {prompt_data(item)}" for item in items)
    aggregate_prompt_bytes = sum(
        len(part.encode("utf-8")) + 1 for part in prompt_parts
    )
    if aggregate_prompt_bytes > MAX_PUBLIC_PROMPT_BYTES:
        raise ValueError(
            "unsafe instance manifest: public prompt data exceeds aggregate byte limit"
        )

    return {
        "mission": {
            "owner_authored": flags["mission_owner_authored"],
            "statement": statement,
            "roadmap_sources": roadmap_sources,
            "owner_signal_policy": owner_signal_policy,
            "voice": MISSION_PERSONALITY_VOICE,
            "creative_posture": MISSION_PERSONALITY_CREATIVE_POSTURE,
            "personality_override_ignored": any(
                supplied_personality.get(key, "") != expected
                for key, expected in (
                    ("voice", MISSION_PERSONALITY_VOICE),
                    ("creative_posture", MISSION_PERSONALITY_CREATIVE_POSTURE),
                )
                if key in supplied_personality
            ),
        },
        "gates": {
            "forbidden_paths": forbidden_paths,
            "readiness_labels": readiness_labels,
            "autonomous_safe_labels": autonomous_safe_labels,
        },
        "aggregate_prompt_bytes": aggregate_prompt_bytes,
        "list_item_count": list_item_count,
    }


def mission_candidate_complete(
    manifest: Mapping[str, Any],
    *,
    prompt: Mapping[str, Any] | None = None,
) -> bool:
    """Return true only when every raw mission candidate field is present."""

    selected_prompt = dict(
        prompt
        or validated_public_prompt_fields(manifest)
    )
    mission = _mapping(manifest.get("mission"), field="mission")
    # Evaluating the prompt above is intentional: raw presence is not a valid
    # candidate unless every rendered public field also passes its contract.
    _mapping(selected_prompt.get("mission"), field="prompt.mission")
    return bool(
        isinstance(mission.get("statement"), str)
        and mission["statement"].strip()
        and isinstance(mission.get("roadmap_sources"), list)
        and mission["roadmap_sources"]
        and isinstance(mission.get("owner_signal_policy"), str)
        and mission["owner_signal_policy"].strip()
    )


def owner_mission_complete(
    manifest: Mapping[str, Any],
    *,
    flags: Mapping[str, bool] | None = None,
    prompt: Mapping[str, Any] | None = None,
) -> bool:
    """Return true only for an explicit, validated owner mission card."""

    selected_flags = dict(flags or manifest_boolean_flags(manifest))
    selected_prompt = dict(
        prompt
        or validated_public_prompt_fields(
            manifest,
            flags=selected_flags,
        )
    )
    return bool(
        selected_flags["mission_owner_authored"]
        and mission_candidate_complete(
            manifest,
            prompt=selected_prompt,
        )
    )


def effective_authority_posture(
    manifest: Mapping[str, Any],
    *,
    contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project requested authority through the mandatory owner-mission gate."""

    selected = dict(contract or validate_manifest_contract(manifest))
    flags = dict(selected["flags"])
    runtime = _mapping(manifest.get("runtime"), field="runtime")
    requested_activation = safe_runtime_activation(runtime.get("activation"))
    mission_ready = bool(selected["mission_complete"])
    return {
        "mission_complete": mission_ready,
        "requested_activation": requested_activation,
        "activation": (
            requested_activation if mission_ready else "owner_gated"
        ),
        "requested_mutation_enabled": flags["runtime_mutation_enabled"],
        "mutation_enabled": (
            flags["runtime_mutation_enabled"] and mission_ready
        ),
        "requested_discord_enabled": flags["discord_enabled"],
        "discord_enabled": flags["discord_enabled"] and mission_ready,
        "requested_guide_gateway_enabled": flags["guide_gateway_enabled"],
        "guide_gateway_enabled": (
            flags["guide_gateway_enabled"] and mission_ready
        ),
        "requested_protected_release_broker_enabled": flags[
            "protected_release_broker_enabled"
        ],
        "protected_release_broker_enabled": (
            flags["protected_release_broker_enabled"] and mission_ready
        ),
        "requested_portfolio_enabled": flags["portfolio_enabled"],
        "portfolio_enabled": flags["portfolio_enabled"] and mission_ready,
    }


def _validate_omh_home(manifest: Mapping[str,Any],workflows: Mapping[str,Any]) -> None:
    needs_omh_path=(workflows.get('omh_home') is not None or workflows.get('omh_enabled') is True or workflows.get('omh_required') is True or workflows.get('implementation_mode')=='omh_codex')
    runtime=manifest.get('runtime')
    if runtime is None and not needs_omh_path:
        return
    if not isinstance(runtime,Mapping):
        raise ValueError('runtime must be a YAML mapping')
    runtime_raw=runtime.get('hermes_home')
    if runtime_raw in (None,'') and not needs_omh_path:
        return
    if not isinstance(runtime_raw,str) or not runtime_raw.strip():
        raise ValueError('runtime.hermes_home must be a path string')
    runtime_home=_reject_symlink_components(Path(runtime_raw),field='runtime.hermes_home').resolve()
    omh_raw=workflows.get('omh_home')
    if omh_raw is None:
        omh_home=runtime_home/'omh'
    else:
        if not isinstance(omh_raw,str) or not omh_raw.strip():
            raise ValueError('workflows.omh_home must be a path string')
        omh_input=Path(omh_raw).expanduser()
        if not omh_input.is_absolute():
            raise ValueError('workflows.omh_home must be an absolute instance-local path')
        omh_home=_reject_symlink_components(omh_input,field='workflows.omh_home').resolve()
    try:
        relative=omh_home.relative_to(runtime_home)
    except ValueError as exc:
        raise ValueError('workflows.omh_home must stay inside runtime.hermes_home') from exc
    if len(relative.parts)!=1 or not relative.name.startswith('omh'):
        raise ValueError('workflows.omh_home must be a dedicated top-level OMH subtree')


def owner_github_logins(manifest: Mapping[str, Any]) -> list[str]:
    authority = manifest.get("authority")
    if authority is None:
        return []
    if not isinstance(authority, Mapping):
        raise ValueError("authority must be a YAML mapping")
    raw = authority.get("owner_github_logins")
    if raw is None:
        return []
    if not isinstance(raw, list) or not raw:
        raise ValueError("authority.owner_github_logins must be a non-empty YAML list")
    values: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, str) or not GITHUB_LOGIN_RE.fullmatch(item.strip()):
            raise ValueError(
                f"authority.owner_github_logins[{index}] must be a GitHub login"
            )
        value = item.strip()
        key = value.casefold()
        if key in seen:
            raise ValueError("authority.owner_github_logins must not contain duplicates")
        seen.add(key)
        values.append(value)
    return values


def owner_override_policy(
    manifest: Mapping[str, Any],
    *,
    configured_owner_logins: list[str] | None = None,
) -> dict[str, Any]:
    raw = _mapping(manifest.get("owner_override"), field="owner_override")
    allowed = {
        "schema_version",
        "enabled",
        "transport",
        "authority",
        "key_id",
        "public_key_sha256",
        "allowed_discord_user_ids",
    }
    unknown = sorted(str(key) for key in raw if key not in allowed)
    if unknown:
        raise ValueError("unsafe instance manifest: owner_override has unknown fields")
    schema = str(raw.get("schema_version") or OWNER_OVERRIDE_POLICY_SCHEMA)
    if schema != OWNER_OVERRIDE_POLICY_SCHEMA:
        raise ValueError("unsafe instance manifest: owner_override.schema_version")
    enabled = raw.get("enabled", False)
    if type(enabled) is not bool:
        raise ValueError("unsafe instance manifest: owner_override.enabled must be boolean")
    transport = str(raw.get("transport") or "discord")
    if transport != "discord":
        raise ValueError("unsafe instance manifest: owner_override.transport")
    authority = str(raw.get("authority") or "acceptance_constraints_only")
    if authority != "acceptance_constraints_only":
        raise ValueError("unsafe instance manifest: owner_override.authority")
    key_id = str(raw.get("key_id") or "").strip()
    if key_id and not SAFE_COMPONENT_RE.fullmatch(key_id):
        raise ValueError("unsafe instance manifest: owner_override.key_id")
    public_key_sha256 = str(raw.get("public_key_sha256") or "").strip().lower()
    if public_key_sha256 and re.fullmatch(r"[0-9a-f]{64}", public_key_sha256) is None:
        raise ValueError("unsafe instance manifest: owner_override.public_key_sha256")
    actor_ids_raw = raw.get("allowed_discord_user_ids", [])
    if not isinstance(actor_ids_raw, list):
        raise ValueError(
            "unsafe instance manifest: owner_override.allowed_discord_user_ids"
        )
    actor_ids: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(actor_ids_raw):
        if not isinstance(item, str) or not DISCORD_USER_ID_RE.fullmatch(item.strip()):
            raise ValueError(
                "unsafe instance manifest: owner_override.allowed_discord_user_ids"
            )
        value = item.strip()
        if value in seen:
            raise ValueError(
                "unsafe instance manifest: owner_override.allowed_discord_user_ids"
            )
        seen.add(value)
        actor_ids.append(value)
    if len(actor_ids) > 4:
        raise ValueError(
            "unsafe instance manifest: owner_override.allowed_discord_user_ids"
        )
    if enabled and not key_id:
        raise ValueError("owner_override.key_id is required before enablement")
    if enabled and not public_key_sha256:
        raise ValueError("owner_override.public_key_sha256 is required before enablement")
    if enabled and not actor_ids:
        raise ValueError(
            "owner_override.allowed_discord_user_ids is required before enablement"
        )
    if enabled and not configured_owner_logins:
        raise ValueError(
            "authority.owner_github_logins is required before owner_override enablement"
        )
    return {
        "schema_version": schema,
        "enabled": enabled,
        "transport": transport,
        "authority": authority,
        "key_id": key_id,
        "public_key_sha256": public_key_sha256,
        "allowed_discord_user_ids": actor_ids,
    }


def validate_manifest_contract(manifest: Mapping[str, Any]) -> dict[str, Any]:
    instance=manifest.get('instance')
    if not isinstance(instance,Mapping):
        raise ValueError('instance must be a YAML mapping')
    instance_slug=str(instance.get('slug') or '').strip()
    flags = manifest_boolean_flags(manifest)
    memory_isolation = model_memory_isolation_mode(manifest)
    workflows=manifest.get('workflows')
    if workflows is None:
        workflows={}
    if not isinstance(workflows,Mapping):
        raise ValueError('workflows must be a YAML mapping')
    guide_policy = guide_dialogue_policy(manifest)
    collaboration = collaboration_policy(manifest)
    owner_logins = owner_github_logins(manifest)
    owner_override = owner_override_policy(
        manifest,
        configured_owner_logins=owner_logins,
    )
    review_quorum = review_quorum_policy(manifest)
    _validate_omh_home(manifest,workflows)
    mode=str(workflows.get('implementation_mode') or 'hermes_direct')
    if mode not in {'hermes_direct','omh_codex'}:
        raise ValueError('unsupported workflows.implementation_mode')
    if flags['omh_required'] and not flags['omh_enabled']:
        raise ValueError('workflows.omh_required requires workflows.omh_enabled: true')
    if mode=='omh_codex' and not flags['omh_enabled']:
        raise ValueError('omh_codex requires workflows.omh_enabled: true')
    honcho = honcho_settings(manifest,instance_slug=instance_slug)
    if flags["guide_gateway_enabled"] and not flags["discord_enabled"]:
        raise ValueError("guide gateway requires Discord to be enabled")
    if (
        flags["protected_release_broker_enabled"]
        and not flags["runtime_mutation_enabled"]
    ):
        raise ValueError(
            "protected release broker requires runtime mutation to be enabled"
        )
    prompt = validated_public_prompt_fields(manifest, flags=flags)
    candidate_complete = mission_candidate_complete(
        manifest,
        prompt=prompt,
    )
    mission_complete = owner_mission_complete(
        manifest,
        flags=flags,
        prompt=prompt,
    )
    if flags["guide_gateway_enabled"] and mission_complete and not honcho["watchdog_enabled"]:
        raise ValueError("memory.honcho.watchdog_enabled must be true before Guide gateway activation")
    if flags["runtime_mutation_enabled"] and mission_complete and not owner_logins:
        raise ValueError(
            "authority.owner_github_logins is required before runtime.mutation_enabled"
        )
    return {
        "flags": flags,
        "mission_candidate_complete": candidate_complete,
        "mission_complete": mission_complete,
        "model_memory_isolation": memory_isolation,
        "autonomy": normalize_policy(manifest.get("autonomy")),
        "collaboration": collaboration,
        "guide_dialogue": guide_policy,
        "owner_override": owner_override,
        "review_quorum": review_quorum,
        "owner_github_logins": owner_logins,
        "omh_skills_by_role": validated_omh_skills_by_role(manifest),
        "prompt": prompt,
    }


def _reject_symlink_components(path: Path, *, field: str) -> Path:
    absolute = Path(os.path.abspath(path.expanduser()))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        if current.is_symlink():
            link_stat = current.lstat()
            parent_stat = current.parent.stat()
            parent_group_writable = bool(
                parent_stat.st_mode & 0o020
                and parent_stat.st_gid in set(os.getgroups())
            )
            parent_public_writable = bool(parent_stat.st_mode & 0o002)
            if (
                link_stat.st_uid == os.getuid()
                or parent_stat.st_uid == os.getuid()
                or parent_group_writable
                or parent_public_writable
            ):
                raise ValueError(
                    f"unsafe instance manifest paths: {field} contains "
                    "an instance-controlled symlink component"
                )
    return absolute


def validate_runtime_checkout_separation(
    local_checkout: Path,
    hermes_home: Path,
) -> tuple[Path, Path]:
    runtime_input = _reject_symlink_components(
        hermes_home,
        field="runtime.hermes_home",
    )
    checkout = local_checkout.expanduser().resolve()
    runtime = runtime_input.resolve()
    overlap = checkout == runtime
    if not overlap:
        try:
            checkout.relative_to(runtime)
            overlap = True
        except ValueError:
            pass
    if not overlap:
        try:
            runtime.relative_to(checkout)
            overlap = True
        except ValueError:
            pass
    if overlap:
        raise ValueError(
            "unsafe instance manifest paths: target.local_checkout and "
            "runtime.hermes_home must not overlap"
        )
    return checkout, runtime


def validate_deploy_managed_paths(
    hermes_home: Path,
    role_profiles: Mapping[str, str],
) -> None:
    """Reject symlinked deployment roots and write targets before mutation."""
    try:
        home_input = _reject_symlink_components(
            hermes_home,
            field="runtime.hermes_home",
        )
    except ValueError as exc:
        raise ValueError(
            f"unsafe deployed runtime path: runtime root contains symlink: "
            f"{hermes_home.expanduser()}"
        ) from exc
    home = home_input.resolve()
    managed_roots = [
        home / "profiles",
        home / "scripts",
        home / "scripts" / "bin",
        home / "scripts" / "release_broker",
        home / "state",
        home / "state" / "honcho",
        home / "private" / "honcho-deletion-tombstones",
        home / "private" / "owner-overrides",
        home / "private" / "owner-overrides" / "inbox",
        home / "private" / "review-receipts",
        home / "state" / "review-runs",
        home / "state" / "autonomy",
        home / "state" / "continuity",
        home / "state" / "workers",
        home / "private" / "release-bundles",
        home / "state" / "protected-actions",
        home / "state" / "protected-actions" / "outbox",
        home / "state" / "protected-actions" / "receipts",
        home / "state" / "protected-releases",
        home / "state" / "protected-releases" / "outbox",
        home / "state" / "protected-releases" / "receipts",
        home / "logs",
        home / "logs" / "workers",
        home / "work",
        home / "plugins",
        home / "plugins" / "john-lomein-continuity",
        home / "plugins" / "john-lomein-guide-lifecycle",
        home / "plugins" / "john-lomein-release-approval",
        home / "plugins" / "omh",
        home / "private",
        home / "private" / "learning-steward",
        home / "private" / "learning-steward" / "learning",
        home / "private" / "learning-steward" / "mnemosyne",
        home / "private" / "learning-steward" / "mnemosyne" / "data",
        home / "state" / "learning",
    ]
    managed_leaves = [
        home / "instance.yaml",
        home / "auth.json",
        home / ".env",
        home / "config.yaml",
        home / "state" / "john-lomein-persona.json",
        home / "state" / "john-lomein-autonomy-policy.json",
        home / "state" / "john-lomein-collaboration-policy.json",
        home / "state" / "john-lomein-review-quorum-policy.json",
        home / "state" / "john-lomein-native-workflows.json",
        home / "scripts" / "john-lomein-instance.env",
        home / "scripts" / "bin" / "gh",
        home / "scripts" / "bin" / "git",
        home / "plugins" / "john-lomein-release-approval" / "__init__.py",
        home / "plugins" / "john-lomein-release-approval" / "plugin.yaml",
        home / "plugins" / "john-lomein-continuity" / "__init__.py",
        home / "plugins" / "john-lomein-continuity" / "plugin.yaml",
        home / "plugins" / "john-lomein-guide-lifecycle" / "__init__.py",
        home / "plugins" / "john-lomein-guide-lifecycle" / "plugin.yaml",
    ]
    for profile in role_profiles.values():
        profile_root = home / "profiles" / profile
        managed_roots.extend(
            [
                profile_root,
                profile_root / "home",
                profile_root / "memories",
                profile_root / "plugins",
                profile_root / "skills",
            ]
        )
        managed_leaves.extend(
            [
                profile_root / "SOUL.md",
                profile_root / ".env",
                profile_root / ".no-bundled-skills",
                profile_root / "config.yaml",
                profile_root / "distribution.yaml",
                profile_root / "honcho.json",
                profile_root / "memories" / "USER.md",
                profile_root / "memories" / "MEMORY.md",
            ]
        )
    for path in managed_roots:
        if path.is_symlink():
            raise ValueError(f"unsafe deployed runtime path: managed path is symlink: {path}")
        if path.exists():
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise ValueError(f"unsafe deployed runtime directory metadata: {path}")
    for path in managed_leaves:
        if path.is_symlink():
            raise ValueError(f"unsafe deployed runtime path: managed path is symlink: {path}")
        if path.exists():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o022:
                raise ValueError(f"unsafe deployed runtime file metadata: {path}")
    root_control=home/'config.yaml'
    if root_control.exists():
        root_info=root_control.lstat()
        if (not stat.S_ISREG(root_info.st_mode) or root_info.st_uid!=os.geteuid()
                or root_info.st_nlink!=1 or root_info.st_mode&0o022):
            raise ValueError(f'unsafe deployed root config metadata: {root_control}')
    for profile in role_profiles.values():
        profile_root=home/'profiles'/profile
        for name in ('distribution.yaml','honcho.json'):
            control=profile_root/name
            if not control.exists():
                continue
            info=control.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o022):
                raise ValueError(f'unsafe deployed profile control metadata: {control}')
    state_root = home / "state"
    # State contains both product-managed control stores and opaque execution
    # artifacts. Forge-cycle sandboxes and retained worktrees may legitimately
    # contain repository/test-fixture symlinks; deploy never traverses or
    # rewrites those trees. Still reject every direct state child symlink so an
    # attacker cannot redirect a fixed product write target, then recurse only
    # through the exact state roots deploy owns.
    if state_root.is_dir():
        for path in state_root.iterdir():
            if path.is_symlink():
                raise ValueError(
                    f"unsafe deployed runtime path: managed tree contains symlink: {path}"
                )
    managed_trees = (
        home / "scripts",
        state_root / "autonomy",
        state_root / "continuity",
        state_root / "workers",
        state_root / "learning",
        home / "private" / "release-bundles",
        state_root / "protected-actions",
        state_root / "protected-releases",
    )
    for root in managed_trees:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_symlink():
                raise ValueError(f"unsafe deployed runtime path: managed tree contains symlink: {path}")
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                unsafe = info.st_uid != os.geteuid() or bool(info.st_mode & 0o022)
            else:
                unsafe = not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or bool(info.st_mode & 0o022)
            if unsafe:
                raise ValueError(f"unsafe deployed runtime tree metadata: {path}")

def _require_confined(path: Path, root: Path, *, field: str) -> Path:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"unsafe OMH skill path confinement: {field}") from exc
    return path


def omh_catalog_skill_sources(omh_home: Path) -> dict[str, str]:
    """Return logical OMH skill names mapped to managed directory names."""
    omh_home = omh_home.expanduser().resolve()
    source_root = (omh_home / "skills").resolve()
    manifest = omh_home / "manifest.json"
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError("invalid instance-local OMH manifest")
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid instance-local OMH manifest") from exc
    entries = data.get("skills") if isinstance(data, Mapping) else None
    if not isinstance(entries, list):
        raise ValueError("instance-local OMH manifest has no skill catalog")

    result: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise ValueError("invalid instance-local OMH skill metadata")
        name = entry.get("name")
        raw_path = entry.get("path")
        if not isinstance(name, str) or not isinstance(raw_path, str):
            raise ValueError("invalid instance-local OMH skill metadata")
        logical_name = safe_component(name, field="OMH catalog skill name")
        relative = PurePosixPath(raw_path)
        if (
            relative.is_absolute()
            or len(relative.parts) != 2
            or relative.parts[1] != "SKILL.md"
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ValueError("unsafe instance-local OMH skill path")
        source_component = safe_component(
            relative.parts[0],
            field="OMH catalog skill path",
        )
        source = source_root / source_component
        if source.is_symlink() or not (source / "SKILL.md").is_file():
            raise ValueError("instance-local OMH catalog source is missing")
        _require_confined(source.resolve(), source_root, field="source")
        if logical_name in result:
            raise ValueError("duplicate instance-local OMH skill")
        result[logical_name] = source_component
    return result


def confined_omh_copy_paths(
    source_root: Path,
    destination_root: Path,
    skill: str,
    *,
    source_component: str | None = None,
) -> tuple[Path, Path]:
    """Resolve and validate both copytree endpoints beneath their fixed roots."""
    component = safe_component(skill, field="workflows.omh_skills_by_role entry")
    source_name = safe_component(
        source_component or component,
        field="OMH catalog skill path",
    )
    source_root = source_root.expanduser().resolve()
    destination_root = destination_root.expanduser()
    if destination_root.is_symlink():
        raise ValueError("unsafe OMH skill path confinement: destination root is symlink")
    destination_root.mkdir(parents=True, exist_ok=True)
    destination_root = destination_root.resolve()

    source_candidate = source_root / source_name
    if source_candidate.is_symlink():
        raise ValueError("unsafe OMH skill path confinement: source skill is symlink")
    source = _require_confined(
        source_candidate.resolve(),
        source_root,
        field="source",
    )
    destination_candidate = destination_root / component
    if destination_candidate.is_symlink():
        raise ValueError(
            "unsafe OMH skill path confinement: destination skill is symlink"
        )
    destination = _require_confined(
        destination_candidate.resolve(),
        destination_root,
        field="destination",
    )
    return source, destination


def validate_omh_source_tree(source_root: Path, source: Path) -> None:
    """Reject symlinked or escaping content before shutil.copytree follows it."""
    source_root = source_root.expanduser().resolve()
    source = source.expanduser().resolve()
    _require_confined(source, source_root, field="source")
    if not source.is_dir():
        raise ValueError("unsafe OMH skill source: expected directory")
    for directory, dirnames, filenames in os.walk(source, followlinks=False):
        parent = Path(directory)
        _require_confined(parent.resolve(), source, field="source tree")
        for name in [*dirnames, *filenames]:
            candidate = parent / name
            if candidate.is_symlink():
                raise ValueError("unsafe OMH skill source: symlinks are not allowed")
            _require_confined(
                candidate.resolve(),
                source,
                field="source tree",
            )
