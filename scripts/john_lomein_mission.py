#!/usr/bin/env python3
"""Owner-adopted mission proposals for dormant John Lomein observers.

This module is deliberately operator-side.  A proposal may be prepared by a
human or an AI, but it stays non-authoritative until an operator adopts its
exact digest.  Adoption writes only the desired instance manifest, resets every
requested external capability to observer posture, and never deploys or starts
services.

The confirmation phrase is a declarative provenance record, not cryptographic
proof that a particular human typed it.  Strong owner identity remains the
responsibility of the separately isolated owner-gateway boundary.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import secrets
import stat
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from john_lomein_factory_receipts import (
    safe_default_branch,
    safe_github_repo,
    safe_instance_slug,
)
from john_lomein_file_contract import (
    StableFileError,
    directory_chain_identity,
    read_stable_regular,
)
from john_lomein_manifest_contract import (
    effective_authority_posture,
    validate_manifest_contract,
)
from john_lomein_service_registry import (
    ServiceRegistryError,
    lifecycle_lock,
)


PROPOSAL_SCHEMA = "john_lomein_mission_candidate/v1"
RESULT_SCHEMA = "john_lomein_mission_confirmation_result/v1"
PROPOSAL_STATUS = "unconfirmed_candidate"
CONFIRMATION_PREFIX = "I AM THE OWNER AND I ADOPT JOHN LOMEIN MISSION "
PROPOSAL_LIFETIME = timedelta(days=7)
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_PROPOSAL_BYTES = 32 * 1024
MAX_PROPOSAL_FILENAME_CHARS = 120
DEFAULT_PROPOSAL_FILENAME = "mission-candidate.json"
DOMAIN_SEPARATOR = b"john-lomein-owner-mission-candidate-v1\x00"
SETUP_ENV_KEYS = (
    "JOHN_LOMEIN_SETUP_MANIFEST_SOURCE",
    "JOHN_LOMEIN_SETUP_MANIFEST_SNAPSHOT",
    "JOHN_LOMEIN_SETUP_MANIFEST_SHA256",
    "JOHN_LOMEIN_SERVICE_LOCK_FD",
)

_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_PROPOSAL_NAME_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.json$"
)
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)
_OPAQUE_LONG_ID_RE = re.compile(r"(?<![0-9])[0-9]{17,20}(?![0-9])")

_POST_CONFIRMATION_AUTHORITY = {
    "activation": "owner_gated",
    "mutation": False,
    "discord": False,
    "guide_gateway": False,
    "protected_release": False,
    "portfolio": False,
    "keep_awake": False,
    "delivery": "local",
}

_ALLOWED_CHANGED_PATHS = frozenset(
    {
        ("runtime", "activation"),
        ("runtime", "mutation_enabled"),
        ("runtime", "discord_enabled"),
        ("runtime", "guide_gateway_enabled"),
        ("runtime", "keep_awake_on_ac"),
        ("discord", "enabled"),
        ("discord", "guide_gateway_enabled"),
        ("discord", "deliver"),
        ("release", "protected_broker_enabled"),
        ("open_scaffold_portfolio", "enabled"),
        ("osc_portfolio", "enabled"),
        ("cron", "deliver"),
    }
)


class MissionWorkflowError(RuntimeError):
    """A bounded mission-workflow failure safe to show to an operator."""

    def __init__(self, code: str, public_message: str):
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class UniqueSafeLoader(yaml.SafeLoader):
    """YAML loader that rejects ambiguous duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueSafeLoader,
    node: yaml.nodes.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise MissionWorkflowError(
                "manifest_unhashable_key",
                "instance manifest contains an unsupported mapping key",
            ) from exc
        if duplicate:
            raise MissionWorkflowError(
                "manifest_duplicate_key",
                "instance manifest contains an ambiguous duplicate field",
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MissionWorkflowError(
                "proposal_duplicate_field",
                "mission proposal contains an ambiguous duplicate field",
            )
        result[key] = value
    return result


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_hex_digest(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX_64_RE.fullmatch(value))


def _proposal_digest(value: Mapping[str, Any]) -> str:
    unsigned = {
        key: copy.deepcopy(child)
        for key, child in value.items()
        if key != "candidate_sha256"
    }
    return _sha256(DOMAIN_SEPARATOR + _canonical_json(unsigned))


def confirmation_phrase(candidate_sha256: str) -> str:
    if not _is_hex_digest(candidate_sha256):
        raise MissionWorkflowError(
            "proposal_digest_invalid",
            "mission proposal digest is invalid",
        )
    return CONFIRMATION_PREFIX + candidate_sha256


def _utc_text(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


def _parse_utc(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise MissionWorkflowError(
            "proposal_time_invalid",
            f"mission proposal {field} is invalid",
        )
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise MissionWorkflowError(
            "proposal_time_invalid",
            f"mission proposal {field} is invalid",
        ) from exc
    if parsed.microsecond or parsed.utcoffset() != timedelta(0):
        raise MissionWorkflowError(
            "proposal_time_invalid",
            f"mission proposal {field} is invalid",
        )
    return parsed


def _reject_bound_environment() -> None:
    if any(os.environ.get(key) for key in SETUP_ENV_KEYS):
        raise MissionWorkflowError(
            "lifecycle_context_active",
            "mission changes are unavailable inside another lifecycle transaction",
        )


def _require_secure_os_primitives() -> None:
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(
        not isinstance(getattr(os, name, None), int)
        for name in required
    ):
        raise MissionWorkflowError(
            "platform_unsupported",
            "mission changes require secure directory and no-follow file opens",
        )


def _path_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise MissionWorkflowError(
            "instance_path_unreadable",
            "instance path is unreadable",
        ) from exc
    return True


def _manifest_path(argument: str | Path) -> Path:
    supplied = Path(argument).expanduser()
    try:
        supplied_info = supplied.lstat()
    except FileNotFoundError:
        supplied_info = None
    except OSError as exc:
        raise MissionWorkflowError(
            "instance_path_unreadable",
            "instance path is unreadable",
        ) from exc
    if supplied_info is not None and stat.S_ISLNK(supplied_info.st_mode):
        raise MissionWorkflowError(
            "instance_path_unsafe",
            "instance path is unsafe",
        )
    if supplied_info is not None and stat.S_ISDIR(supplied_info.st_mode):
        primary = supplied / "instance.yaml"
        legacy = supplied / "bot.yaml"
        primary_present = _path_exists(primary)
        legacy_present = _path_exists(legacy)
        if primary_present and legacy_present:
            raise MissionWorkflowError(
                "manifest_ambiguous",
                "instance has more than one authoritative manifest candidate",
            )
        manifest = primary if primary_present else legacy
    else:
        manifest = supplied
    manifest = Path(os.path.abspath(manifest))
    if manifest.name not in {"instance.yaml", "bot.yaml"}:
        raise MissionWorkflowError(
            "manifest_name_invalid",
            "instance manifest name is invalid",
        )
    if not _path_exists(manifest):
        raise MissionWorkflowError(
            "manifest_missing",
            "instance manifest is missing",
        )
    return manifest


def _instance_paths(
    argument: str | Path,
) -> tuple[Path, Path, Path]:
    manifest = _manifest_path(argument)
    instance = manifest.parent
    try:
        info = instance.lstat()
        directory_chain_identity(manifest)
    except (OSError, StableFileError) as exc:
        raise MissionWorkflowError(
            "instance_directory_unsafe",
            "instance directory could not be bound safely",
        ) from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise MissionWorkflowError(
            "instance_directory_unsafe",
            "instance directory must be owner-controlled with mode 0700",
        )
    private = instance / "private"
    try:
        private_info = private.lstat()
    except OSError as exc:
        raise MissionWorkflowError(
            "private_directory_unsafe",
            "instance private directory is unavailable",
        ) from exc
    if (
        stat.S_ISLNK(private_info.st_mode)
        or not stat.S_ISDIR(private_info.st_mode)
        or private_info.st_uid != os.geteuid()
        or stat.S_IMODE(private_info.st_mode) != 0o700
    ):
        raise MissionWorkflowError(
            "private_directory_unsafe",
            "instance private directory must be owner-controlled with mode 0700",
        )
    return instance, manifest, private


def _stat_signature(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_uid,
        info.st_nlink,
        stat.S_IFMT(info.st_mode),
        stat.S_IMODE(info.st_mode),
    )


def _is_private_regular(
    info: os.stat_result,
    *,
    expected_size: int | None = None,
) -> bool:
    return bool(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and info.st_nlink == 1
        and stat.S_IMODE(info.st_mode) == 0o600
        and (expected_size is None or info.st_size == expected_size)
    )


def _read_manifest_bytes(path: Path) -> tuple[bytes, tuple[int, ...]]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise MissionWorkflowError(
            "manifest_unreadable",
            "instance manifest is unreadable",
        ) from exc
    if not _is_private_regular(before):
        raise MissionWorkflowError(
            "manifest_metadata_unsafe",
            "instance manifest must be an owner-owned single-link mode-0600 file",
        )
    try:
        raw = read_stable_regular(
            path,
            maximum_bytes=MAX_MANIFEST_BYTES,
            owner_only=True,
        )
        after = path.lstat()
    except (OSError, StableFileError) as exc:
        raise MissionWorkflowError(
            "manifest_stable_read_failed",
            "instance manifest could not be read as one stable file",
        ) from exc
    before_signature = _stat_signature(before)
    if _stat_signature(after) != before_signature:
        raise MissionWorkflowError(
            "manifest_changed",
            "instance manifest changed during inspection",
        )
    return raw, before_signature


def _load_unique_yaml(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8", errors="strict")
        events = list(yaml.parse(text))
        if any(isinstance(event, yaml.events.AliasEvent) for event in events):
            raise MissionWorkflowError(
                "manifest_alias_unsupported",
                "instance manifest aliases are unsupported for mission changes",
            )
        loaded = yaml.load(text, Loader=UniqueSafeLoader) or {}
    except MissionWorkflowError:
        raise
    except (UnicodeError, yaml.YAMLError) as exc:
        raise MissionWorkflowError(
            "manifest_invalid",
            "instance manifest is invalid",
        ) from exc
    if not isinstance(loaded, dict):
        raise MissionWorkflowError(
            "manifest_invalid",
            "instance manifest must be a mapping",
        )
    return loaded


def _validated_manifest(
    raw: bytes,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    manifest = _load_unique_yaml(raw)
    try:
        contract = validate_manifest_contract(manifest)
        instance = manifest.get("instance") or {}
        target = manifest.get("target") or {}
        if not isinstance(instance, Mapping) or not isinstance(target, Mapping):
            raise ValueError("manifest identity sections must be mappings")
        identity = {
            "slug": safe_instance_slug(instance.get("slug")),
            "repository": safe_github_repo(target.get("repo")),
            "default_branch": safe_default_branch(
                target.get("default_branch")
            ),
        }
    except (TypeError, ValueError) as exc:
        raise MissionWorkflowError(
            "manifest_contract_invalid",
            "instance manifest violates the product contract",
        ) from exc
    return manifest, contract, identity


def _assert_mission_identity_safe(value: str, *, field: str) -> None:
    if _EMAIL_RE.search(value) or _OPAQUE_LONG_ID_RE.search(value):
        raise MissionWorkflowError(
            "mission_private_identity",
            f"{field} contains a private identity pattern",
        )


def _normalized_candidate_mission(
    manifest: Mapping[str, Any],
    *,
    statement: Any,
    roadmap_sources: Sequence[Any],
    owner_signal_policy: Any,
) -> dict[str, Any]:
    if isinstance(roadmap_sources, (str, bytes)) or not roadmap_sources:
        raise MissionWorkflowError(
            "mission_sources_required",
            "mission proposal requires at least one roadmap source",
        )
    candidate = copy.deepcopy(dict(manifest))
    candidate["mission"] = {
        "owner_authored": False,
        "statement": statement,
        "roadmap_sources": list(roadmap_sources),
        "owner_signal_policy": owner_signal_policy,
    }
    try:
        normalized = validate_manifest_contract(candidate)["prompt"]["mission"]
    except (TypeError, ValueError) as exc:
        raise MissionWorkflowError(
            "mission_public_contract_invalid",
            "mission proposal contains an unsafe or invalid public field",
        ) from exc
    mission = {
        "owner_authored": False,
        "statement": normalized["statement"],
        "roadmap_sources": list(normalized["roadmap_sources"]),
        "owner_signal_policy": normalized["owner_signal_policy"],
    }
    if not mission["roadmap_sources"]:
        raise MissionWorkflowError(
            "mission_sources_required",
            "mission proposal requires at least one roadmap source",
        )
    folded_sources = [source.casefold() for source in mission["roadmap_sources"]]
    if len(folded_sources) != len(set(folded_sources)):
        raise MissionWorkflowError(
            "mission_sources_duplicate",
            "mission proposal contains duplicate roadmap sources",
        )
    _assert_mission_identity_safe(
        mission["statement"],
        field="mission statement",
    )
    _assert_mission_identity_safe(
        mission["owner_signal_policy"],
        field="mission owner signal policy",
    )
    for source in mission["roadmap_sources"]:
        _assert_mission_identity_safe(source, field="mission roadmap source")
    return mission


def _section(
    manifest: dict[str, Any],
    name: str,
) -> dict[str, Any]:
    value = manifest.get(name)
    if value is None:
        value = {}
        manifest[name] = value
    if not isinstance(value, dict):
        raise MissionWorkflowError(
            "manifest_contract_invalid",
            "instance manifest violates the product contract",
        )
    return value


def _detached_clone(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: dict[Any, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise MissionWorkflowError(
                    "manifest_key_unsupported",
                    "instance manifest contains an unsupported mapping key",
                )
            result[key] = _detached_clone(child)
        return result
    if isinstance(value, list):
        return [_detached_clone(child) for child in value]
    if type(value) is float and not math.isfinite(value):
        raise MissionWorkflowError(
            "manifest_value_unsupported",
            "instance manifest contains a non-finite numeric value",
        )
    if value is None or type(value) in {str, int, float, bool}:
        return value
    raise MissionWorkflowError(
        "manifest_value_unsupported",
        "instance manifest contains an unsupported YAML value",
    )


def _changed_paths(
    before: Any,
    after: Any,
    prefix: tuple[str, ...] = (),
) -> set[tuple[str, ...]]:
    if isinstance(before, Mapping) and isinstance(after, Mapping):
        paths: set[tuple[str, ...]] = set()
        for key in set(before) | set(after):
            child_prefix = (*prefix, str(key))
            if key not in before and isinstance(after[key], Mapping):
                paths.update(
                    _changed_paths({}, after[key], child_prefix)
                )
            elif key not in after and isinstance(before[key], Mapping):
                paths.update(
                    _changed_paths(before[key], {}, child_prefix)
                )
            elif key not in before or key not in after:
                paths.add(child_prefix)
            else:
                paths.update(
                    _changed_paths(
                        before[key],
                        after[key],
                        child_prefix,
                    )
                )
        return paths
    if isinstance(before, list) and isinstance(after, list):
        return set() if before == after else {prefix}
    return set() if before == after else {prefix}


def _observer_candidate(
    manifest: Mapping[str, Any],
    mission: Mapping[str, Any],
) -> bytes:
    original = _detached_clone(manifest)
    confirmed_mission = {
        "owner_authored": True,
        "statement": mission["statement"],
        "roadmap_sources": list(mission["roadmap_sources"]),
        "owner_signal_policy": mission["owner_signal_policy"],
    }
    candidate: dict[str, Any] = {}
    inserted_mission = False
    for key, value in original.items():
        if key == "mission":
            candidate[key] = confirmed_mission
            inserted_mission = True
        else:
            candidate[key] = value
        if key == "instance" and not inserted_mission and "mission" not in original:
            candidate["mission"] = confirmed_mission
            inserted_mission = True
    if not inserted_mission:
        candidate["mission"] = confirmed_mission

    runtime = _section(candidate, "runtime")
    runtime.update(
        {
            "activation": "owner_gated",
            "mutation_enabled": False,
            "discord_enabled": False,
            "guide_gateway_enabled": False,
            "keep_awake_on_ac": False,
        }
    )
    discord = _section(candidate, "discord")
    discord["enabled"] = False
    discord["guide_gateway_enabled"] = False
    if "deliver" in discord:
        discord["deliver"] = "local"
    _section(candidate, "release")["protected_broker_enabled"] = False
    portfolio_aliases = (
        "open_scaffold_portfolio",
        "osc_portfolio",
    )
    present_portfolio_aliases = tuple(
        name for name in portfolio_aliases if name in candidate
    )
    if present_portfolio_aliases:
        for name in present_portfolio_aliases:
            _section(candidate, name)["enabled"] = False
    else:
        _section(candidate, portfolio_aliases[0])["enabled"] = False
    _section(candidate, "cron")["deliver"] = "local"

    changed = _changed_paths(original, candidate)
    unexpected = {
        path
        for path in changed
        if not (path and path[0] == "mission")
        and path not in _ALLOWED_CHANGED_PATHS
    }
    if unexpected:
        raise MissionWorkflowError(
            "candidate_scope_invalid",
            "mission proposal would change data outside the dormant allowlist",
        )
    try:
        contract = validate_manifest_contract(candidate)
        posture = effective_authority_posture(candidate, contract=contract)
    except (TypeError, ValueError) as exc:
        raise MissionWorkflowError(
            "candidate_manifest_invalid",
            "confirmed observer candidate violates the product contract",
        ) from exc
    if not _is_dormant_observer(candidate, contract, posture):
        raise MissionWorkflowError(
            "candidate_observer_reset_failed",
            "confirmed mission candidate did not remain a dormant observer",
        )

    raw = yaml.safe_dump(
        candidate,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=100,
    ).encode("utf-8")
    if len(raw) > MAX_MANIFEST_BYTES:
        raise MissionWorkflowError(
            "candidate_manifest_oversized",
            "confirmed observer manifest exceeds the product size limit",
        )
    reparsed = _load_unique_yaml(raw)
    if reparsed != candidate:
        raise MissionWorkflowError(
            "candidate_roundtrip_mismatch",
            "confirmed observer manifest did not round-trip exactly",
        )
    try:
        reparsed_contract = validate_manifest_contract(reparsed)
        reparsed_posture = effective_authority_posture(
            reparsed,
            contract=reparsed_contract,
        )
    except (TypeError, ValueError) as exc:
        raise MissionWorkflowError(
            "candidate_roundtrip_invalid",
            "confirmed observer manifest failed final validation",
        ) from exc
    if not _is_dormant_observer(
        reparsed,
        reparsed_contract,
        reparsed_posture,
    ):
        raise MissionWorkflowError(
            "candidate_roundtrip_unsafe",
            "confirmed observer manifest failed its dormant postcondition",
        )
    return raw


def _requested_authority_summary(
    manifest: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    posture = effective_authority_posture(manifest, contract=contract)
    flags = contract["flags"]
    cron = manifest.get("cron") or {}
    discord = manifest.get("discord") or {}
    cron_delivery = cron.get("deliver") if isinstance(cron, Mapping) else None
    discord_delivery = (
        discord.get("deliver") if isinstance(discord, Mapping) else None
    )
    deliveries = tuple(
        value
        for value in (cron_delivery, discord_delivery)
        if value is not None
    )
    return {
        "activation": posture["requested_activation"],
        "mutation": bool(posture["requested_mutation_enabled"]),
        "discord": bool(posture["requested_discord_enabled"]),
        "guide_gateway": bool(
            posture["requested_guide_gateway_enabled"]
        ),
        "protected_release": bool(
            posture["requested_protected_release_broker_enabled"]
        ),
        "portfolio": bool(posture["requested_portfolio_enabled"]),
        "keep_awake": bool(flags["runtime_keep_awake_on_ac"]),
        "external_delivery": any(
            str(value) != "local" for value in deliveries
        ),
    }


def _is_dormant_observer(
    manifest: Mapping[str, Any],
    contract: Mapping[str, Any],
    posture: Mapping[str, Any],
) -> bool:
    cron = manifest.get("cron")
    discord = manifest.get("discord")
    if not isinstance(cron, Mapping) or cron.get("deliver") != "local":
        return False
    if (
        isinstance(discord, Mapping)
        and "deliver" in discord
        and discord.get("deliver") != "local"
    ):
        return False
    return bool(
        contract["mission_complete"]
        and posture["requested_activation"] == "owner_gated"
        and posture["activation"] == "owner_gated"
        and not contract["flags"]["runtime_keep_awake_on_ac"]
        and not any(
            posture[key]
            for key in (
                "requested_mutation_enabled",
                "mutation_enabled",
                "requested_discord_enabled",
                "discord_enabled",
                "requested_guide_gateway_enabled",
                "guide_gateway_enabled",
                "requested_protected_release_broker_enabled",
                "protected_release_broker_enabled",
                "requested_portfolio_enabled",
                "portfolio_enabled",
            )
        )
    )


def _proposal_path(private: Path, supplied: str | Path | None) -> Path:
    path = (
        private / DEFAULT_PROPOSAL_FILENAME
        if supplied is None
        else Path(supplied).expanduser()
    )
    path = Path(os.path.abspath(path))
    if (
        path.parent != private
        or len(path.name) > MAX_PROPOSAL_FILENAME_CHARS
        or not _SAFE_PROPOSAL_NAME_RE.fullmatch(path.name)
    ):
        raise MissionWorkflowError(
            "proposal_path_unsafe",
            "mission proposal must be a safe JSON file in the instance private directory",
        )
    return path


def _write_all(descriptor: int, raw: bytes, *, failure_code: str) -> None:
    view = memoryview(raw)
    while view:
        try:
            written = os.write(descriptor, view)
        except OSError as exc:
            raise MissionWorkflowError(
                failure_code,
                "private mission file write failed",
            ) from exc
        if written <= 0:
            raise MissionWorkflowError(
                failure_code,
                "private mission file write did not complete",
            )
        view = view[written:]


def _open_directory(path: Path, *, code: str) -> int:
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_NOFOLLOW
    )
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise MissionWorkflowError(
            code,
            "owner-controlled directory could not be bound safely",
        ) from exc


def _write_new_private(path: Path, raw: bytes) -> None:
    try:
        named_parent_before = path.parent.lstat()
    except OSError as exc:
        raise MissionWorkflowError(
            "proposal_directory_unavailable",
            "instance private directory is unavailable",
        ) from exc
    parent_fd = _open_directory(
        path.parent,
        code="proposal_directory_unavailable",
    )
    descriptor: int | None = None
    created = False
    operation_error: BaseException | None = None
    try:
        try:
            opened_parent = os.fstat(parent_fd)
            named_parent_after = path.parent.lstat()
            if (
                not stat.S_ISDIR(opened_parent.st_mode)
                or opened_parent.st_uid != os.geteuid()
                or stat.S_IMODE(opened_parent.st_mode) != 0o700
                or (opened_parent.st_dev, opened_parent.st_ino)
                != (
                    named_parent_before.st_dev,
                    named_parent_before.st_ino,
                )
                or (named_parent_after.st_dev, named_parent_after.st_ino)
                != (opened_parent.st_dev, opened_parent.st_ino)
            ):
                raise MissionWorkflowError(
                    "proposal_directory_ambiguous",
                    "instance private directory changed during proposal creation",
                )
            try:
                descriptor = os.open(
                    path.name,
                    (
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0)
                        | os.O_NOFOLLOW
                    ),
                    0o600,
                    dir_fd=parent_fd,
                )
            except FileExistsError as exc:
                raise MissionWorkflowError(
                    "proposal_exists",
                    "mission proposal output already exists; choose a new private filename",
                ) from exc
            except OSError as exc:
                raise MissionWorkflowError(
                    "proposal_create_failed",
                    "mission proposal file could not be created safely",
                ) from exc
            created = True
            _write_all(
                descriptor,
                raw,
                failure_code="proposal_write_failed",
            )
            try:
                os.fsync(descriptor)
                os.fchmod(descriptor, 0o600)
                info = os.fstat(descriptor)
            except OSError as exc:
                raise MissionWorkflowError(
                    "proposal_write_failed",
                    "mission proposal could not be made durable",
                ) from exc
            if not _is_private_regular(info, expected_size=len(raw)):
                raise MissionWorkflowError(
                    "proposal_metadata_unsafe",
                    "mission proposal metadata is unsafe",
                )
            try:
                os.close(descriptor)
            except OSError as exc:
                descriptor = None
                raise MissionWorkflowError(
                    "proposal_close_failed",
                    "mission proposal descriptor close failed",
                ) from exc
            descriptor = None
            try:
                observed_raw = read_stable_regular(
                    path,
                    maximum_bytes=MAX_PROPOSAL_BYTES,
                    owner_only=True,
                )
            except StableFileError as exc:
                raise MissionWorkflowError(
                    "proposal_postwrite_invalid",
                    "mission proposal changed after it was written",
                ) from exc
            if observed_raw != raw:
                raise MissionWorkflowError(
                    "proposal_postwrite_invalid",
                    "mission proposal changed after it was written",
                )
            try:
                os.fsync(parent_fd)
            except OSError as exc:
                raise MissionWorkflowError(
                    "proposal_directory_fsync_failed",
                    "mission proposal directory could not be made durable",
                ) from exc
        except BaseException as exc:
            operation_error = exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass

    if operation_error is not None:
        cleanup_failed = False
        if created:
            try:
                os.unlink(path.name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError:
                cleanup_failed = True
        try:
            os.close(parent_fd)
        except OSError:
            pass
        if cleanup_failed:
            raise MissionWorkflowError(
                "proposal_cleanup_failed",
                "mission proposal failed and partial-file cleanup was ambiguous",
            ) from operation_error
        raise operation_error
    try:
        os.close(parent_fd)
    except OSError as exc:
        raise MissionWorkflowError(
            "proposal_directory_close_failed",
            "mission proposal directory descriptor close failed",
        ) from exc


def _proposal_bytes(proposal: Mapping[str, Any]) -> bytes:
    raw = (
        json.dumps(
            proposal,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    if len(raw) > MAX_PROPOSAL_BYTES:
        raise MissionWorkflowError(
            "proposal_oversized",
            "mission proposal exceeds the product size limit",
        )
    return raw


def propose(
    instance: str | Path,
    *,
    statement: Any,
    roadmap_sources: Sequence[Any],
    owner_signal_policy: Any,
    output: str | Path | None = None,
    now: datetime | None = None,
    challenge: str | None = None,
) -> dict[str, Any]:
    """Create one exact, unconfirmed, dormant-observer mission proposal."""

    _require_secure_os_primitives()
    _reject_bound_environment()
    _, manifest_path, private = _instance_paths(instance)
    raw, _ = _read_manifest_bytes(manifest_path)
    manifest, contract, identity = _validated_manifest(raw)
    if contract["mission_complete"]:
        raise MissionWorkflowError(
            "mission_already_confirmed",
            "instance already has a complete owner-confirmed mission",
        )
    mission = _normalized_candidate_mission(
        manifest,
        statement=statement,
        roadmap_sources=roadmap_sources,
        owner_signal_policy=owner_signal_policy,
    )
    candidate_raw = _observer_candidate(manifest, mission)
    observed = now or datetime.now(timezone.utc)
    if observed.tzinfo is None:
        raise MissionWorkflowError(
            "proposal_clock_invalid",
            "mission proposal clock must be timezone-aware",
        )
    observed = observed.astimezone(timezone.utc)
    nonce = challenge or secrets.token_hex(32)
    if not _HEX_64_RE.fullmatch(nonce):
        raise MissionWorkflowError(
            "proposal_challenge_invalid",
            "mission proposal challenge is invalid",
        )
    proposal: dict[str, Any] = {
        "schema_version": PROPOSAL_SCHEMA,
        "status": PROPOSAL_STATUS,
        "created_at": _utc_text(observed),
        "expires_at": _utc_text(observed + PROPOSAL_LIFETIME),
        "challenge": nonce,
        "binding": {
            "instance_slug": identity["slug"],
            "repository": identity["repository"],
            "default_branch": identity["default_branch"],
            "base_manifest_sha256": _sha256(raw),
        },
        "mission": mission,
        "requested_authority_before_confirmation": (
            _requested_authority_summary(manifest, contract)
        ),
        "post_confirmation_authority": copy.deepcopy(
            _POST_CONFIRMATION_AUTHORITY
        ),
        "candidate_manifest_sha256": _sha256(candidate_raw),
    }
    proposal["candidate_sha256"] = _proposal_digest(proposal)
    proposal_raw = _proposal_bytes(proposal)
    destination = _proposal_path(private, output)
    _write_new_private(destination, proposal_raw)
    return {
        "schema_version": PROPOSAL_SCHEMA,
        "status": "candidate_created",
        "identity": identity,
        "mission": copy.deepcopy(mission),
        "requested_authority_before_confirmation": copy.deepcopy(
            proposal["requested_authority_before_confirmation"]
        ),
        "post_confirmation_authority": copy.deepcopy(
            proposal["post_confirmation_authority"]
        ),
        "candidate_manifest_sha256": proposal[
            "candidate_manifest_sha256"
        ],
        "candidate_sha256": proposal["candidate_sha256"],
        "owner_confirmation": confirmation_phrase(
            proposal["candidate_sha256"]
        ),
        "expires_at": proposal["expires_at"],
        "assurances": {
            "owner_authorship_asserted": False,
            "source_manifest_changed": False,
            "runtime_reconciled": False,
            "services_changed": False,
            "activation_granted": False,
            "network_used": False,
            "model_invoked": False,
            "credential_files_opened": False,
        },
    }


_PROPOSAL_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "created_at",
        "expires_at",
        "challenge",
        "binding",
        "mission",
        "requested_authority_before_confirmation",
        "post_confirmation_authority",
        "candidate_manifest_sha256",
        "candidate_sha256",
    }
)
_BINDING_KEYS = frozenset(
    {
        "instance_slug",
        "repository",
        "default_branch",
        "base_manifest_sha256",
    }
)
_MISSION_KEYS = frozenset(
    {
        "owner_authored",
        "statement",
        "roadmap_sources",
        "owner_signal_policy",
    }
)
_PRE_AUTHORITY_KEYS = frozenset(
    {
        "activation",
        "mutation",
        "discord",
        "guide_gateway",
        "protected_release",
        "portfolio",
        "keep_awake",
        "external_delivery",
    }
)
_POST_AUTHORITY_KEYS = frozenset(_POST_CONFIRMATION_AUTHORITY)


def _exact_keys(
    value: Any,
    expected: frozenset[str],
    *,
    code: str,
    field: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != expected:
        raise MissionWorkflowError(
            code,
            f"mission proposal {field} has an invalid schema",
        )
    return value


def _load_proposal(
    path: Path,
    *,
    now: datetime,
) -> dict[str, Any]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise MissionWorkflowError(
            "proposal_unreadable",
            "mission proposal is unreadable",
        ) from exc
    if not _is_private_regular(before):
        raise MissionWorkflowError(
            "proposal_metadata_unsafe",
            "mission proposal must be an owner-owned single-link mode-0600 file",
        )
    try:
        raw = read_stable_regular(
            path,
            maximum_bytes=MAX_PROPOSAL_BYTES,
            owner_only=True,
        )
    except StableFileError as exc:
        raise MissionWorkflowError(
            "proposal_stable_read_failed",
            "mission proposal could not be read as one stable file",
        ) from exc
    try:
        loaded = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except MissionWorkflowError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MissionWorkflowError(
            "proposal_invalid",
            "mission proposal is invalid",
        ) from exc
    proposal = _exact_keys(
        loaded,
        _PROPOSAL_KEYS,
        code="proposal_schema_invalid",
        field="root",
    )
    if (
        proposal["schema_version"] != PROPOSAL_SCHEMA
        or proposal["status"] != PROPOSAL_STATUS
        or not _is_hex_digest(proposal["challenge"])
        or not _is_hex_digest(proposal["candidate_manifest_sha256"])
        or not _is_hex_digest(proposal["candidate_sha256"])
    ):
        raise MissionWorkflowError(
            "proposal_schema_invalid",
            "mission proposal root has an invalid schema",
        )
    binding = _exact_keys(
        proposal["binding"],
        _BINDING_KEYS,
        code="proposal_binding_invalid",
        field="binding",
    )
    mission = _exact_keys(
        proposal["mission"],
        _MISSION_KEYS,
        code="proposal_mission_invalid",
        field="mission",
    )
    prior = _exact_keys(
        proposal["requested_authority_before_confirmation"],
        _PRE_AUTHORITY_KEYS,
        code="proposal_authority_invalid",
        field="prior authority",
    )
    post = _exact_keys(
        proposal["post_confirmation_authority"],
        _POST_AUTHORITY_KEYS,
        code="proposal_authority_invalid",
        field="post-confirmation authority",
    )
    if (
        mission["owner_authored"] is not False
        or post != _POST_CONFIRMATION_AUTHORITY
        or type(prior["mutation"]) is not bool
        or type(prior["discord"]) is not bool
        or type(prior["guide_gateway"]) is not bool
        or type(prior["protected_release"]) is not bool
        or type(prior["portfolio"]) is not bool
        or type(prior["keep_awake"]) is not bool
        or type(prior["external_delivery"]) is not bool
        or prior["activation"] not in {"active", "owner_gated"}
        or any(
            not isinstance(binding[key], str)
            for key in (
                "instance_slug",
                "repository",
                "default_branch",
            )
        )
        or not _is_hex_digest(binding["base_manifest_sha256"])
    ):
        raise MissionWorkflowError(
            "proposal_schema_invalid",
            "mission proposal contains an invalid authority or provenance value",
        )
    try:
        safe_instance_slug(binding["instance_slug"])
        safe_github_repo(binding["repository"])
        safe_default_branch(binding["default_branch"])
    except ValueError as exc:
        raise MissionWorkflowError(
            "proposal_binding_invalid",
            "mission proposal identity binding is invalid",
        ) from exc
    created = _parse_utc(proposal["created_at"], field="creation time")
    expires = _parse_utc(proposal["expires_at"], field="expiry time")
    if expires - created != PROPOSAL_LIFETIME:
        raise MissionWorkflowError(
            "proposal_time_invalid",
            "mission proposal validity window is invalid",
        )
    if now.tzinfo is None:
        raise MissionWorkflowError(
            "proposal_clock_invalid",
            "mission confirmation clock must be timezone-aware",
        )
    current = now.astimezone(timezone.utc)
    if created > current + timedelta(minutes=5):
        raise MissionWorkflowError(
            "proposal_not_yet_valid",
            "mission proposal creation time is in the future",
        )
    if _proposal_digest(proposal) != proposal["candidate_sha256"]:
        raise MissionWorkflowError(
            "proposal_digest_mismatch",
            "mission proposal digest does not match its exact content",
        )
    if raw != _proposal_bytes(proposal):
        raise MissionWorkflowError(
            "proposal_encoding_noncanonical",
            "mission proposal bytes are not the canonical reviewed form",
        )
    return proposal


def _write_manifest_candidate(
    manifest_path: Path,
    *,
    expected_raw: bytes,
    expected_signature: tuple[int, ...],
    candidate_raw: bytes,
) -> None:
    parent = manifest_path.parent
    try:
        parent_identity = directory_chain_identity(manifest_path)
    except StableFileError as exc:
        raise MissionWorkflowError(
            "manifest_directory_unavailable",
            "instance directory could not be bound safely",
        ) from exc
    parent_fd = _open_directory(
        parent,
        code="manifest_directory_unavailable",
    )
    temp_name = (
        f".{manifest_path.name}.john-lomein-mission-"
        f"{secrets.token_hex(16)}.tmp"
    )
    descriptor: int | None = None
    temp_created = False
    replaced = False
    operation_error: BaseException | None = None
    try:
        try:
            parent_info = os.fstat(parent_fd)
            named_parent = parent.lstat()
            if (
                not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != os.geteuid()
                or stat.S_IMODE(parent_info.st_mode) != 0o700
                or (parent_info.st_dev, parent_info.st_ino)
                != (named_parent.st_dev, named_parent.st_ino)
            ):
                raise MissionWorkflowError(
                    "manifest_directory_ambiguous",
                    "instance directory changed during mission confirmation",
                )
            try:
                descriptor = os.open(
                    temp_name,
                    (
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | getattr(os, "O_CLOEXEC", 0)
                        | os.O_NOFOLLOW
                    ),
                    0o600,
                    dir_fd=parent_fd,
                )
            except OSError as exc:
                raise MissionWorkflowError(
                    "manifest_candidate_create_failed",
                    "confirmed observer manifest could not be staged safely",
                ) from exc
            temp_created = True
            _write_all(
                descriptor,
                candidate_raw,
                failure_code="manifest_candidate_write_failed",
            )
            try:
                os.fsync(descriptor)
                os.fchmod(descriptor, 0o600)
                temp_info = os.fstat(descriptor)
            except OSError as exc:
                raise MissionWorkflowError(
                    "manifest_candidate_write_failed",
                    "confirmed observer manifest could not be made durable",
                ) from exc
            if not _is_private_regular(
                temp_info,
                expected_size=len(candidate_raw),
            ):
                raise MissionWorkflowError(
                    "manifest_candidate_metadata_unsafe",
                    "confirmed observer manifest metadata is unsafe",
                )
            try:
                os.close(descriptor)
            except OSError as exc:
                descriptor = None
                raise MissionWorkflowError(
                    "manifest_candidate_close_failed",
                    "confirmed observer manifest descriptor close failed",
                ) from exc
            descriptor = None
            staged_raw, _ = _read_manifest_bytes(parent / temp_name)
            if staged_raw != candidate_raw:
                raise MissionWorkflowError(
                    "manifest_candidate_changed",
                    "confirmed observer manifest changed while it was staged",
                )

            current_raw, current_signature = _read_manifest_bytes(
                manifest_path
            )
            if (
                current_raw != expected_raw
                or current_signature != expected_signature
                or directory_chain_identity(manifest_path) != parent_identity
            ):
                raise MissionWorkflowError(
                    "manifest_changed",
                    "instance manifest changed before mission confirmation",
                )
            try:
                os.replace(
                    temp_name,
                    manifest_path.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                replaced = True
                temp_created = False
                os.fsync(parent_fd)
            except OSError as exc:
                code = (
                    "manifest_commit_ambiguous"
                    if replaced
                    else "manifest_replace_failed"
                )
                message = (
                    "mission confirmation commit durability is ambiguous; retry to reconcile"
                    if replaced
                    else "confirmed observer manifest replacement failed"
                )
                raise MissionWorkflowError(code, message) from exc

            final_raw, _ = _read_manifest_bytes(manifest_path)
            if final_raw != candidate_raw:
                raise MissionWorkflowError(
                    "manifest_commit_ambiguous",
                    "mission confirmation result is ambiguous; retry to reconcile",
                )
        except BaseException as exc:
            operation_error = exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass

    if operation_error is not None:
        cleanup_failed = False
        if temp_created:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError:
                cleanup_failed = True
        try:
            os.close(parent_fd)
        except OSError:
            pass
        if cleanup_failed:
            raise MissionWorkflowError(
                "manifest_candidate_cleanup_failed",
                "mission confirmation failed and temporary-file cleanup was ambiguous",
            ) from operation_error
        raise operation_error
    try:
        os.close(parent_fd)
    except OSError as exc:
        raise MissionWorkflowError(
            "manifest_directory_close_failed",
            "mission confirmation directory descriptor close failed; retry to reconcile",
        ) from exc


def _confirmation_result(
    proposal: Mapping[str, Any],
    identity: Mapping[str, str],
    *,
    status: str,
) -> dict[str, Any]:
    return {
        "schema_version": RESULT_SCHEMA,
        "status": status,
        "identity": dict(identity),
        "candidate_sha256": proposal["candidate_sha256"],
        "manifest_sha256": proposal["candidate_manifest_sha256"],
        "mission_complete": True,
        "desired_posture": copy.deepcopy(_POST_CONFIRMATION_AUTHORITY),
        "runtime_reconciled": False,
        "services_changed": False,
        "activation_granted": False,
        "next": "reconcile_observer",
        "assurances": {
            "declarative_owner_adoption_asserted": True,
            "durable_signed_adoption_receipt_written": False,
            "cryptographic_owner_identity_proven": False,
            "runtime_reconciled": False,
            "services_changed": False,
            "activation_granted": False,
            "network_used": False,
            "model_invoked": False,
            "credential_files_opened": False,
        },
    }


def confirm(
    instance: str | Path,
    *,
    proposal_path: str | Path | None,
    owner_confirmation: Any,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Adopt one exact proposal while forcing desired observer posture."""

    _require_secure_os_primitives()
    _reject_bound_environment()
    observed = now or datetime.now(timezone.utc)
    try:
        with lifecycle_lock():
            _, manifest_path, private = _instance_paths(instance)
            selected_proposal = _proposal_path(private, proposal_path)
            proposal = _load_proposal(
                selected_proposal,
                now=observed,
            )
            expected_confirmation = confirmation_phrase(
                proposal["candidate_sha256"]
            )
            if (
                not isinstance(owner_confirmation, str)
                or owner_confirmation != expected_confirmation
            ):
                raise MissionWorkflowError(
                    "owner_confirmation_mismatch",
                    "owner confirmation does not match the exact mission proposal",
                )

            current_raw, current_signature = _read_manifest_bytes(
                manifest_path
            )
            manifest, contract, identity = _validated_manifest(current_raw)
            binding = proposal["binding"]
            if (
                identity["slug"] != binding["instance_slug"]
                or identity["repository"] != binding["repository"]
                or identity["default_branch"] != binding["default_branch"]
            ):
                raise MissionWorkflowError(
                    "proposal_instance_mismatch",
                    "mission proposal belongs to another instance identity",
                )
            mission = _normalized_candidate_mission(
                manifest,
                statement=proposal["mission"]["statement"],
                roadmap_sources=proposal["mission"]["roadmap_sources"],
                owner_signal_policy=proposal["mission"][
                    "owner_signal_policy"
                ],
            )
            if mission != proposal["mission"]:
                raise MissionWorkflowError(
                    "proposal_mission_mismatch",
                    "mission proposal does not match normalized product fields",
                )

            current_digest = _sha256(current_raw)
            if current_digest == proposal["candidate_manifest_sha256"]:
                current_posture = effective_authority_posture(
                    manifest,
                    contract=contract,
                )
                if not _is_dormant_observer(
                    manifest,
                    contract,
                    current_posture,
                ):
                    raise MissionWorkflowError(
                        "proposal_candidate_mismatch",
                        "confirmed manifest does not satisfy observer posture",
                    )
                return _confirmation_result(
                    proposal,
                    identity,
                    status="already_confirmed_observer",
                )

            candidate_raw = _observer_candidate(manifest, mission)
            if (
                _sha256(candidate_raw)
                != proposal["candidate_manifest_sha256"]
            ):
                raise MissionWorkflowError(
                    "proposal_candidate_mismatch",
                    "mission proposal no longer derives the exact observer manifest",
                )
            expires = _parse_utc(
                proposal["expires_at"],
                field="expiry time",
            )
            if observed.astimezone(timezone.utc) > expires:
                raise MissionWorkflowError(
                    "proposal_expired",
                    "mission proposal has expired; create and review a new proposal",
                )
            if current_digest != binding["base_manifest_sha256"]:
                raise MissionWorkflowError(
                    "proposal_stale",
                    "instance manifest changed after this mission proposal was created",
                )
            if contract["mission_complete"]:
                raise MissionWorkflowError(
                    "mission_already_confirmed",
                    "instance already has a different owner-confirmed mission",
                )
            if (
                _requested_authority_summary(manifest, contract)
                != proposal[
                    "requested_authority_before_confirmation"
                ]
            ):
                raise MissionWorkflowError(
                    "proposal_authority_mismatch",
                    "requested authority changed after this proposal was created",
                )

            _write_manifest_candidate(
                manifest_path,
                expected_raw=current_raw,
                expected_signature=current_signature,
                candidate_raw=candidate_raw,
            )
            final_raw, _ = _read_manifest_bytes(manifest_path)
            if _sha256(final_raw) != proposal["candidate_manifest_sha256"]:
                raise MissionWorkflowError(
                    "manifest_commit_ambiguous",
                    "mission confirmation result is ambiguous; retry to reconcile",
                )
            final_manifest, final_contract, final_identity = (
                _validated_manifest(final_raw)
            )
            final_posture = effective_authority_posture(
                final_manifest,
                contract=final_contract,
            )
            if (
                final_identity != identity
                or not _is_dormant_observer(
                    final_manifest,
                    final_contract,
                    final_posture,
                )
            ):
                raise MissionWorkflowError(
                    "manifest_commit_ambiguous",
                    "confirmed manifest failed its final dormant postcondition",
                )
            return _confirmation_result(
                proposal,
                identity,
                status="confirmed_observer",
            )
    except ServiceRegistryError as exc:
        raise MissionWorkflowError(
            "lifecycle_lock_unavailable",
            "mission confirmation could not acquire the lifecycle lock",
        ) from exc


def render_proposal_human(report: Mapping[str, Any]) -> str:
    identity = report["identity"]
    mission = report["mission"]
    prior = report["requested_authority_before_confirmation"]
    post = report["post_confirmation_authority"]
    return "\n".join(
        [
            "John Lomein mission proposal",
            "",
            "Verdict",
            (
                "This is a valid unconfirmed proposal. It grants nothing until "
                "the owner adopts the exact digest."
            ),
            "",
            "Evidence",
            f"- Instance: {identity['slug']}",
            (
                f"- Repository: {identity['repository']} "
                f"({identity['default_branch']})"
            ),
            f"- Statement: {mission['statement']}",
            "- Roadmap sources:",
            *[f"  - {source}" for source in mission["roadmap_sources"]],
            f"- Owner signal policy: {mission['owner_signal_policy']}",
            (
                "- Requested before confirmation: "
                + json.dumps(prior, sort_keys=True, separators=(",", ":"))
            ),
            (
                "- Desired after confirmation: "
                + json.dumps(post, sort_keys=True, separators=(",", ":"))
            ),
            f"- Candidate digest: {report['candidate_sha256']}",
            f"- Expires: {report['expires_at']}",
            "",
            "Next",
            (
                "Review the exact public-safe mission above. If it is yours, "
                "use the full phrase below with the confirm command."
            ),
            (
                "Confirmation records adoption and resets desired configuration "
                "to a dormant observer. It does not deploy, start services, or "
                "cryptographically prove human identity."
            ),
            "",
            report["owner_confirmation"],
        ]
    )


def render_confirmation_human(report: Mapping[str, Any]) -> str:
    identity = report["identity"]
    return "\n".join(
        [
            "John Lomein mission confirmation",
            "",
            "Verdict",
            (
                "The desired manifest now declares owner adoption of the "
                "reviewed mission, with every requested external capability "
                "reset to observer posture."
            ),
            "",
            "Evidence",
            f"- Status: {report['status']}",
            f"- Instance: {identity['slug']}",
            f"- Repository: {identity['repository']}",
            f"- Adopted candidate digest: {report['candidate_sha256']}",
            f"- Manifest digest: {report['manifest_sha256']}",
            "- Runtime reconciled: no",
            "- Services changed: no",
            "- Activation granted: no",
            (
                "- Identity proof: declarative only; not cryptographic "
                "authentication"
            ),
            "- Signed adoption receipt written: no",
            "",
            "Next",
            (
                "Run ./setup.sh <instance> to reconcile the confirmed dormant "
                "observer. Review and grant active authority separately later."
            ),
        ]
    )


__all__ = [
    "CONFIRMATION_PREFIX",
    "DEFAULT_PROPOSAL_FILENAME",
    "MissionWorkflowError",
    "PROPOSAL_SCHEMA",
    "RESULT_SCHEMA",
    "confirm",
    "confirmation_phrase",
    "propose",
    "render_confirmation_human",
    "render_proposal_human",
]
