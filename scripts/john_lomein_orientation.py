#!/usr/bin/env python3
"""Offline, read-only product orientation for a John Lomein instance."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from john_lomein_continuity import (
    ContinuityError,
    continuity_root,
    load_persona_binding,
)
from john_lomein_continuity_importer import (
    ContinuityImporterError,
    inspect_projection_state,
)
from john_lomein_factory_receipts import (
    public_metadata_text,
    safe_default_branch,
    safe_github_repo,
    safe_instance_slug,
    safe_runtime_activation,
)
from john_lomein_file_contract import StableFileError, read_stable_regular
from john_lomein_manifest_contract import (
    validate_manifest_contract,
    validate_runtime_checkout_separation,
)
from john_lomein_persona_contract import load_persona_core
from john_lomein_profile_contract import canonical_role_profiles


SCHEMA_VERSION = "john_lomein_orientation/v1"
MAX_MANIFEST_BYTES = 1024 * 1024
PERSONA_SOURCE = Path(__file__).resolve().parents[1] / "persona" / "JOHN_LOMEIN.md"

STATUS_HEALTHY = "healthy"
STATUS_ATTENTION = "attention_required"
STATUS_BROKEN = "broken"

_NEXT_TEXT = {
    "author_owner_mission": (
        "Author the public-safe repository mission before trusting active "
        "autonomy. John should know what he is maintaining, not improvise it."
    ),
    "confirm_owner_mission": (
        "Review and revise the public-safe mission candidate, then use "
        "scripts/john-lomein-mission.py propose and confirm. Never flip "
        "mission.owner_authored alone."
    ),
    "install_observer": (
        "Install the validated observer with ./setup.sh <instance>. Mutation "
        "and public gateways remain off."
    ),
    "reconcile_runtime": (
        "Reconcile the instance with ./setup.sh <instance>; do not hand-edit "
        "generated runtime files."
    ),
    "repair_continuity": (
        "Run Doctor and inspect the continuity proof. Preserve the ledger; do "
        "not reset or delete evidence to make the warning disappear."
    ),
    "run_doctor": (
        "Run make doctor INSTANCE=<instance> for live checkout, GitHub, model, "
        "service, queue, and optional protected-gate evidence."
    ),
    "observe_before_activation": (
        "Keep observer posture until the repository test command, checkout, "
        "credentials, and Doctor checks are proven. Activation remains an "
        "owner decision."
    ),
}


class OrientationError(RuntimeError):
    """A bounded, public-safe orientation failure."""

    def __init__(self, code: str, public_message: str):
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message


def _path_present(path: Path, *, field: str) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise OrientationError(
            f"{field}_unreadable",
            f"{field} is unreadable",
        ) from exc
    return True


def _read_regular(path: Path, *, field: str, maximum_bytes: int) -> bytes:
    try:
        return read_stable_regular(
            path,
            maximum_bytes=maximum_bytes,
            owner_only=True,
        )
    except StableFileError as exc:
        code = exc.code if exc.code in {
            "missing",
            "unreadable",
            "unsafe",
            "ambiguous",
        } else "unsafe"
        message = {
            "missing": f"{field} is missing",
            "unreadable": f"{field} is unreadable",
            "unsafe": f"{field} metadata is unsafe",
            "ambiguous": f"{field} changed during inspection",
        }[code]
        raise OrientationError(f"{field}_{code}", message) from exc


def _manifest_path(argument: str | Path) -> Path:
    supplied = Path(argument).expanduser()
    try:
        supplied_info = supplied.lstat()
    except FileNotFoundError:
        supplied_info = None
    except OSError as exc:
        raise OrientationError(
            "manifest_path_unreadable",
            "instance manifest path is unreadable",
        ) from exc
    if supplied_info is not None and stat.S_ISLNK(supplied_info.st_mode):
        raise OrientationError(
            "manifest_path_unsafe",
            "instance manifest path is unsafe",
        )
    if supplied_info is not None and stat.S_ISDIR(supplied_info.st_mode):
        primary = supplied / "instance.yaml"
        legacy = supplied / "bot.yaml"
        presence: dict[Path, bool] = {}
        for candidate in (primary, legacy):
            present = _path_present(candidate, field="manifest")
            if present:
                try:
                    candidate_info = candidate.lstat()
                except OSError as exc:
                    raise OrientationError(
                        "manifest_unreadable",
                        "manifest is unreadable",
                    ) from exc
                if stat.S_ISLNK(candidate_info.st_mode):
                    raise OrientationError(
                        "manifest_unsafe",
                        "manifest metadata is unsafe",
                    )
            presence[candidate] = present
        primary_present = presence[primary]
        legacy_present = presence[legacy]
        if primary_present and legacy_present:
            raise OrientationError(
                "manifest_ambiguous",
                "instance has more than one authoritative manifest candidate",
            )
        manifest = primary if primary_present else legacy
    else:
        manifest = supplied
    if not _path_present(manifest, field="manifest"):
        raise OrientationError(
            "manifest_missing",
            "instance manifest is missing",
        )
    return Path(os.path.abspath(manifest))


def _load_manifest(argument: str | Path) -> tuple[bytes, dict[str, Any]]:
    manifest = _manifest_path(argument)
    raw = _read_regular(
        manifest,
        field="manifest",
        maximum_bytes=MAX_MANIFEST_BYTES,
    )
    try:
        loaded = yaml.safe_load(raw.decode("utf-8")) or {}
    except (UnicodeError, yaml.YAMLError) as exc:
        raise OrientationError(
            "manifest_invalid",
            "instance manifest is invalid",
        ) from exc
    if not isinstance(loaded, Mapping):
        raise OrientationError(
            "manifest_invalid",
            "instance manifest is invalid",
        )
    return raw, dict(loaded)


def _manifest_contract(manifest: Mapping[str, Any]) -> dict[str, Any]:
    try:
        contract = validate_manifest_contract(manifest)
        profiles = canonical_role_profiles(manifest)
        instance = manifest.get("instance") or {}
        target = manifest.get("target") or {}
        runtime = manifest.get("runtime") or {}
        slug = safe_instance_slug(instance.get("slug"))
        display_name = public_metadata_text(
            instance.get("display_name"),
            "instance.display_name",
            slug,
            max_length=160,
        )
        repository = safe_github_repo(target.get("repo"))
        branch = safe_default_branch(target.get("default_branch"))
        activation = safe_runtime_activation(runtime.get("activation"))
        _, runtime_home = validate_runtime_checkout_separation(
            Path(
                os.path.expanduser(
                    str(
                        target.get("local_checkout")
                        or target.get("local")
                        or f"~/.john-lomein/instances/{slug}/work/repo"
                    )
                )
            ),
            Path(
                os.path.expanduser(
                    str(
                        runtime.get("hermes_home")
                        or f"~/.john-lomein/instances/{slug}/hermes"
                    )
                )
            ),
        )
    except (TypeError, ValueError) as exc:
        raise OrientationError(
            "manifest_contract_invalid",
            "instance manifest violates the product contract",
        ) from exc
    return {
        "contract": contract,
        "profiles": profiles,
        "slug": slug,
        "display_name": display_name,
        "repository": repository,
        "branch": branch,
        "activation": activation,
        "runtime_home": runtime_home,
    }


def _deployment_proof(
    runtime_home: Path,
    desired_raw: bytes,
) -> dict[str, Any]:
    try:
        info = runtime_home.lstat()
    except FileNotFoundError:
        return {
            "status": "not_installed",
            "matches_desired": None,
        }
    except OSError:
        return {
            "status": "unreadable",
            "matches_desired": False,
        }
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        return {
            "status": "unsafe",
            "matches_desired": False,
        }
    deployed = runtime_home / "instance.yaml"
    if not _path_present(deployed, field="deployed_manifest"):
        return {
            "status": "missing",
            "matches_desired": False,
        }
    try:
        deployed_raw = _read_regular(
            deployed,
            field="deployed_manifest",
            maximum_bytes=MAX_MANIFEST_BYTES,
        )
    except OrientationError as exc:
        return {
            "status": exc.code.removeprefix("deployed_manifest_"),
            "matches_desired": False,
        }
    matches = deployed_raw == desired_raw
    return {
        "status": "proven" if matches else "drift",
        "matches_desired": matches,
    }


def _persona_proof(
    runtime_home: Path,
    *,
    profiles: Mapping[str, str],
    expected_version: str,
    expected_sha256: str,
    deployment_status: str,
) -> dict[str, Any]:
    base = {
        "status": "not_installed",
        "version": expected_version,
        "sha256": expected_sha256,
    }
    if deployment_status == "not_installed":
        return base
    evidence = runtime_home / "state" / "john-lomein-persona.json"
    if not _path_present(evidence, field="persona_evidence"):
        return {**base, "status": "missing"}
    try:
        binding = load_persona_binding(
            runtime_home,
            role="maintainer",
            profile=profiles["maintainer"],
        )
    except ContinuityError as exc:
        return {
            **base,
            "status": "invalid",
            "error_code": exc.code,
        }
    matches = (
        binding["version"] == expected_version
        and binding["sha256"] == expected_sha256
    )
    return {
        **base,
        "status": "proven" if matches else "stale",
    }


def _continuity_proof(
    runtime_home: Path,
    *,
    deployment_status: str,
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "status": "not_installed",
        "sequence": None,
        "entry_count": None,
    }
    if deployment_status == "not_installed":
        return base
    root = continuity_root(runtime_home)
    if not _path_present(root, field="continuity_store"):
        return {**base, "status": "missing"}
    try:
        projection = inspect_projection_state(runtime_home)
    except (ContinuityError, ContinuityImporterError) as exc:
        return {
            **base,
            "status": "invalid",
            "error_code": exc.code,
        }
    return {
        "status": "proven",
        "sequence": int(projection["continuity_sequence"]),
        "entry_count": int(projection["effective_entry_count"]),
        "signed_import": {
            "configured": bool(projection["configured"]),
            "enabled": bool(projection["enabled"]),
            "state_initialized": bool(
                projection["import_state_initialized"]
            ),
            "sequence": int(projection["import_sequence"]),
            "suppressed_entry_count": int(
                projection["suppressed_entry_count"]
            ),
        },
    }


def _capability_state(enabled: bool, *, mission_complete: bool) -> str:
    if not enabled:
        return "gated"
    if not mission_complete:
        return "blocked_missing_owner_mission"
    return "configured_not_live_proven"


def _ordered_next_steps(codes: list[str]) -> list[dict[str, str]]:
    seen: set[str] = set()
    result: list[dict[str, str]] = []
    for code in codes:
        if code in seen:
            continue
        seen.add(code)
        result.append({"code": code, "text": _NEXT_TEXT[code]})
    return result


def build_orientation(argument: str | Path) -> dict[str, Any]:
    """Evaluate one instance using local, deterministic, read-only evidence."""

    manifest_raw, manifest = _load_manifest(argument)
    resolved = _manifest_contract(manifest)
    contract = resolved["contract"]
    flags = contract["flags"]
    mission = contract["prompt"]["mission"]
    runtime_home: Path = resolved["runtime_home"]
    try:
        _, persona_version, persona_sha256 = load_persona_core(PERSONA_SOURCE)
    except ValueError as exc:
        raise OrientationError(
            "persona_source_invalid",
            "canonical persona source is invalid",
        ) from exc

    mission_candidate_complete = bool(contract["mission_candidate_complete"])
    mission_complete = bool(contract["mission_complete"])
    authority_enabled = bool(
        resolved["activation"] == "active"
        or flags["runtime_mutation_enabled"]
        or flags["discord_enabled"]
        or flags["guide_gateway_enabled"]
        or flags["protected_release_broker_enabled"]
        or flags["portfolio_enabled"]
    )
    deployment = _deployment_proof(runtime_home, manifest_raw)
    persona = _persona_proof(
        runtime_home,
        profiles=resolved["profiles"],
        expected_version=persona_version,
        expected_sha256=persona_sha256,
        deployment_status=deployment["status"],
    )
    continuity = _continuity_proof(
        runtime_home,
        deployment_status=deployment["status"],
    )
    installed_proven = (
        deployment["status"] == "proven"
        and persona["status"] == "proven"
        and continuity["status"] == "proven"
    )

    attention_codes: list[str] = []
    next_codes: list[str] = []
    if not mission_complete:
        next_codes.append(
            "confirm_owner_mission"
            if mission_candidate_complete
            else "author_owner_mission"
        )
        if authority_enabled:
            attention_codes.append("owner_mission_required_for_active_posture")
    if deployment["status"] == "not_installed":
        next_codes.append("install_observer")
        if authority_enabled:
            attention_codes.append("active_posture_not_installed")
    elif deployment["status"] != "proven" or persona["status"] in {
        "missing",
        "stale",
        "invalid",
    }:
        attention_codes.append("runtime_identity_drift")
        next_codes.append("reconcile_runtime")
    if continuity["status"] not in {"proven", "not_installed"}:
        attention_codes.append("continuity_proof_unavailable")
        next_codes.append("repair_continuity")

    if authority_enabled:
        next_codes.append("run_doctor")
    elif installed_proven:
        next_codes.append("observe_before_activation")

    if authority_enabled:
        stage = "active_attention" if attention_codes else "active_configured"
    else:
        stage = "proven_observer" if installed_proven else "configured_observer"
    status = STATUS_ATTENTION if attention_codes else STATUS_HEALTHY

    if status == STATUS_ATTENTION:
        verdict = (
            "The configuration has ambition ahead of evidence. Fix the named "
            "local gap before trusting the configured posture."
        )
    elif stage == "proven_observer":
        verdict = (
            "The observer is coherent. John has a mission and verified local "
            "continuity, but repository mutation and public gateways remain off."
        )
    elif stage == "configured_observer":
        verdict = (
            "The observer contract is valid and deliberately powerless. Install "
            "it before treating local identity or continuity as proven."
        )
    else:
        verdict = (
            "The local identity and continuity foundation is coherent. Active "
            "capabilities are configured, not live-proven by this offline briefing."
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "stage": stage,
        "verdict": verdict,
        "attention_codes": attention_codes,
        "identity": {
            "name": "John Lomein",
            "kind": "fictional_ai_software_maintainer",
            "ai_disclosure": True,
            "persona_version": persona_version,
            "persona_sha256": persona_sha256,
        },
        "instance": {
            "slug": resolved["slug"],
            "display_name": resolved["display_name"],
        },
        "mission": {
            "source": (
                "owner_authored"
                if mission_complete
                else (
                    "unconfirmed_candidate"
                    if mission_candidate_complete
                    else "conservative_default"
                )
            ),
            "owner_authored_declared": bool(mission["owner_authored"]),
            "candidate_complete": mission_candidate_complete,
            "complete": mission_complete,
            "statement": mission["statement"],
            "roadmap_sources": list(mission["roadmap_sources"]),
            "owner_signal_policy": mission["owner_signal_policy"],
        },
        "target": {
            "repository": resolved["repository"],
            "default_branch": resolved["branch"],
        },
        "proof": {
            "manifest": {
                "status": "valid",
            },
            "deployment": deployment,
            "persona": persona,
            "continuity": continuity,
        },
        "capabilities": {
            "observe": (
                "local_foundation_proven" if installed_proven else "configured"
            ),
            "activation": _capability_state(
                resolved["activation"] == "active",
                mission_complete=mission_complete,
            ),
            "mutation": _capability_state(
                flags["runtime_mutation_enabled"],
                mission_complete=mission_complete,
            ),
            "discord": _capability_state(
                flags["discord_enabled"],
                mission_complete=mission_complete,
            ),
            "guide_gateway": _capability_state(
                flags["guide_gateway_enabled"],
                mission_complete=mission_complete,
            ),
            "protected_release": _capability_state(
                flags["protected_release_broker_enabled"],
                mission_complete=mission_complete,
            ),
            "portfolio": _capability_state(
                flags["portfolio_enabled"],
                mission_complete=mission_complete,
            ),
        },
        "next_steps": _ordered_next_steps(next_codes),
        "assurances": {
            "offline": True,
            "read_only": True,
            "model_invoked": False,
            "credential_files_opened": False,
            "credential_environment_read": False,
            "authority_changed": False,
            "live_readiness_claimed": False,
        },
    }


def _broken_next_step(error_code: str) -> dict[str, str]:
    if error_code == "manifest_missing":
        return {
            "code": "restore_manifest",
            "text": (
                "Restore exactly one instance.yaml or legacy bot.yaml from "
                "reviewed source or templates/instance.yaml.example, set the "
                "manifest to mode 0600, then run make status "
                "INSTANCE=<instance>."
            ),
        }
    if error_code == "manifest_ambiguous":
        return {
            "code": "select_authoritative_manifest",
            "text": (
                "Stop concurrent manifest edits and retain exactly one "
                "authoritative instance.yaml or legacy bot.yaml; then run "
                "make status INSTANCE=<instance>."
            ),
        }
    if error_code in {"manifest_invalid", "manifest_contract_invalid"}:
        return {
            "code": "repair_manifest_contract",
            "text": (
                "Repair the source manifest against "
                "templates/instance.yaml.example and the reported attention "
                "code, then run make status INSTANCE=<instance>."
            ),
        }
    if error_code.startswith("manifest_"):
        return {
            "code": "repair_manifest_metadata",
            "text": (
                "Use an owner-controlled mode-0700 instance directory and one "
                "regular, single-link, owner-owned mode-0600 manifest; then "
                "run make status INSTANCE=<instance>."
            ),
        }
    if error_code == "persona_source_invalid":
        return {
            "code": "restore_persona_source",
            "text": (
                "Restore persona/JOHN_LOMEIN.md from reviewed product source, "
                "run make verify, then run make status INSTANCE=<instance>."
            ),
        }
    # Intentional fail-safe for internal or future error codes: do not guess at
    # a manifest edit. Preserve the bounded attention code and route the
    # operator through the product verification gate. Regression coverage keeps
    # this branch read-only and free of rejected input.
    return {
        "code": "repair_product_orientation",
        "text": (
            "Run make verify in the product source, repair the first failing "
            "product diagnostic, then run make status INSTANCE=<instance>."
        ),
    }


def broken_report(error: OrientationError) -> dict[str, Any]:
    """Return a bounded failure report without reflecting rejected input."""

    return {
        "schema_version": SCHEMA_VERSION,
        "status": STATUS_BROKEN,
        "stage": "invalid",
        "verdict": error.public_message,
        "attention_codes": [error.code],
        "identity": {
            "name": "John Lomein",
            "kind": "fictional_ai_software_maintainer",
            "ai_disclosure": True,
        },
        "next_steps": [_broken_next_step(error.code)],
        "assurances": {
            "offline": True,
            "read_only": True,
            "model_invoked": False,
            "credential_files_opened": False,
            "credential_environment_read": False,
            "authority_changed": False,
            "live_readiness_claimed": False,
        },
    }


def render_json(report: Mapping[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, sort_keys=True)


def render_human(report: Mapping[str, Any]) -> str:
    identity = report.get("identity") or {}
    attention_codes = [
        str(code) for code in (report.get("attention_codes") or [])
    ]
    if report.get("status") == STATUS_BROKEN:
        next_steps = report.get("next_steps") or []
        next_text = (
            str(next_steps[0].get("text"))
            if next_steps
            else "Repair the invalid instance contract."
        )
        return "\n".join(
            [
                "John Lomein",
                "",
                "Verdict",
                str(report.get("verdict") or "Instance orientation failed."),
                "",
                "Evidence",
                (
                    "- Attention: " + ", ".join(attention_codes)
                    if attention_codes
                    else "- Attention: orientation_failed"
                ),
                "",
                "Next",
                f"1. {next_text}",
            ]
        )

    instance = report.get("instance") or {}
    mission = report.get("mission") or {}
    target = report.get("target") or {}
    proof = report.get("proof") or {}
    capabilities = report.get("capabilities") or {}
    persona = proof.get("persona") or {}
    continuity = proof.get("continuity") or {}
    authority = ", ".join(
        f"{name}={state}"
        for name, state in capabilities.items()
        if name != "observe"
    )
    evidence = [
        (
            "Identity: fictional AI software maintainer; "
            f"persona={identity.get('persona_version')} "
            f"sha256={str(identity.get('persona_sha256') or '')[:12]}"
        ),
        (
            f"Mission ({mission.get('source')}): "
            f"{mission.get('statement')}"
        ),
        (
            f"Repository: {target.get('repository')} "
            f"branch={target.get('default_branch')}"
        ),
        (
            "Local proof: "
            f"deployment={((proof.get('deployment') or {}).get('status'))}; "
            f"persona={persona.get('status')}; "
            f"continuity={continuity.get('status')}"
        ),
        f"Authority posture: {authority}",
    ]
    if attention_codes:
        evidence.append("Attention: " + ", ".join(attention_codes))
    next_lines = [
        f"{index}. {step['text']}"
        for index, step in enumerate(report.get("next_steps") or [], start=1)
    ]
    if not next_lines:
        next_lines = ["1. No local action is required."]
    return "\n".join(
        [
            f"John Lomein — {instance.get('display_name')}",
            "",
            "Verdict",
            str(report.get("verdict") or ""),
            "",
            "Evidence",
            *[f"- {line}" for line in evidence],
            "",
            "Next",
            *next_lines,
        ]
    )


def exit_code(report: Mapping[str, Any]) -> int:
    if report.get("status") == STATUS_BROKEN:
        return 2
    if report.get("status") == STATUS_ATTENTION:
        return 1
    return 0
