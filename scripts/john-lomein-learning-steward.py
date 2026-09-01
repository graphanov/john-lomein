#!/usr/bin/env python3
"""Instance-local john-lomein learning steward.

The steward is the only deterministic lane that writes project-memory updates.
Operational roles emit observations; this script reconciles source-of-truth state,
writes generated non-canonical briefs, upserts profile-native Mnemosyne memories,
and creates quarantined candidate improvement artifacts when repeated evidence
exists. It deliberately does not patch skills/workflows directly.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_owner_actions import (
    TRUST_OWNER,
    normalize_trust_tier,
    normalized_text_hash,
    trusted_owner_approval_blockers,
    verify_trust_assertion,
)
from john_lomein_factory_receipts import safe_github_repo, safe_instance_slug
from john_lomein_manifest_contract import validate_manifest_contract
from john_lomein_profile_contract import (
    canonical_profile_name,
    canonical_role_profiles,
    validate_profile_env,
)

try:
    import yaml
except Exception:  # pragma: no cover - runtime dependency is deployed by product
    yaml = None

SCHEMA = "john_lomein_learning/v1"
DEFAULT_STEWARD_PROFILE = "john-lomein-learning-steward"
DEFAULT_VISION_FILES = [
    "README.md",
    "docs/README.md",
    "ROADMAP.md",
    "docs/ROADMAP.md",
    "docs/PROJECT.md",
    "docs/project.md",
    "docs/vision.md",
    "package.json",
    "pyproject.toml",
]
DEFAULT_MEMORY_TARGET_ROLES = ["maintainer", "forge", "overwatch", "learning_steward"]
PRIVATE_MEMORY_TARGET_ROLES = ("maintainer", "forge", "overwatch", "learning_steward")
PUBLIC_MEMORY_TARGET_ROLES = {"guide"}
CANONICAL_PUBLIC_PROFILES = {"john-lomein-guide"}
CANDIDATE_NAME_RE = re.compile(r"candidate-[A-Fa-f0-9]{12}\.md")
MAX_EXCERPT_CHARS = 1800
MAX_SUMMARY_CHARS = 2400
NON_CANDIDATE_STATUSES = {"ok", "success", "clean", "clean_idle", "owner_gate", "no_action_needed"}
BLOCKED_STATUSES = {"blocked", "blocked_external", "blocked_checkout", "blocked_implementation"}
JOURNEY_CARD_MARKER = "john-lomein-learning-journey-card/v1"
MEMORY_STATUS_ALLOWLIST = {
    "blocked",
    "blocked_checkout",
    "blocked_external",
    "blocked_implementation",
    "clean",
    "clean_idle",
    "failed",
    "no_action_needed",
    "ok",
    "owner_gate",
    "success",
    "unknown",
}
CONTROLLED_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"


def utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def truncate(text: str, limit: int = MAX_SUMMARY_CHARS) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[: max(0, limit - 20)] + "… [truncated]"


def memory_status_counts(value: Any) -> dict[str, int]:
    """Keep only a small status vocabulary in durable prompt context."""
    counts: dict[str, int] = {}
    for raw_key, raw_count in dict(value or {}).items():
        key = str(raw_key or "unknown").strip().lower()
        if key not in MEMORY_STATUS_ALLOWLIST:
            key = "unknown"
        try:
            count = max(0, int(raw_count))
        except (TypeError, ValueError):
            count = 0
        counts[key] = counts.get(key, 0) + count
    return dict(sorted(counts.items()))


def nonnegative_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def memory_pattern_fingerprints(value: Any) -> list[str]:
    """Represent untrusted pattern labels by stable hashes, never raw prose."""
    fingerprints = {
        hashlib.sha256(str(item).encode("utf-8")).hexdigest()[:16]
        for item in list(value or [])
        if str(item)
    }
    return sorted(fingerprints)[-20:]


def memory_candidate_id(value: Any) -> str:
    candidate = str(value or "").strip().lower()
    if re.fullmatch(r"[a-f0-9]{12}", candidate):
        return candidate
    return hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:12] if candidate else "unknown"


def parse_shell_env(path: Path) -> dict[str, str]:
    vals: dict[str, str] = {}
    if not path.exists():
        return vals
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        try:
            parts = shlex.split(value, posix=True)
            vals[key] = parts[0] if parts else ""
        except Exception:
            vals[key] = value.strip().strip("'").strip('"')
    return vals


def runtime_home_from_script_or_env() -> Path:
    deployed_env = SCRIPT_DIR / "john-lomein-instance.env"
    if deployed_env.exists():
        return SCRIPT_DIR.parent.resolve()
    raw = os.environ.get("BOT_HERMES_HOME") or os.environ.get("HERMES_HOME") or ""
    if not raw:
        raise RuntimeError("learning_steward_missing_runtime_home")
    return Path(raw).expanduser().resolve()


def load_env() -> dict[str, str]:
    home = runtime_home_from_script_or_env()
    env_file = (home / "scripts" / "john-lomein-instance.env").resolve()
    requested_raw = os.environ.get("JOHN_LOMEIN_INSTANCE_ENV")
    if requested_raw and Path(requested_raw).expanduser().resolve() != env_file:
        raise RuntimeError("learning_steward_refuses_non_deployed_instance_env")
    if not env_file.exists():
        raise RuntimeError(f"learning_steward_missing_instance_env:{env_file}")
    vals = parse_shell_env(env_file)
    try:
        validate_profile_env(vals)
        if vals.get("BOT_SLUG"):
            safe_instance_slug(vals["BOT_SLUG"])
        if vals.get("BOT_REPO"):
            safe_github_repo(vals["BOT_REPO"])
    except ValueError as exc:
        raise RuntimeError(f"learning_steward_invalid_deployed_env:{exc}") from exc
    vals["BOT_HERMES_HOME"] = str(home)
    vals["HERMES_HOME"] = str(home)
    mode = vals.get("BOT_MODEL_MEMORY_ISOLATION", "disabled")
    if mode not in {"required", "disabled"}:
        raise RuntimeError("learning_steward_invalid_model_memory_isolation")
    private = home / "private" / "learning-steward"
    projection = home / "state" / "learning"
    if mode == "required":
        if vals.get("BOT_STEWARD_PRIVATE_ROOT") != str(private):
            raise RuntimeError("learning_steward_private_root_not_canonical")
        if vals.get("BOT_STEWARD_PROJECTION_ROOT") != str(projection):
            raise RuntimeError("learning_steward_projection_root_not_canonical")
        vals["MNEMOSYNE_DATA_DIR"] = str(private / "mnemosyne" / "data")
    else:
        vals["MNEMOSYNE_DATA_DIR"] = str(home / "mnemosyne" / "data")
    # Never retain the source manifest path exported at deployment time. The
    # runtime copy is the sole manifest authority for this deployed steward.
    vals["JL_INSTANCE_MANIFEST"] = str(home / "instance.yaml")
    if os.environ.get("JOHN_LOMEIN_TRUST_ASSERTION"):
        vals["JOHN_LOMEIN_TRUST_ASSERTION"] = os.environ["JOHN_LOMEIN_TRUST_ASSERTION"]
    return vals


def load_manifest(env: dict[str, str]) -> dict[str, Any]:
    runtime = deployed_runtime_root(env)
    manifest = runtime / "instance.yaml"
    if not manifest.exists():
        raise RuntimeError(f"learning_steward_missing_deployed_manifest:{manifest}")
    if manifest.is_symlink() or not manifest.is_file():
        raise RuntimeError(f"learning_steward_unsafe_deployed_manifest:{manifest}")
    if yaml is None:
        raise RuntimeError("PyYAML is required to load instance.yaml")
    data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise RuntimeError("learning_steward_invalid_deployed_manifest:expected_mapping")
    try:
        validate_manifest_contract(data)
    except ValueError as exc:
        raise RuntimeError(f"learning_steward_invalid_deployed_manifest:{exc}") from exc
    validated_learning_identity(env, data)
    return data


def deployed_runtime_root(env: dict[str, str]) -> Path:
    raw = str(env.get("BOT_HERMES_HOME") or "").strip()
    if not raw or "\x00" in raw:
        raise RuntimeError("learning_steward_missing_runtime_home")
    return Path(raw).expanduser().resolve()


def model_memory_isolation_required(env: dict[str, str]) -> bool:
    mode = str(env.get("BOT_MODEL_MEMORY_ISOLATION") or "disabled")
    if mode not in {"required", "disabled"}:
        raise RuntimeError("learning_steward_invalid_model_memory_isolation")
    return mode == "required"


def require_path_within(path: Path, root: Path, *, label: str, allow_root: bool = False) -> Path:
    try:
        resolved = path.expanduser().resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise RuntimeError(f"{label}_path_invalid:{exc}") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise RuntimeError(f"{label}_outside_deployed_runtime_boundary:{resolved}") from exc
    if not allow_root and resolved == root:
        raise RuntimeError(f"{label}_must_be_below_boundary_root")
    return resolved


def learning_root(env: dict[str, str]) -> Path:
    runtime = deployed_runtime_root(env)
    state_root = (
        runtime / "private" / "learning-steward"
        if model_memory_isolation_required(env)
        else runtime / "state"
    )
    if state_root.is_symlink():
        raise RuntimeError("learning_state_root_symlink_rejected")
    try:
        state_root.mkdir(parents=True, exist_ok=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise RuntimeError(f"learning_state_parent_unavailable:{exc}") from exc
    require_path_within(state_root, runtime, label="learning_state_parent", allow_root=False)
    raw_root = state_root / "learning"
    if raw_root.is_symlink():
        raise RuntimeError("learning_state_root_symlink_rejected")
    require_path_within(raw_root, runtime, label="learning_state", allow_root=False)
    try:
        raw_root.mkdir(parents=True, exist_ok=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise RuntimeError(f"learning_state_root_unavailable:{exc}") from exc
    root = require_path_within(raw_root, runtime, label="learning_state", allow_root=False)
    if not root.is_dir():
        raise RuntimeError(f"learning_state_root_not_directory:{root}")
    return root


def learning_projection_root(env: dict[str, str]) -> Path:
    """Return the model-readable, steward-written sanitized projection root."""

    runtime = deployed_runtime_root(env)
    raw = runtime / "state" / "learning"
    if raw.is_symlink():
        raise RuntimeError("learning_projection_root_symlink_rejected")
    try:
        raw.mkdir(parents=True, exist_ok=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise RuntimeError(f"learning_projection_root_unavailable:{exc}") from exc
    root = require_path_within(
        raw,
        runtime,
        label="learning_projection",
        allow_root=False,
    )
    if not root.is_dir():
        raise RuntimeError(f"learning_projection_root_not_directory:{root}")
    return root


def resolve_learning_artifact(
    env: dict[str, str],
    raw: Any,
    *,
    default_relative: str,
    label: str,
    directory: bool = False,
) -> Path:
    """Resolve an artifact only inside this deployed runtime's learning state.

    Configured paths retain their existing runtime-relative interpretation, but
    absolute paths, traversal, and symlink escapes are rejected. Returning a
    resolved path also prevents later reads from following a configured leaf
    symlink outside the checked boundary.
    """
    root = learning_root(env)
    runtime = deployed_runtime_root(env)
    text = str(raw or "").strip()
    if "\x00" in text:
        raise RuntimeError(f"{label}_path_invalid:nul")
    if text:
        configured = Path(text).expanduser()
        if model_memory_isolation_required(env):
            if configured.is_absolute():
                raise RuntimeError(
                    f"{label}_outside_deployed_runtime_boundary:{configured}"
                )
            parts = configured.parts
            if len(parts) >= 2 and parts[:2] == ("state", "learning"):
                configured = Path(*parts[2:])
            candidate = root / configured
        else:
            candidate = configured if configured.is_absolute() else runtime / configured
    else:
        candidate = root / default_relative
    resolved = require_path_within(candidate, root, label=label, allow_root=False)
    try:
        if directory:
            resolved.mkdir(parents=True, exist_ok=True)
            if not resolved.is_dir():
                raise RuntimeError(f"{label}_not_directory:{resolved}")
        else:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            if resolved.exists() and not resolved.is_file():
                raise RuntimeError(f"{label}_not_regular_file:{resolved}")
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"{label}_path_unavailable:{exc}") from exc
    return require_path_within(resolved, root, label=label, allow_root=False)


def validated_profile_name(value: Any, *, label: str) -> str:
    try:
        return canonical_profile_name(value, field=label)
    except ValueError as exc:
        raise RuntimeError(f"{label}_unsafe_profile_name") from exc


def learning_config(manifest: dict[str, Any]) -> dict[str, Any]:
    cfg = dict(manifest.get("learning") or {})
    cfg.setdefault("enabled", True)
    cfg.setdefault("steward_profile", DEFAULT_STEWARD_PROFILE)
    cfg.setdefault("memory_target_roles", DEFAULT_MEMORY_TARGET_ROLES)
    cfg.setdefault("candidate_threshold", 2)
    return cfg


def role_profiles(manifest: dict[str, Any]) -> dict[str, str]:
    try:
        return canonical_role_profiles(manifest)
    except ValueError as exc:
        raise RuntimeError(f"learning_profile_contract_invalid:{exc}") from exc


def validated_learning_identity(
    env: dict[str, str],
    manifest: dict[str, Any],
) -> tuple[str, str, dict[str, str]]:
    inst = manifest.get("instance") or {}
    target = manifest.get("target") or {}
    if not isinstance(inst, dict) or not isinstance(target, dict):
        raise RuntimeError("learning_identity_manifest_sections_must_be_mappings")
    profiles = role_profiles(manifest)
    try:
        validate_profile_env(env, expected_profiles=profiles)
        slug = safe_instance_slug(inst.get("slug") or env.get("BOT_SLUG"))
        repo = safe_github_repo(target.get("repo") or env.get("BOT_REPO"))
        if env.get("BOT_SLUG") and safe_instance_slug(env["BOT_SLUG"]) != slug:
            raise ValueError("deployed instance slug does not match runtime manifest")
        if env.get("BOT_REPO") and safe_github_repo(env["BOT_REPO"]) != repo:
            raise ValueError("deployed target repo does not match runtime manifest")
    except ValueError as exc:
        raise RuntimeError(f"learning_identity_invalid:{exc}") from exc
    return slug, repo, profiles


def validated_memory_identity(report: dict[str, Any]) -> tuple[str, str]:
    try:
        slug = safe_instance_slug(report.get("instance") or "unknown")
        repo = safe_github_repo(report.get("target_repo"))
    except ValueError as exc:
        raise RuntimeError(f"learning_memory_identity_invalid:{exc}") from exc
    return slug, repo


def runtime_env(env: dict[str, str]) -> dict[str, str]:
    out = {
        key: value
        for key, value in os.environ.items()
        if key in {"LANG", "LC_ALL", "LC_CTYPE", "TMPDIR"}
    }
    out.update(env)
    H = env["BOT_HERMES_HOME"]
    for key in ("GH_TOKEN", "GITHUB_TOKEN", "GH_CONFIG_DIR", "JOHN_LOMEIN_INSTANCE_ENV", "PYTHONHOME", "PYTHONPATH"):
        out.pop(key, None)
    out.update({"HERMES_HOME": H, "BOT_HERMES_HOME": H, "JOHN_LOMEIN_INSTANCE_HERMES_HOME": H})
    out["MNEMOSYNE_DATA_DIR"] = env.get("MNEMOSYNE_DATA_DIR") or str(Path(H) / "mnemosyne" / "data")
    out["GH_PROMPT_DISABLED"] = "1"
    out["GH_NO_UPDATE_NOTIFIER"] = "1"
    out["GH_NO_EXTENSION_UPDATE_NOTIFIER"] = "1"
    out["PATH"] = f"{Path(sys.executable).resolve().parent}:{CONTROLLED_PATH}"
    profile = env.get("BOT_MAINTAINER_PROFILE") or "john-lomein-maintainer"
    profile_home = Path(H) / "profiles" / profile / "home"
    gh_config = profile_home / ".config" / "gh"
    if profile_home.exists():
        out["HOME"] = str(profile_home)
    if gh_config.exists():
        out["GH_CONFIG_DIR"] = str(gh_config)
    return out


def ensure_mnemosyne_import_path(env: dict[str, str]) -> None:
    """Make instance-linked Mnemosyne importable even under system Python.

    Cron and LaunchAgent jobs can otherwise execute this script with macOS
    system Python. The runtime already links the Hermes Mnemosyne provider under
    ``plugins/mnemosyne``; its repo root is the import root for ``mnemosyne``.
    """
    candidates = [
        Path(env.get("BOT_HERMES_HOME", "")) / "plugins" / "mnemosyne",
        Path(env.get("HERMES_HOME", "")) / "plugins" / "mnemosyne",
        Path.home() / "mnemosyne" / "hermes_memory_provider",
    ]
    for candidate in candidates:
        try:
            real = candidate.expanduser().resolve()
        except Exception:
            continue
        for root in (real.parent.parent, real.parent):
            if (root / "mnemosyne").exists() and str(root) not in sys.path:
                sys.path.insert(0, str(root))


def run(cmd: list[str], *, cwd: str | Path | None = None, env: dict[str, str] | None = None, timeout: int = 45) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {"cmd": cmd, "exit_code": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr.strip()}
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        return {"cmd": cmd, "exit_code": 999, "stdout": "", "stderr": str(exc)}


def read_json_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def atomic_write_json(path: Path, data: Any) -> None:
    atomic_write(path, json.dumps(data, indent=2, sort_keys=True) + "\n")


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")


def observations_path(env: dict[str, str], manifest: dict[str, Any]) -> Path:
    cfg = learning_config(manifest)
    return resolve_learning_artifact(
        env,
        cfg.get("observations_path"),
        default_relative="observations.jsonl",
        label="learning_observations",
    )


def brief_path(env: dict[str, str], manifest: dict[str, Any]) -> Path:
    cfg = learning_config(manifest)
    if model_memory_isolation_required(env):
        raw = str(
            cfg.get("generated_operating_brief")
            or "state/learning/current-operating-brief.md"
        ).strip()
        configured = Path(raw)
        if (
            configured.is_absolute()
            or len(configured.parts) < 3
            or configured.parts[:2] != ("state", "learning")
        ):
            raise RuntimeError(
                "learning_operating_brief_outside_projection_boundary"
            )
        root = learning_projection_root(env)
        candidate = root / Path(*configured.parts[2:])
        return require_path_within(
            candidate,
            root,
            label="learning_operating_brief",
            allow_root=False,
        )
    return resolve_learning_artifact(
        env,
        cfg.get("generated_operating_brief"),
        default_relative="current-operating-brief.md",
        label="learning_operating_brief",
    )


def candidate_dir(env: dict[str, str], manifest: dict[str, Any]) -> Path:
    cfg = learning_config(manifest)
    return resolve_learning_artifact(
        env,
        cfg.get("candidate_improvements_dir"),
        default_relative="candidate-improvements",
        label="learning_candidate_directory",
        directory=True,
    )


def recent_observations(path: Path, limit: int = 80) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines()[-limit:]:
        try:
            rows.append(json.loads(raw))
        except Exception:
            continue
    return rows


def safe_repo_file(local: Path, rel: str) -> Path | None:
    rel = str(rel).strip()
    if not rel or rel.startswith("~") or rel.startswith("/"):
        return None
    p = (local / rel).resolve()
    try:
        p.relative_to(local.resolve())
    except Exception:
        return None
    return p


def configured_vision_files(manifest: dict[str, Any]) -> list[str]:
    sources = (learning_config(manifest).get("sources") or {})
    vals = sources.get("vision_files") or DEFAULT_VISION_FILES
    return [str(x) for x in vals]


def read_excerpt(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""
    if path.name == "package.json":
        try:
            data = json.loads(text)
            compact = {k: data.get(k) for k in ("name", "description", "version", "type") if data.get(k)}
            if compact:
                text = json.dumps(compact, indent=2, sort_keys=True)
        except Exception:
            pass
    headings = [line.strip() for line in text.splitlines() if line.strip().startswith("#")]
    non_empty = [line.rstrip() for line in text.splitlines() if line.strip()]
    excerpt = "\n".join((headings[:12] or non_empty[:36]))
    return truncate(excerpt, MAX_EXCERPT_CHARS)


def collect_vision_sources(env: dict[str, str], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    local = Path(env.get("BOT_LOCAL") or "").expanduser()
    results: list[dict[str, Any]] = []
    if not local.exists():
        return results
    for rel in configured_vision_files(manifest):
        matches: list[Path] = []
        if any(ch in rel for ch in "*?["):
            matches = sorted(p for p in local.glob(rel) if p.is_file())[:8]
        else:
            p = safe_repo_file(local, rel)
            if p and p.exists() and p.is_file():
                matches = [p]
        for p in matches:
            try:
                rp = str(p.resolve().relative_to(local.resolve()))
            except Exception:
                continue
            excerpt = read_excerpt(p)
            if excerpt:
                results.append({"path": rp, "chars": len(excerpt), "excerpt": excerpt})
    return results


def collect_dynamic_state(env: dict[str, str], manifest: dict[str, Any]) -> dict[str, Any]:
    renv = runtime_env(env)
    local = Path(env.get("BOT_LOCAL") or "").expanduser()
    H = Path(env["BOT_HERMES_HOME"])
    state: dict[str, Any] = {"source_boundary": "repo/GitHub/Kanban/runtime state remain canonical; this is a derived snapshot"}
    if local.exists():
        status = run(["git", "status", "--short", "--branch"], cwd=local, env=renv, timeout=20)
        head = run(["git", "rev-parse", "--short", "HEAD"], cwd=local, env=renv, timeout=15)
        state["git"] = {"status_exit": status["exit_code"], "status": truncate(status["stdout"], 1200), "head": head["stdout"] if head["exit_code"] == 0 else ""}
    else:
        state["git"] = {"missing_checkout": str(local)}

    queue_script = H / "scripts" / "john-lomein-queue-health.py"
    if queue_script.exists():
        q = run([sys.executable, str(queue_script), "--json"], env=renv, timeout=120)
        try:
            state["queue_health"] = json.loads(q["stdout"] or "{}") if q["exit_code"] in (0, 1) else {"exit_code": q["exit_code"], "error": q["stderr"] or q["stdout"]}
        except Exception:
            state["queue_health"] = {"exit_code": q["exit_code"], "raw": truncate(q["stdout"] or q["stderr"], 1200)}

    worker_script = H / "scripts" / "john-lomein-worker.py"
    if worker_script.exists():
        w = run([sys.executable, str(worker_script), "status"], env=renv, timeout=45)
        try:
            state["workers"] = json.loads(w["stdout"] or "[]") if w["exit_code"] == 0 else {"exit_code": w["exit_code"], "error": w["stderr"] or w["stdout"]}
        except Exception:
            state["workers"] = {"exit_code": w["exit_code"], "raw": truncate(w["stdout"] or w["stderr"], 1000)}

    repo = env.get("BOT_REPO") or ((manifest.get("target") or {}).get("repo"))
    if repo:
        pr = run(["gh", "pr", "list", "--repo", repo, "--state", "open", "--limit", "12", "--json", "number,title,state,isDraft,headRefName,updatedAt,url"], env=renv, timeout=45)
        issues = run(["gh", "issue", "list", "--repo", repo, "--state", "open", "--limit", "12", "--json", "number,title,state,labels,updatedAt,url"], env=renv, timeout=45)
        for key, result in [("open_prs", pr), ("open_issues", issues)]:
            if result["exit_code"] == 0:
                try:
                    state[key] = json.loads(result["stdout"] or "[]")
                except Exception:
                    state[key] = {"raw": truncate(result["stdout"], 1200)}
            else:
                state[key] = {"exit_code": result["exit_code"], "error": truncate(result["stderr"] or result["stdout"], 1200)}
    return state


def count_statuses(observations: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for obs in observations:
        status, _ = normalized_observation_signal(obs)
        counts[status] = counts.get(status, 0) + 1
    return counts


def normalized_observation_signal(obs: dict[str, Any]) -> tuple[str, str]:
    role = str(obs.get("role") or "unknown")
    raw_status = str(obs.get("status") or "unknown").lower()
    raw_pattern = str(obs.get("pattern_key") or "")
    summary = str(obs.get("summary") or "")
    classified_status, classified_pattern = classify_worker_output(role, raw_status, summary)
    generic = f"{role}:post_flight:{raw_status}"
    if classified_pattern != generic:
        return classified_status, classified_pattern
    if raw_pattern:
        return raw_status, raw_pattern
    return raw_status, generic


def is_candidate_status(status: str) -> bool:
    return str(status or "unknown").lower() not in NON_CANDIDATE_STATUSES


def learning_target_profiles(manifest: dict[str, Any]) -> list[str]:
    cfg = learning_config(manifest)
    profiles = role_profiles(manifest)
    public_profiles = {
        validated_profile_name(profiles["guide"], label="learning_public_guide"),
        *CANONICAL_PUBLIC_PROFILES,
    }
    private_by_role: dict[str, str] = {}
    for role in PRIVATE_MEMORY_TARGET_ROLES:
        profile = validated_profile_name(profiles[role], label=f"learning_private_{role}")
        if profile in public_profiles:
            raise RuntimeError(f"learning_private_role_uses_public_profile:{role}:{profile}")
        private_by_role[role] = profile
    configured_targets = cfg.get("memory_target_roles", DEFAULT_MEMORY_TARGET_ROLES)
    if not isinstance(configured_targets, list):
        raise RuntimeError("learning_memory_target_roles_must_be_list")
    targets: list[str] = []
    for raw_target in configured_targets:
        target = str(raw_target or "").strip()
        if target in PUBLIC_MEMORY_TARGET_ROLES or target in public_profiles:
            continue
        if target in private_by_role:
            profile = private_by_role[target]
        elif target in private_by_role.values():
            profile = target
        else:
            raise RuntimeError(f"learning_memory_target_not_private:{target!r}")
        if profile not in targets:
            targets.append(profile)
    steward_profile = private_by_role["learning_steward"]
    if steward_profile not in targets:
        targets.append(steward_profile)
    return targets


def build_operating_brief(env: dict[str, str], manifest: dict[str, Any], *, mode: str) -> tuple[str, dict[str, Any]]:
    inst = manifest.get("instance") or {}
    obs = recent_observations(observations_path(env, manifest))
    vision = collect_vision_sources(env, manifest)
    dynamic = collect_dynamic_state(env, manifest)
    generated_at = utc()
    display = inst.get("display_name") or env.get("BOT_DISPLAY_NAME") or inst.get("slug") or env.get("BOT_SLUG") or "unknown"
    slug, repo, _ = validated_learning_identity(env, manifest)
    source_files = configured_vision_files(manifest)
    mission_statement = str(((manifest.get("mission") or {}).get("statement") or "")).strip()
    memory_targets = learning_target_profiles(manifest)

    lines = [
        f"# John Lomein Operating Brief — {display}",
        "",
        "> Generated by `john-lomein-learning-steward`. This is a derived, non-canonical operating brief.",
        "> Canonical project vision/state remains in repo docs, GitHub, Kanban, and runtime state files.",
        "",
        f"- schema: `{SCHEMA}`",
        f"- generated_at: `{generated_at}`",
        f"- mode: `{mode}`",
        f"- instance: `{slug}`",
        f"- target_repo: `{repo}`",
        f"- managed_checkout: `{env.get('BOT_LOCAL','')}`",
        f"- memory_target_profiles: `{', '.join(memory_targets)}`",
        "",
        "## Source bundle",
    ]
    for rel in source_files:
        lines.append(f"- `{rel}`")
    lines.extend(["", "## Project vision source excerpts"])
    if vision:
        for item in vision:
            lines.extend(["", f"### `{item['path']}`", "", item["excerpt"]])
    else:
        lines.append("- No configured vision source files were readable from the managed checkout.")
    lines.extend(["", "## Dynamic state snapshot", "", "```json", json.dumps(dynamic, indent=2, sort_keys=True)[:6000], "```", "", "## Recent learning observations"])
    if obs:
        lines.append(f"- recent_observation_count: `{len(obs)}`")
        lines.append(f"- status_counts: `{json.dumps(count_statuses(obs), sort_keys=True)}`")
        for item in obs[-8:]:
            lines.append(f"- `{item.get('observed_at','')}` role=`{item.get('role','')}` event=`{item.get('event','')}` status=`{item.get('status','')}` summary={truncate(str(item.get('summary','')), 220)!r}")
    else:
        lines.append("- No post-flight observations recorded yet.")
    lines.extend([
        "",
        "## Learning boundary",
        "",
        "- Operational roles emit observations; they do not directly mutate their own identity/workflows.",
        "- The steward writes profile-native memory and generated brief artifacts.",
        "- Recursive skill/workflow changes remain quarantined candidate artifacts until a review gate accepts them.",
    ])
    brief = "\n".join(lines).rstrip() + "\n"
    report = {
        "schema_version": SCHEMA,
        "generated_at": generated_at,
        "mode": mode,
        "instance": slug,
        "display_name": display,
        "target_repo": repo,
        "mission_statement": truncate(mission_statement, 500),
        "configured_source_files": source_files,
        "vision_sources_read": [v["path"] for v in vision],
        "dynamic_state_keys": sorted(dynamic.keys()),
        "observation_count": len(obs),
        "status_counts": count_statuses(obs),
        "recent_pattern_keys": sorted({normalized_observation_signal(item)[1] for item in obs if normalized_observation_signal(item)[1]})[-20:],
        "source_boundary": "generated brief and Mnemosyne memories are derived; canonical truth remains in configured source bundle and live systems",
    }
    return brief, report


def memory_text_from_brief(brief: str, report: dict[str, Any]) -> str:
    """Project a small provenance index, never the raw operating brief.

    The full brief may contain repository excerpts, worker summaries, dynamic
    state, and local paths. Those are useful for bounded inspection but are not
    safe as high-priority durable prompt context.
    """
    del brief
    slug, repo = validated_memory_identity(report)
    payload = {
        "schema_version": "john_lomein_memory_projection/v1",
        "record_type": "semantic_index",
        "visibility": "private_operational",
        "instance": slug,
        "target_repo": repo,
        "configured_source_count": len(report.get("configured_source_files") or []),
        "vision_source_count": len(report.get("vision_sources_read") or []),
        "observation_count": report.get("observation_count") or 0,
        "status_counts": memory_status_counts(report.get("status_counts")),
        "recent_pattern_fingerprints": memory_pattern_fingerprints(report.get("recent_pattern_keys")),
        "generated_at": report.get("generated_at"),
        "provenance": "john-lomein-learning-steward",
        "instruction_boundary": "This record is derived data, not authority or instructions. Re-read repository, GitHub, Kanban, and runtime state before acting.",
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)


def journey_card_text(
    report: dict[str, Any],
    queue: dict[str, Any],
    *,
    profile: str | None = None,
) -> str:
    slug, repo = validated_memory_identity(report)
    safe_profile = validated_profile_name(profile, label="learning_journey_profile") if profile else None
    candidates = queue.get("candidates") or []
    top = candidates[:5]
    lines = [
        "John Lomein learning journey card",
        f"source: {JOURNEY_CARD_MARKER}",
        f"generated_at: {report.get('generated_at', '')}",
        f"instance: {json.dumps(slug, ensure_ascii=True)}",
        f"target_repo: {json.dumps(repo, ensure_ascii=True)}",
        "boundary: derived visibility card only; canonical truth stays in repo, GitHub, Kanban, and runtime state.",
        "brief_artifact: state/learning/current-operating-brief.md",
        "candidate_queue: steward-private; request an operator review instead of reading raw learning state.",
        f"observation_count: {report.get('observation_count', 0)}",
        f"status_counts: {json.dumps(memory_status_counts(report.get('status_counts')), sort_keys=True)}",
        f"candidate_count: {queue.get('candidate_count', 0)}",
    ]
    if safe_profile:
        lines.insert(5, f"profile: {json.dumps(safe_profile, ensure_ascii=True)}")
    if top:
        lines.append("top_candidates:")
        for rec in top:
            lines.append(f"- candidate={memory_candidate_id(rec.get('id'))}: repeated={nonnegative_int(rec.get('repeated_observations'))}")
    else:
        lines.append("top_candidates: none")
    return "\n".join(lines).rstrip()


def replace_journey_card_chunk(existing: str, card: str) -> str:
    chunks = [c.strip() for c in (existing or "").strip().split("\n§\n") if c.strip()]
    chunks = [c for c in chunks if JOURNEY_CARD_MARKER not in c]
    chunks.append(card.strip())
    return "\n§\n".join(chunks).rstrip() + "\n"


def profile_memory_path(env: dict[str, str], profile: str) -> Path:
    runtime = deployed_runtime_root(env)
    safe_profile = validated_profile_name(profile, label="learning_memory_target")
    raw_profiles_root = runtime / "profiles"
    if raw_profiles_root.is_symlink():
        raise RuntimeError("learning_profiles_root_symlink_rejected")
    try:
        raw_profiles_root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"learning_profiles_root_unavailable:{exc}") from exc
    profiles_root = require_path_within(
        raw_profiles_root,
        runtime,
        label="learning_profiles_root",
        allow_root=False,
    )
    raw_profile_root = profiles_root / safe_profile
    if raw_profile_root.is_symlink():
        raise RuntimeError(f"learning_profile_symlink_rejected:{safe_profile}")
    profile_root = require_path_within(
        raw_profile_root,
        profiles_root,
        label="learning_profile",
        allow_root=False,
    )
    raw_memories = raw_profile_root / "memories"
    if raw_memories.is_symlink():
        raise RuntimeError(f"learning_profile_memories_symlink_rejected:{safe_profile}")
    try:
        raw_memories.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"learning_profile_memories_unavailable:{safe_profile}:{exc}") from exc
    memories = require_path_within(
        raw_memories,
        profile_root,
        label="learning_profile_memories",
        allow_root=False,
    )
    raw_memory = raw_memories / "MEMORY.md"
    if raw_memory.is_symlink():
        raise RuntimeError(f"learning_profile_memory_symlink_rejected:{safe_profile}")
    return require_path_within(
        raw_memory,
        memories,
        label="learning_profile_memory",
        allow_root=False,
    )


def write_profile_journey_cards(env: dict[str, str], manifest: dict[str, Any], report: dict[str, Any], queue: dict[str, Any]) -> dict[str, str]:
    written: dict[str, str] = {}
    for profile in learning_target_profiles(manifest):
        card = journey_card_text(report, queue, profile=profile)
        path = profile_memory_path(env, profile)
        existing = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
        atomic_write(path, replace_journey_card_chunk(existing, card))
        written[profile] = str(path)
    return written


def sanitize_bank_name(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_-]", "_", str(name or "")).strip("_-")
    if not sanitized or not sanitized[0].isalnum():
        sanitized = "b_" + sanitized if sanitized else "default"
    if len(sanitized) > 64:
        sanitized = sanitized[:64].rstrip("_-")
    if ".." in sanitized or "/" in sanitized:
        return "default"
    return sanitized or "default"


def upsert_profile_memories(env: dict[str, str], manifest: dict[str, Any], memory_text: str, report: dict[str, Any]) -> dict[str, Any]:
    os.environ["MNEMOSYNE_DATA_DIR"] = env.get("MNEMOSYNE_DATA_DIR") or str(Path(env["BOT_HERMES_HOME"]) / "mnemosyne" / "data")
    ensure_mnemosyne_import_path(env)
    from mnemosyne import Mnemosyne  # imported lazily so doctor can report dependency failures

    cfg = learning_config(manifest)
    profiles = role_profiles(manifest)
    targets = learning_target_profiles(manifest)
    safe_slug, safe_repo = validated_memory_identity(report)

    root = learning_root(env)
    index_path = root / "memory-index.json"
    index = read_json_file(index_path, {})
    source = "john-lomein-learning:operating-brief"
    results: dict[str, Any] = {}
    for profile in targets:
        bank = sanitize_bank_name(profile)
        mem = Mnemosyne(
            session_id="john_lomein_learning",
            bank=bank,
            author_id=profiles["learning_steward"],
            author_type="agent",
            channel_id="john_lomein_learning",
        )
        key = f"{profile}:operating_brief"
        memory_id = (index.get(key) or {}).get("memory_id")
        updated = False
        if memory_id:
            try:
                updated = bool(mem.update(memory_id, content=memory_text, importance=0.62))
            except Exception:
                updated = False
        if not updated:
            memory_id = mem.remember(
                memory_text,
                source=source,
                importance=0.62,
                # Mnemosyne currently supports session/global. The bank is
                # already isolated per profile and instance, so global means
                # durable within that private bank rather than cross-profile.
                scope="global",
                metadata={
                    "schema_version": SCHEMA,
                    "instance": safe_slug,
                    "target_repo": safe_repo,
                    "generated_at": report.get("generated_at"),
                    "source_boundary": report.get("source_boundary"),
                    "write_authority": "john-lomein-learning-steward",
                },
                extract_entities=False,
                extract=False,
                trust_tier="DERIVED",
            )
        got = mem.get(memory_id) if memory_id else None
        recall = mem.recall(f"{report.get('display_name')} {safe_repo} operating brief project vision", top_k=5, source=source)
        recall_hit = any((r.get("id") or r.get("memory_id")) == memory_id for r in recall)
        index[key] = {"memory_id": memory_id, "profile": profile, "bank": bank, "updated_at": report.get("generated_at"), "source": source}
        results[profile] = {"bank": bank, "memory_id": memory_id, "get_ok": bool(got), "recall_hit": bool(recall_hit), "recall_count": len(recall)}
    atomic_write_json(index_path, index)
    return results


def candidate_id_for_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def suggested_targets_for_key(key: str) -> list[str]:
    text = key.lower()
    targets: list[str] = []
    if text.startswith("maintainer:"):
        targets.append("skills/john-lomein-maintainer/SKILL.md")
    if text.startswith("forge:"):
        targets.append("skills/john-lomein-forge/SKILL.md")
    if text.startswith("overwatch:"):
        targets.append("skills/john-lomein-overwatch/SKILL.md")
    if "learning" in text or not targets:
        targets.append("skills/john-lomein-learning-steward/SKILL.md")
    if any(token in text for token in ("checkout", "dirty", "blocked", "failed", "crashed", "implementation")):
        targets.append("docs/productization/new-maintainer-appliance-runbook.md")
    out: list[str] = []
    for target in targets:
        if target not in out:
            out.append(target)
    return out


def proposal_starter_for_key(key: str, rows: list[dict[str, Any]]) -> list[str]:
    text = key.lower()
    role = str((rows[-1].get("role") if rows else "") or key.split(":", 1)[0] or "role")
    lines = [
        f"- Add a narrowly scoped note for `{key}` rather than a broad rewrite.",
        "- Preserve source-of-truth boundaries: repo/GitHub/runtime state stay canonical; memory/candidates stay derived.",
        "- Include a regression/doctor/smoke check that would catch this pattern next time.",
    ]
    if "checkout" in text or "dirty" in text:
        lines.append("- Document how the role must handle dirty or interrupted managed checkouts before mutating branches.")
    if "implementation" in text or "blocked" in text:
        lines.append("- Document how the role should distinguish implementation blockers from successful no-op/owner-gate states.")
    if "failed" in text or "crashed" in text:
        lines.append(f"- Add exact failure triage for `{role}` post-flight output, including source log pointers.")
    return lines


def write_candidate_improvements(env: dict[str, str], manifest: dict[str, Any], observations: list[dict[str, Any]]) -> list[str]:
    threshold = int(learning_config(manifest).get("candidate_threshold") or 2)
    buckets: dict[str, list[dict[str, Any]]] = {}
    for obs in observations:
        status, key = normalized_observation_signal(obs)
        status = status.lower()
        if not is_candidate_status(status):
            continue
        row = dict(obs)
        row["normalized_status"] = status
        row["normalized_pattern_key"] = key
        buckets.setdefault(key, []).append(row)
    written: list[str] = []
    active_paths: set[Path] = set()
    cdir = candidate_dir(env, manifest)
    for key, rows in sorted(buckets.items()):
        if len(rows) < threshold:
            continue
        digest = candidate_id_for_key(key)
        path = cdir / f"candidate-{digest}.md"
        targets = suggested_targets_for_key(key)
        lines = [
            f"# Candidate learning improvement: `{key}`",
            "",
            "Status: candidate_review_required",
            f"Candidate-ID: `{digest}`",
            f"Source-pattern: `{key}`",
            "",
            "This artifact is quarantined. It is not an applied skill/workflow patch.",
            "",
            f"- repeated_observations: `{len(rows)}`",
            f"- generated_at: `{utc()}`",
            "",
            "## Suggested promotion targets",
            "",
        ]
        lines.extend(f"- `{target}`" for target in targets)
        lines.extend(["", "## Proposal starter", ""])
        lines.extend(proposal_starter_for_key(key, rows))
        lines.extend(["", "## Evidence"])
        for row in rows[-10:]:
            source_refs = row.get("source_refs") or []
            ref_text = ", ".join(f"`{ref}`" for ref in source_refs[:3]) if isinstance(source_refs, list) else ""
            lines.append(
                f"- `{row.get('observed_at','')}` role=`{row.get('role','')}` event=`{row.get('event','')}` "
                f"status=`{row.get('normalized_status') or row.get('status','')}` raw_status=`{row.get('status','')}` summary={truncate(str(row.get('summary','')), 260)!r}"
                + (f" refs={ref_text}" if ref_text else "")
            )
        lines.extend([
            "",
            "## Review gate",
            "",
            "A human or explicit review workflow must decide whether this becomes a product skill/doc patch.",
            "Suggested deterministic path:",
            "",
            "1. Run `review-candidates` to refresh the queue.",
            "2. Run `prepare-promotion` with a concrete product target and proposal text.",
            "3. Apply only with the exact generated approval phrase via `apply-promotion`.",
        ])
        atomic_write(path, "\n".join(lines).rstrip() + "\n")
        active_paths.add(path)
        written.append(str(path))
    for stale in sorted(cdir.glob("candidate-*.md")):
        if stale in active_paths:
            continue
        try:
            if stale.is_symlink():
                stale.unlink()
                continue
            confined_candidate_path(env, manifest, stale)
            text = stale.read_text(encoding="utf-8", errors="ignore")
            if "This artifact is quarantined. It is not an applied skill/workflow patch." in text:
                stale.unlink()
        except OSError:
            pass
    return written


def classify_worker_output(lane: str, process_status: str, output: str) -> tuple[str, str]:
    text = (output or "").lower()
    compact = re.sub(r"[^a-z0-9#]+", " ", text)
    if "john_lomein_implement_status: blocked" in text or "implement_status\": \"blocked" in text:
        return "blocked_implementation", f"{lane}:blocked_implementation"
    if "john_lomein_implement_status: failed" in text or "implement_status\": \"failed" in text:
        return "failed", f"{lane}:implementation:failed"
    if any(token in text for token in ("clean_owner_gate", "owner gate", "owner-gated", "owner_gated", "owner approval", "approval required", "human gate", "needs owner")):
        return "owner_gate", f"{lane}:owner_gate"
    if any(token in text for token in ("no safe mutation", "no safe repo/github mutation", "no safe maintainer mutation", "nothing to move", "nothing to mutate", "no movement needed", "no repo movement", "no pr movement needed", "no prs to move", "no open prs to maintain", "zero open prs to maintain", "steady-state quiescent", "clean no-op", "no-op clean")):
        return "no_action_needed", f"{lane}:no_action_needed"
    if any(token in text for token in ("queue is clean", "queue clean", "clean idle", "idle clean")) or (process_status in {"ok", "success", "clean"} and "empty bundle" in text and "blockers=0" in text):
        return "clean_idle", f"{lane}:clean_idle"
    if any(token in text for token in ("recovery blocker", "managed checkout dirty", "dirty checkout")) or ("interrupted" in text and "checkout" in text):
        return "blocked_checkout", f"{lane}:blocked_checkout"
    if "exhausted_in_cycle_revisions" in text or "deferred status=revise" in text or ("ship gate" in text and "revise" in text):
        return "blocked_implementation", f"{lane}:ship_gate_revise_blocker"
    if any(token in text for token in ("rate limit", "permission denied", "authentication failed", "auth failed", "github unavailable", "network error", "dependency blocked", "blocked by #")) or "blocked by" in compact:
        return "blocked_external", f"{lane}:blocked_external"
    if process_status not in {"ok", "success", "clean"}:
        return process_status, f"{lane}:post_flight:{process_status}"
    return process_status, f"{lane}:post_flight:{process_status}"


def parse_candidate_file(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    cid = path.stem.replace("candidate-", "", 1)
    title = ""
    pattern = ""
    status = "unknown"
    repeated = 0
    targets: list[str] = []
    in_targets = False
    for line in text.splitlines():
        if line.startswith("## "):
            in_targets = line.strip() == "## Suggested promotion targets"
        if line.startswith("# Candidate learning improvement:"):
            title = line.lstrip("# ").strip()
            m = re.search(r"`([^`]+)`", line)
            if m:
                pattern = m.group(1)
        elif line.startswith("Status:"):
            status = line.split(":", 1)[1].strip()
        elif line.startswith("Candidate-ID:"):
            m = re.search(r"`([^`]+)`", line)
            if m:
                cid = m.group(1)
        elif line.startswith("- repeated_observations:"):
            m = re.search(r"`(\d+)`", line)
            if m:
                repeated = int(m.group(1))
        elif in_targets and line.startswith("- `") and line.endswith("`") and ("/" in line):
            targets.append(line.strip()[3:-1])
    return {"id": cid, "path": str(path), "title": title, "pattern_key": pattern, "status": status, "repeated_observations": repeated, "suggested_targets": targets, "text": text}


def confined_candidate_path(
    env: dict[str, str],
    manifest: dict[str, Any],
    path: str | Path,
    *,
    expected_id: str = "",
) -> Path:
    root = candidate_dir(env, manifest).resolve()
    raw = Path(path).expanduser()
    candidate = raw if raw.is_absolute() else root / raw
    if candidate.is_symlink():
        raise RuntimeError(f"learning_candidate_symlink_rejected:{candidate.name}")
    resolved = require_path_within(
        candidate,
        root,
        label="learning_candidate",
        allow_root=False,
    )
    if not CANDIDATE_NAME_RE.fullmatch(resolved.name):
        raise RuntimeError(f"learning_candidate_name_invalid:{resolved.name}")
    if expected_id and resolved.stem.removeprefix("candidate-").lower() != str(expected_id).lower():
        raise RuntimeError("learning_candidate_id_path_mismatch")
    if not resolved.exists() or not resolved.is_file():
        raise RuntimeError(f"learning_candidate_not_regular_file:{resolved}")
    return resolved


def candidate_records(env: dict[str, str], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    cdir = candidate_dir(env, manifest)
    return [
        parse_candidate_file(confined_candidate_path(env, manifest, p))
        for p in sorted(cdir.glob("candidate-*.md"))
    ]


def write_candidate_review_queue(env: dict[str, str], manifest: dict[str, Any], records: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    records = records if records is not None else candidate_records(env, manifest)
    root = learning_root(env)
    queue = {
        "schema_version": "john_lomein_learning_review_queue/v1",
        "generated_at": utc(),
        "candidate_count": len(records),
        "candidates": [{k: v for k, v in rec.items() if k != "text"} for rec in records],
        "boundary": "review queue only; no product skill/doc patch has been applied",
    }
    atomic_write_json(root / "candidate-review-queue.json", queue)
    lines = [
        "# John Lomein learning candidate review queue",
        "",
        f"Generated: `{queue['generated_at']}`",
        "",
        "Boundary: this queue is review metadata only. It is not an applied skill/doc patch.",
        "",
    ]
    if not records:
        lines.append("No candidate improvements currently meet the configured threshold.")
    for rec in records:
        lines.extend([
            f"## Candidate `{rec['id']}`",
            "",
            f"- status: `{rec['status']}`",
            f"- pattern: `{rec['pattern_key']}`",
            f"- repeated_observations: `{rec['repeated_observations']}`",
            f"- artifact: `{rec['path']}`",
            "- suggested_targets:",
        ])
        lines.extend(f"  - `{target}`" for target in rec.get("suggested_targets") or [])
        lines.extend([
            "",
            "Next: write a concrete proposal, then run `prepare-promotion`; apply requires the exact generated approval phrase.",
            "",
        ])
    atomic_write(root / "candidate-review-queue.md", "\n".join(lines).rstrip() + "\n")
    return queue


def find_candidate(env: dict[str, str], manifest: dict[str, Any], candidate: str) -> dict[str, Any]:
    raw = Path(candidate).expanduser()
    if raw.exists():
        try:
            resolved = confined_candidate_path(env, manifest, raw)
        except RuntimeError as exc:
            raise SystemExit(str(exc)) from exc
        return parse_candidate_file(resolved)
    wanted = candidate.replace("candidate-", "").replace(".md", "")
    for rec in candidate_records(env, manifest):
        if rec["id"] == wanted:
            return rec
    raise SystemExit(f"candidate not found: {candidate}")


def product_root_from_args(args: argparse.Namespace, env: dict[str, str]) -> Path:
    raw = env.get("BOT_PRODUCT_ROOT") or getattr(args, "product_root", "") or env.get("JOHN_LOMEIN_PRODUCT_ROOT") or os.environ.get("JOHN_LOMEIN_PRODUCT_ROOT") or "."
    return Path(str(raw)).expanduser().resolve()


def validate_product_target(product_root: Path, target: str) -> Path:
    if not target or target.startswith("/") or target.startswith("~") or "\x00" in target:
        raise SystemExit("target must be a relative product docs/skills path")
    rel = Path(target)
    if any(part in {"..", ""} for part in rel.parts):
        raise SystemExit("target must not contain parent traversal")
    allowed = target == "README.md" or target.startswith("docs/") and target.endswith(".md") or target.startswith("skills/") and target.endswith("/SKILL.md")
    if not allowed:
        raise SystemExit("target must be README.md, docs/**/*.md, or skills/*/SKILL.md")
    path = (product_root / rel).resolve()
    try:
        path.relative_to(product_root)
    except Exception:
        raise SystemExit("target escapes product root")
    return path


def promotion_root(env: dict[str, str]) -> Path:
    return resolve_learning_artifact(
        env,
        None,
        default_relative="promotion-requests",
        label="learning_promotion_directory",
        directory=True,
    )


def request_path(env: dict[str, str], request: str) -> Path:
    root = promotion_root(env).resolve()
    raw = Path(request).expanduser()
    if raw.is_absolute():
        candidate = raw.resolve()
    else:
        rid = request.replace("promotion-", "").replace(".json", "")
        candidate = (root / f"promotion-{rid}.json").resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise SystemExit("promotion request must be inside the instance promotion-request directory")
    if not re.fullmatch(r"promotion-[A-Fa-f0-9]{12}\.json", candidate.name):
        raise SystemExit("promotion request name is invalid")
    return candidate


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes() if path.exists() else b"").hexdigest()


def promotion_request_digest(data: dict[str, Any]) -> str:
    bound = {
        "candidate_id": data.get("candidate_id"),
        "candidate_path": data.get("candidate_path"),
        "candidate_sha256": data.get("candidate_sha256"),
        "target": data.get("target"),
        "target_base_sha256": data.get("target_base_sha256"),
        "title": data.get("title"),
        "proposal_sha256": data.get("proposal_sha256"),
    }
    return hashlib.sha256(json.dumps(bound, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def read_proposal(args: argparse.Namespace) -> str:
    if getattr(args, "proposal_file", ""):
        return Path(args.proposal_file).expanduser().read_text(encoding="utf-8")
    return getattr(args, "proposal_text", "") or ""


def review_candidates(args: argparse.Namespace) -> int:
    env = load_env()
    manifest = load_manifest(env)
    queue = write_candidate_review_queue(env, manifest)
    if args.json:
        print(json.dumps(queue, indent=2, sort_keys=True))
    else:
        print(str(learning_root(env) / "candidate-review-queue.md"))
    return 0


def prepare_promotion(args: argparse.Namespace) -> int:
    env = load_env()
    manifest = load_manifest(env)
    rec = find_candidate(env, manifest, args.candidate)
    product_root = product_root_from_args(args, env)
    target_path = validate_product_target(product_root, args.target)
    proposal = truncate(read_proposal(args), 8000)
    if not proposal.strip():
        raise SystemExit("proposal text is required")
    title = args.title or f"Learning promotion for {rec['pattern_key'] or rec['id']}"
    candidate_path = Path(rec["path"]).resolve()
    candidate_sha256 = sha256_file(candidate_path)
    target_base_sha256 = sha256_file(target_path)
    proposal_sha256 = hashlib.sha256(proposal.encode("utf-8")).hexdigest()
    seed = json.dumps(
        {
            "candidate": rec["id"],
            "candidate_path": str(candidate_path),
            "candidate_sha256": candidate_sha256,
            "target": args.target,
            "target_base_sha256": target_base_sha256,
            "title": title,
            "proposal_sha256": proposal_sha256,
        },
        sort_keys=True,
    )
    request_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
    data = {
        "schema_version": "john_lomein_learning_promotion/v1",
        "request_id": request_id,
        "status": "promotion_review_required",
        "created_at": utc(),
        "candidate_id": rec["id"],
        "candidate_path": str(candidate_path),
        "candidate_sha256": candidate_sha256,
        "candidate_pattern": rec.get("pattern_key"),
        "product_root": str(product_root),
        "target": args.target,
        "target_path": str(target_path),
        "target_base_sha256": target_base_sha256,
        "title": title,
        "proposal": proposal,
        "proposal_sha256": proposal_sha256,
        "boundary": "prepared request only; no product file changed until apply-promotion receives exact approval and a fresh signed owner assertion bound to this request",
    }
    request_digest = promotion_request_digest(data)
    approval = f"APPROVE JOHN-LOMEIN LEARNING PROMOTION {request_id} DIGEST {request_digest}: append to {args.target}"
    data["request_digest"] = request_digest
    data["approval_required"] = approval
    rpath = promotion_root(env) / f"promotion-{request_id}.json"
    atomic_write_json(rpath, data)
    md = [
        f"# Learning promotion request `{request_id}`",
        "",
        "Status: promotion_review_required",
        "",
        "This is a gated request. It has not changed product source.",
        "",
        f"- candidate: `{rec['id']}`",
        f"- pattern: `{rec.get('pattern_key')}`",
        f"- target: `{args.target}`",
        "",
        "## Proposed text",
        "",
        proposal,
        "",
        "## Approval phrase",
        "",
        f"`{approval}`",
    ]
    atomic_write(rpath.with_suffix(".md"), "\n".join(md).rstrip() + "\n")
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        print(str(rpath.with_suffix(".md")))
        print(approval)
    return 0


def apply_promotion(args: argparse.Namespace) -> int:
    env = load_env()
    manifest = load_manifest(env)
    rpath = request_path(env, args.request)
    data = read_json_file(rpath, {})
    if not data:
        raise SystemExit(f"promotion request not found: {args.request}")
    approval = str(args.approval or "")
    required = str(data.get("approval_required") or "")
    if approval != required:
        raise SystemExit("approval did not exactly match the generated promotion phrase")
    request_digest = promotion_request_digest(data)
    if request_digest != str(data.get("request_digest") or ""):
        raise SystemExit("promotion request digest mismatch")
    proposal = str(data.get("proposal") or "").strip()
    if hashlib.sha256(proposal.encode("utf-8")).hexdigest() != str(data.get("proposal_sha256") or ""):
        raise SystemExit("promotion proposal digest mismatch")
    try:
        candidate_path = confined_candidate_path(
            env,
            manifest,
            str(data.get("candidate_path") or ""),
            expected_id=str(data.get("candidate_id") or ""),
        )
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    if sha256_file(candidate_path) != str(data.get("candidate_sha256") or ""):
        raise SystemExit("promotion candidate digest mismatch")
    product_root = product_root_from_args(args, env)
    target_rel = str(data.get("target") or "")
    target_path = validate_product_target(product_root, target_rel)
    target_base_sha256 = str(data.get("target_base_sha256") or "")
    if sha256_file(target_path) != target_base_sha256:
        raise SystemExit("promotion target changed since review; prepare a new request")
    request_id = str(data.get("request_id") or rpath.stem.replace("promotion-", ""))
    if not proposal:
        raise SystemExit("promotion request has no proposal text")
    ok, payload, trust_error = verify_trust_assertion(
        env,
        env.get("JOHN_LOMEIN_TRUST_ASSERTION", ""),
        purpose="learning_promotion",
        expected={
            "request_id": request_id,
            "request_digest": request_digest,
            "target": target_rel,
            "target_base_sha256": target_base_sha256,
            "approval_hash": normalized_text_hash(approval),
        },
    )
    if not ok:
        raise SystemExit(f"learning promotion trust assertion invalid: {trust_error}")
    if normalize_trust_tier(payload.get("tier")) != TRUST_OWNER:
        raise SystemExit("learning promotion trust assertion is not owner-tier")
    approver = str(payload.get("actor") or "").strip()
    owner_blockers = trusted_owner_approval_blockers(env, approver)
    if owner_blockers:
        raise SystemExit("learning promotion owner identity rejected: " + ",".join(owner_blockers))
    marker = f"john-lomein-learning-promotion:{request_id}"
    existing = target_path.read_text(encoding="utf-8") if target_path.exists() else ""
    if marker not in existing:
        section = "\n\n" + "\n".join([
            f"<!-- {marker} start -->",
            f"## Learning promotion: {data.get('title') or request_id}",
            "",
            f"Source candidate: `{data.get('candidate_id')}`",
            f"Approved: `{utc()}`",
            "",
            proposal,
            f"<!-- {marker} end -->",
        ]) + "\n"
        atomic_write(target_path, existing.rstrip() + section)
        applied = True
    else:
        applied = False
    data.update({"status": "applied", "applied_at": utc(), "applied": applied, "applied_target_path": str(target_path), "approved_by": approver})
    atomic_write_json(rpath, data)
    result = {"ok": True, "request_id": request_id, "applied": applied, "target": str(target_path)}
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(json.dumps(result, sort_keys=True))
    return 0


def backfill_worker_logs(args: argparse.Namespace) -> int:
    env = load_env()
    manifest = load_manifest(env)
    lanes = [x.strip() for x in (args.lanes or "maintainer,forge").split(",") if x.strip()]
    log_dir = Path(env["BOT_HERMES_HOME"]) / "logs" / "workers"
    obs_path = observations_path(env, manifest)
    existing = recent_observations(obs_path, limit=1000)
    seen = set()
    for obs in existing:
        refs = obs.get("source_refs") or []
        if isinstance(refs, list):
            for ref in refs:
                seen.add((str(ref), str(obs.get("pattern_key") or "")))
    added: list[dict[str, Any]] = []
    for lane in lanes:
        logs = sorted(log_dir.glob(f"{lane}-*.log"), key=lambda p: p.stat().st_mtime, reverse=True)[: max(1, int(args.limit))]
        for log in logs:
            try:
                text = log.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            process_status = "failed" if "traceback" in text.lower() or " error " in text.lower() and "status: clean" not in text.lower() else "ok"
            status, pattern = classify_worker_output(lane, process_status, text)
            key = (str(log), pattern)
            if key in seen:
                continue
            row = {
                "schema_version": SCHEMA,
                "observed_at": utc(),
                "instance": env.get("BOT_SLUG") or ((manifest.get("instance") or {}).get("slug")),
                "target_repo": env.get("BOT_REPO") or ((manifest.get("target") or {}).get("repo")),
                "role": lane,
                "event": "worker_log_backfill",
                "status": status,
                "summary": truncate(text[-2200:], 1800),
                "pattern_key": pattern,
                "source_refs": [str(log)],
                "metadata": {"source": "worker-log-backfill", "log_mtime": int(log.stat().st_mtime)},
            }
            append_jsonl(obs_path, row)
            added.append(row)
            seen.add(key)
    ns = argparse.Namespace(mode="post-flight", no_memory=args.no_memory, json=False)
    code = reconcile(ns)
    result = {"ok": code == 0, "added": len(added), "observations_path": str(obs_path), "added_patterns": sorted({x["pattern_key"] for x in added})}
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(json.dumps(result, sort_keys=True))
    return code


def observe(args: argparse.Namespace) -> int:
    env = load_env()
    manifest = load_manifest(env)
    path = observations_path(env, manifest)
    row = {
        "schema_version": SCHEMA,
        "observed_at": utc(),
        "instance": env.get("BOT_SLUG") or ((manifest.get("instance") or {}).get("slug")),
        "target_repo": env.get("BOT_REPO") or ((manifest.get("target") or {}).get("repo")),
        "role": args.role,
        "event": args.event,
        "status": args.status,
        "summary": truncate(args.summary or ""),
        "pattern_key": args.pattern_key or "",
        "source_refs": args.source_ref or [],
        "metadata": json.loads(args.metadata_json) if args.metadata_json else {},
    }
    append_jsonl(path, row)
    if args.json:
        print(json.dumps({"ok": True, "observation": row, "path": str(path)}, indent=2, sort_keys=True))
    return 0


def reconcile(args: argparse.Namespace) -> int:
    env = load_env()
    manifest = load_manifest(env)
    cfg = learning_config(manifest)
    if not bool(cfg.get("enabled", True)):
        result = {"ok": True, "status": "disabled"}
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    brief, report = build_operating_brief(env, manifest, mode=args.mode)
    bpath = brief_path(env, manifest)
    atomic_write(bpath, brief)
    obs = recent_observations(observations_path(env, manifest), limit=200)
    candidates = write_candidate_improvements(env, manifest, obs)
    records = candidate_records(env, manifest)
    queue = write_candidate_review_queue(env, manifest, records)
    memory_results: dict[str, Any] = {}
    memory_error = ""
    if not args.no_memory:
        try:
            memory_results = upsert_profile_memories(env, manifest, memory_text_from_brief(brief, report), report)
        except Exception as exc:
            memory_error = f"{type(exc).__name__}: {exc}"
    report.update({
        "ok": not memory_error,
        "brief_path": str(bpath),
        "observations_path": str(observations_path(env, manifest)),
        "candidate_improvements": candidates,
        "candidate_review_queue_path": str(learning_root(env) / "candidate-review-queue.md"),
        "candidate_count": queue.get("candidate_count", 0),
        "memory_results": memory_results,
        "memory_error": memory_error,
    })
    journey_cards = write_profile_journey_cards(env, manifest, report, queue)
    report["journey_card_profiles"] = journey_cards
    atomic_write_json(learning_root(env) / "learning-report.json", report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif memory_error:
        print(memory_error, file=sys.stderr)
    return 2 if memory_error else 0


def smoke(args: argparse.Namespace) -> int:
    env = load_env()
    manifest = load_manifest(env)
    smoke_summary = f"learning steward smoke at {utc()} for {env.get('BOT_SLUG','unknown')}"
    append_jsonl(observations_path(env, manifest), {
        "schema_version": SCHEMA,
        "observed_at": utc(),
        "instance": env.get("BOT_SLUG"),
        "target_repo": env.get("BOT_REPO"),
        "role": "learning_steward",
        "event": "smoke",
        "status": "ok",
        "summary": smoke_summary,
        "pattern_key": "learning_steward:smoke:ok",
        "source_refs": [str(Path(env["BOT_HERMES_HOME"]) / "instance.yaml")],
        "metadata": {"mode": "smoke"},
    })
    ns = argparse.Namespace(mode="smoke", no_memory=args.no_memory, json=False)
    code = reconcile(ns)
    report = read_json_file(learning_root(env) / "learning-report.json", {})
    brief_ok = "derived, non-canonical" in (brief_path(env, manifest).read_text(encoding="utf-8", errors="ignore") if brief_path(env, manifest).exists() else "")
    memory_ok = bool(report.get("memory_results")) and all(v.get("get_ok") for v in (report.get("memory_results") or {}).values()) if not args.no_memory else True
    result = {"ok": code == 0 and brief_ok and memory_ok, "brief_ok": brief_ok, "memory_ok": memory_ok, "report": report}
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("ok" if result["ok"] else "failed")
    return 0 if result["ok"] else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="john-lomein learning steward")
    sub = p.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("observe", help="append a structured role observation")
    o.add_argument("--role", required=True)
    o.add_argument("--event", required=True)
    o.add_argument("--status", required=True)
    o.add_argument("--summary", default="")
    o.add_argument("--pattern-key", default="")
    o.add_argument("--source-ref", action="append", default=[])
    o.add_argument("--metadata-json", default="")
    o.add_argument("--json", action="store_true")
    o.set_defaults(func=observe)
    r = sub.add_parser("reconcile", help="rebuild brief and upsert profile memories")
    r.add_argument("--mode", choices=["scheduled", "post-flight", "manual", "smoke"], default="manual")
    r.add_argument("--no-memory", action="store_true")
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=reconcile)
    s = sub.add_parser("smoke", help="prove brief generation and memory write/recall")
    s.add_argument("--no-memory", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=smoke)
    b = sub.add_parser("backfill-worker-logs", help="ingest recent real maintainer/forge worker logs as observations")
    b.add_argument("--lanes", default="maintainer,forge")
    b.add_argument("--limit", type=int, default=8)
    b.add_argument("--no-memory", action="store_true")
    b.add_argument("--json", action="store_true")
    b.set_defaults(func=backfill_worker_logs)
    q = sub.add_parser("review-candidates", help="write a metadata-only review queue for quarantined candidates")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=review_candidates)
    pp = sub.add_parser("prepare-promotion", help="prepare a gated product skill/doc promotion request")
    pp.add_argument("--candidate", required=True)
    pp.add_argument("--target", required=True, help="relative product path: README.md, docs/**/*.md, or skills/*/SKILL.md")
    pp.add_argument("--product-root", default="")
    pp.add_argument("--title", default="")
    pp.add_argument("--proposal-file", default="")
    pp.add_argument("--proposal-text", default="")
    pp.add_argument("--json", action="store_true")
    pp.set_defaults(func=prepare_promotion)
    ap = sub.add_parser("apply-promotion", help="apply a digest-bound promotion after exact text and a signed owner assertion")
    ap.add_argument("--request", required=True)
    ap.add_argument("--approval", required=True)
    ap.add_argument("--product-root", default="")
    ap.add_argument("--json", action="store_true")
    ap.set_defaults(func=apply_promotion)
    return p


def main(argv: list[str] | None = None) -> int:
    previous_umask = os.umask(0o077)
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        return args.func(args)
    finally:
        # Tests and embedded deterministic callers share a process. Keep the
        # steward's private writes sealed without mutating their later mode
        # semantics after this command returns.
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
