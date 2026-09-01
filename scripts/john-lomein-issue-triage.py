#!/usr/bin/env python3
"""Deterministically classify open issues without granting readiness.

This helper is intentionally dependency-light for LaunchAgent/system-Python
contexts. It reconciles the configured label vocabulary and marks unlabeled
issues for triage. Only a separately authenticated route may grant a
forge-visible readiness label.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_autonomy import (
    AutonomyError,
    begin_run,
    deployed_runtime_control,
    finish_run,
    mutation_lease,
    policy_from_runtime,
)
from john_lomein_manifest_contract import strict_boolean

LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.: /+\-]{0,80}$")
DEFAULT_READINESS_LABELS = ["maintainer-ready", "forge-ready", "ready-for-implementation"]
DEFAULT_TRIAGE_LABEL = "triage-needed"
ACTIONABLE_SECTION_RE = re.compile(r"(?im)^\s*(?:#{1,6}\s*)?acceptance criteria\s*:?\s*$")
CONTROLLED_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"


class TriageError(Exception):
    def __init__(self, code: str, message: str, *, status: int = 2):
        super().__init__(message)
        self.code = code
        self.status = status


def command_env(*, run_id: str | None = None) -> dict[str, str]:
    source = os.environ
    home = runtime_home()
    profile = source.get("BOT_MAINTAINER_PROFILE") or "john-lomein-maintainer"
    profile_home = home / "profiles" / profile / "home"
    gh_config = home / "profiles" / profile / "home" / ".config" / "gh"
    env = {
        "PATH": f"{home / 'scripts' / 'bin'}:{CONTROLLED_PATH}",
        "HERMES_HOME": str(home),
        "BOT_HERMES_HOME": str(home),
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
    }
    if profile_home.exists():
        env["HOME"] = str(profile_home)
    if gh_config.exists():
        env["GH_CONFIG_DIR"] = str(gh_config)
    if run_id:
        env["JOHN_LOMEIN_AUTONOMY_LANE"] = "triage"
        env["JOHN_LOMEIN_AUTONOMY_RUN_ID"] = run_id
    return env


def run(
    cmd: list[str],
    *,
    timeout: int = 45,
    input_text: str | None = None,
    run_id: str | None = None,
) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            env=command_env(run_id=run_id),
            timeout=timeout,
        )
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        return 999, "", str(exc)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def gh_json(
    cmd: list[str],
    *,
    timeout: int = 45,
    run_id: str | None = None,
):
    code, out, err = run(cmd, timeout=timeout, run_id=run_id)
    if code != 0:
        raise TriageError("github_command_failed", f"{' '.join(cmd)} failed: {err or out}")
    return json.loads(out or "null")


def _parse_scalar(raw: str) -> Any:
    value = raw.strip()
    if not value:
        return ""
    if value[0:1] in {"'", '"'} and value[-1:] == value[0]:
        return value[1:-1]
    lowered = value.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    return value


def load_manifest(home: Path) -> dict[str, Any]:
    path = home / "instance.yaml"
    if not path.exists():
        return {}
    data: dict[str, Any] = {}
    section: str | None = None
    pending_list_key: str | None = None
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()
        if raw_line[:1] not in {" ", "\t"} and stripped.endswith(":"):
            section = stripped[:-1]
            data.setdefault(section, {})
            pending_list_key = None
            continue
        if section and indent >= 2 and stripped.startswith("- ") and pending_list_key:
            bucket = data.setdefault(section, {}).setdefault(pending_list_key, [])
            if isinstance(bucket, list):
                bucket.append(_parse_scalar(stripped[2:]))
            continue
        if section and raw_line.startswith("  ") and ":" in stripped:
            key, value = stripped.split(":", 1)
            key = key.strip()
            if value.strip() == "":
                data.setdefault(section, {})[key] = []
                pending_list_key = key
            else:
                data.setdefault(section, {})[key] = _parse_scalar(value)
                pending_list_key = None
    return data


def runtime_home() -> Path:
    deployed_env = SCRIPT_DIR / "john-lomein-instance.env"
    if deployed_env.exists():
        return SCRIPT_DIR.parent.resolve()
    raw = os.environ.get("BOT_HERMES_HOME") or os.environ.get("HERMES_HOME")
    if not raw:
        raise TriageError("missing_runtime_home", "HERMES_HOME or BOT_HERMES_HOME is required")
    return Path(raw).expanduser().resolve()


def normalize_labels(labels: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in labels:
        for part in str(raw).split(","):
            label = part.strip()
            if not label:
                continue
            if not LABEL_RE.match(label):
                raise TriageError("invalid_label", f"invalid label: {label!r}")
            normalized = label.casefold()
            if normalized in seen:
                continue
            seen.add(normalized)
            out.append(label)
    return out


def runtime_config(home: Path | None = None) -> dict[str, Any]:
    home = home or runtime_home()
    manifest = load_manifest(home)
    target = manifest.get("target") or {}
    runtime = manifest.get("runtime") or {}
    gates = manifest.get("gates") or {}
    try:
        manifest_mutation_enabled = strict_boolean(
            runtime.get("mutation_enabled"),
            field="runtime.mutation_enabled",
            default=False,
        )
    except ValueError as exc:
        raise TriageError(
            "unsafe_instance_manifest",
            "deployed instance manifest contains an unsafe boolean field",
            status=3,
        ) from exc
    try:
        control = deployed_runtime_control(home)
    except AutonomyError as exc:
        raise TriageError(
            "unsafe_runtime_control",
            str(exc),
            status=3,
        ) from exc
    repo = control.get("BOT_REPO") or ""
    manifest_repo = str(target.get("repo") or "")
    if manifest_repo and manifest_repo != repo:
        raise TriageError(
            "runtime_control_mismatch",
            "deployed target repository does not match the instance manifest",
            status=3,
        )
    manifest_readiness = gates.get("readiness_labels")
    if not isinstance(manifest_readiness, list):
        manifest_readiness = []
    readiness_labels = normalize_labels(
        [
            *DEFAULT_READINESS_LABELS,
            *[str(item) for item in manifest_readiness],
            control.get("BOT_READINESS_LABELS") or "",
        ]
    )
    readiness_names = {label.casefold() for label in readiness_labels}
    autonomous_safe_labels = [
        label
        for label in normalize_labels(
            [control.get("BOT_AUTONOMOUS_SAFE_LABELS") or ""]
        )
        if label.casefold() not in readiness_names
    ]
    safe_by_name = {
        label.casefold(): label for label in autonomous_safe_labels
    }
    configured_triage_label = normalize_labels(
        [str(gates.get("triage_needed_label") or DEFAULT_TRIAGE_LABEL)]
    )[0]
    triage_label = safe_by_name.get(
        configured_triage_label.casefold(),
        "",
    )
    return {
        "home": str(home),
        "repo": repo,
        "mutation_enabled": (
            manifest_mutation_enabled
            and control.get("BOT_MISSION_COMPLETE") == "1"
            and control.get("BOT_MUTATION_ENABLED") == "1"
        ),
        "readiness_labels": readiness_labels,
        "autonomous_safe_labels": autonomous_safe_labels,
        "configured_triage_needed_label": configured_triage_label,
        "triage_needed_label": triage_label,
    }


def label_names(item: dict) -> set[str]:
    return {str(label.get("name") or "") for label in (item.get("labels") or []) if str(label.get("name") or "")}


def acceptance_criteria_block(body: str) -> list[str]:
    lines = (body or "").splitlines()
    for idx, line in enumerate(lines):
        if not ACTIONABLE_SECTION_RE.match(line):
            continue
        block: list[str] = []
        for following in lines[idx + 1 :]:
            stripped = following.strip()
            if not stripped:
                if block:
                    break
                continue
            if stripped.startswith("#"):
                break
            block.append(stripped)
        return block
    return []


def actionable_reason(issue: dict) -> str:
    """Return the deterministic readiness reason, or an empty string."""
    body = issue.get("body") or ""
    block = acceptance_criteria_block(body)
    if any(line.startswith(("- ", "* ", "- [", "* [")) or re.match(r"^\d+\.\s+", line) for line in block):
        return "acceptance_criteria"
    if block and len(" ".join(block)) >= 40:
        return "acceptance_criteria"
    return ""


def add_label(
    repo: str,
    issue_number: int,
    label: str,
    *,
    dry_run: bool,
    run_id: str | None = None,
) -> None:
    if dry_run:
        return
    code, out, err = run(
        [
            "gh",
            "issue",
            "edit",
            str(issue_number),
            "--repo",
            repo,
            "--add-label",
            label,
        ],
        timeout=45,
        run_id=run_id,
    )
    if code != 0:
        raise TriageError("issue_label_failed", f"failed to label issue #{issue_number} with {label!r}: {err or out}")


def hourly_idempotency_key(repo: str, now: datetime) -> str:
    hour = now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H")
    return f"triage:{repo}:{hour}"


def _scan_and_triage(
    cfg: dict[str, Any],
    *,
    dry_run: bool,
    run_id: str | None,
) -> dict[str, Any]:
    repo = str(cfg.get("repo") or "")
    readiness_labels = list(cfg.get("readiness_labels") or DEFAULT_READINESS_LABELS)
    readiness_names = {label.casefold() for label in readiness_labels}
    configured_triage_label = str(
        cfg.get("configured_triage_needed_label")
        or DEFAULT_TRIAGE_LABEL
    )
    configured_triage_name = configured_triage_label.casefold()
    triage_label = str(cfg.get("triage_needed_label") or "")
    issues = gh_json(
        [
            "gh",
            "issue",
            "list",
            "--repo",
            repo,
            "--state",
            "open",
            "--limit",
            "100",
            "--json",
            "number,title,labels,body,updatedAt",
        ],
        timeout=60,
        run_id=run_id,
    ) or []
    actionable_candidates: list[dict] = []
    triage_needed: list[dict] = []
    already_ready: list[int] = []
    already_triage_needed: list[int] = []
    for issue in issues:
        number = int(issue.get("number") or 0)
        labels = {label.casefold() for label in label_names(issue)}
        if labels & readiness_names:
            already_ready.append(number)
            continue
        if configured_triage_name in labels:
            already_triage_needed.append(number)
            continue
        reason = actionable_reason(issue)
        if reason:
            actionable_candidates.append(
                {
                    "number": number,
                    "label": "",
                    "reason": reason,
                    "required_action": "signed_route_or_trusted_github_label",
                    "title": issue.get("title") or "",
                }
            )
        else:
            if triage_label:
                add_label(
                    repo,
                    number,
                    triage_label,
                    dry_run=dry_run,
                    run_id=run_id,
                )
            item = {
                "number": number,
                "label": triage_label,
                "reason": "missing_acceptance_criteria",
                "title": issue.get("title") or "",
            }
            if not triage_label:
                item["required_action"] = (
                    "configure_triage_label_as_autonomous_safe"
                )
            triage_needed.append(item)

    return {
        "ok": True,
        "status": "dry_run" if dry_run else "ok",
        "dry_run": dry_run,
        "repo": repo,
        "readiness_labels": readiness_labels,
        "autonomous_safe_labels": list(
            cfg.get("autonomous_safe_labels") or []
        ),
        "configured_triage_needed_label": configured_triage_label,
        "triage_needed_label": triage_label,
        "label_actions": [],
        "routed_issues": [],
        "actionable_candidates": actionable_candidates,
        "triage_needed_issues": triage_needed,
        "already_ready_issues": already_ready,
        "already_triage_needed_issues": already_triage_needed,
    }


def triage_issues(
    cfg: dict[str, Any],
    *,
    dry_run: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    repo = str(cfg.get("repo") or "")
    if not repo or "/" not in repo:
        raise TriageError("missing_repo", "target repo is missing or invalid")
    if dry_run:
        return _scan_and_triage(cfg, dry_run=True, run_id=None)
    if not cfg.get("mutation_enabled"):
        raise TriageError(
            "triage_disabled",
            "deployed mission/mutation gate is disabled; use --dry-run for inspection",
            status=3,
        )

    home = Path(str(cfg.get("home") or "")).expanduser().resolve()
    started = time.monotonic()
    run_now = now or datetime.now(timezone.utc)
    try:
        policy = policy_from_runtime(home)
        with mutation_lease(home, "triage"):
            decision = begin_run(
                home,
                policy,
                "triage",
                idempotency_key=hourly_idempotency_key(repo, run_now),
                now=run_now,
            )
            if not decision["allowed"]:
                reason = str(decision.get("reason") or "blocked")
                if reason == "idempotency_completed":
                    return {
                        "ok": True,
                        "status": "idempotent_skip",
                        "dry_run": False,
                        "repo": repo,
                        "readiness_labels": list(
                            cfg.get("readiness_labels") or []
                        ),
                        "autonomous_safe_labels": list(
                            cfg.get("autonomous_safe_labels") or []
                        ),
                        "configured_triage_needed_label": str(
                            cfg.get("configured_triage_needed_label")
                            or DEFAULT_TRIAGE_LABEL
                        ),
                        "triage_needed_label": str(
                            cfg.get("triage_needed_label") or ""
                        ),
                        "label_actions": [],
                        "routed_issues": [],
                        "actionable_candidates": [],
                        "triage_needed_issues": [],
                        "already_ready_issues": [],
                        "already_triage_needed_issues": [],
                        "autonomy": {
                            "lane": "triage",
                            "reason": reason,
                            "run_id": decision.get("run_id"),
                        },
                    }
                raise TriageError(
                    "triage_autonomy_blocked",
                    f"autonomy refused the hourly triage run: {reason}",
                    status=3,
                )
            run_id = str(decision["run_id"])
            try:
                result = _scan_and_triage(
                    cfg,
                    dry_run=False,
                    run_id=run_id,
                )
            except TriageError as exc:
                duration = max(0, int(time.monotonic() - started))
                finish_run(
                    home,
                    run_id,
                    status="failed",
                    exit_code=exc.status,
                    duration_seconds=duration,
                    now=run_now + timedelta(seconds=duration),
                )
                raise
            except Exception as exc:
                duration = max(0, int(time.monotonic() - started))
                finish_run(
                    home,
                    run_id,
                    status="failed",
                    exit_code=2,
                    duration_seconds=duration,
                    now=run_now + timedelta(seconds=duration),
                )
                raise TriageError(
                    "triage_run_failed",
                    str(exc),
                ) from exc
            duration = max(0, int(time.monotonic() - started))
            finish_run(
                home,
                run_id,
                status="ok",
                exit_code=0,
                duration_seconds=duration,
                now=run_now + timedelta(seconds=duration),
            )
            result["autonomy"] = {
                "lane": "triage",
                "reason": "allowed",
                "run_id": run_id,
                "idempotency_key_sha256": decision.get(
                    "idempotency_key_sha256"
                ),
            }
            return result
    except TriageError:
        raise
    except AutonomyError as exc:
        raise TriageError(
            "triage_autonomy_control_failed",
            str(exc),
            status=3,
        ) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classify open john-lomein issues without granting implementation readiness.")
    parser.add_argument("--dry-run", action="store_true", help="Inspect and report actions without mutating GitHub.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args(argv)
    try:
        result = triage_issues(runtime_config(), dry_run=args.dry_run)
    except TriageError as exc:
        payload = {"ok": False, "error": exc.code, "message": str(exc)}
        print(json.dumps(payload, sort_keys=True) if args.json else f"john-lomein issue triage: {exc.code}: {exc}")
        return exc.status
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            "john-lomein issue triage: "
            f"repo={result['repo']} dry_run={int(result['dry_run'])} "
            f"actionable_candidates={[x['number'] for x in result['actionable_candidates']]} "
            f"triage_needed={[x['number'] for x in result['triage_needed_issues']]} "
            f"already_ready={result['already_ready_issues']} already_triage_needed={result['already_triage_needed_issues']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
