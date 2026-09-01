#!/usr/bin/env python3
"""Deterministic factory receipts and verifier-owned completion helpers.

The agent/executor may report what it attempted, but only the verifier contract
in this module may mark a factory run complete.  Receipt projections are kept
path-free and stable so queue-health can expose them without leaking operator
details or generating notification churn.
"""
from __future__ import annotations

import copy
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any

RECEIPT_SCHEMA = "john-lomein.factory-receipt.v1"
VERIFIER_SCHEMA = "john-lomein.factory-verifier.v1"
SIMULATION_SCHEMA = "john-lomein.factory-simulation.v1"
DONE_AUTHORITY = "john-lomein-verifier"
MISSION_PERSONALITY_VOICE = "decisive, calm, concise, and evidence-bound"
MISSION_PERSONALITY_CREATIVE_POSTURE = (
    "When delivery queues are clean, propose bounded roadmap candidates from configured sources; "
    "never let initiative bypass verification or owner gates for merge, publish, or release."
)

FACTORY_LOOPS = {
    "intake",
    "forge",
    "maintainer",
    "ci_repair",
    "owner_gate",
    "release",
    "learning",
    "roadmap_portfolio",
    "watchdog",
    "idle",
}
FACTORY_CLASSIFICATIONS = {
    "in_progress",
    "owner_action",
    "automation_blocker",
    "codex_pending",
    "triage",
    "repair_due",
    "clean_idle",
    "ignored_noise",
    "unsafe_blocked",
    "roadmap_candidate",
}
VERDICTS = {"pending", "passed", "blocked"}
FORGE_COMPLETION_CHECKS = {
    "process_exit_zero",
    "executor_did_not_report_blocked",
    "open_pr_exact_branch",
    "draft_pr",
    "issue_link_present",
    "pr_head_present",
    "isolated_worktree",
    "worktree_exact_branch",
    "worktree_head_present",
    "worktree_head_stable",
    "worktree_clean",
    "pr_head_matches_worktree",
    "changed_files_present",
    "diff_check_passed",
    "configured_test_present",
    "configured_test_passed",
    "verifier_sandbox_enforced",
    "live_verifier_evidence",
    "codex_review_handoff_recorded",
}

PRIVATE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9:/])/(?!/)[^\r\n\]\[(){}<>`'\",;:]+"
)
WINDOWS_ABSOLUTE_PATH_RE = re.compile(
    r"(?i)(?:\b[A-Z]:[\\/][^\r\n\]\[(){}<>`'\",;]+|"
    r"\\\\[^\\\s]+\\[^\r\n\]\[(){}<>`'\",;]+)"
)
UNC_PATH_RE = re.compile(r"(?<![A-Za-z0-9:/])//[^/\s]+/[^\r\n\]\[(){}<>`'\",;]+")
FILE_URL_RE = re.compile(r"(?i)\bfile:/+[^\s\]\[(){}<>`'\"]+")
SENSITIVE_FIELD_NAMES = frozenset(
    {
        "ghtoken",
        "githubtoken",
        "discordbottoken",
        "openaiapikey",
        "anthropicapikey",
        "slacktoken",
        "googleapikey",
        "apikey",
        "token",
        "password",
        "passphrase",
        "secret",
        "secretkey",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "clientsecret",
        "privatetoken",
        "privatekey",
        "signingkey",
        "webhooksecret",
        "awsaccesskeyid",
        "awssecretaccesskey",
        "authorization",
        "credential",
        "credentials",
    }
)
SECRET_RE = re.compile(
    r"(?i)(?:\b(?:GH[\s_-]*TOKEN|GITHUB[\s_-]*TOKEN|DISCORD[\s_-]*BOT[\s_-]*TOKEN|"
    r"OPENAI[\s_-]*API[\s_-]*KEY|ANTHROPIC[\s_-]*API[\s_-]*KEY|SLACK[\s_-]*TOKEN|"
    r"GOOGLE[\s_-]*API[\s_-]*KEY|API[\s_-]*KEY|TOKEN|PASSWORD|PASSPHRASE|"
    r"SECRET(?:[\s_-]*KEY)?|ACCESS[\s_-]*TOKEN|REFRESH[\s_-]*TOKEN|ID[\s_-]*TOKEN|"
    r"CLIENT[\s_-]*SECRET|PRIVATE[\s_-]*(?:TOKEN|KEY)|SIGNING[\s_-]*KEY|"
    r"WEBHOOK[\s_-]*SECRET|AUTHORIZATION|CREDENTIALS?)\b\s*[:=]\s*[\"']?\S+|"
    r"[A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:[^@\s/]+@[^\s]+|"
    r"(?:Bearer\s+[A-Za-z0-9._\-]{20,}|Basic\s+[A-Za-z0-9+/=]{12,})|github_pat_[A-Za-z0-9_]{20,}|"
    r"gh[opsu]_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|"
    r"AIza[A-Za-z0-9_\-]{20,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_\-]{20,}|"
    r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----)"
)
UNSAFE_CONTROL_RE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"
    r"\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]"
)
SAFE_INSTANCE_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SAFE_GITHUB_REPO_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}$"
)
SAFE_GIT_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
SAFE_NPM_DIST_TAG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
SAFE_PUBLISH_WORKFLOW_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,119}\.ya?ml$")


def _is_sensitive_field(value: Any) -> bool:
    canonical = re.sub(r"[^a-z0-9]", "", str(value).casefold())
    return canonical in SENSITIVE_FIELD_NAMES


def utc(now: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if now is None else now))


def stable_hash(payload: Any) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def redact_public(value: Any) -> Any:
    """Return a JSON-compatible public projection with paths/secrets removed."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, child in value.items():
            raw_key = str(key)
            safe_key = str(redact_public(raw_key))
            out[safe_key] = "[REDACTED]" if _is_sensitive_field(raw_key) else redact_public(child)
        return out
    if isinstance(value, (list, tuple, set)):
        return [redact_public(child) for child in value]
    if isinstance(value, Path):
        value = str(value)
    if isinstance(value, str):
        text = SECRET_RE.sub("[REDACTED]", value)
        text = FILE_URL_RE.sub("[private-path]", text)
        text = WINDOWS_ABSOLUTE_PATH_RE.sub("[private-path]", text)
        text = UNC_PATH_RE.sub("[private-path]", text)
        return PRIVATE_PATH_RE.sub("[private-path]", text)
    return value


def public_safe(value: Any) -> bool:
    def structured_fields_safe(item: Any) -> bool:
        if isinstance(item, dict):
            for key, child in item.items():
                if _is_sensitive_field(key) and child not in (None, "", "[REDACTED]"):
                    return False
                if not structured_fields_safe(child):
                    return False
        elif isinstance(item, (list, tuple, set)):
            return all(structured_fields_safe(child) for child in item)
        return True

    def strings(item: Any):
        if isinstance(item, dict):
            for key, child in item.items():
                yield str(key)
                yield from strings(child)
        elif isinstance(item, (list, tuple, set)):
            for child in item:
                yield from strings(child)
        elif isinstance(item, (str, Path)):
            yield str(item)

    return structured_fields_safe(value) and all(
        not PRIVATE_PATH_RE.search(text)
        and not WINDOWS_ABSOLUTE_PATH_RE.search(text)
        and not UNC_PATH_RE.search(text)
        and not FILE_URL_RE.search(text)
        and not SECRET_RE.search(text)
        and not UNSAFE_CONTROL_RE.search(text)
        for text in strings(value)
    )


def public_metadata_text(value: Any, field: str, default: str = "", *, max_length: int = 240) -> str:
    """Normalize public manifest metadata to a bounded single-line scalar."""
    if isinstance(value, (dict, list, tuple, set)):
        raise ValueError(f"unsafe manifest metadata field: {field}")
    text = " ".join(str(value if value not in (None, "") else default).split())
    if (
        not text
        or len(text) > max_length
        or UNSAFE_CONTROL_RE.search(text)
        or not public_safe(text)
        or redact_public(text) != text
    ):
        raise ValueError(f"unsafe manifest metadata field: {field}")
    return text


def prompt_data(value: Any) -> str:
    """Serialize a scalar as inert prompt data, escaping template/Markdown delimiters."""
    if isinstance(value, (dict, list, tuple, set)):
        raise ValueError("prompt data must be a scalar")
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    for literal, escaped in (
        ("`", r"\u0060"),
        ("{", r"\u007b"),
        ("}", r"\u007d"),
        ("<", r"\u003c"),
        (">", r"\u003e"),
        ("&", r"\u0026"),
    ):
        encoded = encoded.replace(literal, escaped)
    return encoded


def safe_instance_slug(value: Any) -> str:
    slug = str(value or "")
    if not SAFE_INSTANCE_SLUG_RE.fullmatch(slug):
        raise ValueError("unsafe instance.slug")
    return slug


def safe_github_repo(value: Any) -> str:
    repo = str(value or "")
    name = repo.partition("/")[2]
    if (
        not SAFE_GITHUB_REPO_RE.fullmatch(repo)
        or name in {".", ".."}
        or repo.endswith(".git")
    ):
        raise ValueError("unsafe target.repo")
    return repo


def safe_default_branch(value: Any) -> str:
    branch = str(value or "main")
    invalid = (
        not SAFE_GIT_BRANCH_RE.fullmatch(branch)
        or branch.startswith(".")
        or branch.endswith((".", "/"))
        or ".." in branch
        or "//" in branch
        or "@{" in branch
        or branch.endswith(".lock")
    )
    if invalid:
        raise ValueError("unsafe target.default_branch")
    return branch


def safe_runtime_activation(value: Any) -> str:
    activation = str(value or "owner_gated")
    if activation not in {"owner_gated", "active"}:
        raise ValueError("unsafe runtime.activation")
    return activation


def safe_authority_level(value: Any, field: str, default: str) -> str:
    raw = value if value not in (None, "") else default
    if isinstance(raw, (dict, list, tuple, set, bool)):
        raise ValueError(f"unsafe manifest metadata field: {field}")
    try:
        level = Decimal(str(raw))
    except InvalidOperation as exc:
        raise ValueError(f"unsafe manifest metadata field: {field}") from exc
    if not level.is_finite() or level < 0 or level > 3:
        raise ValueError(f"unsafe manifest metadata field: {field}")
    return format(level.normalize(), "f")


def safe_npm_tag(value: Any) -> str:
    tag = str(value or "latest")
    if not SAFE_NPM_DIST_TAG_RE.fullmatch(tag) or re.fullmatch(r"[vV][0-9].*", tag):
        raise ValueError("unsafe release.npm_tag")
    return tag


def safe_publish_workflow(value: Any) -> str:
    workflow = str(value or "publish-npm.yml")
    if (
        not SAFE_PUBLISH_WORKFLOW_RE.fullmatch(workflow)
        or ".." in workflow
        or Path(workflow).name != workflow
    ):
        raise ValueError("unsafe release.publish_workflow")
    return workflow


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    """Write JSON through a same-directory temporary file and atomic replace."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(raw_tmp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def read_receipt(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict) or data.get("schema_version") != RECEIPT_SCHEMA:
        return {}
    return data


def _normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        "kind": str(event.get("kind") or "unknown"),
        "id": str(event.get("id") or "unknown"),
        "source": str(event.get("source") or "unknown"),
        "authority": str(event.get("authority") or "none"),
        "content_trust": str(event.get("content_trust") or "untrusted"),
        "summary": str(event.get("summary") or "")[:500],
    }
    return redact_public(normalized)


def _normalize_verifier(verifier: dict[str, Any] | None = None) -> dict[str, Any]:
    raw = dict(verifier or {})
    verdict = str(raw.get("verdict") or "pending").lower()
    if verdict not in VERDICTS:
        raise ValueError(f"unsupported verifier verdict: {verdict}")
    checks = []
    for item in raw.get("checks") or []:
        if not isinstance(item, dict):
            continue
        checks.append(
            {
                "name": str(item.get("name") or "unknown"),
                "passed": bool(item.get("passed")),
                "evidence": str(redact_public(item.get("evidence") or ""))[:300],
            }
        )
    return {
        "authority": DONE_AUTHORITY,
        "verdict": verdict,
        "checks": checks,
        "missing": sorted({str(item) for item in (raw.get("missing") or []) if str(item)}),
    }


def _history_entry(receipt: dict[str, Any], recorded_at: str) -> dict[str, Any]:
    return {
        "revision": int(receipt.get("revision") or 1),
        "loop": str(receipt.get("loop") or "idle"),
        "phase": str(receipt.get("phase") or "unknown"),
        "classification": str(receipt.get("classification") or "in_progress"),
        "verdict": str((receipt.get("verifier") or {}).get("verdict") or "pending"),
        "recorded_at": recorded_at,
    }


def create_receipt(
    *,
    run_id: str,
    event: dict[str, Any],
    loop: str,
    phase: str,
    classification: str,
    evidence: dict[str, Any] | None = None,
    executor_report: dict[str, Any] | None = None,
    verifier: dict[str, Any] | None = None,
    next_action: dict[str, Any] | None = None,
    mission: dict[str, Any] | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    if loop not in FACTORY_LOOPS:
        raise ValueError(f"unsupported factory loop: {loop}")
    if classification not in FACTORY_CLASSIFICATIONS:
        raise ValueError(f"unsupported factory classification: {classification}")
    recorded_at = utc(now)
    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA,
        "run_id": str(run_id),
        "revision": 1,
        "event": _normalize_event(event),
        "loop": loop,
        "phase": str(phase),
        "classification": classification,
        "evidence": redact_public(evidence or {}),
        "executor_report": redact_public(
            executor_report
            or {
                "status": "not_run",
                "exit_code": None,
                "status_source": "none",
            }
        ),
        "done_authority": DONE_AUTHORITY,
        "verifier": _normalize_verifier(verifier),
        "next_action": redact_public(next_action or {"class": "automation", "action": "continue"}),
        "mission": redact_public(mission or {}),
        "created_at": recorded_at,
        "updated_at": recorded_at,
        "history": [],
    }
    receipt["history"] = [_history_entry(receipt, recorded_at)]
    if not public_safe(receipt):  # pragma: no cover - redact_public is defensive
        raise ValueError("factory receipt public fields are not safe")
    return receipt


def update_receipt(
    receipt: dict[str, Any],
    *,
    loop: str | None = None,
    phase: str | None = None,
    classification: str | None = None,
    evidence: dict[str, Any] | None = None,
    executor_report: dict[str, Any] | None = None,
    verifier: dict[str, Any] | None = None,
    next_action: dict[str, Any] | None = None,
    mission: dict[str, Any] | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        raise ValueError("cannot update an unknown receipt schema")
    out = copy.deepcopy(receipt)
    if loop is not None:
        if loop not in FACTORY_LOOPS:
            raise ValueError(f"unsupported factory loop: {loop}")
        out["loop"] = loop
    if classification is not None:
        if classification not in FACTORY_CLASSIFICATIONS:
            raise ValueError(f"unsupported factory classification: {classification}")
        out["classification"] = classification
    if phase is not None:
        out["phase"] = str(phase)
    if evidence is not None:
        merged = dict(out.get("evidence") or {})
        merged.update(redact_public(evidence))
        out["evidence"] = merged
    if executor_report is not None:
        out["executor_report"] = redact_public(executor_report)
    if verifier is not None:
        out["verifier"] = _normalize_verifier(verifier)
    if next_action is not None:
        out["next_action"] = redact_public(next_action)
    if mission is not None:
        out["mission"] = redact_public(mission)
    out["done_authority"] = DONE_AUTHORITY
    out["revision"] = int(out.get("revision") or 1) + 1
    recorded_at = utc(now)
    out["updated_at"] = recorded_at
    history = list(out.get("history") or [])
    history.append(_history_entry(out, recorded_at))
    out["history"] = history[-50:]
    if not public_safe(out):  # pragma: no cover - redact_public is defensive
        raise ValueError("factory receipt public fields are not safe")
    return out


def write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        raise ValueError("refusing to write an unknown receipt schema")
    if not public_safe(receipt):
        raise ValueError("refusing to write a receipt with unsafe public fields")
    atomic_write_json(Path(path), receipt)


def update_receipt_file(path: Path, **changes: Any) -> dict[str, Any]:
    current = read_receipt(path)
    if not current:
        raise ValueError(f"factory receipt missing or invalid: {Path(path).name}")
    updated = update_receipt(current, **changes)
    write_receipt(path, updated)
    return updated


def valid_branch_name(value: str) -> bool:
    branch = str(value or "")
    return bool(
        branch
        and not branch.startswith(("-", "."))
        and not branch.endswith(("/", ".", ".lock"))
        and ".." not in branch
        and "@{" not in branch
        and "//" not in branch
        and not any(ord(char) < 33 or char in "~^:?*[\\" for char in branch)
    )


def valid_commit_oid(value: str) -> bool:
    return bool(re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", str(value or "")))


def completion_verdict(*, executor_report: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """Evaluate independent completion evidence; executor status is only one input."""
    expected_branch = str(evidence.get("expected_branch") or "")
    pr = dict(evidence.get("pr") or {})
    worktree = dict(evidence.get("worktree") or {})
    verification = dict(evidence.get("verification") or {})
    changed_files = [str(item) for item in (evidence.get("files") or []) if str(item)]
    executor_status = str(executor_report.get("status") or "UNKNOWN").upper()
    process_exit = executor_report.get("exit_code")
    local_head = str(worktree.get("head_sha") or "")
    pr_head = str(pr.get("head_sha") or "")
    branch_valid = valid_branch_name(expected_branch)
    pr_head_valid = valid_commit_oid(pr_head)
    local_head_valid = valid_commit_oid(local_head)

    raw_checks = [
        ("process_exit_zero", process_exit == 0, f"exit={process_exit}"),
        ("executor_did_not_report_blocked", executor_status != "BLOCKED", f"status={executor_status}"),
        ("open_pr_exact_branch", branch_valid and bool(pr.get("open")) and str(pr.get("branch") or "") == expected_branch, f"branch={pr.get('branch') or 'missing'}"),
        ("draft_pr", pr.get("draft") is True, f"draft={pr.get('draft')}"),
        ("issue_link_present", pr.get("issue_link") is True, f"issue_link={pr.get('issue_link')}"),
        ("pr_head_present", pr_head_valid, f"head={pr_head[:12] or 'missing'}"),
        ("isolated_worktree", worktree.get("isolated") is True, f"isolated={worktree.get('isolated')}"),
        ("worktree_exact_branch", branch_valid and str(worktree.get("branch") or "") == expected_branch, f"branch={worktree.get('branch') or 'missing'}"),
        ("worktree_head_present", local_head_valid, f"head={local_head[:12] or 'missing'}"),
        ("worktree_head_stable", verification.get("head_stable_during_test") is True, f"stable={verification.get('head_stable_during_test')}"),
        ("worktree_clean", worktree.get("clean") is True, f"clean={worktree.get('clean')}"),
        ("pr_head_matches_worktree", pr_head_valid and local_head_valid and pr_head.lower() == local_head.lower(), f"pr={pr_head[:12] or 'missing'} local={local_head[:12] or 'missing'}"),
        ("changed_files_present", bool(changed_files), f"count={len(changed_files)}"),
        ("diff_check_passed", verification.get("diff_check_exit_code") == 0, f"exit={verification.get('diff_check_exit_code')}"),
        ("configured_test_present", verification.get("configured_test") is True, f"configured={verification.get('configured_test')}"),
        ("configured_test_passed", verification.get("test_exit_code") == 0, f"exit={verification.get('test_exit_code')}"),
        ("verifier_sandbox_enforced", verification.get("sandbox_enforced") is True, f"sandbox={verification.get('sandbox_enforced')}"),
        (
            "live_verifier_evidence",
            evidence.get("provenance") == "live_verifier_commands" and evidence.get("commands_executed") is True,
            f"provenance={evidence.get('provenance') or 'missing'} commands_executed={evidence.get('commands_executed')}",
        ),
    ]
    checks = [{"name": name, "passed": passed, "evidence": detail} for name, passed, detail in raw_checks]
    missing = [item["name"] for item in checks if not item["passed"]]
    return {
        "schema_version": VERIFIER_SCHEMA,
        "authority": DONE_AUTHORITY,
        "verdict": "passed" if not missing else "blocked",
        "checks": checks,
        "missing": missing,
        "executor_report": redact_public(executor_report),
        "evidence": redact_public(evidence),
    }


def public_summary(receipt: dict[str, Any]) -> dict[str, Any]:
    verifier = dict(receipt.get("verifier") or {})
    evidence = dict(receipt.get("evidence") or {})
    event = dict(receipt.get("event") or {})
    next_action = dict(receipt.get("next_action") or {})
    summary = {
        "run_id": str(receipt.get("run_id") or "unknown"),
        "event": {"kind": event.get("kind"), "id": event.get("id")},
        "loop": str(receipt.get("loop") or "idle"),
        "phase": str(receipt.get("phase") or "unknown"),
        "classification": str(receipt.get("classification") or "in_progress"),
        "branch": evidence.get("branch") or "",
        "head_sha": str(evidence.get("head_sha") or "")[:12],
        "verifier_verdict": str(verifier.get("verdict") or "pending"),
        "missing_checks": sorted({str(item) for item in (verifier.get("missing") or [])}),
        "next_action": {
            "class": str(next_action.get("class") or "automation"),
            "action": str(next_action.get("action") or "continue"),
        },
    }
    return redact_public(summary)


def forge_receipt_verified_complete(receipt: dict[str, Any]) -> bool:
    if receipt.get("schema_version") != RECEIPT_SCHEMA or receipt.get("done_authority") != DONE_AUTHORITY:
        return False
    if receipt.get("loop") != "forge" or receipt.get("phase") != "complete" or receipt.get("classification") != "codex_pending":
        return False
    evidence = dict(receipt.get("evidence") or {})
    if evidence.get("verifier_provenance") != "live_verifier_commands" or evidence.get("commands_executed") is not True:
        return False
    verifier = dict(receipt.get("verifier") or {})
    if verifier.get("verdict") != "passed" or verifier.get("missing"):
        return False
    checks = {
        str(item.get("name") or ""): bool(item.get("passed"))
        for item in (verifier.get("checks") or [])
        if isinstance(item, dict)
    }
    return all(checks.get(name) is True for name in FORGE_COMPLETION_CHECKS)


def recent_receipt_summaries(root: Path, limit: int = 10) -> list[dict[str, Any]]:
    root = Path(root)
    if not root.exists() or limit <= 0:
        return []
    candidates: list[Path] = []
    for child in root.iterdir():
        if child.is_dir() and not child.is_symlink():
            path = child / "factory-receipt.json"
            if path.is_file() and not path.is_symlink():
                candidates.append(path)
    candidates.sort(key=lambda item: item.stat().st_mtime, reverse=True)
    out: list[dict[str, Any]] = []
    seen_events: set[tuple[str, str]] = set()
    for path in candidates:
        receipt = read_receipt(path)
        summary = public_summary(receipt) if receipt else redact_public(
            {
                "run_id": path.parent.name,
                "event": {"kind": "invalid_factory_receipt", "id": path.parent.name},
                "loop": "watchdog",
                "phase": "receipt_unreadable_or_unknown_schema",
                "classification": "automation_blocker",
                "branch": "",
                "head_sha": "",
                "verifier_verdict": "blocked",
                "missing_checks": ["valid_factory_receipt"],
                "next_action": {"class": "automation", "action": "repair_or_reconstruct_factory_receipt"},
            }
        )
        event = dict(summary.get("event") or {})
        key = (str(event.get("kind") or "unknown"), str(event.get("id") or summary.get("run_id") or "unknown"))
        if key in seen_events:
            continue
        seen_events.add(key)
        out.append(summary)
        if len(out) >= limit:
            break
    return out


def _stable_unique(items: list[Any]) -> list[Any]:
    seen: set[str] = set()
    out: list[Any] = []
    for item in items:
        key = json.dumps(item, sort_keys=True, separators=(",", ":"), default=str)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return sorted(out, key=lambda item: json.dumps(item, sort_keys=True, default=str))


def factory_loop_view(
    action_board: dict[str, Any],
    *,
    receipt_summaries: list[dict[str, Any]] | None = None,
    ready_issues: list[int] | None = None,
    retry_due_issues: list[int] | None = None,
    roadmap_candidates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a stable additive queue projection without changing action semantics."""
    owner = dict(action_board.get("owner_action") or {})
    automation = dict(action_board.get("automation_blocker") or {})
    codex = dict(action_board.get("codex_pending") or {})
    noise = dict(action_board.get("ignored_noise") or {})
    triage = dict(owner.get("triage_actionable") or {})

    owner_gate: list[Any] = []
    owner_gate.extend({"kind": "pr", "id": int(number)} for number in owner.get("clean_owner_gated_prs") or [])
    owner_gate.extend({"kind": "portfolio_pr", "id": int(number)} for number in owner.get("portfolio_owner_gated_prs") or [])
    owner_gate.extend({"kind": "release_bundle", "id": str(item.get("bundle_id") or "unknown")} for item in owner.get("release_bundles") or [])

    automation_blocker = [{"kind": str(key), "value": redact_public(value)} for key, value in automation.items()]
    codex_pending = [{"kind": "pr", "id": int(number)} for number in codex.get("prs") or []]
    triage_items: list[Any] = []
    for key, values in triage.items():
        triage_items.extend({"kind": str(key), "id": int(number)} for number in values or [])
    repair_due: list[Any] = []
    in_progress: list[Any] = []

    for receipt in receipt_summaries or []:
        item = {
            "run_id": receipt.get("run_id"),
            "event": receipt.get("event"),
            "action": (receipt.get("next_action") or {}).get("action"),
        }
        classification = str(receipt.get("classification") or "in_progress")
        verifier_verdict = str(receipt.get("verifier_verdict") or "pending")
        missing_checks = list(receipt.get("missing_checks") or [])
        if classification in {"owner_action", "codex_pending"} and (
            verifier_verdict != "passed" or missing_checks
        ):
            item.update(
                {
                    "action": "repair_verifier_classification_mismatch",
                    "reported_classification": classification,
                    "verifier_verdict": verifier_verdict,
                }
            )
            classification = "repair_due"
        if classification == "owner_action":
            owner_gate.append(item)
        elif classification in {"automation_blocker", "unsafe_blocked"}:
            automation_blocker.append(item)
        elif classification == "codex_pending":
            codex_pending.append(item)
        elif classification == "triage":
            triage_items.append(item)
        elif classification == "repair_due":
            repair_due.append(item)
        elif classification == "in_progress":
            in_progress.append(item)

    forge = [{"kind": "ready_issue", "id": int(number)} for number in (ready_issues or [])]
    forge.extend({"kind": "retry_due_issue", "id": int(number)} for number in (retry_due_issues or []))
    roadmap = [redact_public(item) for item in (roadmap_candidates or [])]
    ignored = [{"kind": "open_issue", "id": int(number)} for number in noise.get("open_issues") or []]

    view = {
        "owner_gate": _stable_unique(owner_gate),
        "automation_blocker": _stable_unique(automation_blocker),
        "codex_pending": _stable_unique(codex_pending),
        "triage": _stable_unique(triage_items),
        "repair_due": _stable_unique(repair_due),
        "in_progress": _stable_unique(in_progress),
        "forge": _stable_unique(forge),
        "roadmap_candidates": _stable_unique(roadmap),
        "ignored_noise": _stable_unique(ignored),
    }
    view["clean_idle"] = not any(
        view[key]
        for key in ("owner_gate", "automation_blocker", "codex_pending", "triage", "repair_due", "in_progress", "forge")
    )
    return view


def mission_card(manifest: dict[str, Any], *, fallback_statement: str = "") -> dict[str, Any]:
    raw = dict(manifest.get("mission") or {})
    sources = raw.get("roadmap_sources") or []
    if isinstance(sources, str):
        sources = [sources]
    return redact_public(
        {
            "owner_authored": bool(raw.get("owner_authored")),
            "statement": str(raw.get("statement") or fallback_statement or "Maintain the target repository through evidence-bound, owner-gated work."),
            "owner_signal_policy": str(raw.get("owner_signal_policy") or "signed_owner_or_collaborator_route"),
            "roadmap_sources": [str(item) for item in sources],
            "personality": {
                "voice": MISSION_PERSONALITY_VOICE,
                "creative_posture": MISSION_PERSONALITY_CREATIVE_POSTURE,
            },
        }
    )


def classify_mission_signal(
    *,
    signal: str,
    trust_tier: str,
    trust_verified: bool,
    card: dict[str, Any],
    ambiguity: str = "low",
) -> dict[str, Any]:
    tier = str(trust_tier or "public").lower()
    authorized = bool(trust_verified) and tier in {"owner", "collaborator"}
    ambiguous = str(ambiguity or "low").lower() in {"medium", "high", "ambiguous"}
    statement_words = {word for word in re.findall(r"[a-z0-9]{4,}", str(card.get("statement") or "").lower())}
    signal_words = {word for word in re.findall(r"[a-z0-9]{4,}", str(signal or "").lower())}
    overlap = sorted(statement_words & signal_words)
    mission_fit = "high" if overlap or any(word in signal_words for word in {"roadmap", "maintain", "evidence", "reviewable"}) else "needs_review"
    if not authorized:
        route = "triage"
        classification = "triage"
        question = "Should this public suggestion be promoted into the owner mission queue?"
    elif ambiguous:
        route = "owner_clarification"
        classification = "triage"
        question = "Which single outcome should this roadmap signal optimize first?"
    elif mission_fit == "high":
        route = "roadmap_portfolio"
        classification = "roadmap_candidate"
        question = ""
    else:
        route = "owner_clarification"
        classification = "triage"
        question = "How does this request advance the configured repository mission?"
    return {
        "source_trust": tier,
        "trust_verified": bool(trust_verified),
        "authorized_mission_signal": authorized,
        "public_input_is_authority": False,
        "mission_fit": mission_fit,
        "matched_terms": overlap[:8],
        "ambiguity": "high" if ambiguous else "low",
        "route": route,
        "classification": classification,
        "owner_question": question,
    }
