#!/usr/bin/env python3
"""OSC portfolio steward for a john-lomein instance.

This lane audits a repo's `.osc` roadmap/active/backlog portfolio and, when
explicitly enabled, can route detected gaps into public GitHub issues plus draft
PRs that add `.osc/plans/backlog/*` follow-up plans. It is intentionally
conservative and deterministic: no LLM calls, no merge/release/publish authority,
and dry-run by default unless `--apply` is passed by the scheduled trigger.
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
import tempfile
import textwrap
import time
from dataclasses import dataclass, asdict
from pathlib import Path, PurePosixPath
from typing import Any, Callable

try:  # PyYAML exists in deployed Hermes runtimes; tests also run with it.
    import yaml  # type: ignore
except Exception:  # pragma: no cover - fallback keeps dry-run dependency-light
    yaml = None

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_autonomy import AutonomyError, deployed_runtime_control
from john_lomein_factory_receipts import create_receipt, mission_card, read_receipt, redact_public, update_receipt, write_receipt
from john_lomein_manifest_contract import validate_manifest_contract

CONTROLLED_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
AUTONOMY_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
MARKER_PREFIX = "john-lomein-osc-gap"
DEFAULT_LABELS = ["portfolio-gap", "ready-for-implementation"]
CANONICAL_READINESS_LABELS = {
    "maintainer-ready",
    "forge-ready",
    "ready-for-implementation",
}
DEFAULT_MAX_GAPS = 3
PUBLIC_SAFE_PRIVATE_PATH_RE = re.compile(r"/Users/[^\s)\]}>]+")
SECRETISH_RE = re.compile(r"(?i)(\b(GH_TOKEN|GITHUB_TOKEN|DISCORD_BOT_TOKEN|BOT_DISCORD_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|API_KEY|SECRET|PASSWORD)\b\s*[:=]|Bearer\s+[A-Za-z0-9._\-]{20,}|gh[opsu]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_\-]{20,})")


class PortfolioError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PlanRecord:
    plan_id: int | None
    path: str
    folder: str
    title: str
    status: str
    context: str
    goal: str
    open_questions: str
    text: str


@dataclass(frozen=True)
class GapCandidate:
    gap_id: str
    kind: str
    title: str
    summary: str
    evidence: list[str]
    confidence: str
    proposed_plan_slug: str
    source_paths: list[str]

    @property
    def marker(self) -> str:
        return f"<!-- {MARKER_PREFIX}: {self.gap_id} -->"


def utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def slugify(text: str, limit: int = 64) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    slug = re.sub(r"-+", "-", slug)
    return (slug or "osc-follow-up")[:limit].strip("-") or "osc-follow-up"


def short_hash(text: str, n: int = 10) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:n]


def parse_env_file(path: Path) -> dict[str, str]:
    vals: dict[str, str] = {}
    if not path.exists():
        return vals
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        try:
            parts = shlex.split(value, posix=True)
            vals[key.strip()] = parts[0] if parts else ""
        except Exception:
            vals[key.strip()] = value.strip().strip("'").strip('"')
    return vals


def runtime_home_from_script_or_env() -> Path:
    deployed_env = SCRIPT_DIR / "john-lomein-instance.env"
    if deployed_env.exists():
        return SCRIPT_DIR.parent.resolve()
    raw = os.environ.get("BOT_HERMES_HOME") or os.environ.get("HERMES_HOME") or ""
    if not raw:
        raise PortfolioError("portfolio_missing_runtime_home", "BOT_HERMES_HOME/HERMES_HOME is required outside deployed scripts")
    return Path(raw).expanduser().resolve()


def load_env() -> dict[str, str]:
    home = runtime_home_from_script_or_env()
    expected_env = (home / "scripts" / "john-lomein-instance.env").resolve()
    requested_raw = os.environ.get("JOHN_LOMEIN_INSTANCE_ENV")
    if requested_raw:
        requested = Path(requested_raw).expanduser().resolve()
        if requested != expected_env:
            raise PortfolioError("portfolio_refuses_non_deployed_instance_env", "refusing forged JOHN_LOMEIN_INSTANCE_ENV")
    if expected_env.exists():
        vals = parse_env_file(expected_env)
        try:
            vals.update(deployed_runtime_control(home))
        except AutonomyError as exc:
            raise PortfolioError(
                "portfolio_unsafe_runtime_control",
                str(exc),
            ) from exc
    else:
        vals = {}
    vals.setdefault("BOT_HERMES_HOME", str(home))
    vals.setdefault("HERMES_HOME", str(home))
    vals.pop("MNEMOSYNE_DATA_DIR", None)
    return vals


def load_manifest(home: Path) -> dict[str, Any]:
    path = home / "instance.yaml"
    if not path.exists():
        return {}
    text = path.read_text(encoding="utf-8", errors="ignore")
    if yaml is not None:
        data = yaml.safe_load(text) or {}
        try:
            validate_manifest_contract(data)
        except ValueError as exc:
            raise PortfolioError("portfolio_invalid_manifest", str(exc)) from exc
        return data
    # Minimal fallback for disabled/dry-run checks; nested lists are not needed here.
    data: dict[str, Any] = {}
    section: str | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" ") and raw.rstrip().endswith(":"):
            section = raw.strip()[:-1]
            data.setdefault(section, {})
            continue
        if section and raw.startswith("  ") and ":" in raw.strip():
            key, value = raw.strip().split(":", 1)
            raw_value = value.strip()
            quoted = (
                len(raw_value) >= 2
                and raw_value[0] in {"'", '"'}
                and raw_value[-1] == raw_value[0]
            )
            v = raw_value[1:-1] if quoted else raw_value
            if not quoted and v.lower() in {"true", "false"}:
                data[section][key] = v.lower() == "true"
            else:
                data[section][key] = v
    try:
        validate_manifest_contract(data)
    except ValueError as exc:
        raise PortfolioError("portfolio_invalid_manifest", str(exc)) from exc
    return data


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x) for x in value if str(x).strip()]
    if isinstance(value, str):
        return [x.strip() for x in value.split(",") if x.strip()]
    return [str(value)]


def boolish(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def portfolio_config(manifest: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    raw = dict(manifest.get("open_scaffold_portfolio") or manifest.get("osc_portfolio") or {})
    raw.setdefault("enabled", boolish(env.get("BOT_OSC_PORTFOLIO_ENABLED"), False))
    raw.setdefault("open_scaffold_instance_only", True)
    raw.setdefault("enabled_instance_slugs", ["open" + "-scaffold"])
    raw.setdefault("max_gaps_per_tick", int(env.get("BOT_OSC_PORTFOLIO_MAX_GAPS") or DEFAULT_MAX_GAPS))
    raw.setdefault("branch_prefix", env.get("BOT_OSC_PORTFOLIO_BRANCH_PREFIX") or "portfolio/")
    raw.setdefault("plan_dir", ".osc/plans/backlog")
    raw.setdefault("issue_labels", as_list(env.get("BOT_OSC_PORTFOLIO_ISSUE_LABELS")) or list(DEFAULT_LABELS))
    raw.setdefault("draft_prs", True)
    raw.setdefault("mutation_mode", "issue_and_draft_plan_pr")
    return raw


def persist_portfolio_receipt(
    home: Path,
    *,
    manifest: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    """Persist a sanitized latest portfolio receipt for queue/factory visibility."""
    path = home / "state" / "factory" / "portfolio-receipt.json"
    candidates = []
    for item in result.get("candidates") or []:
        if not isinstance(item, dict):
            continue
        candidates.append(
            {
                "gap_id": str(item.get("gap_id") or "unknown"),
                "kind": str(item.get("kind") or "unknown"),
                "title": str(item.get("title") or "")[:240],
                "confidence": str(item.get("confidence") or "unknown"),
                "source_paths": [str(source) for source in (item.get("source_paths") or [])],
            }
        )
    status = str(result.get("status") or "unknown")
    actions = list(result.get("actions") or [])

    def public_text(value: Any, limit: int = 500) -> str:
        return str(redact_public(str(value or "")))[:limit]

    def public_number(value: Any) -> int | None:
        try:
            number = int(value)
        except (TypeError, ValueError):
            return None
        return number if number > 0 else None

    def public_action(item: Any) -> dict[str, Any] | None:
        if not isinstance(item, dict):
            return None
        issue = item.get("issue") if isinstance(item.get("issue"), dict) else {}
        pr = item.get("pr") if isinstance(item.get("pr"), dict) else {}
        branch = public_text(pr.get("branch") or item.get("branch"), 240)
        head = public_text(pr.get("head_sha") or pr.get("head") or item.get("head_sha") or item.get("head"), 128)
        return {
            "gap_id": public_text(item.get("gap_id"), 160),
            "progress": public_text(item.get("progress") or ("draft_pr_created" if pr else "issue_recorded"), 80),
            "issue_reused": bool(item.get("issue_reused")),
            "issue": {
                "number": public_number(issue.get("number")),
                "url": public_text(issue.get("url"), 500),
                "label_status": public_text(issue.get("label_status"), 80),
                "labels_requested": [
                    public_text(label, 80)
                    for label in (issue.get("labels_requested") or [])
                ],
                "labels_applied": [
                    public_text(label, 80)
                    for label in (issue.get("labels_applied") or [])
                ],
                "label_failures": [
                    {
                        "label": public_text(failure.get("label"), 80),
                        "error": public_text(failure.get("error"), 240),
                    }
                    for failure in (issue.get("label_failures") or [])
                    if isinstance(failure, dict)
                ],
            },
            "pr": {
                "number": public_number(pr.get("number")),
                "url": public_text(pr.get("url"), 500),
            }
            if pr
            else None,
            "branch": branch,
            "head_sha": head,
            "head_state": "observed" if head else "not_observed",
            "plan_path": public_text(pr.get("plan_path") or item.get("plan_path"), 300),
        }

    action_evidence = [safe for item in actions if (safe := public_action(item)) is not None]
    planned_evidence = []
    for item in result.get("planned_actions") or []:
        if not isinstance(item, dict):
            continue
        planned_evidence.append(
            {
                "gap_id": public_text(item.get("gap_id"), 160),
                "branch": public_text(item.get("branch"), 240),
                "plan_path": public_text(item.get("plan_path"), 300),
            }
        )

    if status == "blocked_partial":
        classification = "repair_due"
        phase = "blocked_partial"
        next_action = {"class": "automation", "action": "resume_portfolio_issue_or_draft_pr"}
        verifier_verdict = "blocked"
    elif status == "mutation_blocked":
        classification = "automation_blocker"
        phase = "mutation_blocked"
        next_action = {"class": "automation", "action": "repair_portfolio_mutation_precondition"}
        verifier_verdict = "blocked"
    elif status in {"mutation_pending", "applying"}:
        classification = "in_progress"
        phase = status
        next_action = {"class": "automation", "action": "continue_portfolio_mutation"}
        verifier_verdict = "pending"
    elif actions:
        classification = "owner_action"
        phase = "owner_gate"
        next_action = {"class": "owner_action", "action": "review_portfolio_draft_artifacts"}
        verifier_verdict = "passed"
    elif candidates:
        classification = "roadmap_candidate"
        phase = "candidates_proposed"
        next_action = {"class": "owner_action", "action": "review_roadmap_candidates"}
        verifier_verdict = "passed"
    else:
        classification = "clean_idle"
        phase = status
        next_action = {"class": "automation", "action": "wait_for_next_portfolio_signal"}
        verifier_verdict = "passed"
    verifier = {
        "verdict": verifier_verdict,
        "checks": [
            {"name": "portfolio_detection_completed", "passed": status not in {"blocked_partial", "mutation_blocked"}, "evidence": f"status={status}"},
            {"name": "merge_release_publish_owner_gated", "passed": True, "evidence": "forbidden_without_owner_gate"},
        ],
        "missing": [public_text(result.get("error"), 160)] if status in {"blocked_partial", "mutation_blocked"} and result.get("error") else [],
    }
    evidence = {
        "repo": str(result.get("repo") or ""),
        "roadmap_candidates": candidates,
        "selected_gap_ids": [str(item) for item in (result.get("selected_gap_ids") or [])],
        "planned_actions": planned_evidence,
        "mutation_progress": action_evidence,
        "actions_recorded": len(action_evidence),
        "warnings": redact_public(list(result.get("warnings") or [])),
        "error": public_text(result.get("error"), 160),
        "artifacts": ["portfolio-receipt.json"],
    }
    executor_exit = 2 if status in {"blocked_partial", "mutation_blocked"} else (None if status in {"mutation_pending", "applying"} else 0)
    current = read_receipt(path)
    if current:
        receipt = update_receipt(
            current,
            loop="roadmap_portfolio",
            phase=phase,
            classification=classification,
            evidence=evidence,
            executor_report={"status": status.upper(), "exit_code": executor_exit, "status_source": "portfolio_steward"},
            verifier=verifier,
            next_action=next_action,
            mission=mission_card(manifest),
        )
    else:
        instance_slug = str(result.get("instance_slug") or ((manifest.get("instance") or {}).get("slug")) or "unknown")
        receipt = create_receipt(
            run_id=f"portfolio-{instance_slug}",
            event={
                "kind": "roadmap_scan",
                "id": "osc-portfolio",
                "source": "repo_roadmap",
                "authority": "instance_manifest",
                "content_trust": "repository_data",
                "summary": "Audit repository roadmap and portfolio gaps",
            },
            loop="roadmap_portfolio",
            phase=phase,
            classification=classification,
            evidence=evidence,
            executor_report={"status": status.upper(), "exit_code": executor_exit, "status_source": "portfolio_steward"},
            verifier=verifier,
            next_action=next_action,
            mission=mission_card(manifest),
        )
    write_receipt(path, receipt)
    return result


def command_env(env: dict[str, str]) -> dict[str, str]:
    home = Path(env["BOT_HERMES_HOME"]).expanduser().resolve()
    profile = env.get("BOT_MAINTAINER_PROFILE") or "john-lomein-maintainer"
    profile_home = home / "profiles" / profile / "home"
    gh_config = profile_home / ".config" / "gh"
    lane = os.environ.get("JOHN_LOMEIN_AUTONOMY_LANE") or ""
    run_id = os.environ.get("JOHN_LOMEIN_AUTONOMY_RUN_ID") or ""
    if bool(lane) != bool(run_id):
        raise PortfolioError(
            "portfolio_incomplete_autonomy_authority",
            "portfolio commands require both autonomy lane and run id",
        )
    if lane and lane != "portfolio":
        raise PortfolioError(
            "portfolio_wrong_autonomy_lane",
            "portfolio commands refuse authority from another autonomy lane",
        )
    if run_id and not AUTONOMY_RUN_ID_RE.fullmatch(run_id):
        raise PortfolioError(
            "portfolio_invalid_autonomy_run_id",
            "portfolio autonomy run id is malformed",
        )
    guard_bin = home / "scripts" / "bin"
    python_bin = Path(sys.executable).resolve().parent
    out = {
        "PATH": f"{guard_bin}:{python_bin}:{CONTROLLED_PATH}",
        "HERMES_HOME": str(home),
        "BOT_HERMES_HOME": str(home),
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
    }
    if profile_home.exists():
        out["HOME"] = str(profile_home)
    if gh_config.exists():
        out["GH_CONFIG_DIR"] = str(gh_config)
    if lane:
        out["JOHN_LOMEIN_AUTONOMY_LANE"] = lane
        out["JOHN_LOMEIN_AUTONOMY_RUN_ID"] = run_id
    return out


def run(cmd: list[str], *, cwd: Path | str | None = None, env: dict[str, str] | None = None, timeout: int = 60) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:
        return 999, "", str(exc)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def gh_json(repo: str, kind: str, env: dict[str, str]) -> list[dict[str, Any]]:
    if kind == "issues":
        cmd = ["gh", "issue", "list", "--repo", repo, "--state", "all", "--limit", "1000", "--json", "number,title,body,url,labels,state"]
    elif kind == "prs":
        cmd = ["gh", "pr", "list", "--repo", repo, "--state", "all", "--limit", "1000", "--json", "number,title,body,url,headRefName,state"]
    else:  # pragma: no cover
        raise ValueError(kind)
    code, out, err = run(cmd, env=command_env(env), timeout=90)
    if code != 0:
        raise PortfolioError(f"github_{kind}_lookup_failed", err or out or "gh lookup failed")
    return json.loads(out or "[]")


def gh_marker_records(repo: str, env: dict[str, str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    # Search by the hidden marker first. This avoids dedupe depending on the
    # first N recent issues/PRs, where older portfolio markers could age out and
    # allow duplicate public issue/PR spam. `gh search issues --include-prs`
    # returns both issue and PR records; split them for the normal dedupe rules.
    cmd = [
        "gh", "search", "issues", MARKER_PREFIX,
        "--repo", repo,
        "--include-prs",
        "--match", "body",
        "--limit", "1000",
        "--json", "number,title,body,url,labels,state,isPullRequest",
    ]
    code, out, err = run(cmd, env=command_env(env), timeout=120)
    if code != 0:
        raise PortfolioError("github_marker_lookup_failed", err or out or "gh marker search failed")
    records = json.loads(out or "[]")
    issues = [r for r in records if not r.get("isPullRequest")]
    prs = [r for r in records if r.get("isPullRequest")]
    return issues, prs


def gh_marker_records_for_gap_ids(repo: str, env: dict[str, str], gap_ids: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    prs: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for gap_id in sorted(set(gap_ids)):
        cmd = [
            "gh", "search", "issues", gap_id,
            "--repo", repo,
            "--include-prs",
            "--match", "body",
            "--limit", "50",
            "--json", "number,title,body,url,labels,state,isPullRequest",
        ]
        code, out, err = run(cmd, env=command_env(env), timeout=120)
        if code != 0:
            raise PortfolioError("github_marker_lookup_failed", err or out or "gh marker search failed")
        for record in json.loads(out or "[]"):
            key = ("pr" if record.get("isPullRequest") else "issue", int(record.get("number") or 0))
            if key in seen:
                continue
            seen.add(key)
            (prs if record.get("isPullRequest") else issues).append(record)
    return issues, prs


def extract_section(text: str, heading: str) -> str:
    pattern = re.compile(rf"(?ms)^##\s+{re.escape(heading)}\s*$\n(?P<body>.*?)(?=^##\s+|\Z)")
    match = pattern.search(text or "")
    return (match.group("body").strip() if match else "")


def first_h1(text: str, fallback: str) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return fallback


def plan_id_from_name(path: Path) -> int | None:
    match = re.match(r"^(\d+)-", path.name)
    return int(match.group(1)) if match else None


def assert_safe_repo_child(path: Path, root: Path, *, expect_file: bool | None = None) -> None:
    try:
        rel = path.relative_to(root)
    except ValueError as exc:
        raise PortfolioError("unsafe_repo_path", f"repo path is outside checkout: {path}") from exc
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise PortfolioError("unsafe_repo_symlink", f"refusing symlink repo input: {rel.as_posix()}")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise PortfolioError("unsafe_repo_path_escape", f"repo input escapes checkout: {rel.as_posix()}") from exc
    if expect_file is True and not path.is_file():
        raise PortfolioError("unsafe_repo_input_not_file", f"repo input is not a regular file: {rel.as_posix()}")
    if expect_file is False and not path.is_dir():
        raise PortfolioError("unsafe_repo_input_not_directory", f"repo input is not a directory: {rel.as_posix()}")


def read_repo_text(path: Path, root: Path) -> str:
    assert_safe_repo_child(path, root, expect_file=True)
    return path.read_text(encoding="utf-8", errors="ignore")


def load_plan(path: Path, root: Path) -> PlanRecord:
    text = read_repo_text(path, root)
    rel = str(path.relative_to(root))
    folder = path.parent.name
    return PlanRecord(
        plan_id=plan_id_from_name(path),
        path=rel,
        folder=folder,
        title=first_h1(text, path.stem),
        status=extract_section(text, "Status").splitlines()[0].strip().lower() if extract_section(text, "Status") else "",
        context=extract_section(text, "Context"),
        goal=extract_section(text, "Goal"),
        open_questions=extract_section(text, "Open questions"),
        text=text,
    )


def load_plans(repo_root: Path) -> dict[str, list[PlanRecord]]:
    out: dict[str, list[PlanRecord]] = {"active": [], "backlog": [], "blocked": [], "done": []}
    base = repo_root / ".osc" / "plans"
    for folder in list(out):
        d = base / folder
        if not d.exists():
            continue
        assert_safe_repo_child(d, repo_root, expect_file=False)
        out[folder] = [load_plan(p, repo_root) for p in sorted(d.glob("*.md"))]
    return out


def folded_plan_ids(text: str) -> set[int]:
    ids: set[int] = set()
    for match in re.finditer(r"(?i)folds?\s+(?:the\s+)?intent\s+of\s+(?:backlog\s+)?plans?\s+([^\.\n]+)", text or ""):
        ids.update(int(x) for x in re.findall(r"\b(\d{2,4})\b", match.group(1)))
    return ids


def normalized_words(text: str) -> set[str]:
    stop = {"the", "and", "for", "with", "from", "that", "this", "into", "repo", "local", "option", "future", "work", "open", "scaffold", "without", "beyond"}
    return {w for w in re.findall(r"[a-z0-9]{4,}", text.lower()) if w not in stop}


def parking_lot_items(roadmap_text: str) -> list[str]:
    body = extract_section(roadmap_text, "Parking lot")
    items: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("- "):
            items.append(stripped[2:].strip())
    return items


def represented(item: str, plans: list[PlanRecord]) -> bool:
    words = normalized_words(item)
    if not words:
        return True
    corpus = "\n".join(f"{p.title}\n{p.context}\n{p.goal}" for p in plans).lower()
    hits = sum(1 for w in words if w in corpus)
    return hits >= max(2, min(4, len(words)))


def detect_gaps(repo_root: Path) -> list[GapCandidate]:
    plans_by_folder = load_plans(repo_root)
    active = plans_by_folder.get("active", [])
    backlog = plans_by_folder.get("backlog", [])
    done = plans_by_folder.get("done", [])
    all_live = active + backlog
    gaps: list[GapCandidate] = []

    for plan in active:
        questions = [ln.strip("- *\t ") for ln in plan.open_questions.splitlines() if ln.strip().startswith("-")]
        if questions:
            base = f"active-open-questions:{plan.path}:{'|'.join(questions[:5])}"
            gap_id = "active-open-questions-" + short_hash(base)
            gaps.append(
                GapCandidate(
                    gap_id=gap_id,
                    kind="active_open_questions",
                    title=f"Resolve `.osc` active-plan questions for {plan.title}",
                    summary=f"Active plan `{plan.path}` still has unresolved open questions that can block roadmap/backlog alignment.",
                    evidence=[f"Active plan: `{plan.path}`", *[f"Open question: {q}" for q in questions[:6]]],
                    confidence="high",
                    proposed_plan_slug=slugify(gap_id),
                    source_paths=[plan.path],
                )
            )

    backlog_by_id = {p.plan_id: p for p in backlog if p.plan_id is not None}
    for owner in active + backlog:
        folded = sorted(i for i in folded_plan_ids(owner.text) if i in backlog_by_id)
        if folded:
            base = f"folded-backlog:{owner.path}:{','.join(map(str, folded))}"
            gap_id = "folded-backlog-" + short_hash(base)
            gaps.append(
                GapCandidate(
                    gap_id=gap_id,
                    kind="folded_backlog_unreconciled",
                    title=f"Reconcile backlog plans folded into {owner.title}",
                    summary="A live plan says it folds older backlog intent, but those older backlog files still remain independently active in `.osc/plans/backlog`.",
                    evidence=[f"Aggregator: `{owner.path}`", *[f"Still-backlog folded plan: `{backlog_by_id[i].path}`" for i in folded]],
                    confidence="medium",
                    proposed_plan_slug=slugify(gap_id),
                    source_paths=[owner.path, *[backlog_by_id[i].path for i in folded]],
                )
            )

    roadmap = repo_root / "ROADMAP.md"
    if roadmap.exists():
        roadmap_text = read_repo_text(roadmap, repo_root)
        live_plus_done_titles = all_live + done[-60:]
        for item in parking_lot_items(roadmap_text):
            if represented(item, live_plus_done_titles):
                continue
            base = f"roadmap-parking-lot:{item}"
            gap_id = "roadmap-parking-lot-" + short_hash(base)
            gaps.append(
                GapCandidate(
                    gap_id=gap_id,
                    kind="roadmap_parking_lot_unplanned",
                    title=f"Create follow-up plan for roadmap parking-lot item: {item[:80]}",
                    summary="A ROADMAP parking-lot item has no obvious active/backlog plan representation.",
                    evidence=["ROADMAP.md parking lot item:", item],
                    confidence="low",
                    proposed_plan_slug=slugify(gap_id),
                    source_paths=["ROADMAP.md"],
                )
            )
    # Stable order: high-confidence active blockers first, then folded backlog, then parking lot.
    priority = {"active_open_questions": 0, "folded_backlog_unreconciled": 1, "roadmap_parking_lot_unplanned": 2}
    gaps.sort(key=lambda g: (priority.get(g.kind, 9), g.gap_id))
    return gaps


def marker_for(gap_id: str) -> str:
    return f"<!-- {MARKER_PREFIX}: {gap_id} -->"


def existing_markers_from_records(records: list[dict[str, Any]]) -> set[str]:
    return set(existing_marker_records(records))


def existing_marker_records(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    markers: dict[str, dict[str, Any]] = {}
    for item in records:
        body = item.get("body") or ""
        for match in re.finditer(rf"<!--\s*{re.escape(MARKER_PREFIX)}:\s*([^\s>]+)\s*-->", body):
            markers.setdefault(match.group(1).strip(), item)
    return markers


def record_is_closed(item: dict[str, Any]) -> bool:
    return str(item.get("state") or "").strip().upper() in {"CLOSED", "MERGED"}


def dedupe_state(repo: str, env: dict[str, str], *, issue_records: list[dict[str, Any]] | None = None, pr_records: list[dict[str, Any]] | None = None, gap_ids: list[str] | None = None) -> tuple[set[str], dict[str, dict[str, Any]]]:
    if issue_records is None and pr_records is None:
        issue_records, pr_records = gh_marker_records_for_gap_ids(repo, env, gap_ids) if gap_ids else gh_marker_records(repo, env)
    else:
        if issue_records is None:
            issue_records = gh_json(repo, "issues", env)
        if pr_records is None:
            pr_records = gh_json(repo, "prs", env)
    issue_by_gap = existing_marker_records(issue_records)
    pr_by_gap = existing_marker_records(pr_records)
    # A PR marker means the full issue+draft-PR route already happened; never
    # recreate it. A closed issue with no PR is treated as human suppression. An
    # open issue with no PR is resumable so a failed previous PR creation does
    # not permanently suppress the missing draft PR.
    dedupe = set(pr_by_gap) | {gap_id for gap_id, item in issue_by_gap.items() if record_is_closed(item)}
    resumable_open_issues = {gap_id: item for gap_id, item in issue_by_gap.items() if gap_id not in dedupe and not record_is_closed(item)}
    return dedupe, resumable_open_issues


def existing_gap_ids(repo: str, env: dict[str, str], *, issue_records: list[dict[str, Any]] | None = None, pr_records: list[dict[str, Any]] | None = None, gap_ids: list[str] | None = None) -> set[str]:
    dedupe, _ = dedupe_state(repo, env, issue_records=issue_records, pr_records=pr_records, gap_ids=gap_ids)
    return dedupe


def next_plan_id(repo_root: Path) -> int:
    ids: list[int] = []
    for folder in ["active", "backlog", "blocked", "done"]:
        for p in (repo_root / ".osc" / "plans" / folder).glob("*.md"):
            pid = plan_id_from_name(p)
            if pid is not None:
                ids.append(pid)
    return (max(ids) + 1) if ids else 1


def validate_public_safe(text: str) -> None:
    if PUBLIC_SAFE_PRIVATE_PATH_RE.search(text):
        raise PortfolioError("private_path_content", "public issue/plan text would contain a private local path")
    if SECRETISH_RE.search(text):
        raise PortfolioError("secretish_content", "public issue/plan text appears to contain a secret")


def public_issue_title(gap: GapCandidate) -> str:
    # Titles are public GitHub surface and must not echo roadmap/plan text. Keep
    # the human-readable detail in the validated body and use deterministic IDs
    # for dedupe/debugging.
    title = f".osc portfolio gap: {gap.kind} ({gap.gap_id})"
    validate_public_safe(title)
    return title


def render_issue_body(gap: GapCandidate, plan_path: str) -> str:
    evidence = "\n".join(f"- {e}" for e in gap.evidence)
    body = f"""
{gap.marker}

## Status

`.osc` portfolio steward found a roadmap/backlog/active-plan gap.

## Evidence

{evidence}

## Proposed route

- Create `.osc` follow-up plan: `{plan_path}`
- Route through john-lomein as a draft PR linked to this issue.
- Keep merge/release/publish owner-gated.

## Acceptance criteria

- [ ] The follow-up plan states the gap, source evidence, scope, out-of-scope items, and verification.
- [ ] The plan is reviewed against `ROADMAP.md` and the current `.osc/plans/active` / `.osc/plans/backlog` state.
- [ ] No release, publish, merge, workflow dispatch, settings, or secret changes happen from this issue alone.

## Authority boundary

This issue is intake and routing evidence only. It is not approval to merge, release, publish, force-push, rewrite history, change settings, or touch secrets.
""".strip()
    validate_public_safe(body)
    return body


def render_plan(gap: GapCandidate, issue_ref: str) -> str:
    evidence = "\n".join(f"- {e}" for e in gap.evidence)
    body = f"""# Plan: .osc portfolio gap {gap.gap_id}

{gap.marker}

## Status

backlog

## Context

john-lomein's `.osc` portfolio steward detected a `{gap.kind}` gap.

{gap.summary}

Source evidence:

{evidence}

GitHub intake: {issue_ref}

## Goal

Resolve the detected roadmap/backlog/active-plan gap with a small, source-grounded follow-up that keeps the public roadmap and `.osc` work record coherent.

## Constraints / Out of scope

- Do not merge, publish, release, dispatch workflows, change repository settings, or touch secrets from this plan alone.
- Keep public wording owner-neutral and avoid local/private machine context.
- Do not overclaim proof, compliance, or runtime authority.
- If the gap is a false positive, close this plan with evidence rather than forcing implementation.

## Files to touch

- `ROADMAP.md` or relevant docs only if the gap requires wording/priority clarification.
- `.osc/plans/active/*` or `.osc/plans/backlog/*` only through normal plan/amendment flow.
- Source/test files only if a later accepted issue narrows implementation scope.

## Acceptance criteria

- [ ] The gap is confirmed against current `ROADMAP.md` and `.osc/plans` source truth.
- [ ] The chosen outcome is one of: create/update a real follow-up plan, mark the older backlog entry superseded/done with evidence, amend the active plan, or reject the steward finding as a false positive.
- [ ] Any public issue/PR comments use compact Status / Evidence / Next wording.
- [ ] Verification commands appropriate to touched files pass before closeout.

## Verification steps

1. Re-run the portfolio steward dry-run and confirm this gap no longer appears, or document why it remains intentionally open.
2. Run the repository's configured verification for any touched code/docs.
3. Run `git diff --check`.

## Open questions

- Should this gap become implementation work, roadmap clarification, backlog cleanup, or a rejected false-positive record?
- If implementation is needed, which existing active/backlog plan should own it?
""".strip() + "\n"
    validate_public_safe(body)
    return body


LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,49}$")


def validate_labels(labels: list[str]) -> list[str]:
    clean: list[str] = []
    for raw in labels:
        label = str(raw).strip()
        if not label:
            continue
        validate_public_safe(label)
        if "," in label or not LABEL_RE.match(label):
            raise PortfolioError("unsafe_label", f"unsafe public label name: {label!r}")
        clean.append(label)
    return clean


def autonomous_issue_labels(labels: list[str], env: dict[str, str]) -> list[str]:
    requested = validate_labels(labels)
    configured_safe = {
        label.casefold()
        for label in validate_labels(
            as_list(env.get("BOT_AUTONOMOUS_SAFE_LABELS"))
        )
    }
    readiness = set(CANONICAL_READINESS_LABELS)
    readiness.update(
        label.strip().casefold()
        for label in as_list(env.get("BOT_READINESS_LABELS"))
        if label.strip()
    )
    selected: list[str] = []
    seen: set[str] = set()
    for label in requested:
        normalized = label.casefold()
        if (
            normalized in seen
            or normalized in readiness
            or normalized not in configured_safe
        ):
            continue
        seen.add(normalized)
        selected.append(label)
    return selected


def apply_optional_issue_labels(
    repo: str,
    issue_number: int | None,
    labels: list[str],
    env: dict[str, str],
) -> dict[str, Any]:
    labels = validate_labels(labels)
    result: dict[str, Any] = {
        "label_status": "not_requested",
        "labels_requested": list(labels),
        "labels_applied": [],
        "label_failures": [],
    }
    if not labels:
        return result
    if issue_number is None:
        result["label_status"] = "skipped_issue_number_unavailable"
        result["label_failures"] = [
            {
                "label": label,
                "error": "created issue number was unavailable",
            }
            for label in labels
        ]
        return result

    for label in labels:
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
            env=command_env(env),
            timeout=45,
        )
        if code == 0:
            result["labels_applied"].append(label)
            continue
        detail = str(
            redact_public(err or out or "gh issue edit failed")
        ).replace("\n", " ")[:240]
        result["label_failures"].append(
            {
                "label": label,
                "error": detail,
            }
        )
    if not result["label_failures"]:
        result["label_status"] = "applied"
    elif result["labels_applied"]:
        result["label_status"] = "partial"
    else:
        result["label_status"] = "failed"
    return result


def create_issue(repo: str, gap: GapCandidate, plan_path: str, labels: list[str], env: dict[str, str]) -> dict[str, Any]:
    title = public_issue_title(gap)
    body = render_issue_body(gap, plan_path)
    labels = autonomous_issue_labels(labels, env)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
        tmp.write(body)
        tmp_path = tmp.name
    try:
        cmd = ["gh", "issue", "create", "--repo", repo, "--title", title, "--body-file", tmp_path]
        code, out, err = run(cmd, env=command_env(env), timeout=90)
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    if code != 0:
        raise PortfolioError("issue_create_failed", err or out or "gh issue create failed")
    url = out.strip().splitlines()[-1]
    number_match = re.search(r"/(?:issues)/(\d+)", url)
    number = int(number_match.group(1)) if number_match else None
    return {
        "url": url,
        "number": number,
        **apply_optional_issue_labels(repo, number, labels, env),
    }


def repo_clean(path: Path) -> bool:
    code, out, _ = run(["git", "-C", str(path), "status", "--porcelain"], timeout=45)
    return code == 0 and not out.strip()


def safe_portfolio_worktree_root(home: Path) -> Path:
    # Check each owned component before creating it. Calling mkdir(parents=True)
    # first would follow an attacker-controlled symlink under state/worktrees and
    # create files outside the runtime before we notice.
    current = home
    for part in ["state", "worktrees", "portfolio"]:
        current = current / part
        if current.is_symlink():
            raise PortfolioError("portfolio_worktree_symlink", f"unsafe symlink in portfolio worktree root: {current}")
        if current.exists() and not current.is_dir():
            raise PortfolioError("portfolio_worktree_not_directory", f"unsafe non-directory in portfolio worktree root: {current}")
        if not current.exists():
            current.mkdir(mode=0o700)
    return current.resolve()


def plan_rel_for_gap(cfg: dict[str, Any], plan_id: int, gap: GapCandidate) -> str:
    raw_dir = str(cfg.get("plan_dir") or ".osc/plans/backlog").strip().rstrip("/") or ".osc/plans/backlog"
    rel_dir = PurePosixPath(raw_dir)
    if rel_dir.is_absolute() or any(part in {"", ".."} for part in rel_dir.parts):
        raise PortfolioError("unsafe_plan_dir", "portfolio plan_dir must be a relative .osc/plans/backlog path")
    if rel_dir.parts[:3] != (".osc", "plans", "backlog"):
        raise PortfolioError("unsafe_plan_dir", "portfolio follow-up plans must be written under .osc/plans/backlog")
    filename = f"{plan_id:03d}-{slugify(gap.gap_id)}.md"
    return (rel_dir / filename).as_posix()


def branch_for_gap(cfg: dict[str, Any], gap: GapCandidate) -> str:
    branch_prefix = str(cfg.get("branch_prefix") or "portfolio/")
    branch = branch_prefix + slugify(gap.gap_id, 80)
    if branch.startswith("-") or ".." in branch or branch.endswith("/") or re.search(r"[\s~^:?*\[\\]", branch):
        raise PortfolioError("unsafe_branch_name", f"unsafe portfolio branch name for {gap.gap_id}")
    return branch


def preflight_plan_prs(repo: str, repo_root: Path, selected: list[GapCandidate], cfg: dict[str, Any], env: dict[str, str], plan_rels: list[str], resumable_gap_ids: set[str] | None = None) -> None:
    resumable_gap_ids = resumable_gap_ids or set()
    home = Path(env["BOT_HERMES_HOME"]).expanduser().resolve()
    default_branch = env.get("BOT_DEFAULT_BRANCH") or "main"
    worktree_root = safe_portfolio_worktree_root(home)
    code, _, err = run(["git", "-C", str(repo_root), "fetch", "--prune", "origin"], env=command_env(env), timeout=120)
    if code != 0:
        raise PortfolioError("git_fetch_failed", err or "git fetch failed")
    code, _, err = run(["git", "-C", str(repo_root), "rev-parse", "--verify", f"origin/{default_branch}"], env=command_env(env), timeout=45)
    if code != 0:
        raise PortfolioError("git_default_branch_missing", err or f"origin/{default_branch} not found")
    for gap, plan_rel in zip(selected, plan_rels):
        safe_child_path(repo_root, plan_rel, create_parents=False)
        branch = branch_for_gap(cfg, gap)
        worktree = worktree_root / slugify(branch, 96)
        resume = gap.gap_id in resumable_gap_ids
        if worktree.is_symlink():
            raise PortfolioError("portfolio_worktree_symlink", f"unsafe symlink at portfolio worktree path for {gap.gap_id}")
        if worktree.exists() and not resume:
            raise PortfolioError("portfolio_worktree_exists", f"portfolio worktree already exists for {gap.gap_id}")
        branch_exists = remote_branch_exists(repo_root, branch, env)
        if branch_exists and not resume:
            raise PortfolioError("portfolio_branch_exists", f"portfolio branch already exists for {gap.gap_id}: {branch}")
        if branch_exists and resume:
            validate_resume_branch(repo_root, gap, env, plan_rel, branch)


def safe_child_path(root: Path, rel: str, *, create_parents: bool) -> Path:
    root_resolved = root.resolve()
    rel_path = PurePosixPath(rel)
    if rel_path.is_absolute() or any(part in {"", ".."} for part in rel_path.parts):
        raise PortfolioError("unsafe_child_path", f"unsafe relative path: {rel}")
    parent = root
    for part in rel_path.parts[:-1]:
        parent = parent / part
        if parent.is_symlink():
            raise PortfolioError("unsafe_child_path_symlink", f"refusing symlink parent for portfolio plan path: {part}")
        if parent.exists() and not parent.is_dir():
            raise PortfolioError("unsafe_child_path_not_directory", f"refusing non-directory parent for portfolio plan path: {part}")
        if not parent.exists():
            if create_parents:
                parent.mkdir()
            else:
                # Missing parents are fine during preflight; git worktree creation
                # will create the same tracked tree before write-time validation.
                break
    if parent.exists():
        try:
            parent.resolve().relative_to(root_resolved)
        except ValueError as exc:
            raise PortfolioError("unsafe_child_path_escape", f"portfolio plan path escapes worktree: {rel}") from exc
    target = root / rel_path.as_posix()
    if target.is_symlink():
        raise PortfolioError("unsafe_child_path_symlink", f"refusing symlink final target for portfolio plan path: {rel}")
    return target


def public_pr_title(gap: GapCandidate) -> str:
    title = f"docs(osc): add portfolio follow-up ({gap.gap_id})"
    validate_public_safe(title)
    return title


def render_pr_body(gap: GapCandidate, issue_ref: str, plan_rel: str) -> str:
    body = f"""
{gap.marker}

## Summary

Adds `.osc` portfolio follow-up plan `{plan_rel}` for gap `{gap.gap_id}`.

## Scope

- Adds one `.osc` backlog plan file.
- Links the steward-created intake issue with `Closes {issue_ref}`.

## Verification

- Not run by portfolio steward; maintainer/owner review should run repo verification before merge.

## Risk

Low repository mutation, but public roadmap/planning semantics require owner review.

## Linked issue

Closes {issue_ref}

## Authority boundary

Draft PR only. This does not authorize merge, release, publish, workflow dispatch, force-push, settings changes, or secrets access.
""".strip()
    validate_public_safe(body)
    return body


def remote_branch_exists(repo_root: Path, branch: str, env: dict[str, str]) -> bool:
    code, _, err = run(["git", "-C", str(repo_root), "ls-remote", "--exit-code", "--heads", "origin", branch], env=command_env(env), timeout=90)
    if code == 0:
        return True
    if code == 2:
        return False
    raise PortfolioError("git_branch_lookup_failed", err or f"could not check remote branch {branch}")


def validate_resume_branch(repo_root: Path, gap: GapCandidate, env: dict[str, str], plan_rel: str, branch: str) -> None:
    default_branch = env.get("BOT_DEFAULT_BRANCH") or "main"
    code, out, err = run(
        ["git", "-C", str(repo_root), "fetch", "origin", f"refs/heads/{branch}:refs/remotes/origin/{branch}"],
        env=command_env(env),
        timeout=120,
    )
    if code != 0:
        raise PortfolioError("portfolio_resume_branch_fetch_failed", err or out or f"could not fetch resume branch {branch}")
    code, out, err = run(
        ["git", "-C", str(repo_root), "diff", "--name-status", f"origin/{default_branch}...origin/{branch}", "--"],
        env=command_env(env),
        timeout=90,
    )
    if code != 0:
        raise PortfolioError("portfolio_resume_branch_diff_failed", err or out or f"could not diff resume branch {branch}")
    expected = f"A\t{plan_rel}"
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if lines != [expected]:
        raise PortfolioError("portfolio_resume_branch_unsafe", f"resume branch must add only {plan_rel}; got {lines}")
    code, body, err = run(["git", "-C", str(repo_root), "show", f"origin/{branch}:{plan_rel}"], env=command_env(env), timeout=90)
    if code != 0:
        raise PortfolioError("portfolio_resume_branch_plan_missing", err or body or f"resume branch missing {plan_rel}")
    if gap.marker not in body:
        raise PortfolioError("portfolio_resume_branch_marker_missing", f"resume branch plan lacks expected marker for {gap.gap_id}")
    validate_public_safe(body)


def git_head(repo_root: Path, ref: str, env: dict[str, str]) -> str:
    code, out, err = run(
        ["git", "-C", str(repo_root), "rev-parse", "--verify", ref],
        env=command_env(env),
        timeout=45,
    )
    head = out.strip().lower()
    if code != 0 or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", head):
        raise PortfolioError("portfolio_head_lookup_failed", err or out or f"could not resolve {ref}")
    return head


def github_number_from_url(url: str, kind: str) -> int | None:
    segment = "pull" if kind == "pr" else "issues"
    match = re.search(rf"/{segment}/(\d+)(?:\b|/|$)", str(url or ""))
    return int(match.group(1)) if match else None


def create_pr_from_branch(
    repo: str,
    workdir: Path,
    gap: GapCandidate,
    issue: dict[str, Any],
    cfg: dict[str, Any],
    env: dict[str, str],
    plan_rel: str,
    branch: str,
    *,
    head_sha: str | None = None,
) -> dict[str, Any]:
    default_branch = env.get("BOT_DEFAULT_BRANCH") or "main"
    issue_ref = f"#{issue.get('number')}" if issue.get("number") else issue.get("url", "created issue")
    body = render_pr_body(gap, issue_ref, plan_rel)
    head = head_sha or git_head(workdir, f"origin/{branch}", env)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
        tmp.write(body)
        tmp_path = tmp.name
    try:
        cmd = ["gh", "pr", "create", "--repo", repo, "--draft", "--base", default_branch, "--head", branch, "--title", public_pr_title(gap), "--body-file", tmp_path]
        code, out, err = run(cmd, cwd=workdir, env=command_env(env), timeout=120)
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    if code != 0:
        raise PortfolioError("pr_create_failed", err or out or "gh pr create failed")
    url = out.strip().splitlines()[-1]
    return {
        "number": github_number_from_url(url, "pr"),
        "branch": branch,
        "head_sha": head,
        "worktree": str(workdir),
        "plan_path": plan_rel,
        "url": url,
    }


def create_plan_pr(
    repo: str,
    repo_root: Path,
    gap: GapCandidate,
    issue: dict[str, Any],
    cfg: dict[str, Any],
    env: dict[str, str],
    plan_rel: str,
    *,
    resume: bool = False,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    if not repo_clean(repo_root):
        raise PortfolioError("managed_checkout_dirty", "managed checkout is dirty; refusing portfolio mutation")
    home = Path(env["BOT_HERMES_HOME"]).expanduser().resolve()
    default_branch = env.get("BOT_DEFAULT_BRANCH") or "main"
    branch = branch_for_gap(cfg, gap)
    worktree_root = safe_portfolio_worktree_root(home)
    worktree = worktree_root / slugify(branch, 96)
    code, _, err = run(["git", "-C", str(repo_root), "fetch", "--prune", "origin"], env=command_env(env), timeout=120)
    if code != 0:
        raise PortfolioError("git_fetch_failed", err or "git fetch failed")
    if worktree.is_symlink():
        raise PortfolioError("portfolio_worktree_symlink", f"unsafe symlink at portfolio worktree path for {gap.gap_id}")
    if resume and remote_branch_exists(repo_root, branch, env):
        validate_resume_branch(repo_root, gap, env, plan_rel, branch)
        head = git_head(repo_root, f"origin/{branch}", env)
        if progress_callback is not None:
            progress_callback({"progress": "branch_ready", "branch": branch, "head_sha": head})
        return create_pr_from_branch(repo, repo_root, gap, issue, cfg, env, plan_rel, branch, head_sha=head)
    if worktree.exists():
        if not resume:
            raise PortfolioError("portfolio_worktree_exists", f"portfolio worktree already exists for {gap.gap_id}")
        code, out, err = run(["git", "-C", str(repo_root), "worktree", "remove", "--force", str(worktree)], env=command_env(env), timeout=90)
        if code != 0:
            raise PortfolioError("portfolio_resume_worktree_remove_failed", err or out or "could not remove stale portfolio worktree")
    add_flag = "-B" if resume else "-b"
    code, out, err = run(["git", "-C", str(repo_root), "worktree", "add", add_flag, branch, str(worktree), f"origin/{default_branch}"], env=command_env(env), timeout=120)
    if code != 0:
        raise PortfolioError("git_worktree_add_failed", err or out or "git worktree add failed")
    plan_path = safe_child_path(worktree, plan_rel, create_parents=True)
    issue_ref = f"#{issue.get('number')}" if issue.get("number") else issue.get("url", "created issue")
    plan_path.write_text(render_plan(gap, issue_ref), encoding="utf-8")
    for cmd in (
        ["git", "add", plan_rel],
        [
            "git",
            "commit",
            "-m",
            f"docs(osc): add portfolio follow-up for {gap.gap_id}",
        ],
        [
            "git",
            "push",
            "--no-follow-tags",
            "origin",
            f"HEAD:refs/heads/{branch}",
        ],
    ):
        code, out, err = run(cmd, cwd=worktree, env=command_env(env), timeout=180)
        if code != 0:
            raise PortfolioError("git_plan_pr_step_failed", f"{' '.join(cmd)} failed: {err or out}")
    head = git_head(worktree, "HEAD", env)
    if progress_callback is not None:
        progress_callback({"progress": "branch_pushed", "branch": branch, "head_sha": head})
    body = f"""
{gap.marker}

## Summary

Adds `.osc` portfolio follow-up plan `{plan_rel}` for gap `{gap.gap_id}`.

## Scope

- Adds one `.osc` backlog plan file.
- Links the steward-created intake issue with `Closes {issue_ref}`.

## Verification

- Not run by portfolio steward; maintainer/owner review should run repo verification before merge.

## Risk

Low repository mutation, but public roadmap/planning semantics require owner review.

## Linked issue

Closes {issue_ref}

## Authority boundary

Draft PR only. This does not authorize merge, release, publish, workflow dispatch, force-push, settings changes, or secrets access.
""".strip()
    validate_public_safe(body)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as tmp:
        tmp.write(body)
        tmp_path = tmp.name
    try:
        cmd = ["gh", "pr", "create", "--repo", repo, "--draft", "--base", default_branch, "--head", branch, "--title", public_pr_title(gap), "--body-file", tmp_path]
        code, out, err = run(cmd, cwd=worktree, env=command_env(env), timeout=120)
    finally:
        Path(tmp_path).unlink(missing_ok=True)
    if code != 0:
        raise PortfolioError("pr_create_failed", err or out or "gh pr create failed")
    url = out.strip().splitlines()[-1]
    return {
        "number": github_number_from_url(url, "pr"),
        "branch": branch,
        "head_sha": head,
        "worktree": str(worktree),
        "plan_path": plan_rel,
        "url": url,
    }


def select_candidates(candidates: list[GapCandidate], dedupe: set[str], max_gaps: int) -> list[GapCandidate]:
    return [g for g in candidates if g.gap_id not in dedupe][: max(0, max_gaps)]


def prevalidate_public_surfaces(selected: list[GapCandidate], plan_rels: list[str], labels: list[str]) -> list[str]:
    labels = validate_labels(labels)
    for gap, plan_rel in zip(selected, plan_rels):
        public_issue_title(gap)
        public_pr_title(gap)
        render_issue_body(gap, plan_rel)
        render_plan(gap, "#0")
    return labels


def run_portfolio(*, apply: bool, json_output: bool, max_gaps: int | None = None, issue_records: list[dict[str, Any]] | None = None, pr_records: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    env = load_env()
    home = Path(env["BOT_HERMES_HOME"]).expanduser().resolve()
    manifest = load_manifest(home)
    cfg = portfolio_config(manifest, env)
    instance_slug = str(((manifest.get("instance") or {}).get("slug")) or env.get("BOT_SLUG") or "")
    repo = str(((manifest.get("target") or {}).get("repo")) or env.get("BOT_REPO") or "")
    local = Path(str(((manifest.get("target") or {}).get("local_checkout")) or env.get("BOT_LOCAL") or "")).expanduser()
    if apply:
        if env.get("BOT_MISSION_COMPLETE") != "1":
            raise PortfolioError(
                "portfolio_owner_mission_incomplete",
                "portfolio apply requires a complete owner mission",
            )
        if env.get("BOT_MUTATION_ENABLED") != "1":
            raise PortfolioError(
                "portfolio_mutation_disabled",
                "runtime mutation is disabled",
            )
        if env.get("BOT_OSC_PORTFOLIO_ENABLED") != "1":
            raise PortfolioError(
                "portfolio_authority_disabled",
                "effective portfolio authority is disabled",
            )
    if not boolish(cfg.get("enabled"), False):
        return persist_portfolio_receipt(
            home,
            manifest=manifest,
            result={"ok": True, "status": "disabled", "reason": "open_scaffold_portfolio disabled", "repo": repo, "instance_slug": instance_slug, "candidates": [], "selected_gap_ids": [], "actions": []},
        )
    if boolish(cfg.get("open_scaffold_instance_only"), True) and instance_slug not in set(as_list(cfg.get("enabled_instance_slugs")) or ["open" + "-scaffold"]):
        return persist_portfolio_receipt(
            home,
            manifest=manifest,
            result={"ok": True, "status": "disabled", "reason": f"instance {instance_slug!r} not enabled for `.osc` portfolio steward", "repo": repo, "instance_slug": instance_slug, "candidates": [], "selected_gap_ids": [], "actions": []},
        )
    if not repo:
        raise PortfolioError("portfolio_missing_repo", "target.repo/BOT_REPO is required")
    if not local.exists():
        raise PortfolioError("portfolio_missing_checkout", f"target checkout missing: {local}")
    candidates = detect_gaps(local)
    if apply or issue_records is not None or pr_records is not None:
        dedupe, resumable_open_issues = dedupe_state(repo, env, issue_records=issue_records, pr_records=pr_records, gap_ids=[g.gap_id for g in candidates])
    else:
        dedupe, resumable_open_issues = set(), {}
    limit = int(max_gaps if max_gaps is not None else cfg.get("max_gaps_per_tick") or DEFAULT_MAX_GAPS)
    selected = select_candidates(candidates, dedupe, limit)
    result: dict[str, Any] = {
        "ok": True,
        "schema_version": "john_lomein_osc_portfolio/v1",
        "status": "dry_run" if not apply else "applied",
        "repo": repo,
        "instance_slug": instance_slug,
        "generated_at": utc(),
        "candidate_count": len(candidates),
        "deduped_gap_ids": sorted(dedupe),
        "resumable_issue_gap_ids": sorted(resumable_open_issues),
        "selected_gap_ids": [g.gap_id for g in selected],
        "candidates": [asdict(g) | {"marker": g.marker} for g in candidates],
        "actions": [],
        "warnings": [],
    }
    if not selected:
        result["status"] = "no_gaps" if not candidates else "all_candidates_deduped"
        return persist_portfolio_receipt(home, manifest=manifest, result=result)
    if not apply:
        return persist_portfolio_receipt(home, manifest=manifest, result=result)
    if not repo_clean(local):
        raise PortfolioError("managed_checkout_dirty", "managed checkout is dirty; refusing portfolio mutation")
    base_plan_id = next_plan_id(local)
    plan_rels = [plan_rel_for_gap(cfg, base_plan_id + idx, gap) for idx, gap in enumerate(selected)]
    requested_labels = prevalidate_public_surfaces(
        selected,
        plan_rels,
        as_list(cfg.get("issue_labels")) or list(DEFAULT_LABELS),
    )
    labels = autonomous_issue_labels(requested_labels, env)
    preflight_plan_prs(repo, local, selected, cfg, env, plan_rels, set(resumable_open_issues))
    result["planned_actions"] = [
        {
            "gap_id": gap.gap_id,
            "branch": branch_for_gap(cfg, gap),
            "plan_path": plan_rel,
        }
        for gap, plan_rel in zip(selected, plan_rels)
    ]
    # Persist intent after every non-mutating preflight and before the first
    # label/issue/branch/PR side effect. write_receipt uses atomic replace.
    result["status"] = "mutation_pending"
    persist_portfolio_receipt(home, manifest=manifest, result=result)
    try:
        for gap, plan_rel in zip(selected, plan_rels):
            resume = gap.gap_id in resumable_open_issues
            issue = resumable_open_issues.get(gap.gap_id) or create_issue(repo, gap, plan_rel, labels, env)
            if not resume and issue.get("label_status") in {
                "failed",
                "partial",
                "skipped_issue_number_unavailable",
            }:
                result["warnings"].append(
                    {
                        "kind": "optional_issue_labels",
                        "gap_id": gap.gap_id,
                        "issue_number": issue.get("number"),
                        "status": issue.get("label_status"),
                        "labels_requested": list(
                            issue.get("labels_requested") or []
                        ),
                        "labels_applied": list(
                            issue.get("labels_applied") or []
                        ),
                        "label_failures": list(
                            issue.get("label_failures") or []
                        ),
                    }
                )
            action = {
                "gap_id": gap.gap_id,
                "progress": "issue_recorded",
                "issue": issue,
                "issue_reused": resume,
                "pr": None,
                "branch": branch_for_gap(cfg, gap),
                "plan_path": plan_rel,
            }
            result["actions"].append(action)
            result["status"] = "applying"
            persist_portfolio_receipt(home, manifest=manifest, result=result)

            def checkpoint_branch(progress: dict[str, Any]) -> None:
                action.update(
                    {
                        "progress": str(progress.get("progress") or "branch_ready"),
                        "branch": str(progress.get("branch") or action["branch"]),
                        "head_sha": str(progress.get("head_sha") or ""),
                    }
                )
                persist_portfolio_receipt(home, manifest=manifest, result=result)

            pr = create_plan_pr(
                repo,
                local,
                gap,
                issue,
                cfg,
                env,
                plan_rel,
                resume=resume,
                progress_callback=checkpoint_branch,
            )
            action["pr"] = pr
            action["progress"] = "draft_pr_created"
            persist_portfolio_receipt(home, manifest=manifest, result=result)
    except PortfolioError as exc:
        result["ok"] = False
        result["status"] = "blocked_partial" if result["actions"] else "mutation_blocked"
        result["error"] = exc.code
        persist_portfolio_receipt(home, manifest=manifest, result=result)
        raise
    result["status"] = (
        "applied_with_warnings" if result["warnings"] else "applied"
    )
    return persist_portfolio_receipt(home, manifest=manifest, result=result)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit and optionally route `.osc` portfolio gaps.")
    parser.add_argument("--apply", action="store_true", help="perform public GitHub/git mutations; default is dry-run")
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument("--max-gaps", type=int, default=None)
    args = parser.parse_args(argv)
    try:
        data = run_portfolio(apply=args.apply, json_output=args.json, max_gaps=args.max_gaps)
        if args.json:
            print(json.dumps(data, indent=2, sort_keys=True))
        else:
            print(f"john-lomein osc portfolio: status={data.get('status')} candidates={data.get('candidate_count', 0)} selected={data.get('selected_gap_ids', [])}")
        return 0
    except PortfolioError as exc:
        data = {"ok": False, "status": "blocked", "error": exc.code, "message": str(exc)}
        if args.json:
            print(json.dumps(data, indent=2, sort_keys=True))
        else:
            print(f"john-lomein osc portfolio blocked: {exc.code}: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
