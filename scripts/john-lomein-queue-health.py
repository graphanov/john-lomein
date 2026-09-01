#!/usr/bin/env python3
"""Report whether a john-lomein instance queue is actually moving or visibly blocked.

This script is intentionally deterministic and small: it does not call an LLM and
it does not mutate GitHub. It exists so overwatch/doctor can detect the state
that previously broke an instance PR: green CI + mergeable PR + unresolved current review
thread(s), with the maintainer otherwise reporting only liveness.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_owner_actions import DIRTY_CHECKOUT_RECOVERY, notification_meta, queue_action_board
from john_lomein_factory_receipts import factory_loop_view, forge_receipt_verified_complete, public_summary, read_receipt, recent_receipt_summaries
from john_lomein_review_quorum import ReviewQuorumError, current_human_review_evidence, evaluate_review_quorum, load_role_review_receipts, sha256_json, validate_normalized_review_quorum_policy
OK_CONCLUSIONS = {"SUCCESS", "SKIPPED", "NEUTRAL"}
BLOCKING_MERGE_STATES = {"BLOCKED", "DIRTY", "UNSTABLE", "UNKNOWN"}
READY_LABELS = {"forge-ready", "maintainer-ready", "ready-for-implementation"}
TRIAGE_NEEDED_LABEL = "triage-needed"
ACTIONABLE_SECTION_RE = re.compile(r"(?im)^\s*(?:#{1,6}\s*)?acceptance criteria\s*:?\s*$")
DEFAULT_REVISE_RETRY_AFTER_SECONDS = 30 * 60
DEFAULT_REVISE_MAX_RETRIES = 3
DEFAULT_BLOCKED_CYCLE_LOOKBACK_SECONDS = 7 * 24 * 60 * 60
CONTROLLED_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
RUNTIME_ENV: dict[str, str] = {}


def command_env() -> dict[str, str]:
    source = RUNTIME_ENV or os.environ
    home = Path(source.get("BOT_HERMES_HOME") or source.get("HERMES_HOME") or "").expanduser()
    profile = source.get("BOT_MAINTAINER_PROFILE") or "john-lomein-maintainer"
    profile_home = home / "profiles" / profile / "home"
    gh_config = profile_home / ".config" / "gh"
    env = {
        "PATH": CONTROLLED_PATH,
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
    return env


def run(cmd: list[str], *, timeout: int = 45, cwd: str | Path | None = None) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=command_env(), cwd=str(cwd) if cwd else None, timeout=timeout)
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        return 999, "", str(exc)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


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
            parts = shlex.split(value)
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
        raise RuntimeError("queue_health_missing_runtime_home")
    return Path(raw).expanduser().resolve()


def load_env() -> dict[str, str]:
    H = runtime_home_from_script_or_env()
    expected_env = (H / "scripts" / "john-lomein-instance.env").resolve()
    requested_raw = os.environ.get("JOHN_LOMEIN_INSTANCE_ENV")
    if requested_raw:
        requested = Path(requested_raw).expanduser().resolve()
        if requested != expected_env:
            raise RuntimeError("queue_health_refuses_non_deployed_instance_env")
    if not expected_env.exists():
        raise RuntimeError(f"queue_health_missing_instance_env:{expected_env}")
    vals = parse_env_file(expected_env)
    vals["BOT_HERMES_HOME"] = str(H)
    vals["HERMES_HOME"] = str(H)
    vals.pop("MNEMOSYNE_DATA_DIR", None)
    global RUNTIME_ENV
    RUNTIME_ENV = dict(vals)
    os.environ.update(vals)
    return vals


def runtime_review_quorum_policy(vals: dict[str, str]) -> dict:
    raw = str(vals.get("BOT_REVIEW_QUORUM_POLICY_JSON") or "").strip()
    if not raw:
        raise ReviewQuorumError("review quorum runtime policy is missing")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReviewQuorumError("review quorum runtime policy is invalid") from exc
    return validate_normalized_review_quorum_policy(value)


def gh_json(cmd: list[str], *, timeout: int = 45):
    code, out, err = run(cmd, timeout=timeout)
    if code != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {err or out}")
    return json.loads(out or "null")


def check_rollup(pr: dict) -> tuple[str, list[str]]:
    checks = pr.get("statusCheckRollup") or []
    if not checks:
        return "none", []
    bad: list[str] = []
    pending: list[str] = []
    for check in checks:
        name = check.get("name") or check.get("workflowName") or "unknown"
        status = check.get("status")
        conclusion = check.get("conclusion")
        if status and status != "COMPLETED":
            pending.append(name)
        elif conclusion not in OK_CONCLUSIONS:
            bad.append(f"{name}:{conclusion or 'UNKNOWN'}")
    if pending:
        return "pending", pending
    if bad:
        return "failed", bad
    return "success", []


def review_thread_summary(repo: str, number: int) -> dict:
    owner, name = repo.split("/", 1)
    query = """
query($owner:String!, $repo:String!, $number:Int!, $cursor:String) {
  repository(owner:$owner, name:$repo) {
    pullRequest(number:$number) {
      reviewThreads(first:100, after:$cursor) {
        nodes {
          id
          isResolved
          isOutdated
          path
          line
          originalLine
          comments(last:1) {
            nodes { author { login } body url createdAt }
          }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""
    nodes: list[dict] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    for _page in range(100):
        cmd = [
            "gh",
            "api",
            "graphql",
            "-f",
            f"owner={owner}",
            "-f",
            f"repo={name}",
            "-F",
            f"number={number}",
            "-f",
            f"query={query}",
        ]
        if cursor is not None:
            cmd.extend(["-f", f"cursor={cursor}"])
        data = gh_json(cmd, timeout=60)
        pull_request = (
            (((data or {}).get("data") or {}).get("repository") or {}).get(
                "pullRequest"
            )
            if isinstance(data, dict)
            else None
        )
        threads = (
            pull_request.get("reviewThreads")
            if isinstance(pull_request, dict)
            else None
        )
        page_nodes = threads.get("nodes") if isinstance(threads, dict) else None
        page_info = (
            threads.get("pageInfo") if isinstance(threads, dict) else None
        )
        if (
            not isinstance(page_nodes, list)
            or not all(isinstance(node, dict) for node in page_nodes)
            or not isinstance(page_info, dict)
            or type(page_info.get("hasNextPage")) is not bool
        ):
            raise RuntimeError("review_threads_graphql_response_invalid")
        nodes.extend(page_nodes)
        if not page_info["hasNextPage"]:
            break
        next_cursor = page_info.get("endCursor")
        if (
            not isinstance(next_cursor, str)
            or not next_cursor
            or next_cursor in seen_cursors
        ):
            raise RuntimeError("review_threads_pagination_cursor_invalid")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    else:
        raise RuntimeError("review_threads_pagination_limit_exceeded")
    unresolved = [node for node in nodes if not node.get("isResolved")]
    unresolved_current = [node for node in unresolved if not node.get("isOutdated")]
    samples = []
    for node in unresolved_current[:3]:
        comments = (((node.get("comments") or {}).get("nodes")) or [])
        last = comments[-1] if comments else {}
        body = " ".join((last.get("body") or "").split())[:220]
        samples.append(
            {
                "path": node.get("path"),
                "line": node.get("line") or node.get("originalLine"),
                "author": ((last.get("author") or {}).get("login")),
                "url": last.get("url"),
                "body": body,
            }
        )
    return {
        "total": len(nodes),
        "unresolved": len(unresolved),
        "unresolved_current": len(unresolved_current),
        "samples": samples,
    }


CODEX_AUTHORS = {"chatgpt-codex-connector", "chatgpt-codex-connector[bot]"}


def codex_login(login: str) -> bool:
    return str(login or "") in CODEX_AUTHORS


def reviewed_commit(body: str) -> str:
    match = re.search(r"Reviewed commit:\*\*\s*`([0-9a-fA-F]{7,40})`", body or "", re.I)
    return match.group(1).lower() if match else ""


def portfolio_branch_prefix(vals: dict[str, str]) -> str:
    return str(vals.get("BOT_OSC_PORTFOLIO_BRANCH_PREFIX") or "portfolio/").strip()


def is_portfolio_pr(pr: dict, vals: dict[str, str]) -> bool:
    prefix = portfolio_branch_prefix(vals)
    head = str(pr.get("headRefName") or "")
    body = str(pr.get("body") or "")
    title = str(pr.get("title") or "")
    if prefix and head.startswith(prefix):
        return True
    return "john-lomein-osc-gap" in body or "john-lomein-osc-gap" in title


def codex_review_status(
    repo: str,
    number: int,
    head: str,
    *,
    human_reviewer_logins: set[str] | frozenset[str] = frozenset(),
) -> dict:
    """Return compact current-head Codex state from comments/reviews.

    GitHub's `latestReviews` can miss the connector's normal issue comments, which
    are valid clean artifacts. A maintainer must not keep posting `@codex review`
    once a normal Codex comment has already reviewed the current head clean.
    """
    head = (head or "").lower()
    head10 = head[:10]
    if re.fullmatch(r"[0-9a-f]{40}", head) is None:
        return {"status": "invalid_head", "clean_current": False, "pending_trigger": False, "latest_artifact_at": "", "latest_trigger_at": "", "latest_commit": "", "latest_clean_at": "", "human_reviews": [], "evidence_sha256": sha256_json({"status": "invalid_head", "head_sha": head})}
    artifacts: list[dict] = []
    triggers: list[dict] = []
    lookup_errors: list[str] = []
    try:
        comments = gh_json(["gh", "api", f"repos/{repo}/issues/{number}/comments", "--paginate"], timeout=60) or []
    except Exception as exc:
        comments = []
        lookup_errors.append(f"comments:{exc}")
    for item in comments:
        body = item.get("body") or ""
        login = ((item.get("user") or {}).get("login") or "")
        created = item.get("created_at") or ""
        if codex_login(login):
            commit = reviewed_commit(body)
            lowered = body.lower()
            clean = "didn't find any major issues" in lowered and "automated review suggestions" not in lowered
            artifacts.append({"kind": "issue_comment", "created_at": created, "commit": commit, "clean": clean, "reviewed": clean})
        elif "@codex review" in body.lower():
            triggers.append({"created_at": created, "body": body[:160]})
    try:
        reviews = gh_json(["gh", "api", f"repos/{repo}/pulls/{number}/reviews", "--paginate"], timeout=60) or []
    except Exception as exc:
        reviews = []
        lookup_errors.append(f"reviews:{exc}")
    if lookup_errors:
        return {
            "status": "lookup_failed " + ";".join(lookup_errors),
            "clean_current": False,
            "pending_trigger": False,
            "latest_artifact_at": "",
            "latest_trigger_at": "",
            "latest_commit": "",
            "latest_clean_at": "",
            "human_reviews": [],
            "evidence_sha256": sha256_json({"status": "lookup_failed", "head_sha": head}),
        }
    for item in reviews:
        body = item.get("body") or ""
        login = ((item.get("user") or {}).get("login") or "")
        if codex_login(login):
            commit = (item.get("commit_id") or reviewed_commit(body) or "").lower()
            lowered = body.lower()
            clean = "didn't find any major issues" in lowered and "automated review suggestions" not in lowered
            # Formal PR reviews with inline suggestions are not clean owner-gate
            # evidence. The owner-action board requires an explicit clean Codex
            # artifact for the current head, not merely a reviewed commit.
            artifacts.append({"kind": "formal_review", "created_at": item.get("submitted_at") or "", "commit": commit, "clean": clean, "reviewed": bool(commit)})
    current_artifacts = [a for a in artifacts if str(a.get("commit") or "").lower() == head]
    latest_current = max(current_artifacts, key=lambda a: a.get("created_at") or "", default={})
    clean_current = bool(latest_current.get("clean"))
    latest_artifact_at = max([a.get("created_at") or "" for a in artifacts] or [""])
    latest_trigger_at = max([t.get("created_at") or "" for t in triggers] or [""])
    pending_trigger = bool(latest_trigger_at and latest_trigger_at > latest_artifact_at and not clean_current)
    latest_commit = ""
    latest_clean_at = ""
    for art in sorted(artifacts, key=lambda a: a.get("created_at") or "", reverse=True):
        if art.get("commit"):
            latest_commit = str(art.get("commit")).lower()
            break
    for art in artifacts:
        if art.get("clean") and str(art.get("commit") or "").lower() == head:
            latest_clean_at = max(latest_clean_at, art.get("created_at") or "")
    if clean_current:
        status = "clean_current"
    elif pending_trigger:
        status = "pending_trigger"
    elif current_artifacts:
        status = f"current_head_not_clean head={head10}"
    elif latest_commit:
        status = f"stale_or_missing_current latest={latest_commit[:10]} head={head10}"
    else:
        status = f"missing_current head={head10}"
    human_reviews = (
        current_human_review_evidence(
            reviews,
            head_sha=head,
            allowed_logins=human_reviewer_logins,
        )
        if human_reviewer_logins
        else []
    )
    evidence_sha256 = sha256_json(
        {
            "status": status,
            "head_sha": head,
            "latest_artifact_at": latest_artifact_at,
            "latest_clean_at": latest_clean_at,
        }
    )
    return {
        "status": status,
        "clean_current": clean_current,
        "pending_trigger": pending_trigger,
        "latest_artifact_at": latest_artifact_at,
        "latest_trigger_at": latest_trigger_at,
        "latest_commit": latest_commit,
        "latest_clean_at": latest_clean_at,
        "human_reviews": human_reviews,
        "evidence_sha256": evidence_sha256,
    }


def label_names(item: dict) -> set[str]:
    return {str(label.get("name") or "") for label in (item.get("labels") or [])}


def configured_ready_labels(vals: dict[str, str]) -> set[str]:
    raw = vals.get("BOT_READINESS_LABELS") or ""
    labels = {part.strip() for part in raw.split(",") if part.strip()}
    return labels or set(READY_LABELS)


def configured_triage_label(vals: dict[str, str]) -> str:
    return (vals.get("BOT_TRIAGE_NEEDED_LABEL") or TRIAGE_NEEDED_LABEL).strip() or TRIAGE_NEEDED_LABEL


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


def actionable_untriaged_reason(issue: dict) -> str:
    block = acceptance_criteria_block(issue.get("body") or "")
    if any(line.startswith(("- ", "* ", "- [", "* [")) or re.match(r"^\d+\.\s+", line) for line in block):
        return "acceptance_criteria"
    if block and len(" ".join(block)) >= 40:
        return "acceptance_criteria"
    return ""


def dependency_numbers(text: str) -> set[int]:
    deps: set[int] = set()
    in_dependency_section = False
    for raw in (text or "").splitlines():
        line = raw.strip()
        lower = line.lower()
        if re.match(r"^#{1,6}\s*(depends on|dependencies|blocked by|blocked on)\b", lower):
            in_dependency_section = True
            continue
        if in_dependency_section and line.startswith("#"):
            in_dependency_section = False
        if not (in_dependency_section or any(phrase in lower for phrase in ["depends on", "blocked by", "blocked on", "after #"])):
            continue
        for match in re.findall(r"#\s*(\d+)", line):
            try:
                deps.add(int(match))
            except ValueError:
                pass
    return deps


def issue_ref_matches(text: str, number: int) -> bool:
    lower = (text or "").lower()
    n = int(number)
    return bool(
        re.search(rf"(?<!\d)#{n}(?!\d)", lower)
        or re.search(rf"\bissues?[-/]{n}\b", lower)
    )


def pr_references_issue(pr: dict, number: int) -> bool:
    blob = " ".join(str(pr.get(k) or "") for k in ["title", "headRefName", "body"])
    return issue_ref_matches(blob, int(number))


def merged_dependency_prs(repo: str, dependency_numbers: set[int]) -> dict[int, list[dict]]:
    """Find recent merged PRs that visibly satisfy open issue dependencies.

    A phased issue chain often says "Phase 2 depends on #N" where #N is a
    phase/umbrella issue that may stay open after its actual predecessor PR
    landed. In that case the open issue number alone is not enough to block the
    queue: if a merged PR visibly references #N, downstream phases may proceed
    while queue-health still reports the stale dependency for operator cleanup.
    """
    wanted = {int(n) for n in dependency_numbers if int(n) > 0}
    if not wanted:
        return {}
    try:
        merged = gh_json(
            [
                "gh",
                "pr",
                "list",
                "--repo",
                repo,
                "--state",
                "merged",
                "--limit",
                "100",
                "--json",
                "number,title,headRefName,body,mergedAt,url",
            ],
            timeout=60,
        ) or []
    except Exception:
        return {}
    out: dict[int, list[dict]] = {n: [] for n in wanted}
    for pr in merged:
        for number in wanted:
            if pr_references_issue(pr, number):
                out[number].append(
                    {
                        "number": int(pr.get("number") or 0),
                        "title": pr.get("title") or "",
                        "mergedAt": pr.get("mergedAt") or "",
                        "url": pr.get("url") or "",
                    }
                )
    return {number: prs for number, prs in out.items() if prs}


def dependency_status(issue: dict, open_issue_numbers: set[int], satisfied_dependency_prs: dict[int, list[dict]]) -> tuple[list[int], list[dict]]:
    number = int(issue.get("number") or 0)
    unresolved: list[int] = []
    satisfied: list[dict] = []
    for dep in sorted(dependency_numbers(issue.get("body") or "")):
        if dep == number or dep not in open_issue_numbers:
            continue
        prs = satisfied_dependency_prs.get(dep) or []
        if prs:
            satisfied.append({"issue": dep, "prs": [int(pr.get("number") or 0) for pr in prs if pr.get("number")]})
        else:
            unresolved.append(dep)
    return unresolved, satisfied


def issue_is_covered_by_pr(issue: dict, prs: list[dict]) -> bool:
    """Return True when an open PR visibly covers the ready issue.

    Ready labels are intake hints, not proof an issue still needs a new branch.
    If an open PR already references the issue number in its body/title/branch,
    queue-health should not keep reporting that issue as ready work.
    """
    number = int(issue["number"])
    for pr in prs:
        if pr_references_issue(pr, number):
            return True
    return False


def receipt_issue_number(summary: dict) -> int | None:
    """Return the issue number only for the receipt's canonical event id."""
    event = summary.get("event") or {}
    if not isinstance(event, dict):
        return None
    match = re.fullmatch(r"issue#([1-9][0-9]*)", str(event.get("id") or ""))
    return int(match.group(1)) if match else None


def pr_matches_receipt(pr: dict, summary: dict) -> bool:
    """Match a receipt to the exact current branch/head it observed."""
    branch = str(summary.get("branch") or "")
    receipt_head = str(summary.get("head_sha") or "").lower()
    pr_branch = str(pr.get("headRefName") or "")
    pr_head = str(pr.get("headRefOid") or "").lower()
    return bool(branch and len(receipt_head) == 12 and branch == pr_branch and pr_head[:12] == receipt_head)


def reconcile_receipt_summaries(
    receipt_summaries: list[dict],
    *,
    open_issue_numbers: set[int],
    open_pr_details: list[dict],
    codex_pending_prs: list[int],
) -> list[dict]:
    """Project persisted receipts through current GitHub state.

    Recognized closed issues are historical and disappear from the live queue.
    A Codex receipt remains pending only while the exact branch/head is still in
    the live Codex-pending set. Repair/in-progress receipts yield to a covering
    open PR because the PR inspection path now owns the current classification.
    Unrecognized event ids are retained so malformed state stays fail-visible.
    """
    pending_pr_numbers = {int(number) for number in codex_pending_prs}
    ordered_prs = sorted(open_pr_details, key=lambda pr: int(pr.get("number") or 0))
    reconciled: list[dict] = []
    for summary in receipt_summaries:
        issue_number = receipt_issue_number(summary)
        if issue_number is None:
            reconciled.append(summary)
            continue
        if issue_number not in open_issue_numbers:
            continue

        covering_prs = [pr for pr in ordered_prs if pr_references_issue(pr, issue_number)]
        classification = str(summary.get("classification") or "")
        if classification == "codex_pending":
            exact_live_pending = any(
                int(pr.get("number") or 0) in pending_pr_numbers and pr_matches_receipt(pr, summary)
                for pr in covering_prs
            )
            if not exact_live_pending:
                continue
        elif classification in {"repair_due", "in_progress"} and covering_prs:
            continue
        reconciled.append(summary)
    return reconciled


def defer_path(vals: dict[str, str], issue_number: int) -> Path:
    home = Path(vals.get("BOT_HERMES_HOME") or vals.get("HERMES_HOME") or "").expanduser()
    return home / "state" / "forge-deferred" / f"issue-{issue_number}.json"


def parse_utc(value: str) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def deferral_state(vals: dict[str, str], issue: dict) -> tuple[str, dict | None]:
    path = defer_path(vals, int(issue["number"]))
    if not path.exists():
        return "none", None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return "unreadable", None
    recorded_update = str(data.get("issue_updated_at") or "")
    current_update = str(issue.get("updatedAt") or "")
    if current_update and recorded_update and current_update > recorded_update:
        return "ready_issue_updated_since_defer", data
    status = str(data.get("status") or "").upper()
    if status != "REVISE":
        return f"deferred_{status or 'unknown'}", data
    retry_count = int(data.get("retry_count") or 0)
    max_retries = int(vals.get("BOT_FORGE_REVISE_MAX_RETRIES") or DEFAULT_REVISE_MAX_RETRIES)
    if retry_count >= max_retries:
        return f"deferred_revise_retry_limit_{retry_count}/{max_retries}", data
    retry_after = int(vals.get("BOT_FORGE_REVISE_RETRY_AFTER_SECONDS") or DEFAULT_REVISE_RETRY_AFTER_SECONDS)
    deferred_at = parse_utc(str(data.get("deferred_at") or ""))
    if deferred_at is None:
        return "retry_due_missing_timestamp", data
    age = time.time() - deferred_at
    if age >= retry_after:
        return f"retry_due_age={int(age)}s", data
    return f"deferred_revise_wait_age={int(age)}s_after={retry_after}s", data


def is_deferred(vals: dict[str, str], issue: dict) -> bool:
    state, _ = deferral_state(vals, issue)
    return state.startswith("deferred_")


def managed_checkout_alerts(vals: dict[str, str]) -> list[str]:
    local_raw = vals.get("BOT_LOCAL") or ""
    if not local_raw:
        return []
    local = Path(local_raw).expanduser()
    if not (local / ".git").exists():
        return []
    branch = vals.get("BOT_DEFAULT_BRANCH") or "main"
    code, out, err = run(["git", "status", "--short", "--branch"], timeout=25, cwd=local)
    if code != 0:
        return [f"managed_checkout_status_failed branch={branch} error={(err or out)[:160]}"]
    lines = out.splitlines()
    first = lines[0] if lines else ""
    dirty = [line for line in lines[1:] if line.strip()]
    on_default = branch_status_is_default(first, branch)
    if on_default and dirty:
        return [f"managed_checkout_dirty_default_branch branch={branch} items={len(dirty)} {DIRTY_CHECKOUT_RECOVERY}"]
    return []


def branch_status_is_default(first_line: str, branch: str) -> bool:
    if first_line == f"## No commits yet on {branch}":
        return True
    return bool(re.match(rf"^## {re.escape(branch)}(?:$|\.\.\.| \[)", first_line or ""))


def read_json_file(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def issue_active_for_blocked_cycle(issue: object, active_issue_numbers: set[int] | None) -> bool:
    if active_issue_numbers is None:
        return True
    try:
        return int(str(issue)) in active_issue_numbers
    except Exception:
        return False


def issue_number_for_blocked_cycle(issue: object) -> int | None:
    try:
        return int(str(issue))
    except Exception:
        return None


def blocked_cycle_state_from_dir(cycle: Path, active_issue_numbers: set[int] | None = None) -> tuple[int | None, str, str]:
    blocked = read_json_file(cycle / "blocked.json")
    if blocked and str(blocked.get("stage") or "") == "implementation":
        issue = blocked.get("issue") or "?"
        issue_number = issue_number_for_blocked_cycle(issue)
        if not issue_active_for_blocked_cycle(issue, active_issue_numbers):
            return issue_number, "", "inactive"
        reasons = blocked.get("reasons") if isinstance(blocked.get("reasons"), list) else []
        reason = ",".join(str(r) for r in reasons[:3]) or str(blocked.get("status") or "blocked")
        return issue_number, f"blocked_forge_cycle issue={issue} cycle={cycle.name} reason={reason}", "blocked"
    summary = read_json_file(cycle / "summary.json")
    implement_status = str(summary.get("implement_status") or "").upper()
    if implement_status == "BLOCKED":
        issue = summary.get("issue") or "?"
        issue_number = issue_number_for_blocked_cycle(issue)
        if not issue_active_for_blocked_cycle(issue, active_issue_numbers):
            return issue_number, "", "inactive"
        source = summary.get("implement_status_source") or "unknown"
        return issue_number, f"blocked_forge_cycle issue={issue} cycle={cycle.name} source={source}", "blocked"
    if implement_status == "COMPLETE":
        issue = summary.get("issue") or "?"
        issue_number = issue_number_for_blocked_cycle(issue)
        if not issue_active_for_blocked_cycle(issue, active_issue_numbers):
            return issue_number, "", "inactive"
        receipt = read_receipt(cycle / "factory-receipt.json")
        if not forge_receipt_verified_complete(receipt):
            return issue_number, f"unverified_forge_cycle issue={issue} cycle={cycle.name} reason=legacy_complete_without_verifier", "blocked"
        return issue_number, "", "complete"
    return None, "", "unknown"


def blocked_cycle_alert_from_dir(cycle: Path, active_issue_numbers: set[int] | None = None) -> str:
    _, alert, _ = blocked_cycle_state_from_dir(cycle, active_issue_numbers)
    return alert


def recent_blocked_forge_cycle_alerts(vals: dict[str, str], active_issue_numbers: set[int] | None = None) -> list[str]:
    home = Path(vals.get("BOT_HERMES_HOME") or vals.get("HERMES_HOME") or "").expanduser()
    root = home / "state" / "forge-cycles"
    if not root.exists():
        return []
    try:
        lookback = int(vals.get("BOT_BLOCKED_CYCLE_LOOKBACK_SECONDS") or DEFAULT_BLOCKED_CYCLE_LOOKBACK_SECONDS)
    except ValueError:
        lookback = DEFAULT_BLOCKED_CYCLE_LOOKBACK_SECONDS
    now = time.time()
    alerts: list[str] = []
    seen_issues: set[int] = set()
    cycles = sorted([p for p in root.iterdir() if p.is_dir()], key=lambda p: p.stat().st_mtime, reverse=True)
    for cycle in cycles[:25]:
        try:
            if lookback > 0 and now - cycle.stat().st_mtime > lookback:
                continue
        except Exception:
            continue
        issue_number, alert, state = blocked_cycle_state_from_dir(cycle, active_issue_numbers)
        if issue_number is not None:
            if issue_number in seen_issues:
                continue
            if state in {"blocked", "complete"}:
                seen_issues.add(issue_number)
        if alert:
            alerts.append(alert)
        if len(alerts) >= 5:
            break
    return alerts


def main() -> int:
    vals = load_env()
    repo = vals.get("BOT_REPO") or ""
    slug = vals.get("BOT_SLUG") or "unknown"
    mutation_enabled = vals.get("BOT_MUTATION_ENABLED", "0") == "1"
    if not repo or "/" not in repo:
        print(f"john-lomein queue health: instance={slug} repo={repo or '?'} failures=1 details=missing_repo")
        return 2

    failures: list[str] = []
    alerts: list[str] = []
    clean_candidates: list[int] = []
    merge_ready_evidence: list[dict] = []
    drafts: list[int] = []
    codex_clean_prs: list[int] = []
    codex_pending_prs: list[int] = []
    codex_awaiting_prs: list[int] = []
    portfolio_owner_gated_prs: list[int] = []
    open_pr_details: list[dict] = []
    try:
        review_policy = runtime_review_quorum_policy(vals)
    except ReviewQuorumError as exc:
        review_policy = None
        failures.append(f"review_quorum_policy_invalid:{exc}")

    try:
        pr_refs = gh_json(["gh", "pr", "list", "--repo", repo, "--state", "open", "--limit", "30", "--json", "number"])
        issue_refs = gh_json(["gh", "issue", "list", "--repo", repo, "--state", "open", "--limit", "50", "--json", "number,title,labels,body,updatedAt"])
    except Exception as exc:
        print(f"john-lomein queue health: instance={slug} repo={repo} failures=1 details=github_list_failed: {exc}")
        return 2

    for ref in pr_refs or []:
        number = int(ref["number"])
        try:
            pr = gh_json(
                [
                    "gh",
                    "pr",
                    "view",
                    str(number),
                    "--repo",
                    repo,
                    "--json",
                    "number,title,url,headRefName,headRefOid,isDraft,mergeable,mergeStateStatus,reviewDecision,statusCheckRollup,latestReviews,updatedAt,body",
                ]
            )
            open_pr_details.append(pr)
            threads = review_thread_summary(repo, number)
        except Exception as exc:
            failures.append(f"pr#{number}:inspect_failed:{exc}")
            continue

        check_state, check_details = check_rollup(pr)
        title = pr.get("title") or ""
        merge_state = pr.get("mergeStateStatus") or "UNKNOWN"
        mergeable = pr.get("mergeable") or "UNKNOWN"
        if is_portfolio_pr(pr, vals):
            # Portfolio steward PRs are intentionally draft/owner-gated follow-up
            # plan artifacts. The maintainer lane must not auto-promote them or
            # keep requesting Codex reviews; that creates public comment loops.
            portfolio_owner_gated_prs.append(number)
            continue
        if pr.get("isDraft"):
            drafts.append(number)
            continue

        if threads["unresolved_current"]:
            sample = threads["samples"][0] if threads["samples"] else {}
            alerts.append(
                "PR#{n} blocked_by_current_review_threads count={count} state={state} ci={ci} sample={path}:{line} {url}".format(
                    n=number,
                    count=threads["unresolved_current"],
                    state=merge_state,
                    ci=check_state,
                    path=sample.get("path") or "?",
                    line=sample.get("line") or "?",
                    url=sample.get("url") or pr.get("url"),
                )
            )
            continue

        if check_state in {"failed", "pending"}:
            alerts.append(f"PR#{number} checks_{check_state} details={','.join(check_details[:5]) or 'unknown'}")
            continue

        if merge_state in BLOCKING_MERGE_STATES and merge_state != "CLEAN":
            latest_codex_commit = ""
            for review in pr.get("latestReviews") or []:
                author = (review.get("author") or {}).get("login") or ""
                if codex_login(author):
                    latest_codex_commit = ((review.get("commit") or {}).get("oid") or "")[:10]
            head = str(pr.get("headRefOid") or "")[:10]
            if mergeable == "CONFLICTING" or merge_state == "DIRTY":
                alerts.append(
                    f"PR#{number} merge_conflict merge_state={merge_state} mergeable={mergeable} ci={check_state} unresolved_current=0 url={pr.get('url')}"
                )
            elif check_state == "success" and latest_codex_commit != head:
                latest_display = latest_codex_commit or "none"
                alerts.append(
                    f"PR#{number} awaiting_latest_codex_review head={head} latest_codex={latest_display} mergeable={mergeable} ci={check_state} unresolved_current=0 url={pr.get('url')}"
                )
            else:
                alerts.append(
                    f"PR#{number} merge_state_{merge_state.lower()} mergeable={mergeable} ci={check_state} unresolved_current=0 url={pr.get('url')}"
                )
            continue

        if merge_state == "CLEAN" and mergeable == "MERGEABLE" and check_state in {"success", "none"}:
            head = str(pr.get("headRefOid") or "")
            human_logins = set(review_policy["human_reviewer_logins"]) if review_policy else set()
            codex = codex_review_status(
                repo,
                number,
                head,
                human_reviewer_logins=human_logins,
            )
            if codex["clean_current"]:
                codex_clean_prs.append(number)
                if review_policy is None:
                    continue
                try:
                    role_receipts = (
                        load_role_review_receipts(
                            Path(vals.get("BOT_HERMES_HOME") or "") / "private" / "review-receipts",
                            repository=repo,
                            pr_number=number,
                            head_sha=head,
                            policy_sha256=review_policy["policy_sha256"],
                        )
                        if review_policy["enabled"]
                        else []
                    )
                    quorum = evaluate_review_quorum(
                        policy=review_policy,
                        repository=repo,
                        pr_number=number,
                        head_sha=head,
                        evidence={
                            "tests": {
                                "head_sha": head,
                                "status": "success" if check_state == "success" else "missing",
                                "evidence_sha256": sha256_json(
                                    {"head_sha": head, "state": check_state, "details": check_details}
                                ),
                            },
                            "codex": {
                                "head_sha": head,
                                "status": "clean",
                                "evidence_sha256": codex["evidence_sha256"],
                            },
                            "role_reviews": role_receipts,
                            "human_reviews": codex.get("human_reviews") or [],
                        },
                    )
                except ReviewQuorumError as exc:
                    quorum = {"merge_ready": False, "reasons": [f"review_quorum_invalid:{exc}"]}
                if quorum["merge_ready"]:
                    clean_candidates.append(number)
                    merge_ready_evidence.append(
                        {
                            "pr": number,
                            "head_sha": head,
                            "quorum_sha256": quorum["quorum_sha256"],
                            "policy_sha256": quorum["policy_sha256"],
                        }
                    )
                else:
                    alerts.append(
                        f"PR#{number} review_quorum_blocked head={head[:10]} reasons={','.join(quorum['reasons'])} url={pr.get('url')}"
                    )
            elif codex["pending_trigger"]:
                codex_pending_prs.append(number)
            else:
                codex_awaiting_prs.append(number)
                alerts.append(f"PR#{number} awaiting_latest_codex_review {codex['status']} mergeable={mergeable} ci={check_state} unresolved_current=0 url={pr.get('url')}")

    ready_issues: list[int] = []
    covered_ready_issues: list[int] = []
    deferred_ready_issues: list[int] = []
    retry_due_issues: list[int] = []
    dependency_blocked_issues: list[dict] = []
    satisfied_dependency_issues: list[dict] = []
    untriaged_actionable_issues: list[int] = []
    triage_needed_issues: list[int] = []
    ignored_open_issues: list[int] = []
    ready_label_set = configured_ready_labels(vals)
    triage_label = configured_triage_label(vals)
    open_issue_numbers = {int(i.get("number") or 0) for i in issue_refs or [] if i.get("number")}
    dependency_numbers_to_lookup: set[int] = set()
    for item in issue_refs or []:
        if not (label_names(item) & ready_label_set):
            continue
        issue_number = int(item.get("number") or 0)
        for dep in dependency_numbers(item.get("body") or ""):
            if dep != issue_number and dep in open_issue_numbers:
                dependency_numbers_to_lookup.add(dep)
    satisfied_dependency_prs = merged_dependency_prs(repo, dependency_numbers_to_lookup)
    for item in issue_refs or []:
        labels = label_names(item)
        if labels & ready_label_set:
            if issue_is_covered_by_pr(item, open_pr_details):
                covered_ready_issues.append(int(item["number"]))
                continue
            deps, satisfied = dependency_status(item, open_issue_numbers, satisfied_dependency_prs)
            if satisfied:
                satisfied_dependency_issues.append({"issue": int(item["number"]), "satisfied_by": satisfied})
            if deps:
                dependency_blocked_issues.append({"issue": int(item["number"]), "depends_on": deps})
                continue
            state, _ = deferral_state(vals, item)
            if state.startswith("deferred_"):
                deferred_ready_issues.append(int(item["number"]))
            else:
                ready_issues.append(int(item["number"]))
                if state.startswith("retry_due") or state == "ready_issue_updated_since_defer":
                    retry_due_issues.append(int(item["number"]))
        elif triage_label in labels:
            triage_needed_issues.append(int(item["number"]))
        else:
            reason = actionable_untriaged_reason(item)
            if reason:
                untriaged_actionable_issues.append(int(item["number"]))
            else:
                ignored_open_issues.append(int(item["number"]))

    if untriaged_actionable_issues:
        alerts.append(f"untriaged_actionable_issues={untriaged_actionable_issues} reason=acceptance_criteria")
    if triage_needed_issues:
        alerts.append(f"triage_needed_issues={triage_needed_issues}")
    alerts.extend(managed_checkout_alerts(vals))
    blocked_cycle_active_issue_numbers = open_issue_numbers - set(covered_ready_issues)
    blocked_forge_cycles = recent_blocked_forge_cycle_alerts(vals, blocked_cycle_active_issue_numbers)
    alerts.extend(blocked_forge_cycles)

    action_board = queue_action_board(
        clean_candidates=clean_candidates,
        codex_pending_prs=codex_pending_prs,
        codex_awaiting_prs=codex_awaiting_prs,
        drafts=drafts,
        portfolio_owner_gated_prs=portfolio_owner_gated_prs,
        failures=failures,
        alerts=alerts,
        untriaged_actionable_issues=untriaged_actionable_issues,
        triage_needed_issues=triage_needed_issues,
        ignored_open_issues=ignored_open_issues,
        blocked_forge_cycles=blocked_forge_cycles,
    )
    home = Path(vals.get("BOT_HERMES_HOME") or vals.get("HERMES_HOME") or "").expanduser()
    receipt_summaries = reconcile_receipt_summaries(
        recent_receipt_summaries(home / "state" / "forge-cycles"),
        open_issue_numbers=open_issue_numbers,
        open_pr_details=open_pr_details,
        codex_pending_prs=codex_pending_prs,
    )
    portfolio_receipt = read_receipt(home / "state" / "factory" / "portfolio-receipt.json")
    if portfolio_receipt:
        receipt_summaries.append(public_summary(portfolio_receipt))
    roadmap_candidates = list((portfolio_receipt.get("evidence") or {}).get("roadmap_candidates") or [])
    factory_loops = factory_loop_view(
        action_board,
        receipt_summaries=receipt_summaries,
        ready_issues=ready_issues,
        retry_due_issues=retry_due_issues,
        roadmap_candidates=roadmap_candidates,
    )
    notification = notification_meta(source="queue-health", instance=slug, repo=repo, action_board=action_board)

    details: list[str] = []
    if failures:
        details.extend(failures)
    if alerts:
        details.extend(alerts)
    if not details:
        details.append("ok")

    result = {
        "instance": slug,
        "repo": repo,
        "mutation_enabled": mutation_enabled,
        "open_prs": len(pr_refs or []),
        "clean_candidates": clean_candidates,
        "merge_ready_evidence": merge_ready_evidence,
        "drafts": drafts,
        "portfolio_owner_gated_prs": portfolio_owner_gated_prs,
        "codex_clean_prs": codex_clean_prs,
        "codex_pending_prs": codex_pending_prs,
        "codex_awaiting_prs": codex_awaiting_prs,
        "ready_issues": ready_issues,
        "covered_ready_issues": covered_ready_issues,
        "deferred_ready_issues": deferred_ready_issues,
        "retry_due_issues": retry_due_issues,
        "dependency_blocked_issues": dependency_blocked_issues,
        "satisfied_dependency_issues": satisfied_dependency_issues,
        "untriaged_actionable_issues": untriaged_actionable_issues,
        "triage_needed_issues": triage_needed_issues,
        "ignored_open_issues": ignored_open_issues,
        "blocked_forge_cycles": blocked_forge_cycles,
        "action_board": action_board,
        "factory_loops": factory_loops,
        "factory_receipts": receipt_summaries,
        "notification": notification,
        "blockers": len(alerts),
        "failures": len(failures),
        "details": details,
    }
    if "--json" in sys.argv[1:]:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            "john-lomein queue health: "
            f"instance={slug} repo={repo} mutation_enabled={int(mutation_enabled)} "
            f"open_prs={len(pr_refs or [])} clean_candidates={clean_candidates} drafts={drafts} portfolio_owner_gated_prs={portfolio_owner_gated_prs} "
            f"codex_clean_prs={codex_clean_prs} codex_pending_prs={codex_pending_prs} codex_awaiting_prs={codex_awaiting_prs} "
            f"ready_issues={ready_issues} covered_ready_issues={covered_ready_issues} deferred_ready_issues={deferred_ready_issues} retry_due_issues={retry_due_issues} dependency_blocked_issues={dependency_blocked_issues} satisfied_dependency_issues={satisfied_dependency_issues} blocked_forge_cycles={blocked_forge_cycles} blockers={len(alerts)} failures={len(failures)} "
            f"untriaged_actionable_issues={untriaged_actionable_issues} triage_needed_issues={triage_needed_issues} ignored_open_issues={ignored_open_issues} "
            f"action_board={json.dumps(action_board, sort_keys=True)} factory_loops={json.dumps(factory_loops, sort_keys=True)} notification={json.dumps(notification, sort_keys=True)} "
            f"details={' | '.join(details)}"
        )
    if failures:
        return 2
    if alerts:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
