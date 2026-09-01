#!/usr/bin/env python3
"""Prepare human-gated compounded release bundles for john-lomein.

This script does not merge or publish by default. It reconstructs live PR state,
finds latest-head clean PRs, writes a durable bundle packet, and posts a compact
owner gate signal. Dangerous actions require a separate explicit approval path
outside scheduled cron.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_comment_templates import format_release_bundle
from john_lomein_owner_actions import (
    notification_meta,
    publish_workflow_contract,
    RELEASE_BUNDLE_V5_SCHEMA,
    release_bundle_action_board,
    release_bundle_changed_paths_digest,
    release_bundle_digest,
    release_bundle_id_from_digest,
    release_owner_approval_text,
    release_bundle_v5_content_digest,
)
from john_lomein_public_safety import sanitize_public_text
from john_lomein_review_quorum import ReviewQuorumError, current_human_review_evidence, evaluate_review_quorum, load_role_review_receipts, sha256_json, validate_normalized_review_quorum_policy

OK_CONCLUSIONS = {"SUCCESS", "SKIPPED", "NEUTRAL"}
CODEX_AUTHORS = {"chatgpt-codex-connector", "chatgpt-codex-connector[bot]"}
CONTROLLED_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
SAFE_BUNDLE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
AUTHOR_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}(?:\[bot\])?)?$"
)
DEFAULT_BUNDLE_TTL_SECONDS = 60 * 60
MAX_PAGINATION_PAGES = 1000
MAX_RELEASE_PRS = 50
MAX_CHANGED_PATHS_PER_PR = 2000
MAX_CHANGED_PATH_BYTES = 1024
MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991
CRITICAL_RISK_PREFIXES = (
    ".github/workflows/",
    ".github/CODEOWNERS",
    "broker/",
    "scripts/install-protected-broker",
    "scripts/uninstall-protected-broker",
    "scripts/john-lomein-release-",
    "scripts/john_lomein_autonomy.py",
    "scripts/john_lomein_owner_actions.py",
)
HIGH_RISK_NAMES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "uv.lock",
    "pyproject.toml",
    "requirements.txt",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
}
HIGH_RISK_COMPONENTS = {
    "auth",
    "authentication",
    "authorization",
    "credential",
    "credentials",
    "infra",
    "migration",
    "migrations",
    "permission",
    "permissions",
    "secret",
    "secrets",
    "security",
}
SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
}


def utc_from_epoch(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def parse_env(path: Path) -> dict[str, str]:
    vals: dict[str, str] = {}
    if path.exists():
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            try:
                parts = shlex.split(v)
                vals[k.strip()] = parts[0] if parts else ""
            except Exception:
                vals[k.strip()] = v.strip().strip("'").strip('"')
    return vals


def runtime_home_from_script_or_env() -> Path:
    deployed_env = SCRIPT_DIR / "john-lomein-instance.env"
    if deployed_env.exists():
        return SCRIPT_DIR.parent.resolve()
    raw = os.environ.get("BOT_HERMES_HOME") or os.environ.get("HERMES_HOME") or ""
    if not raw:
        raise RuntimeError("release_bundler_missing_runtime_home")
    return Path(raw).expanduser().resolve()


def load_env() -> dict[str, str]:
    H = runtime_home_from_script_or_env()
    expected_env = (H / "scripts" / "john-lomein-instance.env").resolve()
    requested_raw = os.environ.get("JOHN_LOMEIN_INSTANCE_ENV")
    if requested_raw:
        requested = Path(requested_raw).expanduser().resolve()
        if requested != expected_env:
            raise RuntimeError("release_bundler_refuses_non_deployed_instance_env")
    if not expected_env.exists():
        raise RuntimeError(f"release_bundler_missing_instance_env:{expected_env}")
    vals = parse_env(expected_env)
    vals["BOT_HERMES_HOME"] = str(H)
    vals["HERMES_HOME"] = str(H)
    vals.pop("MNEMOSYNE_DATA_DIR", None)
    return vals


def runtime_review_quorum_policy(env: dict[str, str]) -> dict:
    raw = str(env.get("BOT_REVIEW_QUORUM_POLICY_JSON") or "").strip()
    if not raw:
        raise ReviewQuorumError("review quorum runtime policy is missing")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReviewQuorumError("review quorum runtime policy is invalid") from exc
    return validate_normalized_review_quorum_policy(value)


def gh_env(env: dict[str, str]) -> dict[str, str]:
    H = Path(env["BOT_HERMES_HOME"])
    profile = env.get("BOT_MAINTAINER_PROFILE", "john-lomein-maintainer")
    profile_home = H / "profiles" / profile / "home"
    gh_config = profile_home / ".config" / "gh"
    out = dict(env)
    out.pop("GH_CONFIG_DIR", None)
    out.pop("MNEMOSYNE_DATA_DIR", None)
    out["PATH"] = CONTROLLED_PATH
    out.update({
        "HERMES_HOME": str(H),
        "BOT_HERMES_HOME": str(H),
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
    })
    if profile_home.exists():
        out["HOME"] = str(profile_home)
    if gh_config.exists():
        out["GH_CONFIG_DIR"] = str(gh_config)
    return out


def run(cmd: list[str], *, env: dict[str, str], cwd: str | None = None, timeout: int = 60) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=cwd, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:
        return 999, "", str(exc)


def gh_json(cmd: list[str], *, env: dict[str, str], timeout: int = 60):
    c, o, e = run(cmd, env=env, timeout=timeout)
    if c != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {e or o}")
    return json.loads(o or "null")


def default_branch_oid(env: dict[str, str]) -> str:
    repo = env["BOT_REPO"]
    branch = env.get("BOT_DEFAULT_BRANCH", "main")
    ref = gh_json(
        ["gh", "api", f"repos/{repo}/git/ref/heads/{quote(branch, safe='')}"],
        env=gh_env(env),
        timeout=60,
    )
    oid = str(((ref or {}).get("object") or {}).get("sha") or "").lower()
    if not OID_RE.fullmatch(oid):
        raise RuntimeError(f"default_branch_oid_missing:{branch}")
    return oid


def repository_identity(env: dict[str, str]) -> dict[str, object]:
    repo = str(env.get("BOT_REPO") or "")
    default_branch = str(env.get("BOT_DEFAULT_BRANCH") or "main")
    if not REPOSITORY_RE.fullmatch(repo):
        raise RuntimeError("release_bundle_repository_invalid")
    if (
        not BRANCH_RE.fullmatch(default_branch)
    ):
        raise RuntimeError("release_bundle_default_branch_invalid")
    raw_id = str(env.get("BOT_REPO_ID") or "").strip()
    if raw_id:
        if (
            not raw_id.isascii()
            or not raw_id.isdigit()
            or int(raw_id) <= 0
            or int(raw_id) > MAX_SAFE_JSON_INTEGER
        ):
            raise RuntimeError("release_bundle_repository_id_invalid")
        repository_id = int(raw_id)
    else:
        metadata = gh_json(
            ["gh", "api", f"repos/{repo}"],
            env=gh_env(env),
            timeout=60,
        )
        if not isinstance(metadata, dict):
            raise RuntimeError("release_bundle_repository_metadata_invalid")
        repository_id = metadata.get("id")
        if (
            isinstance(repository_id, bool)
            or not isinstance(repository_id, int)
            or repository_id <= 0
            or repository_id > MAX_SAFE_JSON_INTEGER
        ):
            raise RuntimeError("release_bundle_repository_id_missing")
        if str(metadata.get("full_name") or "") != repo:
            raise RuntimeError("release_bundle_repository_name_mismatch")
        if str(metadata.get("default_branch") or "") != default_branch:
            raise RuntimeError("release_bundle_default_branch_mismatch")
    return {
        "full_name": repo,
        "id": repository_id,
        "default_branch": default_branch,
    }


def open_pull_request_numbers(repo: str, env: dict[str, str]) -> list[int]:
    owner, name = repo.split("/", 1)
    query = """
query($owner:String!, $repo:String!, $cursor:String) {
  repository(owner:$owner, name:$repo) {
    pullRequests(
      first:100
      after:$cursor
      states:OPEN
      orderBy:{field:CREATED_AT,direction:ASC}
    ) {
      nodes { number }
      pageInfo { hasNextPage endCursor }
    }
  }
}
"""
    numbers: list[int] = []
    seen_numbers: set[int] = set()
    seen_cursors: set[str] = set()
    cursor: str | None = None
    for _page in range(MAX_PAGINATION_PAGES):
        cmd = [
            "gh",
            "api",
            "graphql",
            "-f",
            f"owner={owner}",
            "-f",
            f"repo={name}",
            "-f",
            f"query={query}",
        ]
        if cursor is not None:
            cmd.extend(["-f", f"cursor={cursor}"])
        data = gh_json(cmd, env=gh_env(env), timeout=60)
        repository = (
            (data.get("data") or {}).get("repository")
            if isinstance(data, dict)
            and isinstance(data.get("data"), dict)
            else None
        )
        connection = (
            repository.get("pullRequests")
            if isinstance(repository, dict)
            else None
        )
        nodes = connection.get("nodes") if isinstance(connection, dict) else None
        page_info = (
            connection.get("pageInfo") if isinstance(connection, dict) else None
        )
        if (
            not isinstance(nodes, list)
            or not all(isinstance(node, dict) for node in nodes)
            or not isinstance(page_info, dict)
            or type(page_info.get("hasNextPage")) is not bool
        ):
            raise RuntimeError("open_prs_graphql_response_invalid")
        for node in nodes:
            number = node.get("number")
            if (
                isinstance(number, bool)
                or not isinstance(number, int)
                or number <= 0
            ):
                raise RuntimeError("open_pr_number_invalid")
            if number in seen_numbers:
                raise RuntimeError("open_pr_number_duplicate")
            seen_numbers.add(number)
            numbers.append(number)
        if not page_info["hasNextPage"]:
            return numbers
        next_cursor = page_info.get("endCursor")
        if (
            not isinstance(next_cursor, str)
            or not next_cursor
            or next_cursor in seen_cursors
        ):
            raise RuntimeError("open_prs_pagination_cursor_invalid")
        seen_cursors.add(next_cursor)
        cursor = next_cursor
    raise RuntimeError("open_prs_pagination_limit_exceeded")


def pull_request_changed_paths(
    repo: str,
    number: int,
    env: dict[str, str],
) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for page in range(1, MAX_PAGINATION_PAGES + 1):
        values = gh_json(
            [
                "gh",
                "api",
                f"repos/{repo}/pulls/{number}/files?per_page=100&page={page}",
            ],
            env=gh_env(env),
            timeout=60,
        )
        if not isinstance(values, list) or not all(
            isinstance(item, dict) for item in values
        ):
            raise RuntimeError("pr_files_response_invalid")
        for item in values:
            path = item.get("filename")
            if not isinstance(path, str) or not path:
                raise RuntimeError("pr_file_path_invalid")
            if path in seen:
                raise RuntimeError("pr_file_path_duplicate")
            seen.add(path)
            paths.append(path)
        if len(values) < 100:
            return sorted(paths)
    raise RuntimeError("pr_files_pagination_limit_exceeded")


def pull_request_expected_merge_tree(
    repo: str,
    number: int,
    env: dict[str, str],
) -> str:
    """Return GitHub's stable test-merge tree for the exact base/head pair."""

    owner, name = repo.split("/", 1)
    query = """
query ReleaseBundlerPotentialMerge(
  $owner:String!,
  $repo:String!,
  $number:Int!
) {
  repository(owner:$owner, name:$repo) {
    databaseId
    nameWithOwner
    pullRequest(number:$number) {
      number
      headRefOid
      baseRefOid
      mergeable
      potentialMergeCommit {
        oid
        tree { oid }
        parents(first:2) {
          totalCount
          nodes { oid }
          pageInfo { hasNextPage endCursor }
        }
      }
    }
  }
}
"""
    data = gh_json(
        [
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
        ],
        env=gh_env(env),
        timeout=60,
    )
    repository = (
        (data.get("data") or {}).get("repository")
        if isinstance(data, dict)
        else None
    )
    pull_request = (
        repository.get("pullRequest")
        if isinstance(repository, dict)
        else None
    )
    configured_id = str(env.get("BOT_REPO_ID") or "")
    if configured_id and (
        not configured_id.isascii()
        or not configured_id.isdigit()
        or int(configured_id) <= 0
    ):
        raise RuntimeError("pr_potential_merge_repository_id_invalid")
    configured_repository_id = int(configured_id) if configured_id else None
    if (
        not isinstance(repository, dict)
        or repository.get("nameWithOwner") != repo
        or (
            configured_repository_id is not None
            and repository.get("databaseId")
            != configured_repository_id
        )
        or not isinstance(pull_request, dict)
        or pull_request.get("number") != number
        or pull_request.get("mergeable") != "MERGEABLE"
    ):
        raise RuntimeError("pr_potential_merge_identity_invalid")
    head_oid = str(pull_request.get("headRefOid") or "").lower()
    base_oid = str(pull_request.get("baseRefOid") or "").lower()
    potential = pull_request.get("potentialMergeCommit")
    if (
        not OID_RE.fullmatch(head_oid)
        or not OID_RE.fullmatch(base_oid)
        or not isinstance(potential, dict)
        or not OID_RE.fullmatch(str(potential.get("oid") or "").lower())
    ):
        raise RuntimeError("pr_potential_merge_commit_unavailable")
    tree = potential.get("tree")
    tree_oid = (
        str(tree.get("oid") or "").lower()
        if isinstance(tree, dict)
        else ""
    )
    parents = potential.get("parents")
    if not isinstance(parents, dict):
        raise RuntimeError("pr_potential_merge_parents_invalid")
    nodes = parents.get("nodes")
    page_info = parents.get("pageInfo")
    parent_oids = (
        [str(node.get("oid") or "").lower() for node in nodes]
        if isinstance(nodes, list)
        and all(isinstance(node, dict) for node in nodes)
        else []
    )
    if (
        not OID_RE.fullmatch(tree_oid)
        or parents.get("totalCount") != 2
        or parent_oids != [base_oid, head_oid]
        or not isinstance(page_info, dict)
        or page_info.get("hasNextPage") is not False
        or page_info.get("endCursor") is not None
    ):
        raise RuntimeError("pr_potential_merge_tree_invalid")
    return tree_oid


def check_state(pr: dict) -> tuple[str, list[str]]:
    rollup = pr.get("statusCheckRollup") or []
    if not rollup:
        return "none", []
    bad: list[str] = []
    pending: list[str] = []
    for check in rollup:
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


def unresolved_threads(repo: str, number: int, env: dict[str, str]) -> dict:
    owner, name = repo.split("/", 1)
    query = """
query($owner:String!, $repo:String!, $number:Int!, $cursor:String) {
  repository(owner:$owner, name:$repo) {
    pullRequest(number:$number) {
      reviewThreads(first:100, after:$cursor) {
        nodes { id isResolved isOutdated }
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
        data = gh_json(cmd, env=env, timeout=60)
        pull_request = (
            ((data.get("data") or {}).get("repository") or {}).get(
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
    unresolved = [n for n in nodes if not n.get("isResolved")]
    current = [n for n in unresolved if not n.get("isOutdated")]
    return {"total": len(nodes), "unresolved": len(unresolved), "unresolved_current": len(current)}


def latest_codex_head(pr: dict) -> str:
    head = str(pr.get("headRefOid") or "")
    for review in pr.get("latestReviews") or []:
        author = ((review.get("author") or {}).get("login") or "")
        if author == "chatgpt-codex-connector":
            return str(((review.get("commit") or {}).get("oid") or ""))
    return ""


def reviewed_commit(body: str) -> str:
    import re

    match = re.search(r"Reviewed commit[^0-9a-fA-F]*([0-9a-fA-F]{7,40})", body or "", re.I)
    return match.group(1).lower() if match else ""


def codex_review_status(
    repo: str,
    number: int,
    head: str,
    env: dict[str, str],
    *,
    human_reviewer_logins: set[str] | frozenset[str] = frozenset(),
) -> dict:
    head = (head or "").lower()
    head10 = head[:10]
    if re.fullmatch(r"[0-9a-f]{40}", head) is None:
        return {"clean_current": False, "pending_trigger": False, "status": "invalid_head", "human_reviews": [], "evidence_sha256": sha256_json({"status": "invalid_head", "head_sha": head})}
    artifacts: list[dict] = []
    triggers: list[dict] = []
    lookup_errors: list[str] = []
    try:
        comments = gh_json(["gh", "api", f"repos/{repo}/issues/{number}/comments", "--paginate"], env=gh_env(env), timeout=60) or []
    except Exception as exc:
        comments = []
        lookup_errors.append(f"comments:{exc}")
    for item in comments:
        body = item.get("body") or ""
        login = ((item.get("user") or {}).get("login") or "")
        created = item.get("created_at") or ""
        if login in CODEX_AUTHORS:
            commit = reviewed_commit(body)
            lowered = body.lower()
            clean = "didn't find any major issues" in lowered and "automated review suggestions" not in lowered
            artifacts.append({"created_at": created, "commit": commit, "reviewed": clean, "clean": clean})
        elif "@codex review" in body.lower():
            triggers.append({"created_at": created})
    try:
        reviews = gh_json(["gh", "api", f"repos/{repo}/pulls/{number}/reviews", "--paginate"], env=gh_env(env), timeout=60) or []
    except Exception as exc:
        reviews = []
        lookup_errors.append(f"reviews:{exc}")
    if lookup_errors:
        return {
            "clean_current": False,
            "pending_trigger": False,
            "status": "lookup_failed " + ";".join(lookup_errors),
            "human_reviews": [],
            "evidence_sha256": sha256_json({"status": "lookup_failed", "head_sha": head}),
        }
    for item in reviews:
        body = item.get("body") or ""
        login = ((item.get("user") or {}).get("login") or "")
        if login in CODEX_AUTHORS:
            commit = (item.get("commit_id") or reviewed_commit(body) or "").lower()
            clean = "didn't find any major issues" in body.lower() and "automated review suggestions" not in body.lower()
            artifacts.append({"created_at": item.get("submitted_at") or "", "commit": commit, "reviewed": bool(commit), "clean": clean})
    current_artifacts = [a for a in artifacts if str(a.get("commit") or "").lower() == head]
    latest_current = max(current_artifacts, key=lambda a: a.get("created_at") or "", default={})
    clean_current = bool(latest_current.get("clean"))
    latest_artifact_at = max([a.get("created_at") or "" for a in artifacts] or [""])
    latest_trigger_at = max([t.get("created_at") or "" for t in triggers] or [""])
    pending_trigger = bool(latest_trigger_at and latest_trigger_at > latest_artifact_at and not clean_current)
    if clean_current:
        status = "clean_current"
    elif pending_trigger:
        status = "pending_trigger"
    elif current_artifacts:
        status = f"current_head_not_clean head={head10}"
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
        {"status": status, "head_sha": head, "latest_artifact_at": latest_artifact_at}
    )
    return {
        "clean_current": clean_current,
        "pending_trigger": pending_trigger,
        "status": status,
        "human_reviews": human_reviews,
        "evidence_sha256": evidence_sha256,
    }


def clean_candidates(env: dict[str, str]) -> tuple[list[dict], list[str]]:
    repo = env["BOT_REPO"]
    review_policy = runtime_review_quorum_policy(env)
    refs = open_pull_request_numbers(repo, env)
    clean: list[dict] = []
    blockers: list[str] = []
    for n in refs:
        try:
            pr = gh_json(
                [
                    "gh",
                    "pr",
                    "view",
                    str(n),
                    "--repo",
                    repo,
                    "--json",
                    "number,title,url,author,headRefName,headRefOid,baseRefName,baseRefOid,isDraft,mergeable,mergeStateStatus,reviewDecision,statusCheckRollup,latestReviews",
                ],
                env=gh_env(env),
                timeout=60,
            )
            if not isinstance(pr, dict) or pr.get("number") != n:
                raise RuntimeError("pr_view_response_invalid")
            pr["changed_paths"] = pull_request_changed_paths(repo, n, env)
            pr["expected_merge_tree_sha"] = (
                pull_request_expected_merge_tree(repo, n, env)
            )
            threads = unresolved_threads(repo, n, gh_env(env))
        except Exception as exc:
            blockers.append(f"PR#{n}: inspect_failed:{exc}")
            continue
        ci, ci_details = check_state(pr)
        if pr.get("isDraft"):
            blockers.append(f"PR#{n}: draft")
            continue
        if threads["unresolved_current"]:
            blockers.append(f"PR#{n}: unresolved_current_threads={threads['unresolved_current']}")
            continue
        if ci not in {"success", "none"}:
            blockers.append(f"PR#{n}: checks_{ci}:{','.join(ci_details[:3])}")
            continue
        if pr.get("mergeStateStatus") != "CLEAN" or pr.get("mergeable") != "MERGEABLE":
            blockers.append(f"PR#{n}: merge_state={pr.get('mergeStateStatus')} mergeable={pr.get('mergeable')}")
            continue
        head = str(pr.get("headRefOid") or "")
        codex = codex_review_status(
            repo,
            n,
            head,
            env,
            human_reviewer_logins=set(review_policy["human_reviewer_logins"]),
        )
        # Current-head Codex evidence is required for release bundle owner gates.
        # Human approval alone must not make a coding PR merge-ready.
        if not codex["clean_current"]:
            blockers.append(f"PR#{n}: codex_{codex['status']}")
            continue
        try:
            role_receipts = (
                load_role_review_receipts(
                    Path(env["BOT_HERMES_HOME"]) / "private" / "review-receipts",
                    repository=repo,
                    pr_number=n,
                    head_sha=head,
                    policy_sha256=review_policy["policy_sha256"],
                )
                if review_policy["enabled"]
                else []
            )
            quorum = evaluate_review_quorum(
                policy=review_policy,
                repository=repo,
                pr_number=n,
                head_sha=head,
                evidence={
                    "tests": {
                        "head_sha": head,
                        "status": "success" if ci == "success" else "missing",
                        "evidence_sha256": sha256_json(
                            {"head_sha": head, "state": ci, "details": ci_details}
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
            blockers.append(f"PR#{n}: review_quorum_invalid:{exc}")
            continue
        if not quorum["merge_ready"]:
            blockers.append(f"PR#{n}: review_quorum_{','.join(quorum['reasons'])}")
            continue
        pr["review_quorum"] = {
            "head_sha": head,
            "quorum_sha256": quorum["quorum_sha256"],
            "policy_sha256": quorum["policy_sha256"],
        }
        clean.append(pr)
    return clean, blockers


def validate_bundle_id(bundle_id: str) -> str:
    value = str(bundle_id or "")
    if not value or not SAFE_BUNDLE_ID_RE.match(value):
        raise ValueError(f"unsafe_bundle_id:{value or '<empty>'}")
    return value


def private_bundle_root(env: dict[str, str]) -> Path:
    root = Path(env["BOT_HERMES_HOME"]) / "private" / "release-bundles"
    if root.is_symlink():
        raise RuntimeError("release_bundle_root_symlink")
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("release_bundle_root_invalid")
    root.chmod(0o700)
    return root


def bundle_paths(env: dict[str, str], bundle_id: str) -> tuple[Path, Path]:
    bundle_id = validate_bundle_id(bundle_id)
    root = private_bundle_root(env)
    return root / f"{bundle_id}.json", root / f"{bundle_id}.md"


def atomic_write_private(path: Path, text: str) -> None:
    path = Path(os.path.abspath(path))
    root = path.parent
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("release_bundle_output_parent_invalid")
    fd = -1
    temporary = ""
    try:
        fd, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=str(root),
            text=False,
        )
        os.fchmod(fd, 0o600)
        data = text.encode("utf-8")
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("release_bundle_atomic_write_short")
            offset += written
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        temporary = ""
        directory_flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            directory_flags |= os.O_DIRECTORY
        directory_fd = os.open(root, directory_flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def release_bundle_window(env: dict[str, str]) -> tuple[str, str]:
    raw_ttl = str(
        env.get("BOT_RELEASE_BUNDLE_TTL_SECONDS")
        or DEFAULT_BUNDLE_TTL_SECONDS
    ).strip()
    if not raw_ttl.isascii() or not raw_ttl.isdigit():
        raise RuntimeError("release_bundle_ttl_invalid")
    ttl_seconds = int(raw_ttl)
    if ttl_seconds < 60 or ttl_seconds > 24 * 60 * 60:
        raise RuntimeError("release_bundle_ttl_out_of_range")
    now = int(time.time())
    return utc_from_epoch(now), utc_from_epoch(now + ttl_seconds)


def normalize_changed_paths(pr: dict) -> list[str]:
    raw_paths = pr.get("changed_paths")
    if raw_paths is None:
        raw_paths = [
            item.get("path") if isinstance(item, dict) else item
            for item in (pr.get("files") or [])
        ]
    if not isinstance(raw_paths, list):
        raise RuntimeError("release_bundle_changed_paths_invalid")
    if len(raw_paths) > MAX_CHANGED_PATHS_PER_PR:
        raise RuntimeError("release_bundle_changed_paths_too_many")
    paths: list[str] = []
    seen: set[str] = set()
    for raw_path in raw_paths:
        if not isinstance(raw_path, str):
            raise RuntimeError("release_bundle_changed_path_invalid")
        path = raw_path
        parts = path.split("/")
        if (
            not path
            or path.startswith("/")
            or path.startswith("./")
            or path.endswith("/")
            or "\\" in path
            or "\x00" in path
            or len(path.encode("utf-8")) > MAX_CHANGED_PATH_BYTES
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise RuntimeError("release_bundle_changed_path_invalid")
        if path in seen:
            raise RuntimeError("release_bundle_changed_path_duplicate")
        seen.add(path)
        paths.append(path)
    return sorted(paths)


def risk_class_for_paths(paths: list[str]) -> str:
    lowered = [path.lower() for path in paths]
    if any(
        path == prefix or path.startswith(prefix)
        for path in lowered
        for prefix in (value.lower() for value in CRITICAL_RISK_PREFIXES)
    ):
        return "critical"
    if any(
        Path(path).name.lower() in HIGH_RISK_NAMES
        or any(component in HIGH_RISK_COMPONENTS for component in path.split("/"))
        for path in lowered
    ):
        return "high"
    has_source = any(
        Path(path).suffix.lower() in SOURCE_SUFFIXES
        and not any(
            component in {"test", "tests", "__tests__"}
            for component in path.split("/")
        )
        for path in lowered
    )
    has_tests = any(
        any(
            component in {"test", "tests", "__tests__"}
            for component in path.split("/")
        )
        or Path(path).name.startswith("test_")
        for path in lowered
    )
    if len(paths) > 20 or (has_source and not has_tests):
        return "medium"
    return "low"


def ordered_pr_contract(
    clean: list[dict],
    *,
    repository_full_name: str,
    default_branch: str,
) -> list[dict[str, object]]:
    if not clean or len(clean) > MAX_RELEASE_PRS:
        raise RuntimeError("release_bundle_ordered_prs_invalid")
    ordered: list[dict[str, object]] = []
    seen_numbers: set[int] = set()
    for position, pr in enumerate(clean):
        if not isinstance(pr, dict):
            raise RuntimeError("release_bundle_pr_invalid")
        number = pr.get("number")
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or number <= 0
            or number > 2**31 - 1
        ):
            raise RuntimeError("release_bundle_pr_number_invalid")
        if number in seen_numbers:
            raise RuntimeError("release_bundle_pr_number_duplicate")
        seen_numbers.add(number)
        head_sha = str(pr.get("headRefOid") or "").lower()
        if not OID_RE.fullmatch(head_sha):
            raise RuntimeError(f"release_bundle_pr_head_invalid:{number}")
        expected_merge_tree_sha = str(
            pr.get("expected_merge_tree_sha") or ""
        ).lower()
        if not OID_RE.fullmatch(expected_merge_tree_sha):
            raise RuntimeError(
                f"release_bundle_pr_expected_merge_tree_invalid:{number}"
            )
        base_branch = str(pr.get("baseRefName") or "")
        if base_branch != default_branch:
            raise RuntimeError(f"release_bundle_pr_base_invalid:{number}")
        url = str(pr.get("url") or "")
        if url != (
            f"https://github.com/{repository_full_name}/pull/{number}"
        ):
            raise RuntimeError(f"release_bundle_pr_url_invalid:{number}")
        author_raw = pr.get("author")
        author_login = str(
            pr.get("author_login")
            or (
                author_raw.get("login")
                if isinstance(author_raw, dict)
                else ""
            )
            or ""
        )
        if (
            not AUTHOR_RE.fullmatch(author_login)
        ):
            raise RuntimeError(f"release_bundle_pr_author_invalid:{number}")
        quorum = pr.get("review_quorum")
        if not isinstance(quorum, dict) or set(quorum) != {"head_sha", "quorum_sha256", "policy_sha256"}:
            raise RuntimeError(f"release_bundle_pr_quorum_invalid:{number}")
        if str(quorum.get("head_sha") or "").lower() != head_sha:
            raise RuntimeError(f"release_bundle_pr_quorum_head_invalid:{number}")
        if any(re.fullmatch(r"sha256:[0-9a-f]{64}", str(quorum.get(key) or "")) is None for key in ("quorum_sha256", "policy_sha256")):
            raise RuntimeError(f"release_bundle_pr_quorum_digest_invalid:{number}")
        paths = normalize_changed_paths(pr)
        ordered.append(
            {
                "position": position,
                "number": number,
                "url": url,
                "head_sha": head_sha,
                "expected_merge_tree_sha": expected_merge_tree_sha,
                "base_branch": base_branch,
                "author_login": author_login,
                "changed_paths": paths,
                "changed_paths_digest": release_bundle_changed_paths_digest(
                    paths
                ),
                "changed_path_count": len(paths),
                "risk_class": risk_class_for_paths(paths),
                "review_quorum_sha256": quorum["quorum_sha256"],
                "review_quorum_policy_sha256": quorum["policy_sha256"],
            }
        )
    return ordered


def post(env: dict[str, str], label: str, body: str) -> None:
    public_body = sanitize_public_text(body, limit=1750)
    script = Path(env["BOT_HERMES_HOME"]) / "scripts" / "john-lomein-overwatch-post.sh"
    if script.exists():
        subprocess.run(
            ["bash", str(script), label],
            input=public_body,
            text=True,
            env=gh_env(env),
            timeout=60,
            check=False,
        )
    else:
        print(f"{label}: {public_body}")


def publish_readiness(env: dict[str, str]) -> dict:
    local = Path(env.get("BOT_LOCAL") or "").expanduser()
    package_path = local / "package.json"
    workflow_name = str(env.get("BOT_PUBLISH_WORKFLOW") or "publish-npm.yml").strip()
    if Path(workflow_name).name != workflow_name or not workflow_name.endswith((".yml", ".yaml")):
        return {
            "package_json": str(package_path) if package_path.exists() else "",
            "publish_workflow": "",
            "publish_workflow_name": workflow_name,
            "package_name": "",
            "package_version": "",
            "npm_latest": "",
            "version_already_published": None,
            "publish_ready_after_merge": False,
            "blocker": "publish_workflow_name_invalid",
        }
    workflow_path = local / ".github" / "workflows" / workflow_name
    info = {
        "package_json": str(package_path) if package_path.exists() else "",
        "publish_workflow": str(workflow_path) if workflow_path.exists() else "",
        "publish_workflow_name": workflow_name,
        "package_name": "",
        "package_version": "",
        "npm_latest": "",
        "version_already_published": None,
        "publish_ready_after_merge": False,
        "blocker": "package_json_missing" if not package_path.exists() else "",
    }
    if package_path.exists():
        try:
            data = json.loads(package_path.read_text(encoding="utf-8"))
            info["package_name"] = str(data.get("name") or "")
            info["package_version"] = str(data.get("version") or "")
        except Exception as exc:
            info["blocker"] = f"package_json_unreadable:{exc}"
            return info
    if not workflow_path.exists():
        info["blocker"] = "publish_workflow_missing"
        return info
    contract = publish_workflow_contract(workflow_path)
    info.update({key: value for key, value in contract.items() if key != "blocker"})
    if contract.get("blocker"):
        info["blocker"] = str(contract["blocker"])
        return info
    if info["package_name"] and info["package_version"]:
        c, out, err = run(
            ["npm", "view", f"{info['package_name']}@{info['package_version']}", "version"],
            env=gh_env(env),
            cwd=str(local) if local.exists() else None,
            timeout=45,
        )
        if c == 0:
            info["npm_latest"] = out.strip().strip('"')
            info["version_already_published"] = True
            info["blocker"] = "package_version_already_published; prepare a version-bump/release-sync PR before npm publish"
        else:
            msg = (out + "\n" + err).lower()
            if "e404" in msg or "no match found" in msg or "could not be found" in msg or "not found" in msg:
                info["version_already_published"] = False
                info["registry_ready_after_merge"] = True
                info["publish_ready_after_merge"] = False
                info["blocker"] = "publish_requires_protected_broker"
            else:
                info["blocker"] = f"npm_view_failed:{(err or out)[:160]}"
    return info


def write_release_status(
    env: dict[str, str],
    blockers: list[str],
    signal: bool,
) -> str:
    """Persist queue status without creating an empty authorization bundle."""
    slug = str(env.get("BOT_SLUG") or "unknown")
    repo = str(env.get("BOT_REPO") or "")
    root = private_bundle_root(env)
    status_path = root / "release-status.md"
    action_board = release_bundle_action_board(
        bundle_id="",
        clean_prs=[],
        blockers=blockers,
    )
    notification = notification_meta(
        source="release-bundler",
        instance=slug,
        repo=repo,
        action_board=action_board,
    )
    lines = [
        "# john-lomein release status",
        "",
        f"Repo: `{repo}`",
        f"Observed: `{utc_from_epoch(int(time.time()))}`",
        "",
        "No protected release bundle was created because there are no eligible PRs.",
    ]
    if blockers:
        lines.extend(["", "Current blockers:"])
        lines.extend(f"- {blocker}" for blocker in blockers)
    atomic_write_private(status_path, "\n".join(lines) + "\n")
    fp = root / ".last-signaled"
    action_fp = root / ".last-owner-action-fingerprint"
    previous_action = (
        action_fp.read_text(encoding="utf-8") if action_fp.exists() else ""
    )
    if (
        signal
        and notification["should_notify"]
        and previous_action != notification["fingerprint"]
    ):
        post(env, "RELEASE_GATE", "\n".join(lines[4:]))
        atomic_write_private(fp, "release-status")
        atomic_write_private(
            action_fp,
            str(notification["fingerprint"]),
        )
    print(
        "john-lomein release bundle: "
        f"status_only repo={repo} blockers={len(blockers)} "
        f"status_file={status_path}"
    )
    return ""


def write_bundle(env: dict[str, str], clean: list[dict], blockers: list[str], signal: bool, *, target_base_oid: str = "") -> str:
    if not isinstance(clean, list) or not isinstance(blockers, list):
        raise RuntimeError("release_bundle_inputs_invalid")
    if not clean:
        return write_release_status(env, blockers, signal)
    slug = str(env.get("BOT_SLUG") or "unknown")
    repository = repository_identity(env)
    repo = str(repository["full_name"])
    default_branch = str(repository["default_branch"])
    initial_base_sha = str(
        target_base_oid or default_branch_oid(env)
    ).lower()
    if not OID_RE.fullmatch(initial_base_sha):
        raise RuntimeError("release_bundle_initial_base_sha_invalid")
    ordered_prs = ordered_pr_contract(
        clean,
        repository_full_name=repo,
        default_branch=default_branch,
    )
    created_at, expires_at = release_bundle_window(env)
    authority = {
        "schema_version": RELEASE_BUNDLE_V5_SCHEMA,
        "instance_slug": slug,
        "repository": repository,
        "created_at": created_at,
        "expires_at": expires_at,
        "initial_base_sha": initial_base_sha,
        "merge_method": "squash",
        "publish": False,
        "train_attestation_digest": None,
        "actions": {"merge": True, "publish": False},
        "ordered_prs": ordered_prs,
    }
    digest = release_bundle_v5_content_digest(authority)
    bundle_id = release_bundle_id_from_digest(digest)
    data = {
        **authority,
        "bundle_id": bundle_id,
        "bundle_digest": digest,
    }
    if release_bundle_digest(data) != digest:
        raise RuntimeError("release_bundle_v5_digest_roundtrip_failed")
    jpath, mpath = bundle_paths(env, bundle_id)
    publish = publish_readiness(env)
    changes_package_json = any(
        path == "package.json"
        for item in ordered_prs
        for path in item["changed_paths"]
    )
    if changes_package_json and str(publish.get("blocker") or "").startswith(
        "package_version_already_published"
    ):
        publish = dict(publish)
        publish["publish_ready_after_merge"] = False
        publish["registry_readiness_conditional_after_merge"] = True
        publish["conditional_after_merge"] = True
        publish["blocker"] = "publish_requires_protected_broker"
        publish["premerge_note"] = (
            "bundle changes package.json; registry readiness remains conditional on the post-merge version, "
            "and live publish remains blocked pending a protected broker"
        )
    publish = dict(publish)
    publish["publish_ready_after_merge"] = False
    publish["blocker"] = str(
        publish.get("blocker") or "publish_requires_protected_broker"
    )
    approval = release_owner_approval_text(data)
    if not approval:
        raise RuntimeError("release_owner_approval_text_unavailable")
    action_board = release_bundle_action_board(
        bundle_id=bundle_id,
        clean_prs=clean,
        blockers=blockers,
    )
    notification = notification_meta(
        source="release-bundler",
        instance=slug,
        repo=repo,
        action_board=action_board,
    )
    atomic_write_private(
        jpath,
        json.dumps(data, indent=2, sort_keys=True) + "\n",
    )
    bundle_body = format_release_bundle(
        bundle_id=bundle_id,
        clean_prs=clean,
        blockers=blockers,
        publish_readiness=publish,
        approval_text=approval,
        trusted_approver_required=True,
    )
    atomic_write_private(
        mpath,
        "\n".join(
            [
                f"# john-lomein release bundle `{bundle_id}`",
                "",
                f"Repo: `{repo}`",
                f"Created: `{created_at}`",
                f"Expires: `{expires_at}`",
                f"Initial base: `{initial_base_sha}`",
                "Merge method: `squash`",
                "Publish: `false`",
                "",
                bundle_body,
            ]
        )
        + "\n",
    )
    notice = bundle_body
    log_notice = f"release bundle ready repo={repo} bundle={bundle_id} clean_prs={[p['number'] for p in clean]} blockers={len(blockers)} gate_file={mpath}"
    fp = Path(env["BOT_HERMES_HOME"]) / "private" / "release-bundles" / ".last-signaled"
    action_fp = Path(env["BOT_HERMES_HOME"]) / "private" / "release-bundles" / ".last-owner-action-fingerprint"
    previous_action = action_fp.read_text(encoding="utf-8") if action_fp.exists() else ""
    if signal and notification["should_notify"] and previous_action != notification["fingerprint"]:
        post(env, "RELEASE_GATE", notice)
        atomic_write_private(fp, bundle_id)
        atomic_write_private(action_fp, str(notification["fingerprint"]))
    print(f"john-lomein release bundle: {log_notice}")
    return bundle_id


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signal", action="store_true", help="post a compact owner-gate notification when a new clean bundle appears")
    args = parser.parse_args(argv[1:])
    env = load_env()
    try:
        clean, blockers = clean_candidates(env)
    except Exception as exc:
        print(f"john-lomein release bundle: failed repo={env.get('BOT_REPO')} error={exc}")
        return 2
    write_bundle(env, clean, blockers, args.signal)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
