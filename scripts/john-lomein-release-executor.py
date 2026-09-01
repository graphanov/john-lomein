#!/usr/bin/env python3
"""Verify a john-lomein release bundle without holding protected mutation authority.

Default mode is dry-run/readiness only. Merge and publish remain fail-closed until
they are delegated to a separately isolated protected broker.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_comment_templates import format_review_reply
from john_lomein_owner_actions import (
    publish_workflow_contract,
    publish_workflow_contract_text,
    release_bundle_digest,
    release_owner_approval_text,
    trusted_owner_approval_from_assertion,
    validate_npm_dist_tag,
)

OK_CONCLUSIONS = {"SUCCESS", "SKIPPED", "NEUTRAL"}
CODEX_AUTHORS = {"chatgpt-codex-connector", "chatgpt-codex-connector[bot]"}
SAFE_BUNDLE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
CONTROLLED_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"


class ReleaseExecutionError(RuntimeError):
    def __init__(self, message: str, events: list[str] | None = None):
        super().__init__(message)
        self.events = list(events or [])


def utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


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
        raise ReleaseExecutionError("release_executor_missing_runtime_home")
    return Path(raw).expanduser().resolve()


def load_env() -> dict[str, str]:
    H = runtime_home_from_script_or_env()
    expected_env = (H / "scripts" / "john-lomein-instance.env").resolve()
    requested_raw = os.environ.get("JOHN_LOMEIN_INSTANCE_ENV")
    if requested_raw:
        requested = Path(requested_raw).expanduser().resolve()
        if requested != expected_env:
            raise ReleaseExecutionError("release_executor_refuses_non_deployed_instance_env")
    if not expected_env.exists():
        raise ReleaseExecutionError(f"release_executor_missing_instance_env:{expected_env}")
    vals = parse_env(expected_env)
    vals["BOT_HERMES_HOME"] = str(H)
    vals["HERMES_HOME"] = str(H)
    vals.pop("MNEMOSYNE_DATA_DIR", None)
    if os.environ.get("JOHN_LOMEIN_TRUST_ASSERTION"):
        vals["JOHN_LOMEIN_TRUST_ASSERTION"] = os.environ["JOHN_LOMEIN_TRUST_ASSERTION"]
    return vals


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


def run(cmd: list[str], *, env: dict[str, str], cwd: str | None = None, timeout: int = 120) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=cwd, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:
        return 999, "", str(exc)


def run_shell(cmd: str, *, env: dict[str, str], cwd: str, timeout: int = 600) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, shell=True, executable="/bin/bash", capture_output=True, text=True, env=env, cwd=cwd, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:
        return 999, "", str(exc)


def verifier_process_env(home: Path) -> dict[str, str]:
    home.mkdir(parents=True, exist_ok=True)
    tmp = home / "tmp"
    tmp.mkdir(mode=0o700, exist_ok=True)
    out = {
        "PATH": CONTROLLED_PATH,
        "HOME": str(home),
        "TMPDIR": str(tmp),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "CI": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
        "GH_PROMPT_DISABLED": "1",
        "NPM_CONFIG_USERCONFIG": "/dev/null",
        "PIP_CONFIG_FILE": "/dev/null",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for key in ("LANG", "LC_ALL", "LC_CTYPE", "TERM", "SHELL"):
        if os.environ.get(key):
            out[key] = os.environ[key]
    return out


def git_admin_path(worktree: Path) -> Path:
    marker = worktree / ".git"
    if marker.is_dir():
        return marker.resolve()
    if marker.is_file() and not marker.is_symlink():
        first = marker.read_text(encoding="utf-8", errors="strict").splitlines()[0]
        prefix = "gitdir:"
        if first.lower().startswith(prefix):
            raw = first[len(prefix):].strip()
            candidate = Path(raw)
            if not candidate.is_absolute():
                candidate = marker.parent / candidate
            resolved = candidate.resolve()
            if resolved.is_dir():
                return resolved
    raise RuntimeError("release_verifier_git_admin_invalid")


def verifier_sandbox_profile(*, worktree: Path, verifier_home: Path, git_admin: Path) -> str:
    worktree = worktree.resolve()
    verifier_home = verifier_home.resolve()
    git_admin = git_admin.resolve()
    protected = [Path("/Users"), Path("/private/tmp"), Path(tempfile.gettempdir()).resolve()]
    readable = [worktree, verifier_home, git_admin]
    deny_read_rules = "\n".join(
        f"  (subpath {json.dumps(str(path.resolve(strict=False)))})"
        for path in protected
    )
    read_rules = "\n".join(
        f"  (subpath {json.dumps(str(path.resolve(strict=False)))})"
        for path in readable
    )
    metadata_ancestors: set[Path] = set()
    for readable_path in readable:
        for protected_root in protected:
            resolved_root = protected_root.resolve(strict=False)
            if not readable_path.is_relative_to(resolved_root):
                continue
            current = readable_path.parent
            while current.is_relative_to(resolved_root):
                metadata_ancestors.add(current)
                if current == resolved_root:
                    break
                current = current.parent
    metadata_rules = "\n".join(
        f"  (literal {json.dumps(str(path))})"
        for path in sorted(metadata_ancestors, key=str)
    ) or '  (literal "/dev/null")'
    return f"""(version 1)
(allow default)
(deny network*)
(deny appleevent-send)
(deny process-exec (literal "/usr/bin/security"))
(deny mach-lookup
  (global-name "com.apple.SecurityServer")
  (global-name "com.apple.securityd")
  (global-name "com.apple.securitydservice")
  (global-name "com.apple.securityd.xpc")
  (global-name "com.apple.securityd.general")
  (global-name "com.apple.securityd.systemkeychain")
  (global-name "com.apple.applekeystored")
  (global-name "com.apple.security.agent")
  (global-name "com.apple.security.agent.login")
  (global-name "com.apple.KeychainStasher")
  (global-name "com.apple.keychainsharingmessagingd")
  (global-name "com.apple.AuthenticationServices.CredentialSharingGroups"))
(deny process-info*)
(allow process-info* (target self))
(deny signal)
(allow signal (target same-sandbox))
(deny file-read*
{deny_read_rules})
(allow file-read-metadata
{metadata_rules})
(allow file-read*
{read_rules})
(deny file-write*)
(allow file-write*
  (literal "/dev/null")
  (subpath {json.dumps(str(worktree))})
  (subpath {json.dumps(str(verifier_home))}))
(deny file-write*
  (subpath {json.dumps(str(git_admin))})
  (literal {json.dumps(str(worktree / ".git"))}))
"""


def run_verifier_command(
    cmd: str,
    *,
    cwd: Path,
    verifier_home: Path,
    git_admin: Path,
    timeout: int,
) -> tuple[int, str, str]:
    sandbox = Path("/usr/bin/sandbox-exec")
    if sys.platform != "darwin" or not sandbox.is_file():
        return 997, "", "release_verifier_sandbox_unavailable"
    profile = verifier_sandbox_profile(
        worktree=cwd,
        verifier_home=verifier_home,
        git_admin=git_admin,
    )
    try:
        proc = subprocess.run(
            [str(sandbox), "-p", profile, "/bin/bash", "-c", cmd],
            capture_output=True,
            text=True,
            env=verifier_process_env(verifier_home),
            cwd=str(cwd),
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:
        return 999, "", str(exc)


def gh_json(cmd: list[str], *, env: dict[str, str], timeout: int = 120):
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
        timeout=90,
    )
    oid = str(((ref or {}).get("object") or {}).get("sha") or "")
    if not oid:
        raise ReleaseExecutionError(f"default_branch_oid_missing:{branch}")
    return oid


def commit_first_parent(env: dict[str, str], oid: str) -> str:
    repo = env["BOT_REPO"]
    commit = gh_json(
        ["gh", "api", f"repos/{repo}/git/commits/{quote(oid, safe='')}"],
        env=gh_env(env),
        timeout=90,
    )
    parents = [str(item.get("sha") or "") for item in ((commit or {}).get("parents") or []) if str(item.get("sha") or "")]
    if len(parents) != 1:
        raise ReleaseExecutionError(f"merge_commit_parent_count oid={oid[:10]} expected=1 current={len(parents)}")
    return parents[0]


def bundle_root(env: dict[str, str]) -> Path:
    root = Path(env["BOT_HERMES_HOME"]) / "private" / "release-bundles"
    root.mkdir(parents=True, exist_ok=True)
    return root


def bundle_id_from_approval(text: str) -> str:
    match = re.search(r"APPROVE\s+JOHN-LOMEIN\s+BUNDLE\s+([^:\s]+)", text or "", re.I)
    return match.group(1) if match else ""


def validate_bundle_id(bundle_id: str) -> str:
    value = str(bundle_id or "")
    if not value or not SAFE_BUNDLE_ID_RE.match(value):
        raise ValueError(f"unsafe_bundle_id:{value or '<empty>'}")
    return value


def load_bundle(env: dict[str, str], bundle_id: str | None, *, approval: str = "") -> tuple[str, dict, Path]:
    root = bundle_root(env)
    if not bundle_id:
        bundle_id = bundle_id_from_approval(approval)
    candidates = []
    if bundle_id:
        bundle_id = validate_bundle_id(bundle_id)
        candidates = [root / f"{bundle_id}.json"]
    else:
        # No explicit approval/bundle: inspect the freshest generated bundle.
        # `.last-signaled` is only an anti-spam notification pointer; it can point
        # at a now-merged stale bundle after the queue goes idle.
        candidates = sorted(root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in candidates:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError(f"release_bundle_root_invalid:{path}")
            stored_id = str(data.get("bundle_id") or "")
            if stored_id != path.stem:
                raise ValueError(f"release_bundle_id_path_mismatch stored={stored_id or '<empty>'} path={path.stem}")
            return stored_id, data, path
    raise FileNotFoundError(f"release bundle not found: {bundle_id or '(latest)'}")


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
        data = gh_json(cmd, env=env, timeout=90)
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


def codex_clean_for_head(repo: str, number: int, head: str, env: dict[str, str]) -> tuple[bool, str]:
    head = str(head or "").lower()
    if not head:
        return False, "missing_latest_head_codex_head"
    comments = gh_json(["gh", "api", f"repos/{repo}/issues/{number}/comments", "--paginate"], env=env, timeout=90) or []
    artifacts: list[dict[str, str | bool]] = []
    for comment in comments:
        author = ((comment.get("user") or {}).get("login") or "")
        body = comment.get("body") or ""
        if author not in CODEX_AUTHORS:
            continue
        lowered = body.lower()
        clean = "didn't find any major issues" in lowered and "automated review suggestions" not in lowered
        m = re.search(r"Reviewed commit[^0-9a-fA-F]*([0-9a-fA-F]{7,40})", body, re.I)
        if m:
            artifacts.append({"kind": "issue_comment", "url": str(comment.get("html_url") or ""), "created_at": str(comment.get("created_at") or ""), "commit": m.group(1).lower(), "clean": clean})
    reviews = gh_json(["gh", "api", f"repos/{repo}/pulls/{number}/reviews", "--paginate"], env=env, timeout=90) or []
    for review in reviews:
        author = ((review.get("user") or {}).get("login") or "")
        body = review.get("body") or ""
        commit_id = str(review.get("commit_id") or "")
        if author not in CODEX_AUTHORS:
            continue
        lowered = body.lower()
        clean = "didn't find any major issues" in lowered and "automated review suggestions" not in lowered
        commit = commit_id.lower()
        if not commit:
            m = re.search(r"Reviewed commit[^0-9a-fA-F]*([0-9a-fA-F]{7,40})", body, re.I)
            commit = m.group(1).lower() if m else ""
        if commit:
            artifacts.append({"kind": "formal_review", "url": str(review.get("html_url") or ""), "created_at": str(review.get("submitted_at") or ""), "commit": commit, "clean": clean})
    current = [a for a in artifacts if (str(a.get("commit") or "")).startswith(head) or head.startswith(str(a.get("commit") or ""))]
    latest = max(current, key=lambda a: str(a.get("created_at") or ""), default={})
    if latest and latest.get("clean"):
        return True, f"{latest.get('kind')}:{latest.get('url')}"
    if latest:
        return False, "latest_head_codex_not_clean"
    return False, "missing_latest_head_codex_clean"


def pr_files(repo: str, number: int, env: dict[str, str]) -> list[str]:
    files = gh_json(["gh", "pr", "view", str(number), "--repo", repo, "--json", "files"], env=env, timeout=90).get("files") or []
    return sorted({str(f.get("path") or "") for f in files if str(f.get("path") or "")})


def approved_pr_files(item: dict) -> list[str]:
    paths = []
    for value in item.get("files") or []:
        path = str(value.get("path") or "") if isinstance(value, dict) else str(value or "")
        if path:
            paths.append(path)
    return sorted(set(paths))


def bundle_pr_number(item: dict) -> int:
    try:
        return int(item.get("number") or 0)
    except (TypeError, ValueError):
        return 0


def verify_bundle(env: dict[str, str], bundle: dict, *, allow_merged: bool = False, merged_prs: list[int] | None = None) -> tuple[list[dict], list[str]]:
    repo = env["BOT_REPO"]
    default_branch = env.get("BOT_DEFAULT_BRANCH", "main")
    ready: list[dict] = []
    blockers: list[str] = []
    expected: dict[int, dict] = {}
    for item in bundle.get("clean_prs") or []:
        try:
            number = int(item.get("number") or 0)
        except (TypeError, ValueError):
            blockers.append("bundle_pr_number_invalid")
            continue
        if number <= 0:
            blockers.append("bundle_pr_number_missing")
            continue
        if number in expected:
            blockers.append(f"PR#{number}: bundle_pr_duplicate")
            continue
        expected[number] = item
    if bundle.get("repo") != repo:
        blockers.append(f"bundle_repo_mismatch bundle={bundle.get('repo')} env={repo}")
        return ready, blockers
    if not expected:
        return ready, blockers
    ordered_expected = sorted(expected.items())
    # baseRefOid is a per-PR snapshot. targetBaseOid is the separately captured
    # live branch tip that anchors the approved sequential squash-merge chain.
    target_base_oids = {str(item.get("targetBaseOid") or "") for _, item in ordered_expected if str(item.get("targetBaseOid") or "")}
    if len(target_base_oids) > 1:
        blockers.append("bundle_target_base_oid_inconsistent")
    expected_live_base_oid = str(ordered_expected[0][1].get("targetBaseOid") or "")
    chain_enabled = bool(expected_live_base_oid)
    seen_open = False
    for number, approved in ordered_expected:
        blocker_count = len(blockers)
        expected_head = str(approved.get("headRefOid") or "")
        expected_base = str(approved.get("baseRefName") or "")
        expected_pr_base_oid = str(approved.get("baseRefOid") or "")
        expected_files = approved_pr_files(approved)
        try:
            pr = gh_json(["gh", "pr", "view", str(number), "--repo", repo, "--json", "number,title,url,state,headRefName,headRefOid,baseRefName,baseRefOid,mergeCommit,isDraft,mergeable,mergeStateStatus,reviewDecision,statusCheckRollup"], env=gh_env(env), timeout=90)
            files = pr_files(repo, number, gh_env(env))
            if expected_base and pr.get("baseRefName") != expected_base:
                blockers.append(f"PR#{number}: base_changed bundle={expected_base} current={pr.get('baseRefName')}")
            if expected_pr_base_oid and str(pr.get("baseRefOid") or "") != expected_pr_base_oid:
                blockers.append(f"PR#{number}: pr_base_snapshot_changed bundle={expected_pr_base_oid[:10]} current={str(pr.get('baseRefOid') or '')[:10]}")
            if expected_files != files:
                blockers.append(f"PR#{number}: files_changed bundle={expected_files} current={files}")
            if pr.get("state") == "MERGED" and allow_merged:
                if seen_open:
                    blockers.append(f"PR#{number}: merged_out_of_bundle_order")
                head = str(pr.get("headRefOid") or "")
                if expected_head and head != expected_head:
                    blockers.append(f"PR#{number}: merged_head_changed bundle={expected_head[:10]} current={head[:10]}")
                if pr.get("baseRefName") != default_branch:
                    blockers.append(f"PR#{number}: merged_base={pr.get('baseRefName')} expected={default_branch}")
                merge_oid = str(((pr.get("mergeCommit") or {}).get("oid") or ""))
                if not merge_oid:
                    blockers.append(f"PR#{number}: merged_commit_missing")
                elif chain_enabled:
                    try:
                        actual_parent = commit_first_parent(env, merge_oid)
                    except Exception as exc:
                        blockers.append(f"PR#{number}: merged_parent_inspect_failed:{exc}")
                    else:
                        if actual_parent != expected_live_base_oid:
                            blockers.append(f"PR#{number}: merged_parent_changed bundle_chain={expected_live_base_oid[:10]} current={actual_parent[:10]}")
                if len(blockers) == blocker_count:
                    if chain_enabled:
                        expected_live_base_oid = merge_oid
                    if merged_prs is not None:
                        merged_prs.append(number)
                continue
            seen_open = True
            threads = unresolved_threads(repo, number, gh_env(env))
            ci, ci_details = check_state(pr)
            head = str(pr.get("headRefOid") or "")
            codex_ok, codex_evidence = codex_clean_for_head(repo, number, head, gh_env(env))
        except Exception as exc:
            blockers.append(f"PR#{number}: inspect_failed:{exc}")
            continue
        if pr.get("state") != "OPEN":
            blockers.append(f"PR#{number}: state={pr.get('state')}")
        if expected_head and head != expected_head:
            blockers.append(f"PR#{number}: head_changed bundle={expected_head[:10]} current={head[:10]}")
        if pr.get("baseRefName") != default_branch:
            blockers.append(f"PR#{number}: base={pr.get('baseRefName')} expected={default_branch}")
        if pr.get("isDraft"):
            blockers.append(f"PR#{number}: draft")
        if ci not in {"success", "none"}:
            blockers.append(f"PR#{number}: checks_{ci}:{','.join(ci_details[:3])}")
        if pr.get("mergeStateStatus") != "CLEAN" or pr.get("mergeable") != "MERGEABLE":
            blockers.append(f"PR#{number}: merge_state={pr.get('mergeStateStatus')} mergeable={pr.get('mergeable')}")
        if threads["unresolved"]:
            blockers.append(f"PR#{number}: unresolved_threads={threads['unresolved']} current={threads['unresolved_current']}")
        if not codex_ok:
            blockers.append(f"PR#{number}: {codex_evidence}")
        if not any(b.startswith(f"PR#{number}:") for b in blockers):
            pr["files"] = files
            pr["codex_evidence"] = codex_evidence
            if chain_enabled:
                pr["targetBaseOid"] = expected_live_base_oid
            ready.append(pr)
    if chain_enabled:
        try:
            current_base_oid = default_branch_oid(env)
        except Exception as exc:
            blockers.append(f"bundle_target_base_inspect_failed:{exc}")
            ready = []
        else:
            if current_base_oid != expected_live_base_oid:
                blockers.append(f"bundle_target_base_changed approved_chain={expected_live_base_oid[:10]} current={current_base_oid[:10]}")
                ready = []
            else:
                for pr in ready:
                    pr["targetBaseOid"] = current_base_oid
    return ready, blockers


def transient_mergeability_blockers(blockers: list[str]) -> bool:
    if not blockers:
        return False
    return all(("merge_state=UNKNOWN" in b or "mergeable=UNKNOWN" in b) for b in blockers)


def verify_bundle_with_settle(env: dict[str, str], bundle: dict, *, allow_merged: bool = False, attempts: int = 1, delay: int = 10) -> tuple[list[dict], list[str], list[int]]:
    last_ready: list[dict] = []
    last_blockers: list[str] = []
    last_merged: list[int] = []
    for attempt in range(max(1, attempts)):
        merged: list[int] = []
        ready, blockers = verify_bundle(env, bundle, allow_merged=allow_merged, merged_prs=merged)
        last_ready, last_blockers, last_merged = ready, blockers, merged
        if not transient_mergeability_blockers(blockers):
            return ready, blockers, merged
        if attempt < max(1, attempts) - 1:
            time.sleep(max(0, delay))
    return last_ready, last_blockers, last_merged


def fully_merged_bundle_proof(env: dict[str, str], bundle: dict) -> tuple[list[str], str]:
    repo = env["BOT_REPO"]
    default_branch = env.get("BOT_DEFAULT_BRANCH", "main")
    prs = sorted(list(bundle.get("clean_prs") or []), key=bundle_pr_number)
    blockers: list[str] = []
    if bundle.get("repo") != repo:
        return [f"bundle_repo_mismatch bundle={bundle.get('repo')} env={repo}"], ""
    if not prs:
        return ["bundle_has_no_clean_prs"], ""
    expected_live_base_oid = str(prs[0].get("targetBaseOid") or "")
    chain_enabled = bool(expected_live_base_oid)
    for item in prs:
        blocker_count = len(blockers)
        try:
            number = int(item.get("number") or 0)
        except (TypeError, ValueError):
            blockers.append("bundle_pr_number_invalid")
            continue
        expected_head = str(item.get("headRefOid") or "")
        expected_base = str(item.get("baseRefName") or "")
        expected_pr_base_oid = str(item.get("baseRefOid") or "")
        expected_files = approved_pr_files(item)
        try:
            pr = gh_json(
                ["gh", "pr", "view", str(number), "--repo", repo, "--json", "number,state,headRefOid,baseRefName,baseRefOid,mergeCommit"],
                env=gh_env(env),
                timeout=90,
            )
            files = pr_files(repo, number, gh_env(env))
        except Exception as exc:
            blockers.append(f"PR#{number}: final_merge_inspect_failed:{exc}")
            continue
        if pr.get("state") != "MERGED":
            blockers.append(f"PR#{number}: final_state={pr.get('state')} expected=MERGED")
        head = str(pr.get("headRefOid") or "")
        if expected_head and head != expected_head:
            blockers.append(f"PR#{number}: final_merged_head_changed bundle={expected_head[:10]} current={head[:10]}")
        if expected_base and pr.get("baseRefName") != expected_base:
            blockers.append(f"PR#{number}: final_merged_base_changed bundle={expected_base} current={pr.get('baseRefName')}")
        if pr.get("baseRefName") != default_branch:
            blockers.append(f"PR#{number}: final_merged_base={pr.get('baseRefName')} expected={default_branch}")
        if expected_pr_base_oid and str(pr.get("baseRefOid") or "") != expected_pr_base_oid:
            blockers.append(f"PR#{number}: final_pr_base_snapshot_changed bundle={expected_pr_base_oid[:10]} current={str(pr.get('baseRefOid') or '')[:10]}")
        if expected_files != files:
            blockers.append(f"PR#{number}: final_merged_files_changed bundle={expected_files} current={files}")
        merge_oid = str(((pr.get("mergeCommit") or {}).get("oid") or ""))
        if not merge_oid:
            blockers.append(f"PR#{number}: final_merged_commit_missing")
        elif chain_enabled:
            try:
                actual_parent = commit_first_parent(env, merge_oid)
            except Exception as exc:
                blockers.append(f"PR#{number}: final_merged_parent_inspect_failed:{exc}")
            else:
                if actual_parent != expected_live_base_oid:
                    blockers.append(f"PR#{number}: final_merged_parent_changed bundle_chain={expected_live_base_oid[:10]} current={actual_parent[:10]}")
        if len(blockers) == blocker_count:
            if chain_enabled:
                expected_live_base_oid = merge_oid
    if chain_enabled:
        try:
            current_base_oid = default_branch_oid(env)
        except Exception as exc:
            blockers.append(f"final_target_base_inspect_failed:{exc}")
        else:
            if current_base_oid != expected_live_base_oid:
                blockers.append(f"final_target_base_changed bundle_chain={expected_live_base_oid[:10]} current={current_base_oid[:10]}")
    return blockers, expected_live_base_oid if chain_enabled and not blockers else ""


def fully_merged_bundle_blockers(env: dict[str, str], bundle: dict) -> list[str]:
    return fully_merged_bundle_proof(env, bundle)[0]


def fully_merged_bundle_proof_with_settle(env: dict[str, str], bundle: dict, *, attempts: int, delay: int) -> tuple[list[str], str]:
    last: tuple[list[str], str] = ([], "")
    for attempt in range(max(1, attempts)):
        last = fully_merged_bundle_proof(env, bundle)
        if not last[0]:
            return last
        if attempt < max(1, attempts) - 1:
            time.sleep(max(0, delay))
    return last


def fully_merged_bundle_blockers_with_settle(env: dict[str, str], bundle: dict, *, attempts: int, delay: int) -> list[str]:
    return fully_merged_bundle_proof_with_settle(env, bundle, attempts=attempts, delay=delay)[0]


def approval_text(args: argparse.Namespace) -> str:
    if args.approval:
        return args.approval
    if args.approval_file:
        return Path(args.approval_file).read_text(encoding="utf-8")
    return os.environ.get("JOHN_LOMEIN_BUNDLE_APPROVAL", "")


def bundle_integrity_blockers(bundle: dict) -> list[str]:
    if not isinstance(bundle, dict):
        return ["bundle_root_invalid"]
    stored = str(bundle.get("bundle_digest") or "")
    if not stored:
        return ["bundle_digest_missing"]
    computed = release_bundle_digest(bundle)
    if stored != computed:
        return [f"bundle_digest_mismatch stored={stored} computed={computed}"]
    blockers: list[str] = []
    for field in ("clean_prs", "blockers", "allowed_after_gate", "forbidden_without_gate"):
        if not isinstance(bundle.get(field), list):
            blockers.append(f"bundle_{field}_invalid")
    if not isinstance(bundle.get("publish_readiness"), dict):
        blockers.append("bundle_publish_readiness_invalid")
    approved_actions = bundle.get("approved_actions")
    if not isinstance(approved_actions, dict):
        blockers.append("bundle_approved_actions_missing")
    elif approved_actions != {"merge": True, "publish": False}:
        blockers.append("bundle_approved_actions_invalid")
    publish_request = bundle.get("publish_request")
    if not isinstance(publish_request, dict):
        blockers.append("bundle_publish_request_missing")
    else:
        _, tag_error = validate_npm_dist_tag(publish_request.get("npm_tag"))
        if tag_error:
            blockers.append(tag_error)
    seen_numbers: set[int] = set()
    target_base_oids: set[str] = set()
    for item in bundle.get("clean_prs") or []:
        if not isinstance(item, dict):
            blockers.append("bundle_pr_entry_invalid")
            continue
        try:
            number = int(item.get("number") or 0)
        except (TypeError, ValueError):
            number = 0
        if number <= 0:
            blockers.append("bundle_pr_number_missing")
            continue
        if number in seen_numbers:
            blockers.append(f"PR#{number}: bundle_pr_duplicate")
        seen_numbers.add(number)
        if not str(item.get("headRefOid") or ""):
            blockers.append(f"PR#{number}: bundle_head_missing")
        if not str(item.get("baseRefName") or ""):
            blockers.append(f"PR#{number}: bundle_base_missing")
        if not str(item.get("baseRefOid") or ""):
            blockers.append(f"PR#{number}: bundle_base_oid_missing")
        target_base_oid = str(item.get("targetBaseOid") or "")
        if not target_base_oid:
            blockers.append(f"PR#{number}: bundle_target_base_oid_missing")
        else:
            target_base_oids.add(target_base_oid)
        if "files" not in item or not isinstance(item.get("files"), list):
            blockers.append(f"PR#{number}: bundle_files_missing")
    if len(target_base_oids) > 1:
        blockers.append("bundle_target_base_oid_inconsistent")
    expected_approval = release_owner_approval_text(bundle)
    if not expected_approval:
        blockers.append("bundle_owner_approval_text_unavailable")
    elif str(bundle.get("owner_approval_text") or "") != expected_approval:
        blockers.append("bundle_owner_approval_text_mismatch")
    return blockers


def approval_approver(env: dict[str, str], *, bundle_id: str, text: str, bundle_digest: str = "") -> tuple[str, list[str]]:
    return trusted_owner_approval_from_assertion(env, bundle_id=bundle_id, approval_text=text, bundle_digest=bundle_digest)


def require_approval_with_identity(bundle_id: str, *, text: str, merge: bool, publish: bool, env: dict[str, str] | None = None, expected_approval: str = "", bundle_digest: str = "") -> tuple[list[str], str]:
    blockers: list[str] = []
    approver = ""
    first = text.strip().splitlines()[0] if text.strip() else ""
    expected = f"APPROVE JOHN-LOMEIN BUNDLE {bundle_id}"
    if bundle_digest:
        expected += f" DIGEST {bundle_digest}"
    normalized_text = " ".join(text.strip().split())
    normalized_expected = " ".join(str(expected_approval or "").strip().split())
    if not normalized_expected:
        blockers.append("approval_bundle_missing_generated_text")
    elif normalized_text != normalized_expected:
        blockers.append("approval_not_exact_generated_text")
    if not first.startswith(expected + ":"):
        blockers.append(f"approval_missing_or_wrong_bundle expected_prefix={expected!r}")
    lowered = text.lower()
    if merge and "merge" not in lowered:
        blockers.append("approval_does_not_name_merge")
    if publish:
        if "do not publish" in lowered or "no publish" in lowered:
            blockers.append("approval_explicitly_blocks_publish")
        elif "publish" not in lowered:
            blockers.append("approval_does_not_name_publish")
    if (merge or publish) and not blockers:
        approver, trust_blockers = trusted_owner_approval_from_assertion(env or {}, bundle_id=bundle_id, approval_text=text, bundle_digest=bundle_digest)
        blockers.extend(trust_blockers)
    return blockers, approver if not blockers else ""


def require_approval(bundle_id: str, *, text: str, merge: bool, publish: bool, env: dict[str, str] | None = None, expected_approval: str = "", bundle_digest: str = "") -> list[str]:
    blockers, _ = require_approval_with_identity(bundle_id, text=text, merge=merge, publish=publish, env=env, expected_approval=expected_approval, bundle_digest=bundle_digest)
    return blockers


def package_info(local: Path) -> dict:
    path = local / "package.json"
    if not path.exists():
        return {"blocker": "package_json_missing"}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {"name": data.get("name") or "", "version": data.get("version") or "", "package_json": str(path)}


def publish_readiness(env: dict[str, str]) -> dict:
    local = Path(env.get("BOT_LOCAL") or ".").expanduser()
    info = package_info(local)
    if info.get("blocker"):
        return info
    workflow_name = str(env.get("BOT_PUBLISH_WORKFLOW") or "publish-npm.yml").strip()
    if Path(workflow_name).name != workflow_name or not workflow_name.endswith((".yml", ".yaml")):
        info["publish_workflow_name"] = workflow_name
        info["blocker"] = "publish_workflow_name_invalid"
        return info
    workflow = local / ".github" / "workflows" / workflow_name
    info["publish_workflow_name"] = workflow_name
    info["workflow"] = str(workflow) if workflow.exists() else ""
    if not workflow.exists():
        info["blocker"] = "publish_workflow_missing"
        return info
    contract = publish_workflow_contract(workflow)
    info.update({key: value for key, value in contract.items() if key != "blocker"})
    if contract.get("blocker"):
        info["blocker"] = str(contract["blocker"])
        return info
    package = info.get("name") or ""
    version = info.get("version") or ""
    code, out, err = run(["npm", "view", f"{package}@{version}", "version"], env=gh_env(env), cwd=str(local), timeout=60)
    if code == 0:
        info["npm_latest_or_exact"] = out.strip()
        info["blocker"] = "package_version_already_published"
        return info
    msg = (out + "\n" + err).lower()
    if "e404" in msg or "no match found" in msg or "could not be found" in msg or "not found" in msg:
        info["publish_ready"] = True
        return info
    info["blocker"] = f"npm_view_failed:{(err or out)[:160]}"
    return info


def write_body_file(text: str) -> str:
    fd, path = tempfile.mkstemp(prefix="john-lomein-release-", suffix=".md")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def post_merge_evidence(repo: str, pr: dict, bundle_id: str, env: dict[str, str]) -> None:
    body = format_review_reply(
        f"release-bundle merge gate satisfied for bundle `{bundle_id}`",
        [
            f"PR head: `{str(pr.get('headRefOid') or '')[:10]}`",
            f"Merge state: `{pr.get('mergeStateStatus')}` / `{pr.get('mergeable')}`",
            "Checks: latest-head green or non-required absent",
            "Review threads: unresolved zero",
            f"Independent review: {pr.get('codex_evidence') or pr.get('reviewDecision')}",
        ],
        "proceeding only because the owner approved this exact bundle id; npm publish/release remains separately gated by package-version readiness and explicit approval",
        marker="<!-- john-lomein-release-executor -->",
    )
    path = write_body_file(body)
    try:
        run(["gh", "pr", "comment", str(pr["number"]), "--repo", repo, "--body-file", path], env=gh_env(env), timeout=90)
    finally:
        Path(path).unlink(missing_ok=True)


def sync_main(env: dict[str, str]) -> tuple[int, str, str]:
    local = Path(env.get("BOT_LOCAL") or ".").expanduser()
    branch = env.get("BOT_DEFAULT_BRANCH", "main")
    cmds = [
        ["git", "fetch", "--prune", "origin"],
        ["git", "checkout", branch],
        ["git", "pull", "--ff-only", "origin", branch],
    ]
    output = []
    for cmd in cmds:
        code, out, err = run(cmd, env=gh_env(env), cwd=str(local), timeout=180)
        output.append(f"$ {' '.join(cmd)}\n{out}\n{err}".strip())
        if code != 0:
            return code, "\n".join(output), err or out
    return 0, "\n".join(output), ""


def run_release_verification(env: dict[str, str]) -> tuple[int, str, str]:
    local = Path(env.get("BOT_LOCAL") or ".").expanduser().resolve()
    test_cmd = env.get("BOT_TEST_CMD") or ""
    try:
        admin = git_admin_path(local)
    except Exception as exc:
        return 997, "", str(exc)
    git_prefix = (
        "git --no-replace-objects --no-optional-locks "
        "-c core.fsmonitor=false -c core.untrackedCache=false "
        "-c core.hooksPath=/dev/null -c credential.helper= "
        "-c core.attributesFile=/dev/null -c core.pager=cat "
        "-c pager.status=false -c diff.external= -c interactive.diffFilter= "
        "-c submodule.recurse=false"
    )
    with tempfile.TemporaryDirectory(prefix="john-lomein-release-verifier-") as tmp:
        verifier_home = Path(tmp).resolve()
        status_code, status_out, status_err = run_verifier_command(
            f"{git_prefix} status --porcelain=v1 --untracked-files=all",
            cwd=local,
            verifier_home=verifier_home,
            git_admin=admin,
            timeout=120,
        )
        if status_code != 0:
            return status_code, status_out, status_err
        if status_out:
            return 1, status_out, "release_checkout_dirty_before_verification"
        code1, out1, err1 = run_verifier_command(
            f"{git_prefix} diff --check",
            cwd=local,
            verifier_home=verifier_home,
            git_admin=admin,
            timeout=120,
        )
        if code1 != 0:
            return code1, out1, err1
        if not test_cmd:
            verification_output = "sandbox enforced; git status clean; git diff --check ok; no BOT_TEST_CMD configured"
        else:
            code2, out2, err2 = run_verifier_command(
                test_cmd,
                cwd=local,
                verifier_home=verifier_home,
                git_admin=admin,
                timeout=900,
            )
            if code2 != 0:
                return code2, f"sandbox enforced; git status clean; git diff --check ok\n$ {test_cmd}\n{out2}", err2
            verification_output = f"sandbox enforced; git status clean; git diff --check ok\n$ {test_cmd}\n{out2}"
        final_status_code, final_status_out, final_status_err = run_verifier_command(
            f"{git_prefix} status --porcelain=v1 --untracked-files=all",
            cwd=local,
            verifier_home=verifier_home,
            git_admin=admin,
            timeout=120,
        )
        if final_status_code != 0:
            return final_status_code, verification_output + "\n" + final_status_out, final_status_err
        if final_status_out:
            return 1, verification_output + "\n" + final_status_out, "release_checkout_dirty_after_verification"
        return 0, verification_output, ""


def local_head_oid(env: dict[str, str]) -> str:
    local = str(Path(env.get("BOT_LOCAL") or ".").expanduser())
    code, out, err = run(["git", "rev-parse", "HEAD"], env=gh_env(env), cwd=local, timeout=60)
    oid = out.strip()
    if code != 0 or not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", oid):
        raise RuntimeError(f"release_local_head_inspect_failed:{err or out}")
    return oid


def merged_commit_oid_with_settle(env: dict[str, str], number: int, *, attempts: int, delay: int) -> str:
    repo = env["BOT_REPO"]
    last = ""
    for attempt in range(max(1, attempts)):
        pr = gh_json(
            ["gh", "pr", "view", str(number), "--repo", repo, "--json", "state,mergeCommit"],
            env=gh_env(env),
            timeout=90,
        )
        last = str(((pr.get("mergeCommit") or {}).get("oid") or ""))
        if pr.get("state") == "MERGED" and last:
            return last
        if attempt < max(1, attempts) - 1:
            time.sleep(max(0, delay))
    raise ReleaseExecutionError(f"PR#{number} merged commit unavailable after merge state={pr.get('state')} oid={last[:10]}")


def merge_ready_prs(env: dict[str, str], ready: list[dict], bundle_id: str) -> list[str]:
    del env, ready, bundle_id
    raise ReleaseExecutionError("merge_requires_protected_broker")


def remote_publish_workflow_contract(env: dict[str, str], workflow_name: str, expected_sha: str) -> dict:
    repo = env["BOT_REPO"]
    workflow_path = f".github/workflows/{workflow_name}"
    data = gh_json(
        [
            "gh",
            "api",
            f"repos/{repo}/contents/{quote(workflow_path, safe='/')}?ref={quote(expected_sha, safe='')}",
        ],
        env=gh_env(env),
        timeout=90,
    )
    if not isinstance(data, dict) or str(data.get("encoding") or "") != "base64":
        return {"blocker": "publish_workflow_remote_content_invalid"}
    try:
        encoded = str(data.get("content") or "").replace("\n", "")
        text = base64.b64decode(encoded.encode("ascii"), validate=True).decode("utf-8")
    except Exception as exc:
        return {"blocker": f"publish_workflow_remote_content_unreadable:{exc}"}
    return publish_workflow_contract_text(text)


def dispatch_publish(env: dict[str, str], npm_tag: str, expected_sha: str) -> str:
    del env, npm_tag, expected_sha
    raise RuntimeError("publish_requires_protected_broker")


def requested_action_blockers(*, merge: bool, publish: bool) -> list[str]:
    if publish and not merge:
        return ["publish_requires_merge"]
    if publish:
        return ["publish_requires_protected_broker"]
    if merge:
        return ["merge_requires_protected_broker"]
    return []


def publish_request_blockers(bundle: dict, *, publish: bool, npm_tag: str) -> list[str]:
    if not publish:
        return []
    publish_request = bundle.get("publish_request")
    if not isinstance(publish_request, dict):
        return ["bundle_publish_npm_tag_missing_or_invalid"]
    approved_tag, approved_error = validate_npm_dist_tag(publish_request.get("npm_tag"))
    if approved_error:
        return ["bundle_publish_npm_tag_missing_or_invalid"]
    requested_tag, requested_error = validate_npm_dist_tag(npm_tag)
    if requested_error:
        return [requested_error]
    if requested_tag != approved_tag:
        return [f"publish_npm_tag_mismatch approved={approved_tag} requested={requested_tag}"]
    return []


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", help="bundle id; defaults to bundle id in approval text or newest generated bundle")
    parser.add_argument("--approval", help="exact owner approval text")
    parser.add_argument("--approval-file", help="file containing exact owner approval text")
    parser.add_argument(
        "--merge",
        action="store_true",
        help="request merge; currently fails closed until a protected broker is installed",
    )
    parser.add_argument("--publish", action="store_true", help="dispatch npm publish workflow after exact approval and post-merge readiness")
    parser.add_argument("--npm-tag", help="must match the npm dist-tag bound into the approved bundle; defaults to that bound value")
    parser.add_argument("--dry-run", action="store_true", help="verify only; perform no side effects")
    args = parser.parse_args(argv[1:])
    action_blockers = requested_action_blockers(merge=args.merge, publish=args.publish)
    if action_blockers:
        print(
            json.dumps(
                {
                    "actions": {"merge": bool(args.merge), "publish": bool(args.publish), "dry_run": bool(args.dry_run)},
                    "blockers": action_blockers,
                    "events": [],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1

    env = load_env()
    text = approval_text(args)
    bundle_id, bundle, path = load_bundle(env, args.bundle, approval=text)
    approved_publish_request = bundle.get("publish_request") if isinstance(bundle.get("publish_request"), dict) else {}
    requested_npm_tag = str(args.npm_tag or approved_publish_request.get("npm_tag") or "")
    approver = ""
    settle_attempts = int(env.get("BOT_RELEASE_SETTLE_ATTEMPTS") or 12) if args.merge else 1
    settle_delay = int(env.get("BOT_RELEASE_SETTLE_DELAY_SECONDS") or 10)
    integrity_blockers = bundle_integrity_blockers(bundle)
    if integrity_blockers:
        ready, blockers, already_merged = [], [], []
    else:
        ready, blockers, already_merged = verify_bundle_with_settle(env, bundle, allow_merged=args.merge, attempts=settle_attempts, delay=settle_delay)
    actions = {"merge": bool(args.merge), "publish": bool(args.publish), "dry_run": bool(args.dry_run or (not args.merge and not args.publish))}
    digest = str(bundle.get("bundle_digest") or "")
    result = {"bundle_id": bundle_id, "bundle_digest": digest, "bundle_path": str(path), "repo": env.get("BOT_REPO"), "actions": actions, "approval_identity": {"approver": approver, "trusted_owner_configured": bool(env.get("BOT_OWNER_APPROVERS") or env.get("BOT_DISCORD_OWNER_USER_IDS")), "signed_assertion_present": bool(env.get("JOHN_LOMEIN_TRUST_ASSERTION"))}, "ready_prs": [p["number"] for p in ready], "already_merged_prs": already_merged, "blockers": list(blockers) + integrity_blockers, "events": []}
    result["blockers"].extend(publish_request_blockers(bundle, publish=args.publish, npm_tag=requested_npm_tag))

    if not args.dry_run and (args.merge or args.publish):
        if env.get("BOT_MISSION_COMPLETE") != "1":
            result["blockers"].append("owner_mission_incomplete")
        if env.get("BOT_MUTATION_ENABLED") != "1":
            result["blockers"].append("mutation_disabled")
        if args.merge and not ready and not already_merged:
            result["blockers"].append("bundle_has_no_clean_prs")
    publish_readiness_data = bundle.get("publish_readiness") if isinstance(bundle.get("publish_readiness"), dict) else {}
    if args.publish and "package_version_already_published" in str(publish_readiness_data.get("blocker", "")):
        changed_package = any("package.json" in approved_pr_files(p) for p in ready)
        if not changed_package:
            result["blockers"].append("publish_requested_but_bundle_does_not_change_package_json_and_current_version_is_already_published")
    if not args.dry_run and (args.merge or args.publish) and not result["blockers"]:
        approval_blockers, approver = require_approval_with_identity(bundle_id, text=text, merge=args.merge, publish=args.publish, env=env, expected_approval=str(bundle.get("owner_approval_text") or ""), bundle_digest=digest)
        result["approval_identity"]["approver"] = approver
        result["blockers"].extend(approval_blockers)

    if result["blockers"]:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1 if (args.merge or args.publish) and not args.dry_run else 0
    if actions["dry_run"]:
        result["events"].append("dry_run_only_no_side_effects")
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    try:
        if args.merge:
            result["events"].extend(merge_ready_prs(env, ready, bundle_id))
        if args.publish:
            final_merge_blockers, approved_publish_sha = fully_merged_bundle_proof_with_settle(
                env,
                bundle,
                attempts=settle_attempts,
                delay=settle_delay,
            )
            if final_merge_blockers:
                raise RuntimeError("exact_bundle_not_fully_merged:" + "; ".join(final_merge_blockers[:5]))
            scode, sout, serr = sync_main(env)
            if scode != 0:
                raise RuntimeError(serr or sout)
            synced_head = local_head_oid(env)
            if synced_head != approved_publish_sha:
                raise RuntimeError(
                    f"release_local_head_not_approved expected={approved_publish_sha[:10]} current={synced_head[:10]}"
                )
            vcode, vout, verr = run_release_verification(env)
            if vcode != 0:
                raise RuntimeError(verr or vout)
            result["events"].append(dispatch_publish(env, requested_npm_tag, approved_publish_sha))
    except Exception as exc:
        if isinstance(exc, ReleaseExecutionError):
            result["events"].extend(exc.events)
        result["blockers"].append(str(exc))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
