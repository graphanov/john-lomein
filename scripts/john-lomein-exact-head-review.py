#!/usr/bin/env python3
"""Rerun Maintainer and Overwatch reviews for one exact PR head."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ExactHeadReviewError(ValueError):
    pass


def load_forge_module(script_dir: Path | None = None):
    root = script_dir or Path(__file__).resolve().parent
    path = root / "john-lomein-forge-orchestrator.py"
    spec = importlib.util.spec_from_file_location("john_lomein_forge_review_runtime", path)
    if spec is None or spec.loader is None:
        raise ExactHeadReviewError("Forge review runtime is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def verify_exact_head_binding(
    *,
    env: dict[str, str],
    repository: str,
    pr_number: int,
    expected_head: str,
    worktree: Path,
    forge: Any,
) -> dict[str, object]:
    head = str(expected_head or "").lower()
    if SHA_RE.fullmatch(head) is None:
        raise ExactHeadReviewError("expected head must be a full commit SHA")
    if not worktree.is_dir() or worktree.is_symlink():
        raise ExactHeadReviewError("review worktree is missing or unsafe")
    pr = forge.gh_json(
        ["gh", "pr", "view", str(int(pr_number)), "--repo", repository,
         "--json", "number,state,headRefOid,headRefName"]
    )
    if not isinstance(pr, dict) or str(pr.get("state") or "").upper() != "OPEN":
        raise ExactHeadReviewError("PR is not open")
    if str(pr.get("headRefOid") or "").lower() != head:
        raise ExactHeadReviewError("PR head does not match expected head")
    command_env = forge.gh_env(env) if hasattr(forge, "gh_env") else env
    code, actual, error = forge.run(
        ["git", "rev-parse", "HEAD"], env=command_env, cwd=str(worktree), timeout=20
    )
    if code != 0 or actual.strip().lower() != head:
        raise ExactHeadReviewError("worktree head does not match expected head")
    code, dirty, error = forge.run(
        ["git", "status", "--porcelain"], env=command_env, cwd=str(worktree), timeout=20
    )
    if code != 0:
        raise ExactHeadReviewError("worktree status failed")
    if dirty.strip():
        raise ExactHeadReviewError("review worktree is dirty")
    return {
        "repository": repository,
        "pr": int(pr_number),
        "head_sha": head,
        "branch": str(pr.get("headRefName") or ""),
        "worktree": str(worktree.resolve()),
    }


def execute(args: argparse.Namespace, *, forge: Any | None = None) -> dict[str, object]:
    runtime = forge or load_forge_module()
    env = runtime.load_env()
    binding = verify_exact_head_binding(
        env=env,
        repository=args.repository or env.get("BOT_REPO") or "",
        pr_number=args.pr,
        expected_head=args.expected_head,
        worktree=Path(args.worktree).expanduser().resolve(),
        forge=runtime,
    )
    home = Path(env["BOT_HERMES_HOME"])
    run_dir = home / "state" / "review-runs" / (
        f"pr-{binding['pr']}-{str(binding['head_sha'])[:12]}"
    )
    if run_dir.exists() and run_dir.is_symlink():
        raise ExactHeadReviewError("review run directory is unsafe")
    run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(run_dir, 0o700)
    passed, receipts, error = runtime.run_required_pr_role_reviews(
        env,
        cycle=run_dir,
        repository=str(binding["repository"]),
        issue_number=args.issue,
        pr_number=int(str(binding["pr"])),
        head_sha=str(binding["head_sha"]),
        worktree=Path(str(binding["worktree"])),
    )
    verify_exact_head_binding(
        env=env,
        repository=str(binding["repository"]),
        pr_number=int(str(binding["pr"])),
        expected_head=str(binding["head_sha"]),
        worktree=Path(str(binding["worktree"])),
        forge=runtime,
    )
    result = {
        "schema_version": "john-lomein.exact-head-review-run.v1",
        "passed": bool(passed),
        "error": str(error or ""),
        "repository": binding["repository"],
        "issue": int(args.issue),
        "pr": binding["pr"],
        "head_sha": binding["head_sha"],
        "roles": [item.get("role") for item in receipts],
    }
    if not passed:
        raise ExactHeadReviewError(str(error or "exact-head role review failed"))
    return result


def parser() -> argparse.ArgumentParser:
    out = argparse.ArgumentParser(description=__doc__)
    out.add_argument("--repository", default="")
    out.add_argument("--issue", type=int, required=True)
    out.add_argument("--pr", type=int, required=True)
    out.add_argument("--expected-head", required=True)
    out.add_argument("--worktree", required=True)
    return out


def main() -> int:
    try:
        result = execute(parser().parse_args())
    except (ExactHeadReviewError, RuntimeError, ValueError) as exc:
        print(json.dumps({"passed": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
