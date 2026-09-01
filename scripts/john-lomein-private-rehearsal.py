#!/usr/bin/env python3
"""Offline deterministic rehearsal of the owner-gated delivery path."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from john_lomein_comment_templates import format_release_bundle
from john_lomein_guide_lifecycle import dialogue_signals, guide_dialogue_policy
from john_lomein_proposal import normalize_proposal
from john_lomein_review_quorum import evaluate_review_quorum, review_quorum_policy, role_review_receipt


HEAD_SHA = "0123456789abcdef0123456789abcdef01234567"


def load_forge() -> Any:
    path = SCRIPT_DIR / "john-lomein-forge-orchestrator.py"
    spec = importlib.util.spec_from_file_location("john_lomein_forge_rehearsal", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Forge orchestrator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256_json(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, target)


def rehearse() -> dict[str, Any]:
    policy = guide_dialogue_policy({})
    question = "Clarifying question: Must the first release preserve the legacy data format?"
    history = [
        {"role": "user", "content": "Add a safer import path."},
        {"role": "assistant", "content": question},
        {"role": "user", "content": "Preserve it."},
        {"role": "assistant", "content": question},
    ]
    guide = dialogue_signals(history, "Preserve it.", policy)

    proposal = normalize_proposal(
        {
            "schema_version": "john-lomein.proposal.v1",
            "title": "Preserve legacy data during safer import",
            "problem": "The import path needs stronger validation without breaking existing data.",
            "desired_outcome": "Reject malformed input while preserving the legacy format.",
            "scope": ["Validate import input", "Keep the legacy format readable"],
            "out_of_scope": ["Release automation", "Publishing"],
            "constraints": ["No data migration", "Owner merge remains manual"],
            "success_signals": ["Malformed input is rejected", "Legacy fixtures still pass"],
            "evidence_plan": ["Failing validation test", "Legacy compatibility regression test"],
            "risks": ["Unexpected legacy edge cases"],
            "open_questions": [],
            "dialogue": {
                "status": "EXHAUSTED",
                "clarification_turns": guide["refinement_turns"],
                "exhaustion_reason": "repeated_exchange",
            },
            "authority": {
                "posture": "proposal_only",
                "owner_readiness_required": True,
                "owner_merge_required": True,
            },
        }
    )

    forge = load_forge()
    owner_event = [
        {
            "event": "labeled",
            "label": {"name": "ready-for-implementation"},
            "actor": {"login": "repo-owner"},
            "created_at": "2026-08-31T10:00:00Z",
            "id": 1,
        }
    ]
    original_gh_json = forge.gh_json
    forge.gh_json = lambda command, **kwargs: owner_event
    try:
        with tempfile.TemporaryDirectory() as tmp:
            readiness = forge.issue_readiness_provenance(
                "repo-owner/example",
                42,
                {"ready-for-implementation"},
                {"ready-for-implementation"},
                {"BOT_HERMES_HOME": str(Path(tmp) / "runtime")},
                {"authority": {"owner_github_logins": ["repo-owner"]}},
            )
    finally:
        forge.gh_json = original_gh_json

    ambiguous_status, ambiguous_valid = forge.status_marker_result(
        "JOHN_LOMEIN_CRITIQUE_STATUS: SHIP\n"
        "A blocker was found.\n"
        "JOHN_LOMEIN_CRITIQUE_STATUS: REVISE\n",
        "JOHN_LOMEIN_CRITIQUE_STATUS",
    )
    final_status, final_valid = forge.status_marker_result(
        "Design is bounded and testable.\nJOHN_LOMEIN_CRITIQUE_STATUS: SHIP\n",
        "JOHN_LOMEIN_CRITIQUE_STATUS",
    )

    quorum_policy = review_quorum_policy({
        "review_quorum": {
            "schema_version": "john-lomein.review-quorum-policy.v1",
            "enabled": True,
            "required_roles": ["maintainer", "overwatch"],
            "require_tests": True, "require_codex": True,
            "minimum_human_reviews": 1, "human_reviewer_logins": ["repo-owner"],
        }
    })
    role_reviews = []
    for role in ("maintainer", "overwatch"):
        output = f"JOHN_LOMEIN_PR_REVIEW_HEAD: {HEAD_SHA}\nJOHN_LOMEIN_PR_REVIEW_STATUS: PASS"
        role_reviews.append(role_review_receipt(
            role=role, profile=f"john-lomein-{role}", repository="owner/repo",
            pr_number=42, head_sha=HEAD_SHA, verdict="PASS",
            prompt_text=f"Review {role} {HEAD_SHA}", output_text=output,
            policy_sha256=quorum_policy["policy_sha256"], created_at="2026-09-01T00:00:00Z",
        ))
    quorum = evaluate_review_quorum(
        policy=quorum_policy, repository="owner/repo", pr_number=42, head_sha=HEAD_SHA,
        evidence={
            "tests": {"head_sha": HEAD_SHA, "status": "success", "evidence_sha256": "sha256:" + "1" * 64},
            "codex": {"head_sha": HEAD_SHA, "status": "clean", "evidence_sha256": "sha256:" + "2" * 64},
            "role_reviews": role_reviews,
            "human_reviews": [{"login": "repo-owner", "commit_sha": HEAD_SHA, "state": "APPROVED", "review_id": 42, "submitted_at": "2026-09-01T00:01:00Z"}],
        },
    )

    report = format_release_bundle(
        bundle_id="offline-rehearsal-42",
        clean_prs=[
            {
                "number": 42,
                "title": proposal["title"],
                "headRefOid": HEAD_SHA,
            }
        ],
        blockers=[],
        publish_readiness={
            "publish_ready_after_merge": False,
            "blocker": "owner_gated",
        },
        approval_text="Manual owner merge only; no automated merge or publication.",
    )

    checks = {
        "guide_exhausted": guide["stage"] == "EXHAUSTED" and not guide["questioning_permitted"],
        "proposal_valid": proposal["authority"]["owner_readiness_required"] is True,
        "owner_readiness_proven": readiness[0] is True,
        "ambiguous_verdict_blocked": (ambiguous_status, ambiguous_valid) == ("BLOCKED", False),
        "final_ship_valid": (final_status, final_valid) == ("SHIP", True),
        "exact_head_reported": HEAD_SHA in report,
        "exact_head_quorum_passed": quorum["merge_ready"] is True and not quorum["reasons"],
        "single_pr_only": report.count("latest-head clean: yes") == 1,
    }
    receipt: dict[str, Any] = {
        "schema_version": "john-lomein.private-rehearsal.v1",
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "status": "PASSED" if all(checks.values()) else "FAILED",
        "checks": checks,
        "guide": {
            "stage": guide["stage"],
            "questioning_permitted": guide["questioning_permitted"],
            "stop_reasons": guide["stop_reasons"],
        },
        "proposal": {
            "proposal_id": proposal["proposal_id"],
            "authority": proposal["authority"]["posture"],
        },
        "owner_readiness": {
            "proven": readiness[0],
            "reason": readiness[1],
            "actor": readiness[2].get("actor_login", ""),
            "source": readiness[2].get("source", ""),
        },
        "verdict_parser": {
            "ambiguous": {"status": ambiguous_status, "valid": ambiguous_valid},
            "final": {"status": final_status, "valid": final_valid},
        },
        "merge_ready": {
            "pr_count": 1,
            "head_sha": HEAD_SHA,
            "report": report,
            "quorum_passed": quorum["merge_ready"],
            "quorum_sha256": quorum["quorum_sha256"],
            "quorum_policy_sha256": quorum["policy_sha256"],
            "owner_manual_merge_required": True,
        },
        "side_effects": {
            "github_mutated": False,
            "runtime_activated": False,
            "merge_executed": False,
            "published": False,
        },
    }
    receipt["receipt_digest"] = sha256_json(receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output")
    args = parser.parse_args()
    receipt = rehearse()
    if args.output:
        write_receipt(Path(args.output), receipt)
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0 if receipt["status"] == "PASSED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
