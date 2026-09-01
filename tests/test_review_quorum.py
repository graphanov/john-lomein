from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "john_lomein_review_quorum.py"


def load_contract():
    spec = importlib.util.spec_from_file_location("john_lomein_review_quorum", SCRIPT)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


HEAD = "a" * 40
OTHER_HEAD = "b" * 40


def configured_manifest() -> dict:
    return {
        "review_quorum": {
            "schema_version": "john-lomein.review-quorum-policy.v1",
            "enabled": True,
            "required_roles": ["maintainer", "overwatch"],
            "require_tests": True,
            "require_codex": True,
            "minimum_human_reviews": 1,
            "human_reviewer_logins": ["RepoOwner"],
        }
    }


def role_receipt(contract, role: str, *, head: str = HEAD, verdict: str = "PASS"):
    policy = contract.review_quorum_policy(configured_manifest())
    return contract.role_review_receipt(
        role=role,
        profile=f"john-lomein-{role}",
        repository="repoowner/sample-project",
        pr_number=125,
        head_sha=head,
        verdict=verdict,
        prompt_text=f"Review {role} {head}",
        output_text=(
            f"Evidence summary.\n"
            f"JOHN_LOMEIN_PR_REVIEW_HEAD: {head}\n"
            f"JOHN_LOMEIN_PR_REVIEW_STATUS: {verdict}"
        ),
        policy_sha256=policy["policy_sha256"],
        created_at="2026-09-01T00:00:00Z",
    )


def complete_evidence(contract) -> dict:
    return {
        "tests": {
            "head_sha": HEAD,
            "status": "success",
            "evidence_sha256": "sha256:" + "1" * 64,
        },
        "codex": {
            "head_sha": HEAD,
            "status": "clean",
            "evidence_sha256": "sha256:" + "2" * 64,
        },
        "role_reviews": [
            role_receipt(contract, "maintainer"),
            role_receipt(contract, "overwatch"),
        ],
        "human_reviews": [
            {
                "login": "RepoOwner",
                "commit_sha": HEAD,
                "state": "APPROVED",
                "review_id": 44,
                "submitted_at": "2026-09-01T00:01:00Z",
            }
        ],
    }


def test_policy_is_fail_closed_and_cannot_drop_required_reviewers():
    contract = load_contract()
    default = contract.review_quorum_policy({})
    assert default["enabled"] is False
    assert default["required_roles"] == ["maintainer", "overwatch"]
    assert default["require_tests"] is True
    assert default["require_codex"] is True
    assert default["minimum_human_reviews"] == 1

    manifest = configured_manifest()
    policy = contract.review_quorum_policy(manifest)
    assert policy["enabled"] is True
    assert policy["human_reviewer_logins"] == ["repoowner"]
    assert policy["policy_sha256"].startswith("sha256:")

    manifest["review_quorum"]["required_roles"] = ["maintainer"]
    with pytest.raises(contract.ReviewQuorumError, match="required_roles"):
        contract.review_quorum_policy(manifest)

    manifest = configured_manifest()
    manifest["review_quorum"]["minimum_human_reviews"] = 0
    with pytest.raises(contract.ReviewQuorumError, match="minimum_human_reviews"):
        contract.review_quorum_policy(manifest)


def test_role_review_output_requires_one_exact_final_head_and_verdict():
    contract = load_contract()
    parsed = contract.parse_role_review_output(
        "Analysis.\n"
        f"JOHN_LOMEIN_PR_REVIEW_HEAD: {HEAD}\n"
        "JOHN_LOMEIN_PR_REVIEW_STATUS: PASS",
        expected_head=HEAD,
    )
    assert parsed == {"head_sha": HEAD, "verdict": "PASS"}

    with pytest.raises(contract.ReviewQuorumError, match="ambiguous"):
        contract.parse_role_review_output(
            f"JOHN_LOMEIN_PR_REVIEW_HEAD: {HEAD}\n"
            "JOHN_LOMEIN_PR_REVIEW_STATUS: PASS\n"
            "JOHN_LOMEIN_PR_REVIEW_STATUS: REVISE",
            expected_head=HEAD,
        )
    with pytest.raises(contract.ReviewQuorumError, match="head"):
        contract.parse_role_review_output(
            f"JOHN_LOMEIN_PR_REVIEW_HEAD: {OTHER_HEAD}\n"
            "JOHN_LOMEIN_PR_REVIEW_STATUS: PASS",
            expected_head=HEAD,
        )


def test_exact_head_quorum_passes_only_with_all_required_evidence():
    contract = load_contract()
    policy = contract.review_quorum_policy(configured_manifest())
    result = contract.evaluate_review_quorum(
        policy=policy,
        repository="repoowner/sample-project",
        pr_number=125,
        head_sha=HEAD,
        evidence=complete_evidence(contract),
    )
    assert result["merge_ready"] is True
    assert result["reasons"] == []
    assert result["head_sha"] == HEAD
    assert result["quorum_sha256"].startswith("sha256:")
    assert result["authority"] == {
        "can_merge": False,
        "can_release": False,
        "can_publish": False,
    }


def test_stale_or_missing_evidence_fails_closed():
    contract = load_contract()
    policy = contract.review_quorum_policy(configured_manifest())
    evidence = complete_evidence(contract)
    evidence["role_reviews"][0] = role_receipt(
        contract,
        "maintainer",
        head=OTHER_HEAD,
    )
    evidence["human_reviews"] = []
    evidence["tests"]["head_sha"] = OTHER_HEAD
    result = contract.evaluate_review_quorum(
        policy=policy,
        repository="repoowner/sample-project",
        pr_number=125,
        head_sha=HEAD,
        evidence=evidence,
    )
    assert result["merge_ready"] is False
    assert "tests_not_clean_current_head" in result["reasons"]
    assert "maintainer_review_missing_current_head" in result["reasons"]
    assert "human_review_quorum_missing_current_head" in result["reasons"]


def test_human_review_filter_requires_configured_login_current_commit_and_nonnegative_state():
    contract = load_contract()
    reviews = [
        {
            "id": 1,
            "state": "COMMENTED",
            "commit_id": HEAD,
            "submitted_at": "2026-09-01T00:00:00Z",
            "user": {"login": "RepoOwner"},
        },
        {
            "id": 2,
            "state": "APPROVED",
            "commit_id": OTHER_HEAD,
            "submitted_at": "2026-09-01T00:00:01Z",
            "user": {"login": "RepoOwner"},
        },
        {
            "id": 3,
            "state": "CHANGES_REQUESTED",
            "commit_id": HEAD,
            "submitted_at": "2026-09-01T00:00:02Z",
            "user": {"login": "RepoOwner"},
        },
        {
            "id": 4,
            "state": "APPROVED",
            "commit_id": HEAD,
            "submitted_at": "2026-09-01T00:00:03Z",
            "user": {"login": "drive-by"},
        },
        {
            "id": 5,
            "state": "APPROVED",
            "commit_id": HEAD,
            "submitted_at": "2026-09-01T00:00:04Z",
            "user": {"login": "RepoOwner"},
        },
    ]
    evidence = contract.current_human_review_evidence(
        reviews[:4],
        head_sha=HEAD,
        allowed_logins={"repoowner"},
    )
    assert evidence == []
    evidence = contract.current_human_review_evidence(
        reviews[:2] + reviews[3:],
        head_sha=HEAD,
        allowed_logins={"repoowner"},
    )
    assert len(evidence) == 1
    assert evidence[0]["login"] == "RepoOwner"
    assert evidence[0]["commit_sha"] == HEAD
    assert evidence[0]["state"] == "APPROVED"
    assert evidence[0]["review_id"] == 5

def test_role_receipt_rejects_claimed_head_not_present_in_output():
    contract = load_contract()
    policy = contract.review_quorum_policy(configured_manifest())
    with pytest.raises(contract.ReviewQuorumError, match="head"):
        contract.role_review_receipt(
            role="maintainer",
            profile="john-lomein-maintainer",
            repository="repoowner/sample-project",
            pr_number=125,
            head_sha=HEAD,
            verdict="PASS",
            prompt_text="Review",
            output_text=(
                f"JOHN_LOMEIN_PR_REVIEW_HEAD: {OTHER_HEAD}\n"
                "JOHN_LOMEIN_PR_REVIEW_STATUS: PASS"
            ),
            policy_sha256=policy["policy_sha256"],
            created_at="2026-09-01T00:00:00Z",
        )
