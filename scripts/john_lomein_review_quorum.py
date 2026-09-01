#!/usr/bin/env python3
"""Exact-head review quorum; never merge/release authority."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

POLICY_SCHEMA = "john-lomein.review-quorum-policy.v1"
ROLE_RECEIPT_SCHEMA = "john-lomein.role-review-receipt.v1"
QUORUM_SCHEMA = "john-lomein.review-quorum.v1"
REQUIRED_ROLES = ("maintainer", "overwatch")
POSITIVE_HUMAN_STATES = frozenset({"APPROVED"})
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
STAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
AUTHORITY = {"can_merge": False, "can_release": False, "can_publish": False}


class ReviewQuorumError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReviewQuorumError(f"{field} must be a mapping")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], field: str) -> None:
    unknown = sorted(set(value) - expected)
    missing = sorted(expected - set(value))
    if unknown:
        raise ReviewQuorumError(f"{field} has unknown fields")
    if missing:
        raise ReviewQuorumError(f"{field} is missing fields")


def _sha(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if SHA_RE.fullmatch(text) is None:
        raise ReviewQuorumError(f"{field} must be a full commit SHA")
    return text


def _digest(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if DIGEST_RE.fullmatch(text) is None:
        raise ReviewQuorumError(f"{field} must be a sha256 digest")
    return text


def review_quorum_policy(manifest: Mapping[str, Any]) -> dict[str, Any]:
    raw = manifest.get("review_quorum") or {}
    raw = _mapping(raw, "review_quorum")
    expected = {
        "schema_version",
        "enabled",
        "required_roles",
        "require_tests",
        "require_codex",
        "minimum_human_reviews",
        "human_reviewer_logins",
    }
    if raw:
        _exact_keys(raw, expected, "review_quorum")
    schema = str(raw.get("schema_version") or POLICY_SCHEMA)
    if schema != POLICY_SCHEMA:
        raise ReviewQuorumError("review_quorum.schema_version is unsupported")
    enabled = raw.get("enabled", False)
    if type(enabled) is not bool:
        raise ReviewQuorumError("review_quorum.enabled must be boolean")
    roles = raw.get("required_roles", list(REQUIRED_ROLES))
    if roles != list(REQUIRED_ROLES):
        raise ReviewQuorumError("review_quorum.required_roles cannot be weakened")
    for field in ("require_tests", "require_codex"):
        if raw.get(field, True) is not True:
            raise ReviewQuorumError(f"review_quorum.{field} must remain true")
    minimum = raw.get("minimum_human_reviews", 1)
    if type(minimum) is not int or not 1 <= minimum <= 5:
        raise ReviewQuorumError(
            "review_quorum.minimum_human_reviews must be between 1 and 5"
        )
    logins_raw = raw.get("human_reviewer_logins", [])
    if not isinstance(logins_raw, list):
        raise ReviewQuorumError("review_quorum.human_reviewer_logins must be a list")
    logins: list[str] = []
    seen: set[str] = set()
    for item in logins_raw:
        value = str(item or "").strip()
        folded = value.casefold()
        if LOGIN_RE.fullmatch(value) is None or folded in seen:
            raise ReviewQuorumError("review_quorum.human_reviewer_logins is invalid")
        seen.add(folded)
        logins.append(folded)
    if enabled and len(logins) < minimum:
        raise ReviewQuorumError(
            "review_quorum.human_reviewer_logins does not satisfy minimum"
        )
    policy = {
        "schema_version": schema,
        "enabled": enabled,
        "required_roles": list(REQUIRED_ROLES),
        "require_tests": True,
        "require_codex": True,
        "minimum_human_reviews": minimum,
        "human_reviewer_logins": logins,
    }
    return {**policy, "policy_sha256": sha256_json(policy)}


def validate_normalized_review_quorum_policy(value: Any) -> dict[str, Any]:
    raw = _mapping(value, "review quorum policy")
    source_keys = {
        "schema_version",
        "enabled",
        "required_roles",
        "require_tests",
        "require_codex",
        "minimum_human_reviews",
        "human_reviewer_logins",
    }
    _exact_keys(raw, source_keys | {"policy_sha256"}, "review quorum policy")
    source = {key: raw[key] for key in source_keys}
    normalized = review_quorum_policy({"review_quorum": source})
    if raw.get("policy_sha256") != normalized["policy_sha256"]:
        raise ReviewQuorumError("review quorum policy digest does not match")
    return normalized


def parse_role_review_output(output_text: str, *, expected_head: str) -> dict[str, str]:
    head = _sha(expected_head, "expected_head")
    text = str(output_text or "")
    head_pattern = re.compile(
        r"^JOHN_LOMEIN_PR_REVIEW_HEAD:\s*([0-9a-fA-F]{40})\s*$",
        re.MULTILINE,
    )
    verdict_pattern = re.compile(
        r"^JOHN_LOMEIN_PR_REVIEW_STATUS:\s*(PASS|REVISE|KILL)\s*$",
        re.MULTILINE,
    )
    heads = head_pattern.findall(text)
    verdicts = verdict_pattern.findall(text)
    if len(heads) != 1 or len(verdicts) != 1:
        raise ReviewQuorumError("role review markers are ambiguous")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < 2 or head_pattern.fullmatch(lines[-2]) is None:
        raise ReviewQuorumError("role review head marker must be penultimate")
    if verdict_pattern.fullmatch(lines[-1]) is None:
        raise ReviewQuorumError("role review verdict marker must be final")
    reviewed = heads[0].lower()
    if reviewed != head:
        raise ReviewQuorumError("role review head does not match expected head")
    return {"head_sha": reviewed, "verdict": verdicts[0]}


def role_review_receipt(
    *,
    role: str,
    profile: str,
    repository: str,
    pr_number: int,
    head_sha: str,
    verdict: str,
    prompt_text: str,
    output_text: str,
    policy_sha256: str,
    created_at: str,
) -> dict[str, Any]:
    role_name = str(role or "").strip().lower()
    if role_name not in REQUIRED_ROLES:
        raise ReviewQuorumError("role review role is unsupported")
    if str(profile or "").strip() != f"john-lomein-{role_name}":
        raise ReviewQuorumError("role review profile does not match role")
    repo = str(repository or "").strip()
    if REPO_RE.fullmatch(repo) is None:
        raise ReviewQuorumError("role review repository is invalid")
    if type(pr_number) is not int or pr_number <= 0:
        raise ReviewQuorumError("role review PR number is invalid")
    head = _sha(head_sha, "role review head")
    stated_verdict = str(verdict or "").strip().upper()
    if stated_verdict not in {"PASS", "REVISE", "KILL"}:
        raise ReviewQuorumError("role review verdict is invalid")
    prompt = str(prompt_text or "")
    output = str(output_text or "")
    if not prompt.strip() or not output.strip():
        raise ReviewQuorumError("role review prompt/output cannot be empty")
    if len(prompt.encode("utf-8")) > 65536 or len(output.encode("utf-8")) > 262144:
        raise ReviewQuorumError("role review prompt/output is too large")
    parsed = parse_role_review_output(output, expected_head=head)
    if parsed["verdict"] != stated_verdict:
        raise ReviewQuorumError("role review verdict does not match output")
    policy_digest = _digest(policy_sha256, "role review policy_sha256")
    stamp = str(created_at or "").strip()
    if STAMP_RE.fullmatch(stamp) is None:
        raise ReviewQuorumError("role review created_at is invalid")
    body = {
        "schema_version": ROLE_RECEIPT_SCHEMA,
        "role": role_name,
        "profile": f"john-lomein-{role_name}",
        "repository": repo,
        "pr_number": pr_number,
        "head_sha": head,
        "verdict": stated_verdict,
        "prompt_sha256": sha256_text(prompt),
        "output_sha256": sha256_text(output),
        "policy_sha256": policy_digest,
        "created_at": stamp,
        "authority": dict(AUTHORITY),
    }
    return {**body, "receipt_sha256": sha256_json(body)}


def _valid_role_receipt(
    value: Any,
    *,
    role: str,
    repository: str,
    pr_number: int,
    head_sha: str,
    policy_sha256: str,
) -> bool:
    if not isinstance(value, Mapping):
        return False
    try:
        if value.get("schema_version") != ROLE_RECEIPT_SCHEMA:
            return False
        if value.get("role") != role or value.get("profile") != f"john-lomein-{role}":
            return False
        if value.get("repository", "").casefold() != repository.casefold():
            return False
        if value.get("pr_number") != pr_number or value.get("head_sha") != head_sha:
            return False
        if value.get("policy_sha256") != policy_sha256:
            return False
        if value.get("verdict") not in {"PASS", "REVISE", "KILL"}:
            return False
        if value.get("authority") != AUTHORITY:
            return False
        digest = str(value.get("receipt_sha256") or "")
        body = {key: item for key, item in value.items() if key != "receipt_sha256"}
        return DIGEST_RE.fullmatch(digest) is not None and sha256_json(body) == digest
    except Exception:
        return False


def _safe_receipt_bytes(path: Path, maximum: int = 65536) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ReviewQuorumError("review receipt file is missing") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or path.is_symlink()
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or before.st_mode & 0o022
    ):
        raise ReviewQuorumError("review receipt file metadata is unsafe")
    data = path.read_bytes()
    if len(data) > maximum:
        raise ReviewQuorumError("review receipt file is too large")
    return data


def load_role_review_receipts(
    directory: str | Path,
    *,
    repository: str,
    pr_number: int,
    head_sha: str,
    policy_sha256: str,
    maximum_files: int = 10,
) -> list[dict[str, Any]]:
    root = Path(directory)
    try:
        info = root.lstat()
    except OSError as exc:
        raise ReviewQuorumError("review receipt directory is missing") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or root.is_symlink()
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o022
    ):
        raise ReviewQuorumError("review receipt directory metadata is unsafe")
    head = _sha(head_sha, "review receipt head")
    candidates = sorted(root.glob(f"*pr-{int(pr_number)}-{head}-*.json"))
    if len(candidates) > maximum_files:
        raise ReviewQuorumError("too many review receipt files")
    loaded: list[dict[str, Any]] = []
    for path in candidates:
        try:
            value = json.loads(_safe_receipt_bytes(path).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReviewQuorumError("review receipt file is invalid") from exc
        if not isinstance(value, dict):
            raise ReviewQuorumError("review receipt file is invalid")
        role = str(value.get("role") or "")
        if role not in REQUIRED_ROLES or not _valid_role_receipt(
            value,
            role=role,
            repository=repository,
            pr_number=pr_number,
            head_sha=head,
            policy_sha256=policy_sha256,
        ):
            raise ReviewQuorumError("review receipt file failed validation")
        loaded.append(value)
    return loaded


def current_human_review_evidence(
    reviews: list[dict],
    *,
    head_sha: str,
    allowed_logins: set[str] | frozenset[str],
) -> list[dict[str, Any]]:
    head = _sha(head_sha, "human review head")
    allowed = {str(item).casefold() for item in allowed_logins}
    latest: dict[str, tuple[str, int, dict]] = {}
    for raw in reviews:
        if not isinstance(raw, dict):
            continue
        user = raw.get("user") or raw.get("author") or {}
        if not isinstance(user, dict):
            continue
        login = str(user.get("login") or "").strip()
        if login.casefold() not in allowed:
            continue
        commit = str(raw.get("commit_id") or raw.get("commitId") or "").lower()
        if commit != head:
            continue
        state = str(raw.get("state") or "").upper()
        stamp = str(raw.get("submitted_at") or raw.get("submittedAt") or "")
        review_id = raw.get("id")
        if type(review_id) is not int or review_id <= 0:
            continue
        order = (stamp, review_id)
        prior = latest.get(login.casefold())
        if prior is None or order > (prior[0], prior[1]):
            latest[login.casefold()] = (stamp, review_id, {
                "login": login,
                "commit_sha": head,
                "state": state,
                "review_id": review_id,
                "submitted_at": stamp,
            })
    result = [item[2] for item in latest.values() if item[2]["state"] in POSITIVE_HUMAN_STATES]
    result.sort(key=lambda item: (item["login"].casefold(), item["review_id"]))
    return result


def _automation_evidence_ok(value: Any, head_sha: str, status: str) -> bool:
    if not isinstance(value, Mapping):
        return False
    return (
        value.get("head_sha") == head_sha
        and str(value.get("status") or "").casefold() == status
        and DIGEST_RE.fullmatch(str(value.get("evidence_sha256") or "")) is not None
    )


def _latest_role_receipt(
    receipts: list[Any],
    *,
    role: str,
    repository: str,
    pr_number: int,
    head_sha: str,
    policy_sha256: str,
) -> Mapping[str, Any] | None:
    valid = [
        item for item in receipts
        if _valid_role_receipt(
            item,
            role=role,
            repository=repository,
            pr_number=pr_number,
            head_sha=head_sha,
            policy_sha256=policy_sha256,
        )
    ]
    if not valid:
        return None
    return sorted(
        valid,
        key=lambda item: (str(item.get("created_at") or ""), str(item.get("receipt_sha256") or "")),
    )[-1]


def evaluate_review_quorum(
    *,
    policy: Mapping[str, Any],
    repository: str,
    pr_number: int,
    head_sha: str,
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    repo = str(repository or "").strip()
    if REPO_RE.fullmatch(repo) is None:
        raise ReviewQuorumError("review quorum repository is invalid")
    if type(pr_number) is not int or pr_number <= 0:
        raise ReviewQuorumError("review quorum PR number is invalid")
    head = _sha(head_sha, "review quorum head")
    normalized_policy = review_quorum_policy({
        "review_quorum": {
            key: value
            for key, value in policy.items()
            if key != "policy_sha256"
        }
    })
    if policy.get("policy_sha256") != normalized_policy["policy_sha256"]:
        raise ReviewQuorumError("review quorum policy digest is stale")
    if not isinstance(evidence, Mapping):
        raise ReviewQuorumError("review quorum evidence must be a mapping")

    reasons: list[str] = []
    if not normalized_policy["enabled"]:
        reasons.append("review_quorum_disabled")
    tests = evidence.get("tests")
    if not _automation_evidence_ok(tests, head, "success"):
        reasons.append("tests_not_clean_current_head")
    codex = evidence.get("codex")
    if not _automation_evidence_ok(codex, head, "clean"):
        reasons.append("codex_not_clean_current_head")

    receipts = evidence.get("role_reviews")
    if not isinstance(receipts, list):
        receipts = []
    role_summary: list[dict[str, Any]] = []
    for role in REQUIRED_ROLES:
        latest = _latest_role_receipt(
            receipts,
            role=role,
            repository=repo,
            pr_number=pr_number,
            head_sha=head,
            policy_sha256=normalized_policy["policy_sha256"],
        )
        if latest is None or latest.get("verdict") != "PASS":
            reasons.append(f"{role}_review_missing_current_head")
            continue
        role_summary.append({
            "role": role,
            "receipt_sha256": latest["receipt_sha256"],
            "verdict": "PASS",
        })

    raw_humans = evidence.get("human_reviews")
    humans = raw_humans if isinstance(raw_humans, list) else []
    allowed = set(normalized_policy["human_reviewer_logins"])
    valid_humans: list[dict[str, Any]] = []
    seen_humans: set[str] = set()
    for item in humans:
        if not isinstance(item, Mapping):
            continue
        login = str(item.get("login") or "")
        folded = login.casefold()
        if folded not in allowed or folded in seen_humans:
            continue
        if item.get("commit_sha") != head:
            continue
        if str(item.get("state") or "").upper() not in POSITIVE_HUMAN_STATES:
            continue
        review_id = item.get("review_id")
        if type(review_id) is not int or review_id <= 0:
            continue
        seen_humans.add(folded)
        valid_humans.append({
            "login": login,
            "review_id": review_id,
            "state": str(item["state"]).upper(),
            "commit_sha": head,
        })
    valid_humans.sort(key=lambda item: (item["login"].casefold(), item["review_id"]))
    if len(valid_humans) < normalized_policy["minimum_human_reviews"]:
        reasons.append("human_review_quorum_missing_current_head")

    basis = {
        "schema_version": QUORUM_SCHEMA,
        "repository": repo,
        "pr_number": pr_number,
        "head_sha": head,
        "policy_sha256": normalized_policy["policy_sha256"],
        "tests_evidence_sha256": tests.get("evidence_sha256") if isinstance(tests, Mapping) else None,
        "codex_evidence_sha256": codex.get("evidence_sha256") if isinstance(codex, Mapping) else None,
        "role_reviews": role_summary,
        "human_reviews": valid_humans,
        "reasons": sorted(set(reasons)),
        "authority": dict(AUTHORITY),
    }
    return {
        **basis,
        "merge_ready": not basis["reasons"],
        "quorum_sha256": sha256_json(basis),
    }
