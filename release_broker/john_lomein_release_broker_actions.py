#!/usr/bin/env python3
"""Release preconditions and mutation fencing for the isolated broker.

This module contains no generic GitHub mutation primitive.  It turns a complete
live snapshot into a digest-bound precondition proof for one exact squash
merge.  Durable attempt charging and the sole merge call are orchestrated by
the service only after this proof succeeds.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .john_lomein_release_broker_protocol import (
    OID_RE,
    ReleaseBrokerProtocolError,
    canonical_json,
    normalize_release_bundle,
    sha256_json,
)


ACCEPTED_CHECK_CONCLUSIONS = frozenset(
    {"SUCCESS", "NEUTRAL", "SKIPPED"}
)
CODEX_MARKER_RE = re.compile(
    r"<!-- john-lomein-release-review:v1 "
    r"head=((?:[0-9a-f]{40}|[0-9a-f]{64})) "
    r"verdict=(clean|changes_requested|unsafe) -->"
)


class ReleaseActionError(RuntimeError):
    """A deterministic precondition or externally visible effect failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        immediate_circuit: bool = False,
    ) -> None:
        if not re.fullmatch(r"^[a-z][a-z0-9_]{2,127}$", code):
            raise ValueError("release action error code is invalid")
        self.code = code
        self.immediate_circuit = immediate_circuit
        super().__init__(message)


@dataclass(frozen=True)
class CodexEvidence:
    verdict: str
    author_login: str
    kind: str
    artifact_id: str
    url: str
    observed_at: str
    head_sha: str

    def as_dict(self) -> dict[str, str]:
        return {
            "verdict": self.verdict,
            "author_login": self.author_login,
            "kind": self.kind,
            "artifact_id": self.artifact_id,
            "url": self.url,
            "observed_at": self.observed_at,
            "head_sha": self.head_sha,
        }


@dataclass(frozen=True)
class ReleasePreflight:
    pr_number: int
    head_sha: str
    expected_base_sha: str
    expected_merge_tree_sha: str
    changed_paths: tuple[str, ...]
    codex_evidence: CodexEvidence
    precondition_digest: str
    evidence: Mapping[str, Any]


def _mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReleaseActionError(
            "live_snapshot_invalid", f"{field} must be an object"
        )
    return value


def _array(value: Any, *, field: str) -> list[Any]:
    if not isinstance(value, (list, tuple)):
        raise ReleaseActionError(
            "live_snapshot_invalid", f"{field} must be an array"
        )
    return list(value)


def _timestamp_key(value: Any, *, field: str) -> tuple[datetime, str]:
    if not isinstance(value, str) or not value:
        raise ReleaseActionError(
            "codex_evidence_invalid", f"{field} timestamp is missing"
        )
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ReleaseActionError(
            "codex_evidence_invalid", f"{field} timestamp is invalid"
        ) from exc
    if parsed.tzinfo is None:
        raise ReleaseActionError(
            "codex_evidence_invalid", f"{field} timestamp has no timezone"
        )
    return parsed.astimezone(timezone.utc), value


def _marker_for_head(body: Any, head_sha: str) -> str | None:
    if not isinstance(body, str):
        raise ReleaseActionError(
            "codex_evidence_invalid",
            "Codex evidence body must be text",
        )
    matches = [
        verdict
        for oid, verdict in CODEX_MARKER_RE.findall(body)
        if oid == head_sha
    ]
    if not matches:
        return None
    if len(set(matches)) != 1:
        raise ReleaseActionError(
            "codex_evidence_conflict",
            "one Codex artifact contains conflicting release verdicts",
        )
    return matches[-1]


def _contains_exact_oid(body: str, head_sha: str) -> bool:
    return re.search(
        rf"(?<![0-9a-f]){re.escape(head_sha)}(?![0-9a-f])",
        body,
    ) is not None


def _legacy_codex_verdict(
    item: Mapping[str, Any],
    *,
    exact_head_bound: bool,
) -> str | None:
    """Interpret the current Codex review format only when GitHub binds head."""

    if not exact_head_bound:
        return None
    body = str(item.get("body") or "")
    lowered = body.lower()
    if (
        "didn't find any major issues" in lowered
        and "automated review suggestions" not in lowered
        and item.get("state") != "CHANGES_REQUESTED"
    ):
        return "clean"
    if (
        item.get("state") == "CHANGES_REQUESTED"
        or "automated review suggestions" in lowered
    ):
        return "changes_requested"
    return None


def select_codex_evidence(
    snapshot: Mapping[str, Any],
    *,
    head_sha: str,
    allowed_authors: Iterable[str],
) -> CodexEvidence:
    """Select the latest exact-head verdict from trusted Codex authors.

    The explicit release marker is preferred.  The current Codex review format
    is also accepted when GitHub itself binds the review/comment to the full
    head OID; abbreviated prose references alone never establish the binding.
    """

    if not isinstance(head_sha, str) or not OID_RE.fullmatch(head_sha):
        raise ReleaseActionError(
            "codex_evidence_invalid",
            "Codex evidence requires a full head OID",
        )
    authors = frozenset(allowed_authors)
    if not authors or not all(
        isinstance(author, str) and author for author in authors
    ):
        raise ReleaseActionError(
            "codex_evidence_policy_invalid",
            "Codex evidence author policy is invalid",
        )
    candidates: list[
        tuple[datetime, str, str, str, str, str, str]
    ] = []

    def add(
        item: Mapping[str, Any],
        *,
        kind: str,
        timestamp_field: str,
        exact_head_bound: bool,
    ) -> None:
        author = item.get("author_login")
        if author not in authors:
            return
        verdict = _marker_for_head(item.get("body"), head_sha)
        if verdict is None:
            verdict = _legacy_codex_verdict(
                item,
                exact_head_bound=exact_head_bound,
            )
        if verdict is None:
            return
        observed, original = _timestamp_key(
            item.get(timestamp_field), field=f"{kind} evidence"
        )
        artifact_id = str(item.get("id") or "")
        url = str(item.get("url") or "")
        if not artifact_id or not url:
            raise ReleaseActionError(
                "codex_evidence_invalid",
                "Codex evidence identity is incomplete",
            )
        candidates.append(
            (
                observed,
                kind,
                artifact_id,
                verdict,
                str(author),
                url,
                original,
            )
        )

    for raw in _array(
        snapshot.get("issue_comments"), field="issue comments"
    ):
        item = _mapping(raw, field="issue comment")
        add(
            item,
            kind="issue_comment",
            timestamp_field="updated_at",
            exact_head_bound=_contains_exact_oid(
                str(item.get("body") or ""), head_sha
            ),
        )
    for raw in _array(snapshot.get("reviews"), field="reviews"):
        item = _mapping(raw, field="review")
        add(
            item,
            kind="pull_request_review",
            timestamp_field="submitted_at",
            exact_head_bound=(
                item.get("commit_oid") == head_sha
                or _contains_exact_oid(
                    str(item.get("body") or ""), head_sha
                )
            ),
        )
    for raw_thread in _array(
        snapshot.get("review_threads"), field="review threads"
    ):
        thread = _mapping(raw_thread, field="review thread")
        for raw in _array(
            thread.get("comments"), field="review-thread comments"
        ):
            item = _mapping(raw, field="review-thread comment")
            add(
                item,
                kind="review_thread_comment",
                timestamp_field="created_at",
                exact_head_bound=(
                    item.get("commit_oid") == head_sha
                    or item.get("original_commit_oid") == head_sha
                    or _contains_exact_oid(
                        str(item.get("body") or ""), head_sha
                    )
                ),
            )
    if not candidates:
        raise ReleaseActionError(
            "codex_evidence_missing",
            "no trusted Codex verdict exists for the exact head",
        )
    candidates.sort(
        key=lambda item: (item[0], item[1], item[2])
    )
    (
        _observed,
        kind,
        artifact_id,
        verdict,
        author,
        url,
        observed_at,
    ) = candidates[-1]
    evidence = CodexEvidence(
        verdict=verdict,
        author_login=author,
        kind=kind,
        artifact_id=artifact_id,
        url=url,
        observed_at=observed_at,
        head_sha=head_sha,
    )
    if verdict != "clean":
        raise ReleaseActionError(
            "codex_evidence_adverse",
            "the latest trusted exact-head Codex verdict is adverse",
        )
    return evidence


def _required_check_evidence(
    snapshot: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> list[dict[str, Any]]:
    checks = [
        dict(_mapping(item, field="check run"))
        for item in _array(snapshot.get("checks"), field="check runs")
    ]
    statuses = [
        dict(_mapping(item, field="commit status"))
        for item in _array(snapshot.get("statuses"), field="commit statuses")
    ]
    selected: list[dict[str, Any]] = []
    for raw_spec in _array(
        policy.get("required_checks"), field="required check policy"
    ):
        spec = _mapping(raw_spec, field="required check policy entry")
        kind = spec.get("kind")
        name = spec.get("name")
        if kind == "check_run":
            matches = [
                item
                for item in checks
                if item.get("name") == name
                and item.get("producer_app_id")
                == spec.get("producer_app_id")
                and item.get("producer_slug")
                == spec.get("producer_slug")
            ]
            if not matches:
                raise ReleaseActionError(
                    "required_check_missing",
                    f"required check run {name!r} is missing",
                )
            if any(
                item.get("status") != "COMPLETED"
                or item.get("conclusion")
                not in ACCEPTED_CHECK_CONCLUSIONS
                for item in matches
            ):
                raise ReleaseActionError(
                    "required_check_not_green",
                    f"required check run {name!r} is not green",
                )
        elif kind == "commit_status":
            matches = [
                item
                for item in statuses
                if item.get("context") == name
                and item.get("creator_login")
                == spec.get("producer_login")
            ]
            if not matches:
                raise ReleaseActionError(
                    "required_check_missing",
                    f"required commit status {name!r} is missing",
                )
            if any(item.get("state") != "SUCCESS" for item in matches):
                raise ReleaseActionError(
                    "required_check_not_green",
                    f"required commit status {name!r} is not green",
                )
        else:
            raise ReleaseActionError(
                "required_check_policy_invalid",
                "required check policy kind is invalid",
            )
        selected.append(
            {
                "policy": dict(spec),
                "observations": matches,
            }
        )
    if policy.get("reject_unconfigured_failures") is True:
        if any(
            item.get("status") != "COMPLETED"
            or item.get("conclusion") not in ACCEPTED_CHECK_CONCLUSIONS
            for item in checks
        ) or any(item.get("state") != "SUCCESS" for item in statuses):
            raise ReleaseActionError(
                "observed_check_not_green",
                "an observed check or status is not green",
            )
    return selected


def _snapshot_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "as_dict") and callable(value.as_dict):
        value = value.as_dict()
    if not isinstance(value, Mapping):
        raise ReleaseActionError(
            "live_snapshot_invalid", "live snapshot must be an object"
        )
    # The GitHub boundary already canonicalizes its values; round-tripping here
    # prevents custom Mapping implementations from changing during validation.
    try:
        return json.loads(canonical_json(dict(value)))
    except (TypeError, ValueError, ReleaseBrokerProtocolError) as exc:
        raise ReleaseActionError(
            "live_snapshot_invalid",
            "live snapshot is not canonical JSON",
        ) from exc


def validate_preflight(
    snapshot_value: Any,
    bundle_value: Any,
    policy_value: Mapping[str, Any],
) -> ReleasePreflight:
    """Validate one exact live PR and return its durable precondition proof."""

    snapshot = _snapshot_dict(snapshot_value)
    try:
        bundle = normalize_release_bundle(bundle_value)
    except ReleaseBrokerProtocolError as exc:
        raise ReleaseActionError(
            "release_bundle_invalid", str(exc)
        ) from exc
    policy = _mapping(policy_value, field="release policy")
    if len(bundle["ordered_prs"]) != 1:
        raise ReleaseActionError(
            "release_train_unavailable",
            "live release v1 accepts exactly one PR",
        )
    expected = bundle["ordered_prs"][0]
    expected_base = bundle["initial_base_sha"]
    expected_merge_tree = expected["expected_merge_tree_sha"]
    repository_policy = _mapping(
        snapshot.get("repository_policy"),
        field="repository policy",
    )
    if repository_policy.get("is_archived") is not False:
        raise ReleaseActionError(
            "repository_archived", "repository is archived"
        )
    if repository_policy.get("is_disabled") is not False:
        raise ReleaseActionError(
            "repository_disabled", "repository is disabled"
        )
    if repository_policy.get("squash_merge_allowed") is not True:
        raise ReleaseActionError(
            "squash_merge_disabled",
            "repository does not allow squash merging",
        )
    repository = bundle["repository"]
    if (
        snapshot.get("repository") != repository["full_name"]
        or snapshot.get("repository_id") != repository["id"]
    ):
        raise ReleaseActionError(
            "repository_identity_mismatch",
            "live repository does not match the release bundle",
        )
    pr = _mapping(snapshot.get("pr"), field="pull request")
    exact_pr_bindings = {
        "number": expected["number"],
        "url": expected["url"],
        "head_oid": expected["head_sha"],
        "base_branch": expected["base_branch"],
        "base_oid": expected_base,
        "author_login": expected["author_login"],
        "changed_files": expected["changed_path_count"],
    }
    for field, value in exact_pr_bindings.items():
        if pr.get(field) != value:
            raise ReleaseActionError(
                "pull_request_identity_mismatch",
                f"live pull request {field} does not match the bundle",
            )
    if (
        pr.get("state") != "OPEN"
        or pr.get("merged") is not False
        or pr.get("is_draft") is not False
    ):
        raise ReleaseActionError(
            "pull_request_not_open_ready",
            "pull request is not open and ready",
        )
    if pr.get("same_repository_head") is not True:
        raise ReleaseActionError(
            "cross_repository_head",
            "pull request head is not in the configured repository",
        )
    if pr.get("auto_merge_requested") is not False:
        raise ReleaseActionError(
            "auto_merge_conflict",
            "pull request already has an auto-merge request",
        )
    if pr.get("merge_queue_entry_present") is not False:
        raise ReleaseActionError(
            "merge_queue_conflict",
            "pull request already has a merge-queue entry",
        )
    if pr.get("mergeable") != "MERGEABLE":
        raise ReleaseActionError(
            "pull_request_not_mergeable",
            "pull request is not mergeable",
        )
    if pr.get("merge_state_status") != "CLEAN":
        raise ReleaseActionError(
            "pull_request_not_clean",
            "pull request merge state is not clean",
        )
    if pr.get("review_decision") in {"CHANGES_REQUESTED", "REVIEW_REQUIRED"}:
        raise ReleaseActionError(
            "review_decision_blocked",
            "pull request review decision blocks merging",
        )
    potential_merge_oid = pr.get("potential_merge_commit_oid")
    if (
        not isinstance(potential_merge_oid, str)
        or not OID_RE.fullmatch(potential_merge_oid)
    ):
        raise ReleaseActionError(
            "potential_merge_commit_invalid",
            "live potential merge commit identity is invalid",
        )
    if pr.get("potential_merge_tree_oid") != expected_merge_tree:
        raise ReleaseActionError(
            "potential_merge_tree_mismatch",
            "live potential merge tree does not match signed authority",
        )
    potential_parents = _array(
        pr.get("potential_merge_parent_oids"),
        field="potential merge parents",
    )
    if potential_parents != [expected_base, expected["head_sha"]]:
        raise ReleaseActionError(
            "potential_merge_topology_mismatch",
            "potential merge parents do not match exact base and head",
        )
    default_branch = _mapping(
        snapshot.get("default_branch"), field="default branch"
    )
    if (
        default_branch.get("name") != repository["default_branch"]
        or default_branch.get("qualified_name")
        != f"refs/heads/{repository['default_branch']}"
    ):
        raise ReleaseActionError(
            "default_branch_identity_mismatch",
            "live default branch does not match the release bundle",
        )
    default_commit = _mapping(
        default_branch.get("commit"), field="default branch commit"
    )
    if default_commit.get("oid") != expected_base:
        raise ReleaseActionError(
            "default_branch_advanced",
            "default branch no longer matches the authorized base",
        )
    files = [
        _mapping(item, field="changed file")
        for item in _array(snapshot.get("files"), field="changed files")
    ]
    live_paths = [str(item.get("path") or "") for item in files]
    if (
        len(live_paths) != len(set(live_paths))
        or sorted(live_paths) != expected["changed_paths"]
    ):
        raise ReleaseActionError(
            "changed_paths_mismatch",
            "live changed paths do not exactly match the release bundle",
        )
    if snapshot.get("unresolved_thread_count") != 0:
        raise ReleaseActionError(
            "unresolved_review_threads",
            "pull request has unresolved review threads",
        )
    selected_checks = _required_check_evidence(snapshot, policy)
    codex = select_codex_evidence(
        snapshot,
        head_sha=expected["head_sha"],
        allowed_authors=policy.get(
            "codex_evidence_author_logins"
        )
        or (),
    )
    evidence: dict[str, Any] = {
        "schema_version": "john-lomein.release-precondition-evidence.v1",
        "repository": {
            "id": repository["id"],
            "full_name": repository["full_name"],
            "policy": dict(repository_policy),
        },
        "pull_request": {
            key: pr.get(key)
            for key in (
                "number",
                "url",
                "state",
                "is_draft",
                "merged",
                "head_oid",
                "base_branch",
                "base_oid",
                "author_login",
                "same_repository_head",
                "changed_files",
                "mergeable",
                "merge_state_status",
                "review_decision",
                "potential_merge_commit_oid",
                "potential_merge_tree_oid",
                "potential_merge_parent_oids",
                "auto_merge_requested",
                "merge_queue_entry_present",
            )
        },
        "expected_merge_tree_sha": expected_merge_tree,
        "default_branch": {
            "name": default_branch["name"],
            "qualified_name": default_branch["qualified_name"],
            "head_sha": default_commit.get("oid"),
            "tree_sha": default_commit.get("tree_oid"),
        },
        "changed_paths": live_paths,
        "required_checks": selected_checks,
        "unresolved_thread_count": 0,
        "codex_evidence": codex.as_dict(),
        "minimum_rate_limit_remaining": snapshot.get(
            "minimum_rate_limit_remaining"
        ),
    }
    return ReleasePreflight(
        pr_number=expected["number"],
        head_sha=expected["head_sha"],
        expected_base_sha=expected_base,
        expected_merge_tree_sha=expected_merge_tree,
        changed_paths=tuple(live_paths),
        codex_evidence=codex,
        precondition_digest=sha256_json(evidence),
        evidence=evidence,
    )


def validate_immediate_base_fence(
    branch_value: Any,
    *,
    expected_branch: str,
    expected_base_sha: str,
) -> None:
    """Re-read the branch immediately before the mutation."""

    branch = (
        branch_value.as_dict()
        if hasattr(branch_value, "as_dict")
        and callable(branch_value.as_dict)
        else branch_value
    )
    branch = _mapping(branch, field="immediate default branch")
    commit = _mapping(
        branch.get("commit"), field="immediate default branch commit"
    )
    if (
        branch.get("name") != expected_branch
        or branch.get("qualified_name") != f"refs/heads/{expected_branch}"
        or commit.get("oid") != expected_base_sha
    ):
        raise ReleaseActionError(
            "immediate_base_fence_failed",
            "default branch changed immediately before merge",
        )
