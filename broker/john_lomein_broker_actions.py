"""Protected broker action preconditions and mutation state machines."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Any, Mapping, Protocol

from .john_lomein_broker_protocol import evidence_marker_for_packet
from .john_lomein_github_live import GitHubLiveError, LiveSnapshot


HARD_FORBIDDEN_PATTERNS = (
    ".github/workflows/**",
    ".github/actions/**",
    ".github/CODEOWNERS",
    "CODEOWNERS",
    ".env",
    ".env.*",
    ".npmrc",
    ".gitmodules",
)
COMPLETION_STATUSES = frozenset(
    {"completed", "already_satisfied", "reconciled_completed"}
)
OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class BrokerActionError(RuntimeError):
    """The live state does not authorize the requested protected action."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class MutationIndeterminate(BrokerActionError):
    """A mutation may have happened but safe readback could not prove it."""

    def __init__(
        self,
        reason_code: str,
        message: str,
        *,
        mutation_evidence: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(reason_code, message)
        self.mutation_evidence = dict(mutation_evidence or {})


class LiveActionClient(Protocol):
    def fetch_snapshot(
        self,
        *,
        pr_number: int,
        evidence_comment_url: str,
    ) -> LiveSnapshot:
        ...

    def mark_pr_ready(
        self,
        *,
        pr_node_id: str,
        client_mutation_id: str,
    ) -> Mapping[str, Any]:
        ...

    def resolve_review_thread(
        self,
        *,
        thread_id: str,
        client_mutation_id: str,
    ) -> Mapping[str, Any]:
        ...


@dataclass(frozen=True)
class EvaluatedAction:
    action: str
    repository: str
    pr_number: int
    pr_node_id: str
    head_sha: str
    target_thread_id: str | None
    already_satisfied: bool
    before_digest: str
    before: Mapping[str, Any]


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _utc(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise BrokerActionError("invalid_timestamp", f"{field} is invalid")
    try:
        return datetime.strptime(value, UTC_FORMAT).replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise BrokerActionError(
            "invalid_timestamp", f"{field} is invalid"
        ) from exc


def evidence_marker(packet: Mapping[str, Any]) -> str:
    return evidence_marker_for_packet(packet)


def _snapshot_dict(snapshot: LiveSnapshot | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(snapshot, LiveSnapshot):
        return snapshot.as_dict()
    if not isinstance(snapshot, Mapping):
        raise BrokerActionError(
            "invalid_live_snapshot", "live snapshot is invalid"
        )
    return json.loads(json.dumps(dict(snapshot)))


def _instance(config: Mapping[str, Any]) -> Mapping[str, Any]:
    value = config.get("instance")
    if not isinstance(value, Mapping):
        raise BrokerActionError(
            "invalid_broker_config", "broker instance config is missing"
        )
    return value


def _repository_config(config: Mapping[str, Any]) -> Mapping[str, Any]:
    instance = _instance(config)
    value = instance.get("repository")
    if not isinstance(value, Mapping):
        raise BrokerActionError(
            "invalid_broker_config", "broker repository config is missing"
        )
    return value


def _policy(config: Mapping[str, Any]) -> Mapping[str, Any]:
    value = _instance(config).get("policy")
    if not isinstance(value, Mapping):
        raise BrokerActionError(
            "invalid_broker_config", "broker policy is missing"
        )
    return value


def _allowed_authors(policy: Mapping[str, Any]) -> frozenset[str]:
    values = policy.get("allowed_pr_authors")
    if isinstance(values, list) and all(
        isinstance(item, str) and item for item in values
    ):
        return frozenset(values)
    expected = policy.get("expected_pr_author_login")
    if isinstance(expected, str) and expected:
        return frozenset({expected})
    raise BrokerActionError(
        "invalid_broker_config", "broker PR-author policy is missing"
    )


def _safe_repo_path(path: Any) -> str:
    if (
        not isinstance(path, str)
        or not path
        or "\x00" in path
        or "\\" in path
        or path.startswith("/")
    ):
        raise BrokerActionError(
            "unsafe_changed_path", "changed path is invalid"
        )
    parsed = PurePosixPath(path)
    if any(part in {"", ".", ".."} for part in parsed.parts):
        raise BrokerActionError(
            "unsafe_changed_path", "changed path is invalid"
        )
    normalized = str(parsed)
    if normalized != path:
        raise BrokerActionError(
            "unsafe_changed_path", "changed path is not canonical"
        )
    return path


def _forbidden_patterns(policy: Mapping[str, Any]) -> tuple[str, ...]:
    configured = policy.get("forbidden_paths")
    if not isinstance(configured, list):
        configured = policy.get("forbidden_path_prefixes", [])
    if not isinstance(configured, list) or not all(
        isinstance(item, str) and item for item in configured
    ):
        raise BrokerActionError(
            "invalid_broker_config", "forbidden-path policy is invalid"
        )
    return tuple(dict.fromkeys((*HARD_FORBIDDEN_PATTERNS, *configured)))


def _path_matches(path: str, pattern: str) -> bool:
    if pattern.endswith("/") and path.startswith(pattern):
        return True
    if not any(character in pattern for character in "*?["):
        return path == pattern or path.startswith(pattern.rstrip("/") + "/")
    return fnmatch.fnmatchcase(path, pattern)


def _validate_paths(
    files: Any,
    *,
    policy: Mapping[str, Any],
) -> tuple[str, ...]:
    if not isinstance(files, list):
        raise BrokerActionError(
            "invalid_live_snapshot", "live changed files are invalid"
        )
    normalized = tuple(_safe_repo_path(item) for item in files)
    if len(set(normalized)) != len(normalized):
        raise BrokerActionError(
            "duplicate_changed_path", "live changed files contain duplicates"
        )
    patterns = _forbidden_patterns(policy)
    blocked = [
        path
        for path in normalized
        if any(_path_matches(path, pattern) for pattern in patterns)
    ]
    if blocked:
        raise BrokerActionError(
            "forbidden_path_changed",
            "pull request changes a broker-forbidden path",
        )
    maximum = policy.get("maximum_changed_files", 1000)
    if (
        isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or maximum <= 0
        or len(normalized) > maximum
    ):
        raise BrokerActionError(
            "changed_file_limit",
            "pull request changed-file count exceeds broker policy",
        )
    return normalized


def _accepted_conclusions(
    policy: Mapping[str, Any],
) -> frozenset[str]:
    values = policy.get(
        "accepted_check_conclusions", ["SUCCESS", "NEUTRAL", "SKIPPED"]
    )
    if not isinstance(values, list) or not all(
        isinstance(item, str) and item for item in values
    ):
        raise BrokerActionError(
            "invalid_broker_config", "accepted-check policy is invalid"
        )
    return frozenset(item.upper() for item in values)


def _validate_checks(
    checks: Any,
    *,
    policy: Mapping[str, Any],
) -> str:
    if not isinstance(checks, list):
        raise BrokerActionError(
            "invalid_live_snapshot", "live checks are invalid"
        )
    required = policy.get("required_check_contexts")
    if not isinstance(required, list):
        required = policy.get("required_checks", [])
    if not isinstance(required, list) or not all(
        isinstance(item, str) and item for item in required
    ):
        raise BrokerActionError(
            "invalid_broker_config", "required-check policy is invalid"
        )
    allow_none = bool(
        policy.get(
            "allow_no_checks",
            policy.get("allow_no_required_checks", False),
        )
    )
    if not checks:
        if required or not allow_none:
            raise BrokerActionError(
                "required_checks_missing",
                "GitHub returned no status contexts",
            )
        return "none"
    accepted = _accepted_conclusions(policy)
    names: set[str] = set()
    for raw in checks:
        if not isinstance(raw, Mapping):
            raise BrokerActionError(
                "invalid_live_snapshot", "status context is invalid"
            )
        kind = raw.get("kind")
        name = raw.get("name")
        status = raw.get("status")
        if not isinstance(name, str) or not name:
            raise BrokerActionError(
                "invalid_live_snapshot", "status context name is invalid"
            )
        names.add(name)
        if kind == "check_run":
            if status != "COMPLETED" or raw.get("conclusion") not in accepted:
                raise BrokerActionError(
                    "check_not_successful",
                    "a GitHub check run is pending or unsuccessful",
                )
        elif kind == "commit_status":
            if status != "SUCCESS":
                raise BrokerActionError(
                    "check_not_successful",
                    "a GitHub commit status is pending or unsuccessful",
                )
        else:
            raise BrokerActionError(
                "invalid_live_snapshot", "status context kind is invalid"
            )
    missing = sorted(set(required) - names)
    if missing:
        raise BrokerActionError(
            "required_checks_missing",
            "one or more configured required checks are missing",
        )
    return "success"


def _validate_evidence(
    *,
    packet: Mapping[str, Any],
    comment: Any,
    allowed_authors: frozenset[str],
    maximum_clock_skew_seconds: int,
) -> Mapping[str, Any]:
    if not isinstance(comment, Mapping):
        raise BrokerActionError(
            "invalid_live_snapshot", "evidence comment is invalid"
        )
    request = packet["request"]
    expected_url = request["preconditions"]["evidence_comment_url"]
    if comment.get("url") != expected_url:
        raise BrokerActionError(
            "evidence_comment_mismatch",
            "evidence comment URL does not match the packet",
        )
    if comment.get("author_login") not in allowed_authors:
        raise BrokerActionError(
            "evidence_author_mismatch",
            "evidence comment author is not an allowed bot identity",
        )
    body = comment.get("body")
    marker = evidence_marker(packet)
    if not isinstance(body, str):
        raise BrokerActionError(
            "evidence_marker_missing", "evidence comment body is invalid"
        )
    lines = body.splitlines()
    if not lines or lines[0] != marker or body.count(marker) != 1:
        raise BrokerActionError(
            "evidence_marker_missing",
            "evidence comment does not carry the exact broker marker",
        )
    observed = _utc(
        request["observed_at"], field="packet observation timestamp"
    )
    created = _utc(packet["created_at"], field="packet creation timestamp")
    comment_created = _utc(
        comment.get("created_at"), field="evidence comment timestamp"
    )
    skew = timedelta(seconds=maximum_clock_skew_seconds)
    if comment_created < observed - skew or comment_created > created + skew:
        raise BrokerActionError(
            "evidence_timestamp_mismatch",
            "evidence comment timestamp is outside the packet window",
        )
    return {
        "url": expected_url,
        "author_login": comment["author_login"],
        "created_at": comment["created_at"],
        "marker_sha256": hashlib.sha256(marker.encode("utf-8")).hexdigest(),
    }


def _threads(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list):
        raise BrokerActionError(
            "invalid_live_snapshot", "live review threads are invalid"
        )
    output: list[Mapping[str, Any]] = []
    ids: set[str] = set()
    for raw in value:
        if not isinstance(raw, Mapping):
            raise BrokerActionError(
                "invalid_live_snapshot", "live review thread is invalid"
            )
        thread_id = raw.get("id")
        if not isinstance(thread_id, str) or not thread_id or thread_id in ids:
            raise BrokerActionError(
                "invalid_live_snapshot", "live review-thread id is invalid"
            )
        if type(raw.get("is_resolved")) is not bool:
            raise BrokerActionError(
                "invalid_live_snapshot",
                "live review-thread resolved state is invalid",
            )
        if type(raw.get("is_outdated")) is not bool:
            raise BrokerActionError(
                "invalid_live_snapshot",
                "live review-thread outdated state is invalid",
            )
        urls = raw.get("urls")
        if not isinstance(urls, list) or not all(
            isinstance(item, str) and item for item in urls
        ):
            raise BrokerActionError(
                "invalid_live_snapshot", "review-thread URLs are invalid"
            )
        ids.add(thread_id)
        output.append(raw)
    return tuple(output)


def evaluate_snapshot(
    *,
    config: Mapping[str, Any],
    packet: Mapping[str, Any],
    snapshot: LiveSnapshot | Mapping[str, Any],
    allow_already_satisfied: bool = False,
) -> EvaluatedAction:
    live = _snapshot_dict(snapshot)
    request = packet.get("request")
    if not isinstance(request, Mapping):
        raise BrokerActionError(
            "invalid_packet", "protected-action request is missing"
        )
    action = request.get("action")
    repository_config = _repository_config(config)
    policy = _policy(config)
    expected_repository = repository_config.get(
        "full_name", repository_config.get("repo")
    )
    expected_repository_id = repository_config.get(
        "id", repository_config.get("repository_id")
    )
    if (
        live.get("repository") != expected_repository
        or live.get("repository_id") != expected_repository_id
        or request.get("repo") != expected_repository
    ):
        raise BrokerActionError(
            "repository_mismatch", "live repository does not match broker config"
        )
    pr = live.get("pr")
    packet_pr = request.get("pr")
    if not isinstance(pr, Mapping) or not isinstance(packet_pr, Mapping):
        raise BrokerActionError(
            "invalid_live_snapshot", "pull request identity is invalid"
        )
    exact_pr_fields = {
        "number": packet_pr.get("number"),
        "url": packet_pr.get("url"),
        "base_branch": packet_pr.get("base_branch"),
        "head_sha": packet_pr.get("head_sha"),
        "author_login": packet_pr.get("author_login"),
    }
    for field, expected in exact_pr_fields.items():
        if pr.get(field) != expected:
            raise BrokerActionError(
                f"pr_{field}_mismatch",
                f"live pull request {field} does not match the packet",
            )
    mark_ready_already_satisfied = (
        action == "mark_pr_ready"
        and allow_already_satisfied
        and packet_pr.get("is_draft") is True
        and pr.get("is_draft") is False
    )
    if (
        pr.get("is_draft") != packet_pr.get("is_draft")
        and not mark_ready_already_satisfied
    ):
        raise BrokerActionError(
            "pr_is_draft_mismatch",
            "live pull request is_draft does not match the packet",
        )
    if pr.get("state") != "OPEN":
        raise BrokerActionError(
            "pr_not_open", "pull request is not open"
        )
    if pr.get("base_branch") != repository_config.get(
        "default_branch"
    ):
        raise BrokerActionError(
            "base_branch_mismatch",
            "pull request base branch does not match broker config",
        )
    if pr.get("author_login") not in _allowed_authors(policy):
        raise BrokerActionError(
            "pr_author_mismatch",
            "pull request author is not allowed by broker policy",
        )
    if pr.get("same_repository_head") is not True:
        raise BrokerActionError(
            "cross_repository_head",
            "cross-repository pull requests are not eligible",
        )
    head_sha = pr.get("head_sha")
    if not isinstance(head_sha, str) or not OID_RE.fullmatch(head_sha):
        raise BrokerActionError(
            "invalid_live_snapshot", "live pull request head SHA is invalid"
        )
    files = _validate_paths(live.get("files"), policy=policy)
    if pr.get("changed_files") != len(files):
        raise BrokerActionError(
            "changed_file_count_mismatch",
            "live pull request changed-file count is inconsistent",
        )
    checks_state = _validate_checks(live.get("checks"), policy=policy)
    preconditions = request.get("preconditions")
    if not isinstance(preconditions, Mapping):
        raise BrokerActionError(
            "invalid_packet", "packet preconditions are invalid"
        )
    if preconditions.get("checks_state") != checks_state:
        raise BrokerActionError(
            "checks_state_mismatch",
            "live checks state does not match the packet",
        )
    allowed_authors = _allowed_authors(policy)
    skew = policy.get("maximum_clock_skew_seconds", 300)
    if (
        isinstance(skew, bool)
        or not isinstance(skew, int)
        or skew < 0
        or skew > 3600
    ):
        raise BrokerActionError(
            "invalid_broker_config", "broker clock-skew policy is invalid"
        )
    evidence = _validate_evidence(
        packet=packet,
        comment=live.get("evidence_comment"),
        allowed_authors=allowed_authors,
        maximum_clock_skew_seconds=skew,
    )
    threads = _threads(live.get("threads"))
    unresolved = [item for item in threads if not item["is_resolved"]]
    if live.get("unresolved_thread_count") != len(unresolved):
        raise BrokerActionError(
            "thread_count_inconsistent",
            "live unresolved-thread count is internally inconsistent",
        )
    target_thread_id: str | None = None
    already_satisfied = mark_ready_already_satisfied
    targets = request.get("targets")
    if not isinstance(targets, Mapping):
        raise BrokerActionError("invalid_packet", "packet targets are invalid")
    target_ids = targets.get("thread_node_ids")
    target_urls = targets.get("thread_urls")
    if not isinstance(target_ids, list) or not isinstance(target_urls, list):
        raise BrokerActionError("invalid_packet", "packet targets are invalid")
    if action == "mark_pr_ready":
        if pr.get("is_draft") is not True and not already_satisfied:
            raise BrokerActionError(
                "pr_not_draft", "pull request is no longer draft"
            )
        if unresolved or target_ids or target_urls:
            raise BrokerActionError(
                "mark_ready_threads_present",
                "mark-ready requires zero unresolved review threads",
            )
    elif action == "resolve_review_thread":
        if len(target_ids) != 1 or len(target_urls) != 1:
            raise BrokerActionError(
                "invalid_thread_target",
                "broker v1 requires exactly one review-thread target",
            )
        target_thread_id = target_ids[0]
        matches = [
            item for item in threads if item["id"] == target_thread_id
        ]
        if len(matches) != 1:
            raise BrokerActionError(
                "thread_not_found",
                "target review thread does not belong to this pull request",
            )
        target = matches[0]
        thread_already_satisfied = (
            allow_already_satisfied and target["is_resolved"] is True
        )
        if target["is_resolved"] and not thread_already_satisfied:
            raise BrokerActionError(
                "thread_already_resolved",
                "target review thread is already resolved",
            )
        if target_urls[0] not in target["urls"]:
            raise BrokerActionError(
                "thread_url_mismatch",
                "target review-thread URL does not match live GitHub state",
            )
        outdated_only = policy.get(
            "resolve_outdated_threads_only",
            policy.get("resolve_policy") == "outdated_only",
        )
        if outdated_only is not True or target["is_outdated"] is not True:
            raise BrokerActionError(
                "current_thread_requires_verifier",
                "current review threads require independent verifier authority",
            )
        already_satisfied = thread_already_satisfied
    else:
        raise BrokerActionError(
            "unsupported_action", "protected action is unsupported"
        )
    expected_thread_count = preconditions.get("unresolved_thread_count")
    if already_satisfied and action == "resolve_review_thread":
        if isinstance(expected_thread_count, int):
            expected_thread_count -= 1
    if expected_thread_count != len(unresolved):
        raise BrokerActionError(
            "thread_count_mismatch",
            "live unresolved-thread count does not match the packet",
        )
    before = {
        "repository": expected_repository,
        "repository_id": expected_repository_id,
        "pr": {
            "id": pr.get("id"),
            "number": pr.get("number"),
            "url": pr.get("url"),
            "state": pr.get("state"),
            "is_draft": pr.get("is_draft"),
            "head_sha": head_sha,
            "base_branch": pr.get("base_branch"),
            "author_login": pr.get("author_login"),
        },
        "changed_files_sha256": digest_json(list(files)),
        "checks_sha256": digest_json(live.get("checks")),
        "evidence": evidence,
        "unresolved_thread_count": len(unresolved),
        "target_thread": (
            {
                "id": target_thread_id,
                "is_resolved": already_satisfied,
                "is_outdated": True,
                "url": target_urls[0],
            }
            if target_thread_id is not None
            else None
        ),
    }
    return EvaluatedAction(
        action=str(action),
        repository=str(expected_repository),
        pr_number=int(pr["number"]),
        pr_node_id=str(pr["id"]),
        head_sha=head_sha,
        target_thread_id=target_thread_id,
        already_satisfied=already_satisfied,
        before_digest=digest_json(before),
        before=before,
    )


def desired_state_observed(
    *,
    packet: Mapping[str, Any],
    snapshot: LiveSnapshot | Mapping[str, Any],
) -> bool:
    live = _snapshot_dict(snapshot)
    request = packet["request"]
    pr = live.get("pr")
    if not isinstance(pr, Mapping):
        return False
    if (
        pr.get("number") != request["pr"]["number"]
        or pr.get("url") != request["pr"]["url"]
        or pr.get("head_sha") != request["pr"]["head_sha"]
        or pr.get("state") != "OPEN"
    ):
        return False
    if request["action"] == "mark_pr_ready":
        return pr.get("is_draft") is False
    target_id = request["targets"]["thread_node_ids"][0]
    try:
        threads = _threads(live.get("threads"))
    except BrokerActionError:
        return False
    matching = [item for item in threads if item["id"] == target_id]
    return len(matching) == 1 and matching[0]["is_resolved"] is True


def execute_evaluated_action(
    *,
    live: LiveActionClient,
    config: Mapping[str, Any],
    packet: Mapping[str, Any],
    evaluated: EvaluatedAction,
    attempt_id: str,
) -> dict[str, Any]:
    mutation_started = datetime.now(timezone.utc).strftime(UTC_FORMAT)
    mutation_result: Mapping[str, Any]
    try:
        if evaluated.action == "mark_pr_ready":
            mutation_result = live.mark_pr_ready(
                pr_node_id=evaluated.pr_node_id,
                client_mutation_id=attempt_id,
            )
            if (
                mutation_result.get("id") != evaluated.pr_node_id
                or mutation_result.get("number") != evaluated.pr_number
                or mutation_result.get("head_sha") != evaluated.head_sha
                or mutation_result.get("state") != "OPEN"
                or mutation_result.get("is_draft") is not False
            ):
                raise MutationIndeterminate(
                    "mutation_response_mismatch",
                    "mark-ready mutation returned an unexpected result",
                    mutation_evidence=mutation_result,
                )
        else:
            assert evaluated.target_thread_id is not None
            mutation_result = live.resolve_review_thread(
                thread_id=evaluated.target_thread_id,
                client_mutation_id=attempt_id,
            )
            if (
                mutation_result.get("id") != evaluated.target_thread_id
                or mutation_result.get("is_resolved") is not True
            ):
                raise MutationIndeterminate(
                    "mutation_response_mismatch",
                    "resolve-thread mutation returned an unexpected result",
                    mutation_evidence=mutation_result,
                )
    except MutationIndeterminate:
        raise
    except GitHubLiveError as exc:
        raise MutationIndeterminate(
            "mutation_transport_indeterminate",
            "GitHub mutation did not return a trustworthy result",
        ) from exc

    try:
        readback = live.fetch_snapshot(
            pr_number=evaluated.pr_number,
            evidence_comment_url=packet["request"]["preconditions"][
                "evidence_comment_url"
            ],
        )
    except GitHubLiveError as exc:
        raise MutationIndeterminate(
            "readback_unavailable",
            "GitHub mutation could not be read back",
            mutation_evidence=mutation_result,
        ) from exc
    readback_dict = _snapshot_dict(readback)
    readback_pr = readback_dict.get("pr")
    if not isinstance(readback_pr, Mapping):
        raise MutationIndeterminate(
            "readback_invalid",
            "GitHub mutation readback is invalid",
            mutation_evidence=mutation_result,
        )
    if (
        readback_pr.get("id") != evaluated.pr_node_id
        or readback_pr.get("number") != evaluated.pr_number
        or readback_pr.get("url") != packet["request"]["pr"]["url"]
        or readback_pr.get("state") != "OPEN"
        or readback_pr.get("head_sha") != evaluated.head_sha
    ):
        raise MutationIndeterminate(
            "head_changed_during_mutation",
            "pull request identity or head changed during mutation",
            mutation_evidence=mutation_result,
        )
    try:
        confirmed = evaluate_snapshot(
            config=config,
            packet=packet,
            snapshot=readback_dict,
            allow_already_satisfied=True,
        )
    except BrokerActionError as exc:
        raise MutationIndeterminate(
            "readback_preconditions_changed",
            "GitHub readback no longer satisfies the authorized preconditions",
            mutation_evidence=mutation_result,
        ) from exc
    if (
        not confirmed.already_satisfied
        or not desired_state_observed(packet=packet, snapshot=readback_dict)
    ):
        raise MutationIndeterminate(
            "readback_not_satisfied",
            "GitHub readback did not prove the requested state",
            mutation_evidence=mutation_result,
        )
    after = {
        "pr": {
            "id": readback_pr.get("id"),
            "number": readback_pr.get("number"),
            "state": readback_pr.get("state"),
            "is_draft": readback_pr.get("is_draft"),
            "head_sha": readback_pr.get("head_sha"),
        },
        "target_thread": (
            next(
                (
                    {
                        "id": item["id"],
                        "is_resolved": item["is_resolved"],
                    }
                    for item in readback_dict.get("threads", [])
                    if item.get("id") == evaluated.target_thread_id
                ),
                None,
            )
            if evaluated.target_thread_id is not None
            else None
        ),
    }
    return {
        "action": evaluated.action,
        "attempt_id": attempt_id,
        "mutation_started_at": mutation_started,
        "mutation": dict(mutation_result),
        "before": dict(evaluated.before),
        "before_digest": evaluated.before_digest,
        "after": after,
        "after_digest": digest_json(after),
        "readback_verified": True,
    }
