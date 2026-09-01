"""Live GitHub state collection and protected PR mutations.

All authority decisions are made from these independently fetched snapshots;
packet booleans are comparison hints only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import quote

from .john_lomein_github_app import (
    GitHubAppClient,
    GitHubAppError,
    InstallationCredential,
)


REPO_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
EVIDENCE_URL_RE = re.compile(
    r"^https://github\.com/(?P<repo>[^/]+/[^/]+)/pull/"
    r"(?P<pr>[1-9][0-9]*)#issuecomment-(?P<comment>[1-9][0-9]*)$"
)
MAX_CONNECTION_PAGES = 200
PAGE_SIZE = 100
MAX_STATUS_CONTEXTS = 1000
MAX_REVIEW_THREADS = 500
MAX_THREAD_COMMENTS = PAGE_SIZE


class GitHubLiveError(RuntimeError):
    """Live state was missing, truncated, inconsistent, or unsafe."""


PR_IDENTITY_QUERY = """
query BrokerPrIdentity($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    id
    databaseId
    nameWithOwner
    pullRequest(number: $number) {
      id
      number
      url
      state
      isDraft
      headRefOid
      baseRefName
      changedFiles
      author { login }
      headRepository { id databaseId nameWithOwner }
      baseRepository { id databaseId nameWithOwner }
    }
  }
  rateLimit { remaining resetAt }
}
"""

PR_FILES_QUERY = """
query BrokerPrFiles(
  $owner: String!,
  $name: String!,
  $number: Int!,
  $cursor: String
) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      files(first: 100, after: $cursor) {
        totalCount
        nodes { path }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
  rateLimit { remaining resetAt }
}
"""

CHECKS_QUERY = """
query BrokerChecks(
  $owner: String!,
  $name: String!,
  $oid: GitObjectID!,
  $cursor: String
) {
  repository(owner: $owner, name: $name) {
    object(oid: $oid) {
      ... on Commit {
        oid
        statusCheckRollup {
          contexts(first: 100, after: $cursor) {
            totalCount
            nodes {
              __typename
              ... on CheckRun {
                name
                status
                conclusion
                app { slug }
              }
              ... on StatusContext {
                context
                state
                creator { login }
              }
            }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }
  }
  rateLimit { remaining resetAt }
}
"""

THREADS_QUERY = """
query BrokerThreads(
  $owner: String!,
  $name: String!,
  $number: Int!,
  $cursor: String
) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: 100, after: $cursor) {
        totalCount
        nodes {
          id
          isResolved
          isOutdated
          comments(first: 100) {
            totalCount
            nodes { id databaseId url }
            pageInfo { hasNextPage endCursor }
          }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
  rateLimit { remaining resetAt }
}
"""

THREAD_COMMENTS_QUERY = """
query BrokerThreadComments($id: ID!, $cursor: String) {
  node(id: $id) {
    ... on PullRequestReviewThread {
      id
      comments(first: 100, after: $cursor) {
        totalCount
        nodes { id databaseId url }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
  rateLimit { remaining resetAt }
}
"""

MARK_READY_MUTATION = """
mutation BrokerMarkReady($id: ID!, $clientMutationId: String!) {
  markPullRequestReadyForReview(
    input: {
      pullRequestId: $id
      clientMutationId: $clientMutationId
    }
  ) {
    clientMutationId
    pullRequest {
      id
      number
      isDraft
      headRefOid
      state
      updatedAt
    }
  }
  rateLimit { remaining resetAt }
}
"""

RESOLVE_THREAD_MUTATION = """
mutation BrokerResolveThread($threadId: ID!, $clientMutationId: String!) {
  resolveReviewThread(
    input: {
      threadId: $threadId
      clientMutationId: $clientMutationId
    }
  ) {
    clientMutationId
    thread { id isResolved }
  }
  rateLimit { remaining resetAt }
}
"""


def _object(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GitHubLiveError(f"{field} is missing or invalid")
    return value


def _array(value: Any, *, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise GitHubLiveError(f"{field} is missing or invalid")
    return value


def _text(value: Any, *, field: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise GitHubLiveError(f"{field} is missing or invalid")
    return value


def _positive_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise GitHubLiveError(f"{field} is missing or invalid")
    return value


@dataclass(frozen=True)
class LiveSnapshot:
    repository: str
    repository_id: int
    pr: Mapping[str, Any]
    files: tuple[str, ...]
    checks: tuple[Mapping[str, Any], ...]
    evidence_comment: Mapping[str, Any]
    threads: tuple[Mapping[str, Any], ...]
    unresolved_thread_count: int
    minimum_rate_limit_remaining: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "repository_id": self.repository_id,
            "pr": dict(self.pr),
            "files": list(self.files),
            "checks": [dict(item) for item in self.checks],
            "evidence_comment": dict(self.evidence_comment),
            "threads": [dict(item) for item in self.threads],
            "unresolved_thread_count": self.unresolved_thread_count,
            "minimum_rate_limit_remaining": self.minimum_rate_limit_remaining,
        }


class GitHubLiveClient:
    def __init__(
        self,
        *,
        app: GitHubAppClient,
        credential: InstallationCredential,
        repository: str,
        repository_id: int,
        minimum_rate_limit_remaining: int,
        maximum_changed_files: int,
    ) -> None:
        if not REPO_RE.fullmatch(repository):
            raise GitHubLiveError("configured repository is invalid")
        if credential.repository_id != repository_id:
            raise GitHubLiveError("credential repository binding does not match")
        if (
            isinstance(minimum_rate_limit_remaining, bool)
            or not isinstance(minimum_rate_limit_remaining, int)
            or minimum_rate_limit_remaining < 0
        ):
            raise GitHubLiveError("minimum rate-limit floor is invalid")
        if (
            isinstance(maximum_changed_files, bool)
            or not isinstance(maximum_changed_files, int)
            or maximum_changed_files <= 0
        ):
            raise GitHubLiveError("maximum changed-file count is invalid")
        self.app = app
        self.credential = credential
        self.repository = repository
        self.repository_id = repository_id
        self.owner, self.name = repository.split("/", 1)
        self.minimum_rate_limit_remaining = minimum_rate_limit_remaining
        self.maximum_changed_files = maximum_changed_files
        self._observed_rate_limits: list[int] = []

    def _record_graphql_rate(self, data: Mapping[str, Any]) -> None:
        rate = _object(data.get("rateLimit"), field="GraphQL rate limit")
        remaining = rate.get("remaining")
        if (
            isinstance(remaining, bool)
            or not isinstance(remaining, int)
            or remaining < 0
        ):
            raise GitHubLiveError("GraphQL rate-limit result is invalid")
        self._observed_rate_limits.append(remaining)
        if remaining < self.minimum_rate_limit_remaining:
            raise GitHubLiveError("GitHub rate-limit floor has been reached")

    def _record_rest_rate(
        self,
        headers: Mapping[str, str],
        *,
        required: bool = False,
    ) -> None:
        value = next(
            (
                item
                for key, item in headers.items()
                if isinstance(key, str)
                and key.lower() == "x-ratelimit-remaining"
            ),
            None,
        )
        if value is None:
            if required:
                raise GitHubLiveError(
                    "REST rate-limit header is missing"
                )
            return
        try:
            remaining = int(value)
        except (TypeError, ValueError) as exc:
            raise GitHubLiveError("REST rate-limit header is invalid") from exc
        if remaining < 0:
            raise GitHubLiveError("REST rate-limit header is invalid")
        self._observed_rate_limits.append(remaining)
        if remaining < self.minimum_rate_limit_remaining:
            raise GitHubLiveError("GitHub rate-limit floor has been reached")

    def _graphql(
        self,
        query: str,
        variables: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            data, headers = self.app.graphql(
                token=self.credential.token,
                query=query,
                variables=variables,
            )
        except GitHubAppError as exc:
            raise GitHubLiveError("GitHub GraphQL operation failed") from exc
        self._record_graphql_rate(data)
        self._record_rest_rate(headers, required=True)
        return data

    @staticmethod
    def _connection_page(
        connection: Any,
        *,
        field: str,
    ) -> tuple[int, list[Any], bool, str | None]:
        value = _object(connection, field=field)
        total = value.get("totalCount")
        if isinstance(total, bool) or not isinstance(total, int) or total < 0:
            raise GitHubLiveError(f"{field} totalCount is invalid")
        nodes = _array(value.get("nodes"), field=f"{field} nodes")
        page_info = _object(
            value.get("pageInfo"), field=f"{field} pageInfo"
        )
        has_next = page_info.get("hasNextPage")
        if type(has_next) is not bool:
            raise GitHubLiveError(f"{field} pagination flag is invalid")
        cursor = page_info.get("endCursor")
        if has_next and (not isinstance(cursor, str) or not cursor):
            raise GitHubLiveError(f"{field} pagination cursor is invalid")
        if not has_next and cursor is not None and not isinstance(cursor, str):
            raise GitHubLiveError(f"{field} pagination cursor is invalid")
        return total, nodes, has_next, cursor

    def _fetch_identity(self, pr_number: int) -> dict[str, Any]:
        data = self._graphql(
            PR_IDENTITY_QUERY,
            {
                "owner": self.owner,
                "name": self.name,
                "number": pr_number,
            },
        )
        repository = _object(data.get("repository"), field="repository")
        if (
            repository.get("databaseId") != self.repository_id
            or repository.get("nameWithOwner") != self.repository
        ):
            raise GitHubLiveError("live repository identity does not match config")
        pr = _object(repository.get("pullRequest"), field="pull request")
        if pr.get("number") != pr_number:
            raise GitHubLiveError("live pull request number does not match")
        base_repository = _object(
            pr.get("baseRepository"), field="pull request base repository"
        )
        head_repository = pr.get("headRepository")
        same_repo_head = (
            isinstance(head_repository, dict)
            and head_repository.get("databaseId") == self.repository_id
            and head_repository.get("nameWithOwner") == self.repository
            and base_repository.get("databaseId") == self.repository_id
            and base_repository.get("nameWithOwner") == self.repository
        )
        author = _object(pr.get("author"), field="pull request author")
        changed_files = pr.get("changedFiles")
        if (
            isinstance(changed_files, bool)
            or not isinstance(changed_files, int)
            or changed_files < 0
            or changed_files > self.maximum_changed_files
        ):
            raise GitHubLiveError(
                "pull request changed-file count is invalid or exceeds policy"
            )
        for boolean_field in ("isDraft",):
            if type(pr.get(boolean_field)) is not bool:
                raise GitHubLiveError(
                    f"pull request {boolean_field} is invalid"
                )
        return {
            "id": _text(pr.get("id"), field="pull request id"),
            "number": pr_number,
            "url": _text(pr.get("url"), field="pull request URL"),
            "state": _text(pr.get("state"), field="pull request state"),
            "is_draft": pr["isDraft"],
            "head_sha": _text(
                pr.get("headRefOid"), field="pull request head SHA"
            ).lower(),
            "base_branch": _text(
                pr.get("baseRefName"), field="pull request base branch"
            ),
            "author_login": _text(
                author.get("login"), field="pull request author login"
            ),
            "same_repository_head": same_repo_head,
            "changed_files": changed_files,
        }

    def _fetch_files(
        self,
        pr_number: int,
        *,
        expected_count: int,
    ) -> tuple[str, ...]:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        paths: list[str] = []
        total_expected: int | None = None
        for _ in range(MAX_CONNECTION_PAGES):
            data = self._graphql(
                PR_FILES_QUERY,
                {
                    "owner": self.owner,
                    "name": self.name,
                    "number": pr_number,
                    "cursor": cursor,
                },
            )
            repository = _object(data.get("repository"), field="repository")
            pr = _object(repository.get("pullRequest"), field="pull request")
            total, nodes, has_next, next_cursor = self._connection_page(
                pr.get("files"), field="pull request files"
            )
            if total_expected is None:
                total_expected = total
                if total != expected_count:
                    raise GitHubLiveError(
                        "changed-file count changed during observation"
                    )
                if total > self.maximum_changed_files:
                    raise GitHubLiveError(
                        "pull request exceeds maximum changed files"
                    )
            elif total != total_expected:
                raise GitHubLiveError(
                    "changed-file count changed during pagination"
                )
            for node in nodes:
                item = _object(node, field="pull request file")
                paths.append(_text(item.get("path"), field="file path"))
            if not has_next:
                break
            assert next_cursor is not None
            if next_cursor in seen_cursors:
                raise GitHubLiveError("file pagination cursor repeated")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise GitHubLiveError("file pagination exceeded page limit")
        if total_expected is None or len(paths) != total_expected:
            raise GitHubLiveError("pull request file pagination was truncated")
        if len(set(paths)) != len(paths):
            raise GitHubLiveError("pull request file pagination duplicated paths")
        return tuple(paths)

    def _fetch_checks(self, head_sha: str) -> tuple[Mapping[str, Any], ...]:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        contexts: list[dict[str, Any]] = []
        total_expected: int | None = None
        for _ in range(MAX_CONNECTION_PAGES):
            data = self._graphql(
                CHECKS_QUERY,
                {
                    "owner": self.owner,
                    "name": self.name,
                    "oid": head_sha,
                    "cursor": cursor,
                },
            )
            repository = _object(data.get("repository"), field="repository")
            commit = _object(repository.get("object"), field="head commit")
            if commit.get("oid") != head_sha:
                raise GitHubLiveError("check rollup commit does not match head")
            rollup = commit.get("statusCheckRollup")
            if rollup is None:
                if cursor is not None:
                    raise GitHubLiveError("check rollup disappeared during pagination")
                return ()
            rollup_obj = _object(rollup, field="status check rollup")
            total, nodes, has_next, next_cursor = self._connection_page(
                rollup_obj.get("contexts"), field="status contexts"
            )
            if total_expected is None:
                total_expected = total
                if total > MAX_STATUS_CONTEXTS:
                    raise GitHubLiveError(
                        "status-context count exceeds the safety limit"
                    )
            elif total != total_expected:
                raise GitHubLiveError(
                    "status-context count changed during pagination"
                )
            for node in nodes:
                item = _object(node, field="status context")
                kind = item.get("__typename")
                if kind == "CheckRun":
                    app = item.get("app")
                    contexts.append(
                        {
                            "kind": "check_run",
                            "name": _text(
                                item.get("name"), field="check-run name"
                            ),
                            "status": _text(
                                item.get("status"), field="check-run status"
                            ).upper(),
                            "conclusion": (
                                _text(
                                    item.get("conclusion"),
                                    field="check-run conclusion",
                                    allow_empty=True,
                                ).upper()
                                if item.get("conclusion") is not None
                                else None
                            ),
                            "producer": (
                                str(app.get("slug") or "")
                                if isinstance(app, dict)
                                else ""
                            ),
                        }
                    )
                elif kind == "StatusContext":
                    creator = item.get("creator")
                    contexts.append(
                        {
                            "kind": "commit_status",
                            "name": _text(
                                item.get("context"),
                                field="commit-status context",
                            ),
                            "status": _text(
                                item.get("state"),
                                field="commit-status state",
                            ).upper(),
                            "conclusion": None,
                            "producer": (
                                str(creator.get("login") or "")
                                if isinstance(creator, dict)
                                else ""
                            ),
                        }
                    )
                else:
                    raise GitHubLiveError(
                        "status rollup returned an unsupported context type"
                    )
            if not has_next:
                break
            assert next_cursor is not None
            if next_cursor in seen_cursors:
                raise GitHubLiveError("status pagination cursor repeated")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise GitHubLiveError("status pagination exceeded page limit")
        if total_expected is None or len(contexts) != total_expected:
            raise GitHubLiveError("status context pagination was truncated")
        return tuple(contexts)

    def _thread_comments(
        self,
        thread_id: str,
        first_page: Mapping[str, Any],
    ) -> tuple[str, ...]:
        total, nodes, has_next, cursor = self._connection_page(
            first_page, field="review-thread comments"
        )
        if total > MAX_THREAD_COMMENTS:
            raise GitHubLiveError(
                "review-thread comment count exceeds the safety limit"
            )
        urls: list[str] = []
        for node in nodes:
            item = _object(node, field="review-thread comment")
            urls.append(_text(item.get("url"), field="review-thread comment URL"))
        seen_cursors: set[str] = set()
        pages = 1
        while has_next:
            if pages >= MAX_CONNECTION_PAGES:
                raise GitHubLiveError(
                    "review-thread comment pagination exceeded page limit"
                )
            assert cursor is not None
            if cursor in seen_cursors:
                raise GitHubLiveError(
                    "review-thread comment cursor repeated"
                )
            seen_cursors.add(cursor)
            data = self._graphql(
                THREAD_COMMENTS_QUERY,
                {"id": thread_id, "cursor": cursor},
            )
            node = _object(data.get("node"), field="review thread")
            if node.get("id") != thread_id:
                raise GitHubLiveError(
                    "review thread changed during comment pagination"
                )
            page_total, page_nodes, has_next, cursor = self._connection_page(
                node.get("comments"), field="review-thread comments"
            )
            if page_total != total:
                raise GitHubLiveError(
                    "review-thread comment count changed during pagination"
                )
            for comment in page_nodes:
                item = _object(comment, field="review-thread comment")
                urls.append(
                    _text(
                        item.get("url"), field="review-thread comment URL"
                    )
                )
            pages += 1
        if len(urls) != total:
            raise GitHubLiveError(
                "review-thread comment pagination was truncated"
            )
        if len(set(urls)) != len(urls):
            raise GitHubLiveError(
                "review-thread comment pagination duplicated URLs"
            )
        return tuple(urls)

    def _fetch_threads(
        self, pr_number: int
    ) -> tuple[Mapping[str, Any], ...]:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        threads: list[dict[str, Any]] = []
        total_expected: int | None = None
        for _ in range(MAX_CONNECTION_PAGES):
            data = self._graphql(
                THREADS_QUERY,
                {
                    "owner": self.owner,
                    "name": self.name,
                    "number": pr_number,
                    "cursor": cursor,
                },
            )
            repository = _object(data.get("repository"), field="repository")
            pr = _object(repository.get("pullRequest"), field="pull request")
            total, nodes, has_next, next_cursor = self._connection_page(
                pr.get("reviewThreads"), field="review threads"
            )
            if total_expected is None:
                total_expected = total
                if total > MAX_REVIEW_THREADS:
                    raise GitHubLiveError(
                        "review-thread count exceeds the safety limit"
                    )
            elif total != total_expected:
                raise GitHubLiveError(
                    "review-thread count changed during pagination"
                )
            for node in nodes:
                item = _object(node, field="review thread")
                thread_id = _text(item.get("id"), field="review-thread id")
                if type(item.get("isResolved")) is not bool:
                    raise GitHubLiveError(
                        "review-thread resolved state is invalid"
                    )
                if type(item.get("isOutdated")) is not bool:
                    raise GitHubLiveError(
                        "review-thread outdated state is invalid"
                    )
                comments = _object(
                    item.get("comments"), field="review-thread comments"
                )
                threads.append(
                    {
                        "id": thread_id,
                        "is_resolved": item["isResolved"],
                        "is_outdated": item["isOutdated"],
                        "urls": list(
                            self._thread_comments(thread_id, comments)
                        ),
                    }
                )
            if not has_next:
                break
            assert next_cursor is not None
            if next_cursor in seen_cursors:
                raise GitHubLiveError("review-thread pagination cursor repeated")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise GitHubLiveError("review-thread pagination exceeded page limit")
        if total_expected is None or len(threads) != total_expected:
            raise GitHubLiveError("review-thread pagination was truncated")
        ids = [item["id"] for item in threads]
        if len(set(ids)) != len(ids):
            raise GitHubLiveError("review-thread pagination duplicated ids")
        return tuple(threads)

    def _fetch_evidence_comment(
        self,
        *,
        pr_number: int,
        evidence_comment_url: str,
    ) -> dict[str, Any]:
        match = EVIDENCE_URL_RE.fullmatch(evidence_comment_url)
        if (
            not match
            or match.group("repo") != self.repository
            or int(match.group("pr")) != pr_number
        ):
            raise GitHubLiveError("evidence comment URL is not bound to the PR")
        comment_id = int(match.group("comment"))
        try:
            data, headers = self.app.request_json(
                "GET",
                (
                    f"/repos/{quote(self.owner, safe='')}/"
                    f"{quote(self.name, safe='')}/issues/comments/{comment_id}"
                ),
                token=self.credential.token,
            )
        except GitHubAppError as exc:
            raise GitHubLiveError("evidence comment lookup failed") from exc
        self._record_rest_rate(headers, required=True)
        comment = _object(data, field="evidence comment")
        user = _object(comment.get("user"), field="evidence comment author")
        if (
            comment.get("id") != comment_id
            or comment.get("html_url") != evidence_comment_url
        ):
            raise GitHubLiveError("evidence comment identity does not match")
        return {
            "id": comment_id,
            "url": evidence_comment_url,
            "author_login": _text(
                user.get("login"), field="evidence comment author login"
            ),
            "body": _text(
                comment.get("body"),
                field="evidence comment body",
                allow_empty=True,
            ),
            "created_at": _text(
                comment.get("created_at"),
                field="evidence comment creation time",
            ),
        }

    def fetch_snapshot(
        self,
        *,
        pr_number: int,
        evidence_comment_url: str,
    ) -> LiveSnapshot:
        if (
            isinstance(pr_number, bool)
            or not isinstance(pr_number, int)
            or pr_number <= 0
        ):
            raise GitHubLiveError("pull request number is invalid")
        self._observed_rate_limits = []
        identity = self._fetch_identity(pr_number)
        files = self._fetch_files(
            pr_number, expected_count=identity["changed_files"]
        )
        checks = self._fetch_checks(identity["head_sha"])
        evidence = self._fetch_evidence_comment(
            pr_number=pr_number,
            evidence_comment_url=evidence_comment_url,
        )
        threads = self._fetch_threads(pr_number)
        final_identity = self._fetch_identity(pr_number)
        if final_identity != identity:
            raise GitHubLiveError(
                "pull request identity changed during observation"
            )
        if not self._observed_rate_limits:
            raise GitHubLiveError("no GitHub rate-limit evidence was observed")
        return LiveSnapshot(
            repository=self.repository,
            repository_id=self.repository_id,
            pr=identity,
            files=files,
            checks=checks,
            evidence_comment=evidence,
            threads=threads,
            unresolved_thread_count=sum(
                1 for item in threads if not item["is_resolved"]
            ),
            minimum_rate_limit_remaining=min(self._observed_rate_limits),
        )

    def mark_pr_ready(
        self,
        *,
        pr_node_id: str,
        client_mutation_id: str,
    ) -> Mapping[str, Any]:
        data = self._graphql(
            MARK_READY_MUTATION,
            {"id": pr_node_id, "clientMutationId": client_mutation_id},
        )
        result = _object(
            data.get("markPullRequestReadyForReview"),
            field="mark-ready mutation result",
        )
        if result.get("clientMutationId") != client_mutation_id:
            raise GitHubLiveError("mark-ready mutation id does not match")
        pr = _object(result.get("pullRequest"), field="mark-ready pull request")
        return {
            "id": _text(pr.get("id"), field="mark-ready pull request id"),
            "number": _positive_int(
                pr.get("number"), field="mark-ready pull request number"
            ),
            "is_draft": pr.get("isDraft"),
            "head_sha": _text(
                pr.get("headRefOid"), field="mark-ready head SHA"
            ).lower(),
            "state": _text(
                pr.get("state"), field="mark-ready pull request state"
            ),
            "updated_at": _text(
                pr.get("updatedAt"), field="mark-ready update time"
            ),
        }

    def resolve_review_thread(
        self,
        *,
        thread_id: str,
        client_mutation_id: str,
    ) -> Mapping[str, Any]:
        data = self._graphql(
            RESOLVE_THREAD_MUTATION,
            {
                "threadId": thread_id,
                "clientMutationId": client_mutation_id,
            },
        )
        result = _object(
            data.get("resolveReviewThread"),
            field="resolve-thread mutation result",
        )
        if result.get("clientMutationId") != client_mutation_id:
            raise GitHubLiveError("resolve-thread mutation id does not match")
        thread = _object(
            result.get("thread"), field="resolve-thread result"
        )
        if type(thread.get("isResolved")) is not bool:
            raise GitHubLiveError("resolve-thread state is invalid")
        return {
            "id": _text(thread.get("id"), field="resolve-thread id"),
            "is_resolved": thread["isResolved"],
        }
