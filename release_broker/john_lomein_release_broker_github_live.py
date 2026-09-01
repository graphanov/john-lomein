"""Live GitHub reads and the sole release-broker merge mutation.

Authority is reconstructed from independently fetched GitHub state.  All
connection reads are complete and race-checked, OIDs are full-width, and the
only mutation available through this module is an exact-head squash merge.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from urllib.parse import quote

from .john_lomein_release_broker_github_app import (
    ReleaseGitHubAppClient,
    ReleaseGitHubAppError,
    ReleaseInstallationCredential,
)


REPO_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
MAX_CONNECTION_PAGES = 200
PAGE_SIZE = 100
MAX_STATUS_CONTEXTS = 2000
MAX_REVIEW_THREADS = 1000
MAX_THREAD_COMMENTS = 5000
MAX_ISSUE_COMMENTS = 5000
MAX_REVIEWS = 2000


class ReleaseGitHubLiveError(RuntimeError):
    """Live release state was missing, truncated, inconsistent, or unsafe."""


PR_IDENTITY_QUERY = """
query ReleaseBrokerPrIdentity(
  $owner: String!,
  $name: String!,
  $number: Int!
) {
  repository(owner: $owner, name: $name) {
    id
    databaseId
    nameWithOwner
    isArchived
    isDisabled
    squashMergeAllowed
    pullRequest(number: $number) {
      id
      number
      url
      state
      isDraft
      merged
      mergedAt
      headRefOid
      baseRefName
      baseRefOid
      changedFiles
      mergeable
      mergeStateStatus
      reviewDecision
      author { login }
      mergeCommit { oid }
      potentialMergeCommit {
        oid
        tree { oid }
        parents(first: 2) {
          totalCount
          nodes { oid }
          pageInfo { hasNextPage endCursor }
        }
      }
      mergedBy { login }
      autoMergeRequest {
        mergeMethod
      }
      mergeQueueEntry {
        id
        state
      }
      headRepository { id databaseId nameWithOwner }
      baseRepository { id databaseId nameWithOwner }
    }
  }
  rateLimit { remaining resetAt }
}
"""

PR_FILES_QUERY = """
query ReleaseBrokerPrFiles(
  $owner: String!,
  $name: String!,
  $number: Int!,
  $cursor: String
) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      files(first: 100, after: $cursor) {
        totalCount
        nodes { path additions deletions changeType }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
  rateLimit { remaining resetAt }
}
"""

CHECKS_AND_STATUSES_QUERY = """
query ReleaseBrokerChecksAndStatuses(
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
                detailsUrl
                app {
                  databaseId
                  slug
                }
              }
              ... on StatusContext {
                context
                state
                targetUrl
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

REVIEW_THREADS_QUERY = """
query ReleaseBrokerReviewThreads(
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
            nodes {
              id
              databaseId
              url
              body
              createdAt
              author { login }
              commit { oid }
              originalCommit { oid }
            }
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
query ReleaseBrokerThreadComments($id: ID!, $cursor: String) {
  node(id: $id) {
    ... on PullRequestReviewThread {
      id
      comments(first: 100, after: $cursor) {
        totalCount
        nodes {
          id
          databaseId
          url
          body
          createdAt
          author { login }
          commit { oid }
          originalCommit { oid }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
  rateLimit { remaining resetAt }
}
"""

ISSUE_COMMENTS_QUERY = """
query ReleaseBrokerIssueComments(
  $owner: String!,
  $name: String!,
  $number: Int!,
  $cursor: String
) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      comments(first: 100, after: $cursor) {
        totalCount
        nodes {
          id
          databaseId
          url
          body
          createdAt
          updatedAt
          author { login }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
  rateLimit { remaining resetAt }
}
"""

REVIEWS_QUERY = """
query ReleaseBrokerReviews(
  $owner: String!,
  $name: String!,
  $number: Int!,
  $cursor: String
) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviews(first: 100, after: $cursor) {
        totalCount
        nodes {
          id
          databaseId
          url
          body
          state
          submittedAt
          author { login }
          commit { oid }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
  rateLimit { remaining resetAt }
}
"""

DEFAULT_BRANCH_REF_QUERY = """
query ReleaseBrokerDefaultBranch(
  $owner: String!,
  $name: String!
) {
  repository(owner: $owner, name: $name) {
    id
    databaseId
    nameWithOwner
    isArchived
    isDisabled
    squashMergeAllowed
    defaultBranchRef {
      name
      prefix
      target {
        ... on Commit { oid }
      }
    }
  }
  rateLimit { remaining resetAt }
}
"""

COMMIT_QUERY = """
query ReleaseBrokerCommit(
  $owner: String!,
  $name: String!,
  $oid: GitObjectID!,
  $cursor: String
) {
  repository(owner: $owner, name: $name) {
    object(oid: $oid) {
      ... on Commit {
        oid
        committedDate
        tree { oid }
        author {
          name
          email
          date
          user { login }
        }
        committer {
          name
          email
          date
          user { login }
        }
        parents(first: 100, after: $cursor) {
          totalCount
          nodes { oid }
          pageInfo { hasNextPage endCursor }
        }
      }
    }
  }
  rateLimit { remaining resetAt }
}
"""


def _object(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseGitHubLiveError(f"{field} is missing or invalid")
    return value


def _array(value: Any, *, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReleaseGitHubLiveError(f"{field} is missing or invalid")
    return value


def _text(value: Any, *, field: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise ReleaseGitHubLiveError(f"{field} is missing or invalid")
    return value


def _nullable_text(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    return _text(value, field=field, allow_empty=True)


def _positive_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ReleaseGitHubLiveError(f"{field} is missing or invalid")
    return value


def _nonnegative_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReleaseGitHubLiveError(f"{field} is missing or invalid")
    return value


def _boolean(value: Any, *, field: str) -> bool:
    if type(value) is not bool:
        raise ReleaseGitHubLiveError(f"{field} is missing or invalid")
    return value


def _oid(value: Any, *, field: str, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    if not isinstance(value, str):
        raise ReleaseGitHubLiveError(f"{field} is missing or invalid")
    if value != value.lower() or not OID_RE.fullmatch(value):
        raise ReleaseGitHubLiveError(
            f"{field} must be an exact full lowercase OID"
        )
    return value


def contains_exact_full_oid(text: str, oid: str) -> bool:
    """Return true only for the complete, lowercase OID as a hex token."""

    expected = _oid(oid, field="expected evidence OID")
    assert expected is not None
    if not isinstance(text, str):
        return False
    return (
        re.search(
            rf"(?<![0-9a-fA-F]){re.escape(expected)}(?![0-9a-fA-F])",
            text,
        )
        is not None
    )


@dataclass(frozen=True)
class ReleaseCommitActor:
    name: str
    email: str
    date: str
    github_login: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "email": self.email,
            "date": self.date,
            "github_login": self.github_login,
        }


@dataclass(frozen=True)
class ReleaseCommitState:
    oid: str
    tree_oid: str
    parent_oids: tuple[str, ...]
    committed_at: str
    author: ReleaseCommitActor
    committer: ReleaseCommitActor

    def as_dict(self) -> dict[str, Any]:
        return {
            "oid": self.oid,
            "tree_oid": self.tree_oid,
            "parent_oids": list(self.parent_oids),
            "committed_at": self.committed_at,
            "author": self.author.as_dict(),
            "committer": self.committer.as_dict(),
        }


@dataclass(frozen=True)
class ReleaseDefaultBranchState:
    name: str
    qualified_name: str
    commit: ReleaseCommitState

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "qualified_name": self.qualified_name,
            "commit": self.commit.as_dict(),
        }


@dataclass(frozen=True)
class ReleaseLiveSnapshot:
    repository: str
    repository_id: int
    repository_policy: Mapping[str, Any]
    pr: Mapping[str, Any]
    default_branch: ReleaseDefaultBranchState
    files: tuple[Mapping[str, Any], ...]
    checks: tuple[Mapping[str, Any], ...]
    statuses: tuple[Mapping[str, Any], ...]
    review_threads: tuple[Mapping[str, Any], ...]
    issue_comments: tuple[Mapping[str, Any], ...]
    reviews: tuple[Mapping[str, Any], ...]
    unresolved_thread_count: int
    unresolved_current_thread_count: int
    exact_head_evidence: tuple[Mapping[str, Any], ...]
    minimum_rate_limit_remaining: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "repository_id": self.repository_id,
            "repository_policy": dict(self.repository_policy),
            "pr": dict(self.pr),
            "default_branch": self.default_branch.as_dict(),
            "files": [dict(item) for item in self.files],
            "checks": [dict(item) for item in self.checks],
            "statuses": [dict(item) for item in self.statuses],
            "review_threads": [dict(item) for item in self.review_threads],
            "issue_comments": [dict(item) for item in self.issue_comments],
            "reviews": [dict(item) for item in self.reviews],
            "unresolved_thread_count": self.unresolved_thread_count,
            "unresolved_current_thread_count": (
                self.unresolved_current_thread_count
            ),
            "exact_head_evidence": [
                dict(item) for item in self.exact_head_evidence
            ],
            "minimum_rate_limit_remaining": (
                self.minimum_rate_limit_remaining
            ),
        }


@dataclass(frozen=True)
class ReleaseMergeMutationResult:
    merged: bool
    merge_commit_oid: str
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "merged": self.merged,
            "merge_commit_oid": self.merge_commit_oid,
            "message": self.message,
        }


@dataclass(frozen=True)
class ReleaseMergeReadback:
    repository: str
    repository_id: int
    repository_policy: Mapping[str, Any]
    pr: Mapping[str, Any]
    default_branch: ReleaseDefaultBranchState
    minimum_rate_limit_remaining: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "repository": self.repository,
            "repository_id": self.repository_id,
            "repository_policy": dict(self.repository_policy),
            "pr": dict(self.pr),
            "default_branch": self.default_branch.as_dict(),
            "minimum_rate_limit_remaining": (
                self.minimum_rate_limit_remaining
            ),
        }


class ReleaseGitHubLiveClient:
    def __init__(
        self,
        *,
        app: ReleaseGitHubAppClient,
        credential: ReleaseInstallationCredential,
        repository: str,
        repository_id: int,
        default_branch: str,
        minimum_rate_limit_remaining: int,
        maximum_changed_files: int,
    ) -> None:
        if not isinstance(repository, str) or not REPO_RE.fullmatch(repository):
            raise ReleaseGitHubLiveError(
                "configured repository is invalid"
            )
        if (
            isinstance(repository_id, bool)
            or not isinstance(repository_id, int)
            or repository_id <= 0
        ):
            raise ReleaseGitHubLiveError(
                "configured repository id is invalid"
            )
        if credential.repository_id != repository_id:
            raise ReleaseGitHubLiveError(
                "credential repository binding does not match"
            )
        if (
            not isinstance(default_branch, str)
            or not BRANCH_RE.fullmatch(default_branch)
            or ".." in default_branch
            or "//" in default_branch
        ):
            raise ReleaseGitHubLiveError(
                "configured default branch is invalid"
            )
        if (
            isinstance(minimum_rate_limit_remaining, bool)
            or not isinstance(minimum_rate_limit_remaining, int)
            or minimum_rate_limit_remaining < 0
        ):
            raise ReleaseGitHubLiveError(
                "minimum rate-limit floor is invalid"
            )
        if (
            isinstance(maximum_changed_files, bool)
            or not isinstance(maximum_changed_files, int)
            or maximum_changed_files <= 0
        ):
            raise ReleaseGitHubLiveError(
                "maximum changed-file count is invalid"
            )
        self.app = app
        self.credential = credential
        self.repository = repository
        self.repository_id = repository_id
        self.owner, self.name = repository.split("/", 1)
        self.default_branch = default_branch
        self.minimum_rate_limit_remaining = minimum_rate_limit_remaining
        self.maximum_changed_files = maximum_changed_files
        self._observed_rate_limits: list[int] = []

    def _record_rate_headers(self, headers: Mapping[str, str]) -> None:
        values = [
            value
            for key, value in headers.items()
            if isinstance(key, str)
            and key.lower() == "x-ratelimit-remaining"
        ]
        if len(values) != 1:
            raise ReleaseGitHubLiveError(
                "REST rate-limit header is missing or duplicated"
            )
        try:
            remaining = int(values[0])
        except (TypeError, ValueError) as exc:
            raise ReleaseGitHubLiveError(
                "REST rate-limit header is invalid"
            ) from exc
        if remaining < 0:
            raise ReleaseGitHubLiveError(
                "REST rate-limit header is invalid"
            )
        self._observed_rate_limits.append(remaining)
        if remaining < self.minimum_rate_limit_remaining:
            raise ReleaseGitHubLiveError(
                "GitHub rate-limit floor has been reached"
            )

    def _record_graphql_rate(self, data: Mapping[str, Any]) -> None:
        rate = _object(data.get("rateLimit"), field="GraphQL rate limit")
        remaining = rate.get("remaining")
        if (
            isinstance(remaining, bool)
            or not isinstance(remaining, int)
            or remaining < 0
        ):
            raise ReleaseGitHubLiveError(
                "GraphQL rate-limit result is invalid"
            )
        self._observed_rate_limits.append(remaining)
        if remaining < self.minimum_rate_limit_remaining:
            raise ReleaseGitHubLiveError(
                "GitHub rate-limit floor has been reached"
            )

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
        except ReleaseGitHubAppError as exc:
            raise ReleaseGitHubLiveError(
                "GitHub GraphQL operation failed"
            ) from exc
        self._record_graphql_rate(data)
        self._record_rate_headers(headers)
        return data

    @staticmethod
    def _connection_page(
        connection: Any,
        *,
        field: str,
    ) -> tuple[int, list[Any], bool, str | None]:
        value = _object(connection, field=field)
        total = _nonnegative_int(
            value.get("totalCount"), field=f"{field} totalCount"
        )
        nodes = _array(value.get("nodes"), field=f"{field} nodes")
        page_info = _object(
            value.get("pageInfo"), field=f"{field} pageInfo"
        )
        has_next = _boolean(
            page_info.get("hasNextPage"),
            field=f"{field} pagination flag",
        )
        cursor = page_info.get("endCursor")
        if has_next and (not isinstance(cursor, str) or not cursor):
            raise ReleaseGitHubLiveError(
                f"{field} pagination cursor is invalid"
            )
        if not has_next and cursor is not None and not isinstance(cursor, str):
            raise ReleaseGitHubLiveError(
                f"{field} pagination cursor is invalid"
            )
        return total, nodes, has_next, cursor

    @staticmethod
    def _actor(value: Any, *, field: str) -> ReleaseCommitActor:
        actor = _object(value, field=field)
        user = actor.get("user")
        login = None
        if user is not None:
            login = _text(
                _object(user, field=f"{field} GitHub user").get("login"),
                field=f"{field} GitHub login",
            )
        return ReleaseCommitActor(
            name=_text(actor.get("name"), field=f"{field} name"),
            email=_text(
                actor.get("email"),
                field=f"{field} email",
                allow_empty=True,
            ),
            date=_text(actor.get("date"), field=f"{field} date"),
            github_login=login,
        )

    def _validate_repository(self, value: Any) -> dict[str, Any]:
        repository = _object(value, field="repository")
        if (
            repository.get("databaseId") != self.repository_id
            or repository.get("nameWithOwner") != self.repository
        ):
            raise ReleaseGitHubLiveError(
                "live repository identity does not match config"
            )
        _text(repository.get("id"), field="repository node id")
        return repository

    @staticmethod
    def _repository_state(
        repository: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "is_archived": _boolean(
                repository.get("isArchived"),
                field="repository archived state",
            ),
            "is_disabled": _boolean(
                repository.get("isDisabled"),
                field="repository disabled state",
            ),
            "squash_merge_allowed": _boolean(
                repository.get("squashMergeAllowed"),
                field="repository squash-merge setting",
            ),
        }

    def _fetch_pr_identity(
        self, pr_number: int
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        data = self._graphql(
            PR_IDENTITY_QUERY,
            {
                "owner": self.owner,
                "name": self.name,
                "number": pr_number,
            },
        )
        repository = self._validate_repository(data.get("repository"))
        repository_state = self._repository_state(repository)
        pr = _object(repository.get("pullRequest"), field="pull request")
        if pr.get("number") != pr_number:
            raise ReleaseGitHubLiveError(
                "live pull request number does not match"
            )
        base_repository = _object(
            pr.get("baseRepository"),
            field="pull request base repository",
        )
        if (
            base_repository.get("databaseId") != self.repository_id
            or base_repository.get("nameWithOwner") != self.repository
        ):
            raise ReleaseGitHubLiveError(
                "pull request base repository does not match config"
            )
        head_repository = pr.get("headRepository")
        same_repo_head = (
            isinstance(head_repository, dict)
            and head_repository.get("databaseId") == self.repository_id
            and head_repository.get("nameWithOwner") == self.repository
        )
        author = _object(pr.get("author"), field="pull request author")
        changed_files = _nonnegative_int(
            pr.get("changedFiles"), field="pull request changed-file count"
        )
        if changed_files > self.maximum_changed_files:
            raise ReleaseGitHubLiveError(
                "pull request changed-file count exceeds policy"
            )
        base_branch = _text(
            pr.get("baseRefName"), field="pull request base branch"
        )
        if base_branch != self.default_branch:
            raise ReleaseGitHubLiveError(
                "pull request does not target the configured default branch"
            )
        merged = _boolean(
            pr.get("merged"), field="pull request merged state"
        )
        head_oid = _oid(
            pr.get("headRefOid"), field="pull request head OID"
        )
        base_oid = _oid(
            pr.get("baseRefOid"), field="pull request base OID"
        )
        assert head_oid is not None
        assert base_oid is not None
        potential_merge = pr.get("potentialMergeCommit")
        potential_merge_commit_oid = None
        potential_merge_tree_oid = None
        potential_merge_parent_oids = None
        if potential_merge is not None:
            potential = _object(
                potential_merge,
                field="pull request potential merge commit",
            )
            potential_merge_commit_oid = _oid(
                potential.get("oid"),
                field="pull request potential merge-commit OID",
            )
            potential_tree = _object(
                potential.get("tree"),
                field="pull request potential merge tree",
            )
            potential_merge_tree_oid = _oid(
                potential_tree.get("oid"),
                field="pull request potential merge-tree OID",
            )
            (
                parent_total,
                parent_nodes,
                parent_has_next,
                _parent_cursor,
            ) = self._connection_page(
                potential.get("parents"),
                field="pull request potential merge parents",
            )
            if (
                parent_total != 2
                or len(parent_nodes) != 2
                or parent_has_next
            ):
                raise ReleaseGitHubLiveError(
                    "potential merge commit must have exactly two parents"
                )
            potential_merge_parent_oids = [
                _oid(
                    _object(
                        node,
                        field="pull request potential merge parent",
                    ).get("oid"),
                    field="pull request potential merge parent OID",
                )
                for node in parent_nodes
            ]
            if potential_merge_parent_oids != [base_oid, head_oid]:
                raise ReleaseGitHubLiveError(
                    "potential merge parents do not match exact base and head"
                )
        elif not merged:
            raise ReleaseGitHubLiveError(
                "open pull request potential merge commit is missing"
            )
        merge_commit = pr.get("mergeCommit")
        merge_commit_oid = None
        if merge_commit is not None:
            merge_commit_oid = _oid(
                _object(
                    merge_commit, field="pull request merge commit"
                ).get("oid"),
                field="pull request merge-commit OID",
            )
        if "mergedBy" not in pr:
            raise ReleaseGitHubLiveError(
                "pull request merged-by actor is missing"
            )
        merged_by = pr.get("mergedBy")
        merged_by_login = None
        if merged_by is not None:
            merged_by_login = _text(
                _object(
                    merged_by, field="pull request merged-by actor"
                ).get("login"),
                field="pull request merged-by login",
            )
        if "autoMergeRequest" not in pr:
            raise ReleaseGitHubLiveError(
                "pull request auto-merge state is missing"
            )
        auto_merge = pr.get("autoMergeRequest")
        auto_merge_method = None
        if auto_merge is not None:
            auto_merge_method = _text(
                _object(
                    auto_merge, field="pull request auto-merge request"
                ).get("mergeMethod"),
                field="pull request auto-merge method",
            ).upper()
        if "mergeQueueEntry" not in pr:
            raise ReleaseGitHubLiveError(
                "pull request merge-queue state is missing"
            )
        merge_queue = pr.get("mergeQueueEntry")
        merge_queue_id = None
        merge_queue_state = None
        if merge_queue is not None:
            merge_queue_object = _object(
                merge_queue, field="pull request merge-queue entry"
            )
            merge_queue_id = _text(
                merge_queue_object.get("id"),
                field="pull request merge-queue entry id",
            )
            merge_queue_state = _text(
                merge_queue_object.get("state"),
                field="pull request merge-queue entry state",
            ).upper()
        return repository_state, {
            "id": _text(pr.get("id"), field="pull request id"),
            "number": pr_number,
            "url": _text(pr.get("url"), field="pull request URL"),
            "state": _text(
                pr.get("state"), field="pull request state"
            ).upper(),
            "is_draft": _boolean(
                pr.get("isDraft"), field="pull request draft state"
            ),
            "merged": merged,
            "merged_at": _nullable_text(
                pr.get("mergedAt"), field="pull request merge time"
            ),
            "head_oid": head_oid,
            "base_branch": base_branch,
            "base_oid": base_oid,
            "author_login": _text(
                author.get("login"), field="pull request author login"
            ),
            "same_repository_head": same_repo_head,
            "changed_files": changed_files,
            "mergeable": _text(
                pr.get("mergeable"), field="pull request mergeable state"
            ).upper(),
            "merge_state_status": _text(
                pr.get("mergeStateStatus"),
                field="pull request merge-state status",
            ).upper(),
            "review_decision": (
                _text(
                    pr.get("reviewDecision"),
                    field="pull request review decision",
                ).upper()
                if pr.get("reviewDecision") is not None
                else None
            ),
            "merge_commit_oid": merge_commit_oid,
            "potential_merge_commit_oid": potential_merge_commit_oid,
            "potential_merge_tree_oid": potential_merge_tree_oid,
            "potential_merge_parent_oids": (
                potential_merge_parent_oids
            ),
            "merged_by_login": merged_by_login,
            "auto_merge_requested": auto_merge is not None,
            "auto_merge_method": auto_merge_method,
            "merge_queue_entry_present": merge_queue is not None,
            "merge_queue_entry_id": merge_queue_id,
            "merge_queue_entry_state": merge_queue_state,
        }

    def _fetch_files(
        self,
        pr_number: int,
        *,
        expected_count: int,
    ) -> tuple[Mapping[str, Any], ...]:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        files: list[dict[str, Any]] = []
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
                    raise ReleaseGitHubLiveError(
                        "changed-file count changed during observation"
                    )
                if total > self.maximum_changed_files:
                    raise ReleaseGitHubLiveError(
                        "pull request exceeds maximum changed files"
                    )
            elif total != total_expected:
                raise ReleaseGitHubLiveError(
                    "changed-file count changed during pagination"
                )
            for node in nodes:
                item = _object(node, field="pull request file")
                files.append(
                    {
                        "path": _text(
                            item.get("path"), field="pull request file path"
                        ),
                        "additions": _nonnegative_int(
                            item.get("additions"),
                            field="pull request file additions",
                        ),
                        "deletions": _nonnegative_int(
                            item.get("deletions"),
                            field="pull request file deletions",
                        ),
                        "change_type": _text(
                            item.get("changeType"),
                            field="pull request file change type",
                        ).upper(),
                    }
                )
            if not has_next:
                break
            assert next_cursor is not None
            if next_cursor in seen_cursors:
                raise ReleaseGitHubLiveError(
                    "file pagination cursor repeated"
                )
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise ReleaseGitHubLiveError(
                "file pagination exceeded page limit"
            )
        if total_expected is None or len(files) != total_expected:
            raise ReleaseGitHubLiveError(
                "pull request file pagination was truncated"
            )
        paths = [str(item["path"]) for item in files]
        if len(set(paths)) != len(paths):
            raise ReleaseGitHubLiveError(
                "pull request file pagination duplicated paths"
            )
        return tuple(files)

    def _fetch_checks_and_statuses(
        self,
        head_oid: str,
    ) -> tuple[
        tuple[Mapping[str, Any], ...],
        tuple[Mapping[str, Any], ...],
    ]:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        checks: list[dict[str, Any]] = []
        statuses: list[dict[str, Any]] = []
        observed_count = 0
        total_expected: int | None = None
        for _ in range(MAX_CONNECTION_PAGES):
            data = self._graphql(
                CHECKS_AND_STATUSES_QUERY,
                {
                    "owner": self.owner,
                    "name": self.name,
                    "oid": head_oid,
                    "cursor": cursor,
                },
            )
            repository = _object(data.get("repository"), field="repository")
            commit = _object(repository.get("object"), field="head commit")
            if _oid(
                commit.get("oid"), field="status-rollup commit OID"
            ) != head_oid:
                raise ReleaseGitHubLiveError(
                    "status rollup commit does not match head"
                )
            rollup = commit.get("statusCheckRollup")
            if rollup is None:
                if cursor is not None:
                    raise ReleaseGitHubLiveError(
                        "status rollup disappeared during pagination"
                    )
                return (), ()
            total, nodes, has_next, next_cursor = self._connection_page(
                _object(
                    rollup, field="status check rollup"
                ).get("contexts"),
                field="status contexts",
            )
            if total_expected is None:
                total_expected = total
                if total > MAX_STATUS_CONTEXTS:
                    raise ReleaseGitHubLiveError(
                        "status-context count exceeds the safety limit"
                    )
            elif total != total_expected:
                raise ReleaseGitHubLiveError(
                    "status-context count changed during pagination"
                )
            for node in nodes:
                item = _object(node, field="status context")
                kind = item.get("__typename")
                if kind == "CheckRun":
                    app = _object(
                        item.get("app"), field="check-run producer App"
                    )
                    producer_app_id = _positive_int(
                        app.get("databaseId"),
                        field="check-run producer App database id",
                    )
                    producer_slug = _text(
                        app.get("slug"),
                        field="check-run producer App slug",
                    )
                    checks.append(
                        {
                            "name": _text(
                                item.get("name"), field="check-run name"
                            ),
                            "status": _text(
                                item.get("status"),
                                field="check-run status",
                            ).upper(),
                            "conclusion": (
                                _text(
                                    item.get("conclusion"),
                                    field="check-run conclusion",
                                ).upper()
                                if item.get("conclusion") is not None
                                else None
                            ),
                            "details_url": _nullable_text(
                                item.get("detailsUrl"),
                                field="check-run details URL",
                            ),
                            "producer": producer_slug,
                            "producer_app_id": producer_app_id,
                            "producer_slug": producer_slug,
                        }
                    )
                elif kind == "StatusContext":
                    creator = item.get("creator")
                    statuses.append(
                        {
                            "context": _text(
                                item.get("context"),
                                field="commit-status context",
                            ),
                            "state": _text(
                                item.get("state"),
                                field="commit-status state",
                            ).upper(),
                            "target_url": _nullable_text(
                                item.get("targetUrl"),
                                field="commit-status target URL",
                            ),
                            "creator_login": (
                                _text(
                                    creator.get("login"),
                                    field="commit-status creator",
                                )
                                if isinstance(creator, dict)
                                and creator.get("login") is not None
                                else None
                            ),
                        }
                    )
                else:
                    raise ReleaseGitHubLiveError(
                        "status rollup returned an unsupported context type"
                    )
                observed_count += 1
            if not has_next:
                break
            assert next_cursor is not None
            if next_cursor in seen_cursors:
                raise ReleaseGitHubLiveError(
                    "status pagination cursor repeated"
                )
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise ReleaseGitHubLiveError(
                "status pagination exceeded page limit"
            )
        if total_expected is None or observed_count != total_expected:
            raise ReleaseGitHubLiveError(
                "status context pagination was truncated"
            )
        return tuple(checks), tuple(statuses)

    @staticmethod
    def _review_comment(value: Any) -> dict[str, Any]:
        item = _object(value, field="review-thread comment")
        author = item.get("author")
        commit = item.get("commit")
        original_commit = item.get("originalCommit")
        return {
            "id": _text(
                item.get("id"), field="review-thread comment id"
            ),
            "database_id": _positive_int(
                item.get("databaseId"),
                field="review-thread comment database id",
            ),
            "url": _text(
                item.get("url"), field="review-thread comment URL"
            ),
            "body": _text(
                item.get("body"),
                field="review-thread comment body",
                allow_empty=True,
            ),
            "created_at": _text(
                item.get("createdAt"),
                field="review-thread comment creation time",
            ),
            "author_login": (
                _text(
                    author.get("login"),
                    field="review-thread comment author",
                )
                if isinstance(author, dict)
                and author.get("login") is not None
                else None
            ),
            "commit_oid": (
                _oid(
                    commit.get("oid"),
                    field="review-thread comment commit OID",
                )
                if isinstance(commit, dict)
                else None
            ),
            "original_commit_oid": (
                _oid(
                    original_commit.get("oid"),
                    field="review-thread comment original commit OID",
                )
                if isinstance(original_commit, dict)
                else None
            ),
        }

    def _fetch_thread_comments(
        self,
        thread_id: str,
        first_page: Mapping[str, Any],
    ) -> tuple[Mapping[str, Any], ...]:
        total, nodes, has_next, cursor = self._connection_page(
            first_page, field="review-thread comments"
        )
        if total > MAX_THREAD_COMMENTS:
            raise ReleaseGitHubLiveError(
                "review-thread comment count exceeds the safety limit"
            )
        comments = [self._review_comment(node) for node in nodes]
        seen_cursors: set[str] = set()
        pages = 1
        while has_next:
            if pages >= MAX_CONNECTION_PAGES:
                raise ReleaseGitHubLiveError(
                    "review-thread comment pagination exceeded page limit"
                )
            assert cursor is not None
            if cursor in seen_cursors:
                raise ReleaseGitHubLiveError(
                    "review-thread comment pagination cursor repeated"
                )
            seen_cursors.add(cursor)
            data = self._graphql(
                THREAD_COMMENTS_QUERY,
                {"id": thread_id, "cursor": cursor},
            )
            thread = _object(data.get("node"), field="review thread")
            if thread.get("id") != thread_id:
                raise ReleaseGitHubLiveError(
                    "review thread changed during comment pagination"
                )
            page_total, page_nodes, has_next, cursor = (
                self._connection_page(
                    thread.get("comments"),
                    field="review-thread comments",
                )
            )
            if page_total != total:
                raise ReleaseGitHubLiveError(
                    "review-thread comment count changed during pagination"
                )
            comments.extend(
                self._review_comment(node) for node in page_nodes
            )
            pages += 1
        if len(comments) != total:
            raise ReleaseGitHubLiveError(
                "review-thread comment pagination was truncated"
            )
        ids = [str(item["id"]) for item in comments]
        if len(set(ids)) != len(ids):
            raise ReleaseGitHubLiveError(
                "review-thread comment pagination duplicated ids"
            )
        return tuple(comments)

    def _fetch_review_threads(
        self,
        pr_number: int,
    ) -> tuple[Mapping[str, Any], ...]:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        threads: list[dict[str, Any]] = []
        total_expected: int | None = None
        for _ in range(MAX_CONNECTION_PAGES):
            data = self._graphql(
                REVIEW_THREADS_QUERY,
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
                    raise ReleaseGitHubLiveError(
                        "review-thread count exceeds the safety limit"
                    )
            elif total != total_expected:
                raise ReleaseGitHubLiveError(
                    "review-thread count changed during pagination"
                )
            for node in nodes:
                item = _object(node, field="review thread")
                thread_id = _text(
                    item.get("id"), field="review-thread id"
                )
                threads.append(
                    {
                        "id": thread_id,
                        "is_resolved": _boolean(
                            item.get("isResolved"),
                            field="review-thread resolved state",
                        ),
                        "is_outdated": _boolean(
                            item.get("isOutdated"),
                            field="review-thread outdated state",
                        ),
                        "comments": list(
                            self._fetch_thread_comments(
                                thread_id,
                                _object(
                                    item.get("comments"),
                                    field="review-thread comments",
                                ),
                            )
                        ),
                    }
                )
            if not has_next:
                break
            assert next_cursor is not None
            if next_cursor in seen_cursors:
                raise ReleaseGitHubLiveError(
                    "review-thread pagination cursor repeated"
                )
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise ReleaseGitHubLiveError(
                "review-thread pagination exceeded page limit"
            )
        if total_expected is None or len(threads) != total_expected:
            raise ReleaseGitHubLiveError(
                "review-thread pagination was truncated"
            )
        ids = [str(item["id"]) for item in threads]
        if len(set(ids)) != len(ids):
            raise ReleaseGitHubLiveError(
                "review-thread pagination duplicated ids"
            )
        return tuple(threads)

    def _fetch_issue_comments(
        self,
        pr_number: int,
    ) -> tuple[Mapping[str, Any], ...]:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        comments: list[dict[str, Any]] = []
        total_expected: int | None = None
        for _ in range(MAX_CONNECTION_PAGES):
            data = self._graphql(
                ISSUE_COMMENTS_QUERY,
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
                pr.get("comments"), field="pull request issue comments"
            )
            if total_expected is None:
                total_expected = total
                if total > MAX_ISSUE_COMMENTS:
                    raise ReleaseGitHubLiveError(
                        "issue-comment count exceeds the safety limit"
                    )
            elif total != total_expected:
                raise ReleaseGitHubLiveError(
                    "issue-comment count changed during pagination"
                )
            for node in nodes:
                item = _object(node, field="pull request issue comment")
                author = item.get("author")
                comments.append(
                    {
                        "id": _text(
                            item.get("id"), field="issue-comment id"
                        ),
                        "database_id": _positive_int(
                            item.get("databaseId"),
                            field="issue-comment database id",
                        ),
                        "url": _text(
                            item.get("url"), field="issue-comment URL"
                        ),
                        "body": _text(
                            item.get("body"),
                            field="issue-comment body",
                            allow_empty=True,
                        ),
                        "created_at": _text(
                            item.get("createdAt"),
                            field="issue-comment creation time",
                        ),
                        "updated_at": _text(
                            item.get("updatedAt"),
                            field="issue-comment update time",
                        ),
                        "author_login": (
                            _text(
                                author.get("login"),
                                field="issue-comment author",
                            )
                            if isinstance(author, dict)
                            and author.get("login") is not None
                            else None
                        ),
                    }
                )
            if not has_next:
                break
            assert next_cursor is not None
            if next_cursor in seen_cursors:
                raise ReleaseGitHubLiveError(
                    "issue-comment pagination cursor repeated"
                )
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise ReleaseGitHubLiveError(
                "issue-comment pagination exceeded page limit"
            )
        if total_expected is None or len(comments) != total_expected:
            raise ReleaseGitHubLiveError(
                "issue-comment pagination was truncated"
            )
        ids = [str(item["id"]) for item in comments]
        if len(set(ids)) != len(ids):
            raise ReleaseGitHubLiveError(
                "issue-comment pagination duplicated ids"
            )
        return tuple(comments)

    def _fetch_reviews(
        self,
        pr_number: int,
    ) -> tuple[Mapping[str, Any], ...]:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        reviews: list[dict[str, Any]] = []
        total_expected: int | None = None
        for _ in range(MAX_CONNECTION_PAGES):
            data = self._graphql(
                REVIEWS_QUERY,
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
                pr.get("reviews"), field="pull request reviews"
            )
            if total_expected is None:
                total_expected = total
                if total > MAX_REVIEWS:
                    raise ReleaseGitHubLiveError(
                        "review count exceeds the safety limit"
                    )
            elif total != total_expected:
                raise ReleaseGitHubLiveError(
                    "review count changed during pagination"
                )
            for node in nodes:
                item = _object(node, field="pull request review")
                author = item.get("author")
                commit = item.get("commit")
                reviews.append(
                    {
                        "id": _text(
                            item.get("id"), field="pull request review id"
                        ),
                        "database_id": _positive_int(
                            item.get("databaseId"),
                            field="pull request review database id",
                        ),
                        "url": _text(
                            item.get("url"), field="pull request review URL"
                        ),
                        "body": _text(
                            item.get("body"),
                            field="pull request review body",
                            allow_empty=True,
                        ),
                        "state": _text(
                            item.get("state"),
                            field="pull request review state",
                        ).upper(),
                        "submitted_at": _nullable_text(
                            item.get("submittedAt"),
                            field="pull request review submission time",
                        ),
                        "author_login": (
                            _text(
                                author.get("login"),
                                field="pull request review author",
                            )
                            if isinstance(author, dict)
                            and author.get("login") is not None
                            else None
                        ),
                        "commit_oid": (
                            _oid(
                                commit.get("oid"),
                                field="pull request review commit OID",
                            )
                            if isinstance(commit, dict)
                            else None
                        ),
                    }
                )
            if not has_next:
                break
            assert next_cursor is not None
            if next_cursor in seen_cursors:
                raise ReleaseGitHubLiveError(
                    "review pagination cursor repeated"
                )
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise ReleaseGitHubLiveError(
                "review pagination exceeded page limit"
            )
        if total_expected is None or len(reviews) != total_expected:
            raise ReleaseGitHubLiveError(
                "review pagination was truncated"
            )
        ids = [str(item["id"]) for item in reviews]
        if len(set(ids)) != len(ids):
            raise ReleaseGitHubLiveError(
                "review pagination duplicated ids"
            )
        return tuple(reviews)

    def _fetch_commit(self, commit_oid: str) -> ReleaseCommitState:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        parent_oids: list[str] = []
        total_expected: int | None = None
        stable_fields: tuple[Any, ...] | None = None
        actor_author: ReleaseCommitActor | None = None
        actor_committer: ReleaseCommitActor | None = None
        tree_oid: str | None = None
        committed_at: str | None = None
        for _ in range(MAX_CONNECTION_PAGES):
            data = self._graphql(
                COMMIT_QUERY,
                {
                    "owner": self.owner,
                    "name": self.name,
                    "oid": commit_oid,
                    "cursor": cursor,
                },
            )
            repository = _object(data.get("repository"), field="repository")
            commit = _object(repository.get("object"), field="commit")
            observed_oid = _oid(commit.get("oid"), field="commit OID")
            if observed_oid != commit_oid:
                raise ReleaseGitHubLiveError(
                    "commit lookup returned a different OID"
                )
            observed_tree = _oid(
                _object(commit.get("tree"), field="commit tree").get("oid"),
                field="commit tree OID",
            )
            observed_time = _text(
                commit.get("committedDate"), field="commit time"
            )
            observed_author = self._actor(
                commit.get("author"), field="commit author"
            )
            observed_committer = self._actor(
                commit.get("committer"), field="commit committer"
            )
            observed_stable = (
                observed_oid,
                observed_tree,
                observed_time,
                observed_author,
                observed_committer,
            )
            if stable_fields is None:
                stable_fields = observed_stable
                tree_oid = observed_tree
                committed_at = observed_time
                actor_author = observed_author
                actor_committer = observed_committer
            elif observed_stable != stable_fields:
                raise ReleaseGitHubLiveError(
                    "commit identity changed during parent pagination"
                )
            total, nodes, has_next, next_cursor = self._connection_page(
                commit.get("parents"), field="commit parents"
            )
            if total_expected is None:
                total_expected = total
            elif total != total_expected:
                raise ReleaseGitHubLiveError(
                    "commit parent count changed during pagination"
                )
            for node in nodes:
                parent_oids.append(
                    _oid(
                        _object(node, field="commit parent").get("oid"),
                        field="commit parent OID",
                    )
                    or ""
                )
            if not has_next:
                break
            assert next_cursor is not None
            if next_cursor in seen_cursors:
                raise ReleaseGitHubLiveError(
                    "commit-parent pagination cursor repeated"
                )
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise ReleaseGitHubLiveError(
                "commit-parent pagination exceeded page limit"
            )
        if total_expected is None or len(parent_oids) != total_expected:
            raise ReleaseGitHubLiveError(
                "commit-parent pagination was truncated"
            )
        if len(set(parent_oids)) != len(parent_oids):
            raise ReleaseGitHubLiveError(
                "commit-parent pagination duplicated OIDs"
            )
        assert tree_oid is not None
        assert committed_at is not None
        assert actor_author is not None
        assert actor_committer is not None
        return ReleaseCommitState(
            oid=commit_oid,
            tree_oid=tree_oid,
            parent_oids=tuple(parent_oids),
            committed_at=committed_at,
            author=actor_author,
            committer=actor_committer,
        )

    def _fetch_default_branch_observation(
        self,
    ) -> tuple[dict[str, Any], ReleaseDefaultBranchState]:
        data = self._graphql(
            DEFAULT_BRANCH_REF_QUERY,
            {"owner": self.owner, "name": self.name},
        )
        repository = self._validate_repository(data.get("repository"))
        repository_state = self._repository_state(repository)
        ref = _object(
            repository.get("defaultBranchRef"), field="default branch ref"
        )
        name = _text(ref.get("name"), field="default branch name")
        prefix = _text(ref.get("prefix"), field="default branch prefix")
        if name != self.default_branch or prefix != "refs/heads/":
            raise ReleaseGitHubLiveError(
                "live default branch ref does not match config"
            )
        target = _object(ref.get("target"), field="default branch target")
        commit_oid = _oid(
            target.get("oid"), field="default branch commit OID"
        )
        assert commit_oid is not None
        return (
            repository_state,
            ReleaseDefaultBranchState(
                name=name,
                qualified_name=f"{prefix}{name}",
                commit=self._fetch_commit(commit_oid),
            ),
        )

    def fetch_default_branch_state(self) -> ReleaseDefaultBranchState:
        _, branch = self._fetch_default_branch_observation()
        return branch

    @staticmethod
    def _exact_head_evidence(
        head_oid: str,
        *,
        issue_comments: Iterable[Mapping[str, Any]],
        reviews: Iterable[Mapping[str, Any]],
        review_threads: Iterable[Mapping[str, Any]],
    ) -> tuple[Mapping[str, Any], ...]:
        evidence: list[dict[str, Any]] = []
        for item in issue_comments:
            if contains_exact_full_oid(str(item.get("body") or ""), head_oid):
                evidence.append(
                    {
                        "kind": "issue_comment",
                        "id": item["id"],
                        "url": item["url"],
                        "author_login": item.get("author_login"),
                        "created_at": item["created_at"],
                    }
                )
        for item in reviews:
            if (
                item.get("commit_oid") == head_oid
                or contains_exact_full_oid(
                    str(item.get("body") or ""), head_oid
                )
            ):
                evidence.append(
                    {
                        "kind": "pull_request_review",
                        "id": item["id"],
                        "url": item["url"],
                        "author_login": item.get("author_login"),
                            "created_at": item.get("submitted_at"),
                        "commit_oid": item.get("commit_oid"),
                    }
                )
        for thread in review_threads:
            for item in thread.get("comments") or []:
                if (
                    item.get("commit_oid") == head_oid
                    or item.get("original_commit_oid") == head_oid
                    or contains_exact_full_oid(
                        str(item.get("body") or ""), head_oid
                    )
                ):
                    evidence.append(
                        {
                            "kind": "review_thread_comment",
                            "id": item["id"],
                            "url": item["url"],
                            "author_login": item.get("author_login"),
                            "created_at": item["created_at"],
                            "commit_oid": item.get("commit_oid"),
                            "original_commit_oid": item.get(
                                "original_commit_oid"
                            ),
                        }
                    )
        ids = [(item["kind"], item["id"]) for item in evidence]
        if len(set(ids)) != len(ids):
            raise ReleaseGitHubLiveError(
                "exact-head evidence contains duplicate identities"
            )
        return tuple(evidence)

    def fetch_merge_snapshot(
        self,
        *,
        pr_number: int,
    ) -> ReleaseLiveSnapshot:
        if (
            isinstance(pr_number, bool)
            or not isinstance(pr_number, int)
            or pr_number <= 0
        ):
            raise ReleaseGitHubLiveError(
                "pull request number is invalid"
            )
        self._observed_rate_limits = []
        repository_state, identity = self._fetch_pr_identity(pr_number)
        branch_repository_state, branch = (
            self._fetch_default_branch_observation()
        )
        if branch_repository_state != repository_state:
            raise ReleaseGitHubLiveError(
                "repository policy changed during observation"
            )
        files = self._fetch_files(
            pr_number, expected_count=identity["changed_files"]
        )
        checks, statuses = self._fetch_checks_and_statuses(
            str(identity["head_oid"])
        )
        threads = self._fetch_review_threads(pr_number)
        issue_comments = self._fetch_issue_comments(pr_number)
        reviews = self._fetch_reviews(pr_number)
        final_repository_state, final_identity = self._fetch_pr_identity(
            pr_number
        )
        final_branch_repository_state, final_branch = (
            self._fetch_default_branch_observation()
        )
        if (
            final_repository_state != repository_state
            or final_branch_repository_state != repository_state
        ):
            raise ReleaseGitHubLiveError(
                "repository policy changed during observation"
            )
        if final_identity != identity:
            raise ReleaseGitHubLiveError(
                "pull request identity changed during observation"
            )
        if final_branch != branch:
            raise ReleaseGitHubLiveError(
                "default branch changed during observation"
            )
        if not self._observed_rate_limits:
            raise ReleaseGitHubLiveError(
                "no GitHub rate-limit evidence was observed"
            )
        exact_evidence = self._exact_head_evidence(
            str(identity["head_oid"]),
            issue_comments=issue_comments,
            reviews=reviews,
            review_threads=threads,
        )
        return ReleaseLiveSnapshot(
            repository=self.repository,
            repository_id=self.repository_id,
            repository_policy=repository_state,
            pr=identity,
            default_branch=branch,
            files=files,
            checks=checks,
            statuses=statuses,
            review_threads=threads,
            issue_comments=issue_comments,
            reviews=reviews,
            unresolved_thread_count=sum(
                1 for item in threads if not item["is_resolved"]
            ),
            unresolved_current_thread_count=sum(
                1
                for item in threads
                if not item["is_resolved"] and not item["is_outdated"]
            ),
            exact_head_evidence=exact_evidence,
            minimum_rate_limit_remaining=min(
                self._observed_rate_limits
            ),
        )

    # A service may use the shorter name while retaining explicit merge scope.
    fetch_snapshot = fetch_merge_snapshot

    def merge_pull_request(
        self,
        *,
        pr_number: int,
        expected_head_oid: str,
    ) -> ReleaseMergeMutationResult:
        if (
            isinstance(pr_number, bool)
            or not isinstance(pr_number, int)
            or pr_number <= 0
        ):
            raise ReleaseGitHubLiveError(
                "pull request number is invalid"
            )
        head_oid = _oid(
            expected_head_oid, field="expected pull request head OID"
        )
        assert head_oid is not None
        path = (
            f"/repos/{quote(self.owner, safe='')}/"
            f"{quote(self.name, safe='')}/pulls/{pr_number}/merge"
        )
        try:
            data, headers = self.app.installation_request_json(
                "PUT",
                path,
                token=self.credential.token,
                payload={"sha": head_oid, "merge_method": "squash"},
                expected_statuses=frozenset({200}),
            )
        except ReleaseGitHubAppError as exc:
            raise ReleaseGitHubLiveError(
                "GitHub squash merge failed"
            ) from exc
        self._record_rate_headers(headers)
        result = _object(data, field="squash-merge result")
        if not _boolean(
            result.get("merged"), field="squash-merge result state"
        ):
            raise ReleaseGitHubLiveError(
                "GitHub did not confirm the squash merge"
            )
        merge_oid = _oid(
            result.get("sha"), field="squash-merge commit OID"
        )
        assert merge_oid is not None
        return ReleaseMergeMutationResult(
            merged=True,
            merge_commit_oid=merge_oid,
            message=_text(
                result.get("message"),
                field="squash-merge result message",
                allow_empty=True,
            ),
        )

    def fetch_merge_readback(
        self,
        *,
        pr_number: int,
    ) -> ReleaseMergeReadback:
        if (
            isinstance(pr_number, bool)
            or not isinstance(pr_number, int)
            or pr_number <= 0
        ):
            raise ReleaseGitHubLiveError(
                "pull request number is invalid"
            )
        self._observed_rate_limits = []
        repository_state, identity = self._fetch_pr_identity(pr_number)
        branch_repository_state, branch = (
            self._fetch_default_branch_observation()
        )
        final_repository_state, final_identity = self._fetch_pr_identity(
            pr_number
        )
        final_branch_repository_state, final_branch = (
            self._fetch_default_branch_observation()
        )
        if (
            branch_repository_state != repository_state
            or final_repository_state != repository_state
            or final_branch_repository_state != repository_state
        ):
            raise ReleaseGitHubLiveError(
                "repository policy changed during merge readback"
            )
        if final_identity != identity or final_branch != branch:
            raise ReleaseGitHubLiveError(
                "merge readback changed during observation"
            )
        if not self._observed_rate_limits:
            raise ReleaseGitHubLiveError(
                "no GitHub rate-limit evidence was observed"
            )
        return ReleaseMergeReadback(
            repository=self.repository,
            repository_id=self.repository_id,
            repository_policy=repository_state,
            pr=identity,
            default_branch=branch,
            minimum_rate_limit_remaining=min(
                self._observed_rate_limits
            ),
        )

    def validate_merge_readback(
        self,
        readback: ReleaseMergeReadback,
        *,
        expected_head_oid: str,
        expected_previous_default_oid: str,
        expected_merge_oid: str,
        expected_merged_by_login: str,
        expected_tree_oid: str,
        allowed_author_logins: Iterable[str] | None = None,
        allowed_committer_logins: Iterable[str] | None = None,
    ) -> None:
        """Validate exact squash topology, tree, and optional actor policy."""

        head_oid = _oid(
            expected_head_oid, field="expected pull request head OID"
        )
        previous_oid = _oid(
            expected_previous_default_oid,
            field="expected previous default-branch OID",
        )
        merge_oid = _oid(
            expected_merge_oid, field="expected merge-commit OID"
        )
        tree_oid = _oid(
            expected_tree_oid, field="expected merge tree OID"
        )
        assert tree_oid is not None
        if (
            not isinstance(expected_merged_by_login, str)
            or not expected_merged_by_login
        ):
            raise ReleaseGitHubLiveError(
                "expected merged-by login is invalid"
            )
        pr = readback.pr
        branch_commit = readback.default_branch.commit
        if (
            readback.repository != self.repository
            or readback.repository_id != self.repository_id
            or readback.default_branch.name != self.default_branch
            or readback.default_branch.qualified_name
            != f"refs/heads/{self.default_branch}"
        ):
            raise ReleaseGitHubLiveError(
                "merge readback repository binding does not match config"
            )
        if (
            pr.get("state") != "MERGED"
            or pr.get("merged") is not True
            or not isinstance(pr.get("merged_at"), str)
            or not pr.get("merged_at")
            or pr.get("head_oid") != head_oid
            or pr.get("merge_commit_oid") != merge_oid
            or pr.get("merged_by_login") != expected_merged_by_login
        ):
            raise ReleaseGitHubLiveError(
                "pull request readback does not prove the exact merge"
            )
        if (
            branch_commit.oid != merge_oid
            or branch_commit.parent_oids != (previous_oid,)
        ):
            raise ReleaseGitHubLiveError(
                "default-branch topology does not prove one squash merge"
            )
        if branch_commit.tree_oid != tree_oid:
            raise ReleaseGitHubLiveError(
                "merge-commit tree does not match approved tree"
            )
        if allowed_author_logins is not None:
            if isinstance(allowed_author_logins, (str, bytes)):
                raise ReleaseGitHubLiveError(
                    "merge-commit author policy is invalid"
                )
            allowed = frozenset(allowed_author_logins)
            if not all(
                isinstance(item, str) and item for item in allowed
            ):
                raise ReleaseGitHubLiveError(
                    "merge-commit author policy is invalid"
                )
            if (
                not allowed
                or branch_commit.author.github_login not in allowed
            ):
                raise ReleaseGitHubLiveError(
                    "merge-commit author is outside policy"
                )
        if allowed_committer_logins is not None:
            if isinstance(allowed_committer_logins, (str, bytes)):
                raise ReleaseGitHubLiveError(
                    "merge-commit committer policy is invalid"
                )
            allowed = frozenset(allowed_committer_logins)
            if not all(
                isinstance(item, str) and item for item in allowed
            ):
                raise ReleaseGitHubLiveError(
                    "merge-commit committer policy is invalid"
                )
            if (
                not allowed
                or branch_commit.committer.github_login not in allowed
            ):
                raise ReleaseGitHubLiveError(
                    "merge-commit committer is outside policy"
                )


# Short aliases remain package-local to the release identity.
GitHubLiveClient = ReleaseGitHubLiveClient
GitHubLiveError = ReleaseGitHubLiveError
LiveSnapshot = ReleaseLiveSnapshot
