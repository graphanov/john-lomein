from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from broker.john_lomein_github_app import (
    FixedGitHubTransport,
    GitHubAppClient,
    GitHubAppError,
    HTTPResponse,
    InstallationCredential,
    REQUESTED_PERMISSIONS,
    generate_app_jwt,
)
from broker.john_lomein_github_live import (
    GitHubLiveClient,
    GitHubLiveError,
)


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
REPO = "acme/widget"
REPO_ID = 123456
PR_URL = "https://github.com/acme/widget/pull/17"
COMMENT_URL = PR_URL + "#issuecomment-123"


def _json_response(
    status: int,
    value: Any,
    *,
    remaining: int = 5000,
) -> HTTPResponse:
    return HTTPResponse(
        status=status,
        headers={"x-ratelimit-remaining": str(remaining)},
        body=json.dumps(value, separators=(",", ":")).encode("utf-8"),
    )


class QueueTransport:
    def __init__(self, responses: list[HTTPResponse]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> HTTPResponse:
        self.calls.append(
            {
                "method": method,
                "path": path,
                "headers": dict(headers),
                "body": body,
                "timeout": timeout_seconds,
            }
        )
        if not self.responses:
            raise AssertionError("unexpected HTTP request")
        return self.responses.pop(0)


class GitHubAppContractTest(unittest.TestCase):
    def _private_key(self, root: Path) -> Path:
        private = root / "app.pem"
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        private.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        private.chmod(0o600)
        return private

    def test_app_jwt_is_rs256_and_signature_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private = self._private_key(root)
            with mock.patch(
                "subprocess.run",
                side_effect=AssertionError("external crypto was invoked"),
            ):
                token = generate_app_jwt(
                    app_id=42,
                    private_key_path=private,
                    now=NOW,
                )
            header_part, payload_part, signature_part = token.split(".")

            def decode(part: str) -> bytes:
                return base64.urlsafe_b64decode(
                    part + "=" * (-len(part) % 4)
                )

            self.assertEqual(
                json.loads(decode(header_part)),
                {"alg": "RS256", "typ": "JWT"},
            )
            self.assertEqual(json.loads(decode(payload_part))["iss"], "42")
            key = serialization.load_pem_private_key(
                private.read_bytes(),
                password=None,
            )
            assert isinstance(key, rsa.RSAPrivateKey)
            key.public_key().verify(
                decode(signature_part),
                f"{header_part}.{payload_part}".encode("ascii"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )

    def test_installation_token_is_scoped_and_permissions_are_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = self._private_key(Path(tmp))
            transport = QueueTransport(
                [
                    _json_response(200, {"id": 42, "slug": "protected"}),
                    _json_response(
                        200,
                        {"id": 77, "app_id": 42},
                    ),
                    _json_response(
                        201,
                        {
                            "token": "installation-token",
                            "expires_at": "2026-07-16T13:00:00Z",
                            "permissions": {
                                **REQUESTED_PERMISSIONS,
                                "metadata": "read",
                            },
                        },
                    ),
                    _json_response(
                        200,
                        {
                            "total_count": 1,
                            "repositories": [{"id": REPO_ID}],
                        },
                    ),
                ]
            )
            client = GitHubAppClient(
                app_id=42,
                installation_id=77,
                app_slug="protected",
                private_key_path=private,
                repository_id=REPO_ID,
                transport=transport,
            )
            credential = client.authenticate_installation(now=NOW)
            self.assertEqual(credential.token, "installation-token")
            request = transport.calls[2]
            self.assertEqual(
                request["path"],
                "/app/installations/77/access_tokens",
            )
            payload = json.loads(request["body"])
            self.assertEqual(payload["repository_ids"], [REPO_ID])
            self.assertEqual(payload["permissions"], REQUESTED_PERMISSIONS)
            self.assertNotIn("contents", payload["permissions"])
            self.assertNotIn("actions", payload["permissions"])

    def test_unexpected_returned_permission_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = self._private_key(Path(tmp))
            transport = QueueTransport(
                [
                    _json_response(200, {"id": 42, "slug": "protected"}),
                    _json_response(200, {"id": 77, "app_id": 42}),
                    _json_response(
                        201,
                        {
                            "token": "installation-token",
                            "expires_at": "2026-07-16T13:00:00Z",
                            "permissions": {
                                **REQUESTED_PERMISSIONS,
                                "contents": "write",
                            },
                        },
                    ),
                ]
            )
            client = GitHubAppClient(
                app_id=42,
                installation_id=77,
                app_slug="protected",
                private_key_path=private,
                repository_id=REPO_ID,
                transport=transport,
            )
            with self.assertRaisesRegex(
                GitHubAppError, "unexpected permission"
            ):
                client.authenticate_installation(now=NOW)

    def test_private_key_must_not_be_group_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = self._private_key(Path(tmp))
            private.chmod(0o640)
            with self.assertRaisesRegex(GitHubAppError, "group or others"):
                generate_app_jwt(
                    app_id=42,
                    private_key_path=private,
                    now=NOW,
                )

    def test_redirect_is_not_followed_and_token_is_not_disclosed(self):
        transport = QueueTransport(
            [_json_response(302, {"token": "response-secret"})]
        )
        client = GitHubAppClient(
            app_id=42,
            installation_id=77,
            app_slug="protected",
            private_key_path=Path("/not-used"),
            repository_id=REPO_ID,
            transport=transport,
        )
        secret = "installation-secret"
        with self.assertRaisesRegex(
            GitHubAppError, "status 302"
        ) as raised:
            client.request_json("GET", "/redirect", token=secret)
        self.assertEqual(len(transport.calls), 1)
        self.assertNotIn(secret, str(raised.exception))
        self.assertNotIn("response-secret", str(raised.exception))

    def test_tls_trust_environment_override_fails_closed(self):
        with mock.patch.dict(
            os.environ,
            {"SSL_CERT_FILE": "/tmp/model-owned-ca.pem"},
        ):
            with self.assertRaisesRegex(
                GitHubAppError, "TLS trust environment"
            ):
                FixedGitHubTransport()


def _rate(remaining: int = 5000) -> dict[str, Any]:
    return {
        "rateLimit": {
            "remaining": remaining,
            "resetAt": "2026-07-16T13:00:00Z",
        }
    }


class FakeApp:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, Any]]] = []
        self.file_page = 0
        self.identity_calls = 0
        self.malformed_files = False
        self.changed_head_after_observation = False
        self.omit_rest_rate_header = False
        self.rate_remaining = 5000
        self.status_context_total = 1

    def graphql(
        self,
        *,
        token: str,
        query: str,
        variables: Mapping[str, Any],
    ) -> tuple[dict[str, Any], Mapping[str, str]]:
        self.calls.append((query, dict(variables)))
        rate = _rate(self.rate_remaining)
        if "BrokerPrIdentity" in query:
            self.identity_calls += 1
            head_sha = (
                "d" * 40
                if self.changed_head_after_observation
                and self.identity_calls > 1
                else "a" * 40
            )
            return (
                {
                    "repository": {
                        "id": "R_repo",
                        "databaseId": REPO_ID,
                        "nameWithOwner": REPO,
                        "pullRequest": {
                            "id": "PR_node",
                            "number": 17,
                            "url": PR_URL,
                            "state": "OPEN",
                            "isDraft": True,
                            "headRefOid": head_sha,
                            "baseRefName": "main",
                            "changedFiles": 2,
                            "author": {"login": "john-lomein[bot]"},
                            "headRepository": {
                                "id": "R_repo",
                                "databaseId": REPO_ID,
                                "nameWithOwner": REPO,
                            },
                            "baseRepository": {
                                "id": "R_repo",
                                "databaseId": REPO_ID,
                                "nameWithOwner": REPO,
                            },
                        },
                    },
                    **rate,
                },
                {"x-ratelimit-remaining": str(self.rate_remaining)},
            )
        if "BrokerPrFiles" in query:
            self.file_page += 1
            if self.file_page == 1:
                files = {
                    "totalCount": 2,
                    "nodes": [{"path": "src/a.py"}],
                    "pageInfo": {"hasNextPage": True, "endCursor": "p2"},
                }
            else:
                files = {
                    "totalCount": 2,
                    "nodes": []
                    if self.malformed_files
                    else [{"path": "tests/test_a.py"}],
                    "pageInfo": {"hasNextPage": False, "endCursor": "p2"},
                }
            return (
                {
                    "repository": {
                        "pullRequest": {"files": files}
                    },
                    **rate,
                },
                {"x-ratelimit-remaining": str(self.rate_remaining)},
            )
        if "BrokerChecks" in query:
            return (
                {
                    "repository": {
                        "object": {
                            "oid": "a" * 40,
                            "statusCheckRollup": {
                                "contexts": {
                                    "totalCount": (
                                        self.status_context_total
                                    ),
                                    "nodes": [
                                        {
                                            "__typename": "CheckRun",
                                            "name": "test",
                                            "status": "COMPLETED",
                                            "conclusion": "SUCCESS",
                                            "app": {"slug": "actions"},
                                        }
                                    ],
                                    "pageInfo": {
                                        "hasNextPage": False,
                                        "endCursor": None,
                                    },
                                }
                            },
                        }
                    },
                    **rate,
                },
                {"x-ratelimit-remaining": str(self.rate_remaining)},
            )
        if "BrokerThreads" in query:
            return (
                {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "totalCount": 1,
                                "nodes": [
                                    {
                                        "id": "PRRT_old",
                                        "isResolved": False,
                                        "isOutdated": True,
                                        "comments": {
                                            "totalCount": 1,
                                            "nodes": [
                                                {
                                                    "id": "PRRC_comment",
                                                    "databaseId": 321,
                                                    "url": (
                                                        PR_URL
                                                        + "#discussion_r321"
                                                    ),
                                                }
                                            ],
                                            "pageInfo": {
                                                "hasNextPage": False,
                                                "endCursor": None,
                                            },
                                        },
                                    }
                                ],
                                "pageInfo": {
                                    "hasNextPage": False,
                                    "endCursor": None,
                                },
                            }
                        }
                    },
                    **rate,
                },
                {"x-ratelimit-remaining": str(self.rate_remaining)},
            )
        if "BrokerMarkReady" in query:
            return (
                {
                    "markPullRequestReadyForReview": {
                        "clientMutationId": variables["clientMutationId"],
                        "pullRequest": {
                            "id": "PR_node",
                            "number": 17,
                            "isDraft": False,
                            "headRefOid": "a" * 40,
                            "state": "OPEN",
                            "updatedAt": "2026-07-16T12:00:01Z",
                        },
                    },
                    **rate,
                },
                {"x-ratelimit-remaining": str(self.rate_remaining)},
            )
        if "BrokerResolveThread" in query:
            return (
                {
                    "resolveReviewThread": {
                        "clientMutationId": variables["clientMutationId"],
                        "thread": {
                            "id": variables["threadId"],
                            "isResolved": True,
                        },
                    },
                    **rate,
                },
                {"x-ratelimit-remaining": str(self.rate_remaining)},
            )
        raise AssertionError("unknown GraphQL operation")

    def request_json(
        self,
        method: str,
        path: str,
        *,
        token: str,
        payload: Any | None = None,
        expected_statuses: frozenset[int] = frozenset({200}),
    ) -> tuple[Any, Mapping[str, str]]:
        self.calls.append((path, {}))
        return (
            {
                "id": 123,
                "html_url": COMMENT_URL,
                "user": {"login": "john-lomein[bot]"},
                "body": "<!-- evidence -->",
                "created_at": "2026-07-16T11:59:00Z",
            },
            (
                {}
                if self.omit_rest_rate_header
                else {
                    "x-ratelimit-remaining": str(
                        self.rate_remaining
                    )
                }
            ),
        )


def _credential() -> InstallationCredential:
    return InstallationCredential(
        token="token",
        expires_at=NOW + timedelta(hours=1),
        repository_id=REPO_ID,
        installation_id=77,
        app_slug="protected",
        permissions=REQUESTED_PERMISSIONS,
    )


class GitHubLiveContractTest(unittest.TestCase):
    def _client(self, app: FakeApp) -> GitHubLiveClient:
        return GitHubLiveClient(
            app=app,  # type: ignore[arg-type]
            credential=_credential(),
            repository=REPO,
            repository_id=REPO_ID,
            minimum_rate_limit_remaining=100,
            maximum_changed_files=1000,
        )

    def test_snapshot_is_fully_paginated_and_repository_bound(self):
        app = FakeApp()
        snapshot = self._client(app).fetch_snapshot(
            pr_number=17,
            evidence_comment_url=COMMENT_URL,
        )
        self.assertEqual(
            snapshot.files, ("src/a.py", "tests/test_a.py")
        )
        self.assertTrue(snapshot.pr["same_repository_head"])
        self.assertEqual(snapshot.checks[0]["name"], "test")
        self.assertEqual(snapshot.unresolved_thread_count, 1)
        self.assertTrue(snapshot.threads[0]["is_outdated"])
        self.assertEqual(snapshot.evidence_comment["id"], 123)

    def test_truncated_file_pagination_fails_closed(self):
        app = FakeApp()
        app.malformed_files = True
        with self.assertRaisesRegex(GitHubLiveError, "truncated"):
            self._client(app).fetch_snapshot(
                pr_number=17,
                evidence_comment_url=COMMENT_URL,
            )

    def test_rate_limit_floor_blocks_before_mutation_path(self):
        app = FakeApp()
        app.rate_remaining = 99
        with self.assertRaisesRegex(GitHubLiveError, "rate-limit floor"):
            self._client(app).fetch_snapshot(
                pr_number=17,
                evidence_comment_url=COMMENT_URL,
            )

    def test_head_change_during_snapshot_fails_before_mutation(self):
        app = FakeApp()
        app.changed_head_after_observation = True
        with self.assertRaisesRegex(
            GitHubLiveError, "changed during observation"
        ):
            self._client(app).fetch_snapshot(
                pr_number=17,
                evidence_comment_url=COMMENT_URL,
            )

    def test_missing_rest_rate_limit_header_fails_closed(self):
        app = FakeApp()
        app.omit_rest_rate_header = True
        with self.assertRaisesRegex(
            GitHubLiveError, "rate-limit header is missing"
        ):
            self._client(app).fetch_snapshot(
                pr_number=17,
                evidence_comment_url=COMMENT_URL,
            )

    def test_oversized_status_context_set_fails_before_pagination(self):
        app = FakeApp()
        app.status_context_total = 1001
        with self.assertRaisesRegex(
            GitHubLiveError, "exceeds the safety limit"
        ):
            self._client(app).fetch_snapshot(
                pr_number=17,
                evidence_comment_url=COMMENT_URL,
            )

    def test_mutations_bind_node_target_and_client_id(self):
        app = FakeApp()
        client = self._client(app)
        ready = client.mark_pr_ready(
            pr_node_id="PR_node",
            client_mutation_id="attempt-1",
        )
        resolved = client.resolve_review_thread(
            thread_id="PRRT_old",
            client_mutation_id="attempt-2",
        )
        self.assertFalse(ready["is_draft"])
        self.assertTrue(resolved["is_resolved"])
        mark_call = next(
            variables
            for query, variables in app.calls
            if "BrokerMarkReady" in query
        )
        resolve_call = next(
            variables
            for query, variables in app.calls
            if "BrokerResolveThread" in query
        )
        self.assertEqual(mark_call["id"], "PR_node")
        self.assertEqual(resolve_call["threadId"], "PRRT_old")


if __name__ == "__main__":
    unittest.main()
