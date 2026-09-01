from __future__ import annotations

import base64
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from release_broker import john_lomein_release_broker_github_app as github_app
from release_broker.john_lomein_release_broker_github_app import (
    API_VERSION,
    REQUIRED_PERMISSIONS,
    TOKEN_REQUEST_PERMISSIONS,
    FixedReleaseGitHubTransport,
    ReleaseGitHubAppClient,
    ReleaseGitHubAppError,
    ReleaseHTTPResponse,
    ReleaseInstallationCredential,
    generate_release_app_jwt,
)
from release_broker.john_lomein_release_broker_github_live import (
    ReleaseGitHubLiveClient,
    ReleaseGitHubLiveError,
    contains_exact_full_oid,
)


class StatView:
    def __init__(self, source: os.stat_result, **overrides: int) -> None:
        self._source = source
        self._overrides = overrides

    def __getattr__(self, name: str) -> Any:
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._source, name)


NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)
REPO = "acme/widget"
REPO_ID = 123456
HEAD = "a" * 40
BASE = "b" * 40
TREE = "c" * 40
PARENT = "d" * 40
MERGE = "e" * 40
MERGE_TREE = "f" * 40
ADVANCE = "1" * 40
POTENTIAL_MERGE = "9" * 40


def _response(
    status: int,
    value: Any,
    *,
    remaining: int = 5000,
    rate_header: bool = True,
) -> ReleaseHTTPResponse:
    headers = (
        {"x-ratelimit-remaining": str(remaining)}
        if rate_header
        else {}
    )
    return ReleaseHTTPResponse(
        status=status,
        headers=headers,
        body=json.dumps(value, separators=(",", ":")).encode("utf-8"),
    )


class QueueTransport:
    def __init__(self, responses: list[ReleaseHTTPResponse]) -> None:
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
    ) -> ReleaseHTTPResponse:
        self.calls.append(
            {
                "method": method,
                "path": path,
                "headers": dict(headers),
                "body": body,
                "timeout_seconds": timeout_seconds,
            }
        )
        if not self.responses:
            raise AssertionError("unexpected HTTP request")
        return self.responses.pop(0)


class ReleaseGitHubAppContractTest(unittest.TestCase):
    def _private_key(self, root: Path) -> Path:
        path = root / "release-app.pem"
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        path.chmod(0o600)
        return path

    def _client(
        self,
        private_key: Path,
        transport: QueueTransport,
    ) -> ReleaseGitHubAppClient:
        return ReleaseGitHubAppClient(
            app_id=42,
            installation_id=77,
            app_slug="john-lomein-release",
            private_key_path=private_key,
            private_key_owner_uid=os.geteuid(),
            private_key_gid=os.getegid(),
            private_key_mode=0o600,
            repository_id=REPO_ID,
            transport=transport,
        )

    def _auth_responses(
        self,
        *,
        permissions: Mapping[str, str] = REQUIRED_PERMISSIONS,
        repositories: list[Mapping[str, Any]] | None = None,
        total_count: int = 1,
    ) -> list[ReleaseHTTPResponse]:
        return [
            _response(
                200, {"id": 42, "slug": "john-lomein-release"}
            ),
            _response(
                200,
                {
                    "id": 77,
                    "app_id": 42,
                    "permissions": REQUIRED_PERMISSIONS,
                    "suspended_at": None,
                },
            ),
            _response(
                201,
                {
                    "token": "release-installation-token",
                    "expires_at": "2026-07-16T13:00:00Z",
                    "permissions": dict(permissions),
                },
            ),
            _response(
                200,
                {
                    "total_count": total_count,
                    "repositories": (
                        repositories
                        if repositories is not None
                        else [{"id": REPO_ID}]
                    ),
                },
            ),
        ]

    def test_api_version_and_effective_permissions_are_exact(self):
        self.assertEqual(API_VERSION, "2026-03-10")
        self.assertEqual(
            REQUIRED_PERMISSIONS,
            {
                "checks": "read",
                "contents": "write",
                "issues": "read",
                "metadata": "read",
                "pull_requests": "read",
                "statuses": "read",
            },
        )
        self.assertEqual(
            TOKEN_REQUEST_PERMISSIONS, REQUIRED_PERMISSIONS
        )
        self.assertNotIn("administration", REQUIRED_PERMISSIONS)
        self.assertNotIn("actions", REQUIRED_PERMISSIONS)

    def test_release_app_jwt_is_rs256_without_external_crypto(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = self._private_key(Path(tmp))
            with mock.patch(
                "subprocess.run",
                side_effect=AssertionError("external crypto was invoked"),
            ):
                token = generate_release_app_jwt(
                    app_id=42,
                    private_key_path=private,
                    private_key_owner_uid=os.geteuid(),
                    private_key_gid=os.getegid(),
                    private_key_mode=0o600,
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
                private.read_bytes(), password=None
            )
            assert isinstance(key, rsa.RSAPrivateKey)
            key.public_key().verify(
                decode(signature_part),
                f"{header_part}.{payload_part}".encode("ascii"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )

    def test_token_is_one_repository_and_exact_release_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = self._private_key(Path(tmp))
            transport = QueueTransport(self._auth_responses())
            credential = self._client(
                private, transport
            ).authenticate_installation(now=NOW)
        self.assertEqual(credential.repository_id, REPO_ID)
        self.assertEqual(credential.permissions, REQUIRED_PERMISSIONS)
        token_call = transport.calls[2]
        self.assertEqual(
            token_call["path"],
            "/app/installations/77/access_tokens",
        )
        self.assertEqual(
            json.loads(token_call["body"]),
            {
                "repository_ids": [REPO_ID],
                "permissions": TOKEN_REQUEST_PERMISSIONS,
            },
        )
        for call in transport.calls:
            self.assertEqual(
                call["headers"]["X-GitHub-Api-Version"],
                "2026-03-10",
            )
            self.assertEqual(
                call["headers"]["User-Agent"],
                "john-lomein-release-broker/1",
            )

    def test_permission_superset_or_subset_fails_closed(self):
        cases = [
            {
                key: value
                for key, value in REQUIRED_PERMISSIONS.items()
                if key != "checks"
            },
            {**REQUIRED_PERMISSIONS, "administration": "write"},
            {**REQUIRED_PERMISSIONS, "pull_requests": "write"},
        ]
        for permissions in cases:
            with self.subTest(permissions=permissions):
                with tempfile.TemporaryDirectory() as tmp:
                    private = self._private_key(Path(tmp))
                    transport = QueueTransport(
                        self._auth_responses(permissions=permissions)
                    )
                    with self.assertRaisesRegex(
                        ReleaseGitHubAppError,
                        "exactly match",
                    ):
                        self._client(
                            private, transport
                        ).authenticate_installation(now=NOW)

    def test_more_than_one_repository_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = self._private_key(Path(tmp))
            transport = QueueTransport(
                self._auth_responses(
                    repositories=[
                        {"id": REPO_ID},
                        {"id": REPO_ID + 1},
                    ],
                    total_count=2,
                )
            )
            with self.assertRaisesRegex(
                ReleaseGitHubAppError, "not restricted"
            ):
                self._client(
                    private, transport
                ).authenticate_installation(now=NOW)

    def test_installation_credential_write_allowlist_is_one_exact_endpoint(self):
        client = ReleaseGitHubAppClient(
            app_id=42,
            installation_id=77,
            app_slug="john-lomein-release",
            private_key_path=Path("/unused"),
            private_key_owner_uid=os.geteuid(),
            private_key_gid=os.getegid(),
            private_key_mode=0o600,
            repository_id=REPO_ID,
            transport=QueueTransport([]),
        )
        rejected = [
            (
                "DELETE",
                "/repos/acme/widget/pulls/17/merge",
                None,
            ),
            (
                "POST",
                "/repos/acme/widget/issues/17/comments",
                {"body": "no"},
            ),
            (
                "PUT",
                "/repos/acme/widget/branches/main/protection",
                {},
            ),
            (
                "PUT",
                "/repos/acme/widget/pulls/17/merge",
                {"sha": HEAD, "merge_method": "merge"},
            ),
            (
                "PUT",
                "/repos/acme/widget/pulls/17/merge",
                {"sha": HEAD[:12], "merge_method": "squash"},
            ),
        ]
        for method, path, payload in rejected:
            with self.subTest(method=method, path=path, payload=payload):
                with self.assertRaises(ReleaseGitHubAppError):
                    client.installation_request_json(
                        method,
                        path,
                        token="secret",
                        payload=payload,
                    )
        with self.assertRaisesRegex(
            ReleaseGitHubAppError, "read-only"
        ):
            client.installation_request_json(
                "POST",
                "/graphql",
                token="secret",
                payload={
                    "query": (
                        "mutation Evil { deleteRepository(input:{}) { "
                        "clientMutationId } }"
                    ),
                    "variables": {},
                },
            )

    def test_direct_transport_cannot_bypass_the_release_allowlist(self):
        cleared = {key: "" for key in github_app.UNTRUSTED_NETWORK_ENV_KEYS}
        with mock.patch.dict(os.environ, cleared, clear=False):
            transport = FixedReleaseGitHubTransport()
            rejected = [
                ("POST", "/repos/acme/widget/issues/17/comments", b"{}"),
                (
                    "POST",
                    "/graphql",
                    json.dumps(
                        {
                            "query": "mutation Evil { __typename }",
                            "variables": {},
                        }
                    ).encode("utf-8"),
                ),
                (
                    "PUT",
                    "/repos/acme/widget/pulls/17/merge",
                    json.dumps(
                        {"sha": HEAD, "merge_method": "merge"}
                    ).encode("utf-8"),
                ),
            ]
            for method, path, body in rejected:
                with self.subTest(method=method, path=path):
                    with self.assertRaises(ReleaseGitHubAppError):
                        transport.request(
                            method,
                            path,
                            headers={},
                            body=body,
                            timeout_seconds=1,
                        )

    def test_exact_squash_merge_request_is_the_only_allowed_write(self):
        transport = QueueTransport(
            [
                _response(
                    200,
                    {
                        "sha": MERGE,
                        "merged": True,
                        "message": "Pull Request successfully merged",
                    },
                )
            ]
        )
        client = ReleaseGitHubAppClient(
            app_id=42,
            installation_id=77,
            app_slug="john-lomein-release",
            private_key_path=Path("/unused"),
            private_key_owner_uid=os.geteuid(),
            private_key_gid=os.getegid(),
            private_key_mode=0o600,
            repository_id=REPO_ID,
            transport=transport,
        )
        data, _ = client.installation_request_json(
            "PUT",
            "/repos/acme/widget/pulls/17/merge",
            token="release-secret",
            payload={"sha": HEAD, "merge_method": "squash"},
        )
        self.assertTrue(data["merged"])
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(
            json.loads(transport.calls[0]["body"]),
            {"sha": HEAD, "merge_method": "squash"},
        )

    def test_redirect_is_not_followed_and_secrets_are_not_disclosed(self):
        transport = QueueTransport(
            [_response(307, {"token": "response-secret"})]
        )
        client = ReleaseGitHubAppClient(
            app_id=42,
            installation_id=77,
            app_slug="john-lomein-release",
            private_key_path=Path("/unused"),
            private_key_owner_uid=os.geteuid(),
            private_key_gid=os.getegid(),
            private_key_mode=0o600,
            repository_id=REPO_ID,
            transport=transport,
        )
        with self.assertRaisesRegex(
            ReleaseGitHubAppError, "status 307"
        ) as raised:
            client.installation_request_json(
                "GET",
                "/installation/repositories?per_page=100",
                token="installation-secret",
            )
        self.assertEqual(len(transport.calls), 1)
        self.assertNotIn("installation-secret", str(raised.exception))
        self.assertNotIn("response-secret", str(raised.exception))

    def test_missing_rate_header_fails_closed(self):
        transport = QueueTransport(
            [_response(200, {"total_count": 1}, rate_header=False)]
        )
        client = ReleaseGitHubAppClient(
            app_id=42,
            installation_id=77,
            app_slug="john-lomein-release",
            private_key_path=Path("/unused"),
            private_key_owner_uid=os.geteuid(),
            private_key_gid=os.getegid(),
            private_key_mode=0o600,
            repository_id=REPO_ID,
            transport=transport,
        )
        with self.assertRaisesRegex(
            ReleaseGitHubAppError, "rate-limit header"
        ):
            client.installation_request_json(
                "GET",
                "/installation/repositories?per_page=100",
                token="secret",
            )

    def test_network_and_tls_environment_overrides_fail_closed(self):
        for key in ("SSL_CERT_FILE", "HTTPS_PROXY", "http_proxy"):
            with self.subTest(key=key):
                with mock.patch.dict(
                    os.environ, {key: "/tmp/model-controlled"}, clear=True
                ):
                    with self.assertRaisesRegex(
                        ReleaseGitHubAppError,
                        "environment overrides",
                    ):
                        FixedReleaseGitHubTransport()

    def test_direct_private_key_mode_is_explicitly_0600(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = self._private_key(Path(tmp))
            private.chmod(0o640)
            with self.assertRaisesRegex(
                ReleaseGitHubAppError, "exactly 0600"
            ):
                generate_release_app_jwt(
                    app_id=42,
                    private_key_path=private,
                    private_key_owner_uid=os.geteuid(),
                    private_key_gid=os.getegid(),
                    private_key_mode=0o600,
                    now=NOW,
                )

    def test_configured_private_key_requires_root_gid_0640_stable_snapshot(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            private = self._private_key(Path(tmp))
            private.chmod(0o640)
            expected_gid = 4242
            real_fstat = os.fstat
            real_lstat = os.lstat

            def trusted(info: os.stat_result, **overrides: int) -> StatView:
                values = {
                    "st_uid": 0,
                    "st_gid": expected_gid,
                    "st_mode": stat.S_IFMT(info.st_mode) | 0o640,
                }
                values.update(overrides)
                return StatView(info, **values)

            def trusted_lstat(path: os.PathLike[str] | str) -> Any:
                info = real_lstat(path)
                if Path(path) == private:
                    return trusted(info)
                return info

            with (
                mock.patch.object(
                    github_app.os,
                    "fstat",
                    side_effect=lambda fd: trusted(real_fstat(fd)),
                ),
                mock.patch.object(
                    github_app.os, "lstat", side_effect=trusted_lstat
                ),
            ):
                self.assertEqual(
                    github_app.read_private_key_snapshot(
                        private,
                        expected_owner_uid=0,
                        expected_gid=expected_gid,
                        expected_mode=0o640,
                    ),
                    private.read_bytes(),
                )

            cases = [
                ("owner", {"st_uid": 1}, "owner is untrusted"),
                ("group", {"st_gid": expected_gid + 1}, "group is untrusted"),
                (
                    "mode",
                    {"st_mode": stat.S_IFMT(real_lstat(private).st_mode) | 0o600},
                    "exactly 0640",
                ),
            ]
            for label, overrides, message in cases:
                with self.subTest(label=label):
                    with mock.patch.object(
                        github_app.os,
                        "fstat",
                        side_effect=lambda fd, values=overrides: trusted(
                            real_fstat(fd), **values
                        ),
                    ):
                        with self.assertRaisesRegex(
                            ReleaseGitHubAppError, message
                        ):
                            github_app.read_private_key_snapshot(
                                private,
                                expected_owner_uid=0,
                                expected_gid=expected_gid,
                                expected_mode=0o640,
                            )

            hardlink = private.with_name("release-app-hardlink.pem")
            os.link(private, hardlink)
            try:
                with mock.patch.object(
                    github_app.os,
                    "fstat",
                    side_effect=lambda fd: trusted(real_fstat(fd)),
                ):
                    with self.assertRaisesRegex(
                        ReleaseGitHubAppError, "hard links"
                    ):
                        github_app.read_private_key_snapshot(
                            private,
                            expected_owner_uid=0,
                            expected_gid=expected_gid,
                            expected_mode=0o640,
                        )
            finally:
                hardlink.unlink()

            def swapped_lstat(path: os.PathLike[str] | str) -> Any:
                info = real_lstat(path)
                if Path(path) == private:
                    return trusted(info, st_ino=info.st_ino + 1)
                return info

            with (
                mock.patch.object(
                    github_app.os,
                    "fstat",
                    side_effect=lambda fd: trusted(real_fstat(fd)),
                ),
                mock.patch.object(
                    github_app.os, "lstat", side_effect=swapped_lstat
                ),
            ):
                with self.assertRaisesRegex(
                    ReleaseGitHubAppError, "changed while being read"
                ):
                    github_app.read_private_key_snapshot(
                        private,
                        expected_owner_uid=0,
                        expected_gid=expected_gid,
                        expected_mode=0o640,
                    )


def _rate(remaining: int = 5000) -> dict[str, Any]:
    return {
        "rateLimit": {
            "remaining": remaining,
            "resetAt": "2026-07-16T13:00:00Z",
        }
    }


def _page(
    total: int,
    nodes: list[dict[str, Any]],
    *,
    next_cursor: str | None,
) -> dict[str, Any]:
    return {
        "totalCount": total,
        "nodes": nodes,
        "pageInfo": {
            "hasNextPage": next_cursor is not None,
            "endCursor": next_cursor,
        },
    }


class FakeReleaseApp:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, Any]]] = []
        self.installation_calls: list[dict[str, Any]] = []
        self.rate_remaining = 5000
        self.omit_rate_header = False
        self.identity_calls = 0
        self.branch_calls = 0
        self.change_head_on_final = False
        self.change_branch_on_final = False
        self.change_repository_policy_on_final = False
        self.change_auto_merge_on_final = False
        self.change_merge_queue_on_final = False
        self.change_merged_by_on_final = False
        self.change_potential_tree_on_final = False
        self.truncate_files = False
        self.truncate_statuses = False
        self.repeat_issue_cursor = False
        self.truncate_thread_comments = False
        self.truncate_reviews = False
        self.malformed_repository_policy = False
        self.malformed_check_app = False
        self.malformed_auto_merge = False
        self.malformed_merge_queue = False
        self.malformed_merged_by = False
        self.malformed_potential_tree = False
        self.missing_potential_merge = False
        self.wrong_potential_parents = False
        self.truncated_potential_parents = False
        self.auto_merge_requested = False
        self.merge_queue_entry_present = False
        self.merged = False
        self.branch_oid = BASE
        self.branch_parent = PARENT
        self.branch_tree = TREE

    def _headers(self) -> Mapping[str, str]:
        return (
            {}
            if self.omit_rate_header
            else {"x-ratelimit-remaining": str(self.rate_remaining)}
        )

    def _identity(self) -> dict[str, Any]:
        self.identity_calls += 1
        head = (
            ADVANCE
            if self.change_head_on_final and self.identity_calls > 1
            else HEAD
        )
        policy_changed = (
            self.change_repository_policy_on_final
            and self.identity_calls > 1
        )
        archived: Any = policy_changed
        if self.malformed_repository_policy:
            archived = "false"
        merged_by: Any = (
            {"login": "john-lomein-release[bot]"}
            if self.merged
            else None
        )
        if (
            self.change_merged_by_on_final
            and self.identity_calls > 1
        ):
            merged_by = {"login": "unexpected-actor"}
        if self.malformed_merged_by:
            merged_by = {}
        auto_merge: Any = (
            {"mergeMethod": "SQUASH"}
            if self.auto_merge_requested
            else None
        )
        if (
            self.change_auto_merge_on_final
            and self.identity_calls > 1
        ):
            auto_merge = (
                None
                if self.auto_merge_requested
                else {"mergeMethod": "SQUASH"}
            )
        if self.malformed_auto_merge:
            auto_merge = {}
        merge_queue: Any = (
            {"id": "MQE_1", "state": "AWAITING_CHECKS"}
            if self.merge_queue_entry_present
            else None
        )
        if (
            self.change_merge_queue_on_final
            and self.identity_calls > 1
        ):
            merge_queue = (
                None
                if self.merge_queue_entry_present
                else {"id": "MQE_1", "state": "AWAITING_CHECKS"}
            )
        if self.malformed_merge_queue:
            merge_queue = {}
        potential_tree: Any = {"oid": MERGE_TREE}
        if (
            self.change_potential_tree_on_final
            and self.identity_calls > 1
        ):
            potential_tree = {"oid": TREE}
        if self.malformed_potential_tree:
            potential_tree = {}
        potential_parent_nodes = [
            {"oid": BASE},
            {"oid": head},
        ]
        if self.wrong_potential_parents:
            potential_parent_nodes.reverse()
        potential_parent_total = 2
        if self.truncated_potential_parents:
            potential_parent_nodes = potential_parent_nodes[:1]
        potential_merge: Any = {
            "oid": POTENTIAL_MERGE,
            "tree": potential_tree,
            "parents": _page(
                potential_parent_total,
                potential_parent_nodes,
                next_cursor=None,
            ),
        }
        if self.missing_potential_merge:
            potential_merge = None
        return {
            "repository": {
                "id": "R_repo",
                "databaseId": REPO_ID,
                "nameWithOwner": REPO,
                "isArchived": archived,
                "isDisabled": False,
                "squashMergeAllowed": True,
                "pullRequest": {
                    "id": "PR_node",
                    "number": 17,
                    "url": "https://github.com/acme/widget/pull/17",
                    "state": "MERGED" if self.merged else "OPEN",
                    "isDraft": False,
                    "merged": self.merged,
                    "mergedAt": (
                        "2026-07-16T12:05:00Z"
                        if self.merged
                        else None
                    ),
                    "headRefOid": head,
                    "baseRefName": "main",
                    "baseRefOid": BASE,
                    "changedFiles": 2,
                    "mergeable": (
                        "UNKNOWN" if self.merged else "MERGEABLE"
                    ),
                    "mergeStateStatus": (
                        "UNKNOWN" if self.merged else "CLEAN"
                    ),
                    "reviewDecision": "APPROVED",
                    "author": {"login": "john-lomein[bot]"},
                    "mergeCommit": (
                        {"oid": MERGE} if self.merged else None
                    ),
                    "potentialMergeCommit": potential_merge,
                    "mergedBy": merged_by,
                    "autoMergeRequest": auto_merge,
                    "mergeQueueEntry": merge_queue,
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
            **_rate(self.rate_remaining),
        }

    def graphql(
        self,
        *,
        token: str,
        query: str,
        variables: Mapping[str, Any],
    ) -> tuple[dict[str, Any], Mapping[str, str]]:
        self.calls.append((query, dict(variables)))
        if "ReleaseBrokerPrIdentity" in query:
            return self._identity(), self._headers()
        if "ReleaseBrokerDefaultBranch" in query:
            self.branch_calls += 1
            oid = (
                ADVANCE
                if self.change_branch_on_final and self.branch_calls > 1
                else self.branch_oid
            )
            policy_changed = (
                self.change_repository_policy_on_final
                and self.branch_calls > 1
            )
            archived: Any = policy_changed
            if self.malformed_repository_policy:
                archived = "false"
            return (
                {
                    "repository": {
                        "id": "R_repo",
                        "databaseId": REPO_ID,
                        "nameWithOwner": REPO,
                        "isArchived": archived,
                        "isDisabled": False,
                        "squashMergeAllowed": True,
                        "defaultBranchRef": {
                            "name": "main",
                            "prefix": "refs/heads/",
                            "target": {"oid": oid},
                        },
                    },
                    **_rate(self.rate_remaining),
                },
                self._headers(),
            )
        if "ReleaseBrokerCommit" in query:
            oid = str(variables["oid"])
            if oid == ADVANCE:
                parent = self.branch_oid
                tree = "2" * 40
            else:
                parent = self.branch_parent
                tree = self.branch_tree
            return (
                {
                    "repository": {
                        "object": {
                            "oid": oid,
                            "committedDate": "2026-07-16T12:00:00Z",
                            "tree": {"oid": tree},
                            "author": {
                                "name": "John Lomein",
                                "email": "author.invalid",
                                "date": "2026-07-16T12:00:00Z",
                                "user": {
                                    "login": "john-lomein-release[bot]"
                                },
                            },
                            "committer": {
                                "name": "GitHub",
                                "email": "committer.invalid",
                                "date": "2026-07-16T12:00:00Z",
                                "user": {"login": "web-flow"},
                            },
                            "parents": _page(
                                1,
                                [{"oid": parent}],
                                next_cursor=None,
                            ),
                        }
                    },
                    **_rate(self.rate_remaining),
                },
                self._headers(),
            )
        if "ReleaseBrokerPrFiles" in query:
            if variables.get("cursor") is None:
                page = _page(
                    2,
                    [
                        {
                            "path": "src/a.py",
                            "additions": 3,
                            "deletions": 1,
                            "changeType": "MODIFIED",
                        }
                    ],
                    next_cursor="files-2",
                )
            else:
                page = _page(
                    2,
                    []
                    if self.truncate_files
                    else [
                        {
                            "path": "tests/test_a.py",
                            "additions": 5,
                            "deletions": 0,
                            "changeType": "ADDED",
                        }
                    ],
                    next_cursor=None,
                )
            return (
                {
                    "repository": {
                        "pullRequest": {"files": page}
                    },
                    **_rate(self.rate_remaining),
                },
                self._headers(),
            )
        if "ReleaseBrokerChecksAndStatuses" in query:
            if variables.get("cursor") is None:
                page = _page(
                    2,
                    [
                        {
                            "__typename": "CheckRun",
                            "name": "tests",
                            "status": "COMPLETED",
                            "conclusion": "SUCCESS",
                            "detailsUrl": "https://example.invalid/check",
                            "app": {
                                "databaseId": (
                                    None
                                    if self.malformed_check_app
                                    else 15368
                                ),
                                "slug": "github-actions",
                            },
                        }
                    ],
                    next_cursor="statuses-2",
                )
            else:
                page = _page(
                    2,
                    []
                    if self.truncate_statuses
                    else [
                        {
                            "__typename": "StatusContext",
                            "context": "security",
                            "state": "SUCCESS",
                            "targetUrl": None,
                            "creator": {"login": "security-bot"},
                        }
                    ],
                    next_cursor=None,
                )
            return (
                {
                    "repository": {
                        "object": {
                            "oid": HEAD,
                            "statusCheckRollup": {"contexts": page},
                        }
                    },
                    **_rate(self.rate_remaining),
                },
                self._headers(),
            )
        if "ReleaseBrokerReviewThreads" in query:
            if variables.get("cursor") is None:
                page = _page(
                    2,
                    [
                        {
                            "id": "THREAD_1",
                            "isResolved": False,
                            "isOutdated": False,
                            "comments": _page(
                                2,
                                [
                                    {
                                        "id": "RC_1",
                                        "databaseId": 501,
                                        "url": (
                                            "https://github.com/acme/widget/"
                                            "pull/17#discussion_r501"
                                        ),
                                        "body": f"Verified {HEAD}",
                                        "createdAt": (
                                            "2026-07-16T11:00:00Z"
                                        ),
                                        "author": {
                                            "login": "review-bot"
                                        },
                                        "commit": {"oid": HEAD},
                                        "originalCommit": {"oid": HEAD},
                                    }
                                ],
                                next_cursor="thread-comments-2",
                            ),
                        }
                    ],
                    next_cursor="threads-2",
                )
            else:
                page = _page(
                    2,
                    [
                        {
                            "id": "THREAD_2",
                            "isResolved": False,
                            "isOutdated": True,
                            "comments": _page(
                                0, [], next_cursor=None
                            ),
                        }
                    ],
                    next_cursor=None,
                )
            return (
                {
                    "repository": {
                        "pullRequest": {"reviewThreads": page}
                    },
                    **_rate(self.rate_remaining),
                },
                self._headers(),
            )
        if "ReleaseBrokerThreadComments" in query:
            page = _page(
                2,
                []
                if self.truncate_thread_comments
                else [
                    {
                        "id": "RC_2",
                        "databaseId": 502,
                        "url": (
                            "https://github.com/acme/widget/"
                            "pull/17#discussion_r502"
                        ),
                        "body": "follow-up",
                        "createdAt": "2026-07-16T11:01:00Z",
                        "author": {"login": "review-bot"},
                        "commit": {"oid": HEAD},
                        "originalCommit": {"oid": HEAD},
                    }
                ],
                next_cursor=None,
            )
            return (
                {
                    "node": {"id": "THREAD_1", "comments": page},
                    **_rate(self.rate_remaining),
                },
                self._headers(),
            )
        if "ReleaseBrokerIssueComments" in query:
            if variables.get("cursor") is None:
                page = _page(
                    2,
                    [
                        {
                            "id": "IC_1",
                            "databaseId": 601,
                            "url": (
                                "https://github.com/acme/widget/"
                                "pull/17#issuecomment-601"
                            ),
                            "body": f"Reviewed commit {HEAD}",
                            "createdAt": "2026-07-16T11:02:00Z",
                            "updatedAt": "2026-07-16T11:02:00Z",
                            "author": {"login": "codex-review[bot]"},
                        }
                    ],
                    next_cursor="issue-comments-2",
                )
            else:
                page = _page(
                    2,
                    [
                        {
                            "id": "IC_2",
                            "databaseId": 602,
                            "url": (
                                "https://github.com/acme/widget/"
                                "pull/17#issuecomment-602"
                            ),
                            "body": f"Abbreviation {HEAD[:12]} only",
                            "createdAt": "2026-07-16T11:03:00Z",
                            "updatedAt": "2026-07-16T11:03:00Z",
                            "author": {"login": "codex-review[bot]"},
                        }
                    ],
                    next_cursor=(
                        "issue-comments-2"
                        if self.repeat_issue_cursor
                        else None
                    ),
                )
            return (
                {
                    "repository": {
                        "pullRequest": {"comments": page}
                    },
                    **_rate(self.rate_remaining),
                },
                self._headers(),
            )
        if "ReleaseBrokerReviews" in query:
            if variables.get("cursor") is None:
                page = _page(
                    2,
                    [
                        {
                            "id": "REV_1",
                            "databaseId": 701,
                            "url": (
                                "https://github.com/acme/widget/"
                                "pull/17#pullrequestreview-701"
                            ),
                            "body": "clean",
                            "state": "APPROVED",
                            "submittedAt": "2026-07-16T11:04:00Z",
                            "author": {"login": "codex-review[bot]"},
                            "commit": {"oid": HEAD},
                        }
                    ],
                    next_cursor="reviews-2",
                )
            else:
                page = _page(
                    2,
                    []
                    if self.truncate_reviews
                    else [
                        {
                            "id": "REV_2",
                            "databaseId": 702,
                            "url": (
                                "https://github.com/acme/widget/"
                                "pull/17#pullrequestreview-702"
                            ),
                            "body": "older",
                            "state": "COMMENTED",
                            "submittedAt": "2026-07-16T10:00:00Z",
                            "author": {"login": "human"},
                            "commit": {"oid": BASE},
                        }
                    ],
                    next_cursor=None,
                )
            return (
                {
                    "repository": {
                        "pullRequest": {"reviews": page}
                    },
                    **_rate(self.rate_remaining),
                },
                self._headers(),
            )
        raise AssertionError("unexpected GraphQL query")

    def installation_request_json(
        self,
        method: str,
        path: str,
        *,
        token: str,
        payload: Any | None = None,
        expected_statuses: frozenset[int] = frozenset({200}),
    ) -> tuple[Any, Mapping[str, str]]:
        self.installation_calls.append(
            {
                "method": method,
                "path": path,
                "token": token,
                "payload": payload,
                "expected_statuses": expected_statuses,
            }
        )
        return (
            {
                "sha": MERGE,
                "merged": True,
                "message": "Pull Request successfully merged",
            },
            self._headers(),
        )


def _credential() -> ReleaseInstallationCredential:
    return ReleaseInstallationCredential(
        token="release-token",
        expires_at=datetime(
            2026, 7, 16, 13, 0, tzinfo=timezone.utc
        ),
        repository_id=REPO_ID,
        installation_id=77,
        app_slug="john-lomein-release",
        permissions=REQUIRED_PERMISSIONS,
    )


class ReleaseGitHubLiveContractTest(unittest.TestCase):
    def _client(
        self, app: FakeReleaseApp
    ) -> ReleaseGitHubLiveClient:
        return ReleaseGitHubLiveClient(
            app=app,  # type: ignore[arg-type]
            credential=_credential(),
            repository=REPO,
            repository_id=REPO_ID,
            default_branch="main",
            minimum_rate_limit_remaining=100,
            maximum_changed_files=100,
        )

    def test_snapshot_fully_paginates_every_evidence_surface(self):
        app = FakeReleaseApp()
        snapshot = self._client(app).fetch_merge_snapshot(pr_number=17)
        self.assertEqual(len(snapshot.files), 2)
        self.assertEqual(len(snapshot.checks), 1)
        self.assertEqual(
            snapshot.checks[0]["producer_app_id"], 15368
        )
        self.assertEqual(
            snapshot.checks[0]["producer_slug"], "github-actions"
        )
        self.assertEqual(len(snapshot.statuses), 1)
        self.assertEqual(len(snapshot.review_threads), 2)
        self.assertEqual(
            len(snapshot.review_threads[0]["comments"]), 2
        )
        self.assertEqual(len(snapshot.issue_comments), 2)
        self.assertEqual(len(snapshot.reviews), 2)
        self.assertEqual(snapshot.unresolved_thread_count, 2)
        self.assertEqual(snapshot.unresolved_current_thread_count, 1)
        self.assertEqual(snapshot.default_branch.commit.oid, BASE)
        self.assertEqual(
            snapshot.default_branch.commit.parent_oids, (PARENT,)
        )
        self.assertEqual(snapshot.default_branch.commit.tree_oid, TREE)
        self.assertEqual(
            snapshot.repository_policy,
            {
                "is_archived": False,
                "is_disabled": False,
                "squash_merge_allowed": True,
            },
        )
        self.assertFalse(snapshot.pr["auto_merge_requested"])
        self.assertFalse(snapshot.pr["merge_queue_entry_present"])
        self.assertIsNone(snapshot.pr["merged_by_login"])
        self.assertEqual(
            snapshot.pr["potential_merge_commit_oid"],
            POTENTIAL_MERGE,
        )
        self.assertEqual(
            snapshot.pr["potential_merge_tree_oid"], MERGE_TREE
        )
        self.assertEqual(
            snapshot.pr["potential_merge_parent_oids"],
            [BASE, HEAD],
        )
        identity_queries = [
            query
            for query, _variables in app.calls
            if "ReleaseBrokerPrIdentity" in query
        ]
        self.assertTrue(identity_queries)
        self.assertIn(
            "potentialMergeCommit", identity_queries[0]
        )
        self.assertIn("parents(first: 2)", identity_queries[0])
        kinds = {item["kind"] for item in snapshot.exact_head_evidence}
        self.assertEqual(
            kinds,
            {
                "issue_comment",
                "pull_request_review",
                "review_thread_comment",
            },
        )
        cursors = [
            variables.get("cursor")
            for _query, variables in app.calls
        ]
        for expected in (
            "files-2",
            "statuses-2",
            "threads-2",
            "thread-comments-2",
            "issue-comments-2",
            "reviews-2",
        ):
            self.assertIn(expected, cursors)

    def test_exact_oid_evidence_never_accepts_an_abbreviation(self):
        self.assertTrue(contains_exact_full_oid(f"commit {HEAD}", HEAD))
        self.assertFalse(
            contains_exact_full_oid(f"commit {HEAD[:12]}", HEAD)
        )
        self.assertFalse(
            contains_exact_full_oid(f"x{HEAD}f", HEAD)
        )
        with self.assertRaisesRegex(
            ReleaseGitHubLiveError, "exact full"
        ):
            contains_exact_full_oid(HEAD, HEAD[:12])

    def test_each_truncated_connection_fails_closed(self):
        cases = [
            ("truncate_files", "file pagination was truncated"),
            (
                "truncate_statuses",
                "status context pagination was truncated",
            ),
            (
                "truncate_thread_comments",
                "comment pagination was truncated",
            ),
            ("truncate_reviews", "review pagination was truncated"),
        ]
        for flag, message in cases:
            with self.subTest(flag=flag):
                app = FakeReleaseApp()
                setattr(app, flag, True)
                with self.assertRaisesRegex(
                    ReleaseGitHubLiveError, message
                ):
                    self._client(app).fetch_merge_snapshot(pr_number=17)

    def test_repeated_comment_cursor_fails_closed(self):
        app = FakeReleaseApp()
        app.repeat_issue_cursor = True
        with self.assertRaisesRegex(
            ReleaseGitHubLiveError, "cursor repeated"
        ):
            self._client(app).fetch_merge_snapshot(pr_number=17)

    def test_head_or_default_branch_race_fails_closed(self):
        cases = [
            ("change_head_on_final", "pull request identity changed"),
            ("change_branch_on_final", "default branch changed"),
            (
                "change_potential_tree_on_final",
                "pull request identity changed",
            ),
        ]
        for flag, message in cases:
            with self.subTest(flag=flag):
                app = FakeReleaseApp()
                setattr(app, flag, True)
                with self.assertRaisesRegex(
                    ReleaseGitHubLiveError, message
                ):
                    self._client(app).fetch_merge_snapshot(pr_number=17)

    def test_repository_policy_race_fails_closed(self):
        app = FakeReleaseApp()
        app.change_repository_policy_on_final = True
        with self.assertRaisesRegex(
            ReleaseGitHubLiveError, "repository policy changed"
        ):
            self._client(app).fetch_merge_snapshot(pr_number=17)

    def test_repository_pr_and_check_identity_fields_are_strict(self):
        cases = [
            (
                "malformed_repository_policy",
                "repository archived state",
            ),
            ("malformed_check_app", "producer App database id"),
            ("malformed_auto_merge", "auto-merge method"),
            ("malformed_merge_queue", "merge-queue entry id"),
            ("malformed_merged_by", "merged-by login"),
            (
                "malformed_potential_tree",
                "potential merge-tree OID",
            ),
        ]
        for flag, message in cases:
            with self.subTest(flag=flag):
                app = FakeReleaseApp()
                setattr(app, flag, True)
                with self.assertRaisesRegex(
                    ReleaseGitHubLiveError, message
                ):
                    self._client(app).fetch_merge_snapshot(pr_number=17)

    def test_open_pr_requires_exact_potential_merge_topology(self):
        cases = [
            (
                "missing_potential_merge",
                "potential merge commit is missing",
            ),
            (
                "wrong_potential_parents",
                "exact base and head",
            ),
            (
                "truncated_potential_parents",
                "exactly two parents",
            ),
        ]
        for flag, message in cases:
            with self.subTest(flag=flag):
                app = FakeReleaseApp()
                setattr(app, flag, True)
                with self.assertRaisesRegex(
                    ReleaseGitHubLiveError, message
                ):
                    self._client(app).fetch_merge_snapshot(pr_number=17)

    def test_auto_merge_and_merge_queue_presence_are_race_stable(self):
        app = FakeReleaseApp()
        app.auto_merge_requested = True
        app.merge_queue_entry_present = True
        snapshot = self._client(app).fetch_merge_snapshot(pr_number=17)
        self.assertTrue(snapshot.pr["auto_merge_requested"])
        self.assertEqual(snapshot.pr["auto_merge_method"], "SQUASH")
        self.assertTrue(snapshot.pr["merge_queue_entry_present"])
        self.assertEqual(snapshot.pr["merge_queue_entry_id"], "MQE_1")
        self.assertEqual(
            snapshot.pr["merge_queue_entry_state"],
            "AWAITING_CHECKS",
        )

    def test_pr_execution_mode_and_merge_actor_races_fail_closed(self):
        cases = [
            "change_auto_merge_on_final",
            "change_merge_queue_on_final",
            "change_merged_by_on_final",
        ]
        for flag in cases:
            with self.subTest(flag=flag):
                app = FakeReleaseApp()
                if flag == "change_merged_by_on_final":
                    app.merged = True
                    app.branch_oid = MERGE
                    app.branch_parent = BASE
                    app.branch_tree = MERGE_TREE
                setattr(app, flag, True)
                with self.assertRaisesRegex(
                    ReleaseGitHubLiveError,
                    "pull request identity changed",
                ):
                    self._client(app).fetch_merge_snapshot(pr_number=17)

    def test_rate_floor_and_missing_header_fail_closed(self):
        app = FakeReleaseApp()
        app.rate_remaining = 99
        with self.assertRaisesRegex(
            ReleaseGitHubLiveError, "rate-limit floor"
        ):
            self._client(app).fetch_merge_snapshot(pr_number=17)
        app = FakeReleaseApp()
        app.omit_rate_header = True
        with self.assertRaisesRegex(
            ReleaseGitHubLiveError, "rate-limit header"
        ):
            self._client(app).fetch_merge_snapshot(pr_number=17)

    def test_merge_helper_sends_only_exact_head_squash_request(self):
        app = FakeReleaseApp()
        result = self._client(app).merge_pull_request(
            pr_number=17,
            expected_head_oid=HEAD,
        )
        self.assertTrue(result.merged)
        self.assertEqual(result.merge_commit_oid, MERGE)
        self.assertEqual(
            app.installation_calls,
            [
                {
                    "method": "PUT",
                    "path": "/repos/acme/widget/pulls/17/merge",
                    "token": "release-token",
                    "payload": {
                        "sha": HEAD,
                        "merge_method": "squash",
                    },
                    "expected_statuses": frozenset({200}),
                }
            ],
        )
        with self.assertRaisesRegex(
            ReleaseGitHubLiveError, "exact full"
        ):
            self._client(FakeReleaseApp()).merge_pull_request(
                pr_number=17,
                expected_head_oid=HEAD[:12],
            )

    def test_readback_proves_exact_parent_tree_and_actors(self):
        app = FakeReleaseApp()
        app.merged = True
        app.branch_oid = MERGE
        app.branch_parent = BASE
        app.branch_tree = MERGE_TREE
        client = self._client(app)
        readback = client.fetch_merge_readback(pr_number=17)
        client.validate_merge_readback(
            readback,
            expected_head_oid=HEAD,
            expected_previous_default_oid=BASE,
            expected_merge_oid=MERGE,
            expected_merged_by_login="john-lomein-release[bot]",
            expected_tree_oid=MERGE_TREE,
            allowed_author_logins={"john-lomein-release[bot]"},
            allowed_committer_logins={"web-flow"},
        )

    def test_readback_rejects_wrong_topology_tree_or_actor(self):
        app = FakeReleaseApp()
        app.merged = True
        app.branch_oid = MERGE
        app.branch_parent = BASE
        app.branch_tree = MERGE_TREE
        client = self._client(app)
        readback = client.fetch_merge_readback(pr_number=17)
        cases = [
            {
                "expected_previous_default_oid": PARENT,
                "expected_merged_by_login": (
                    "john-lomein-release[bot]"
                ),
                "expected_tree_oid": MERGE_TREE,
            },
            {
                "expected_previous_default_oid": BASE,
                "expected_merged_by_login": (
                    "john-lomein-release[bot]"
                ),
                "expected_tree_oid": TREE,
            },
            {
                "expected_previous_default_oid": BASE,
                "expected_merged_by_login": (
                    "john-lomein-release[bot]"
                ),
                "expected_tree_oid": MERGE_TREE,
                "allowed_author_logins": {"attacker"},
            },
            {
                "expected_previous_default_oid": BASE,
                "expected_merged_by_login": (
                    "john-lomein-release[bot]"
                ),
                "expected_tree_oid": MERGE_TREE,
                "allowed_committer_logins": {"attacker"},
            },
            {
                "expected_previous_default_oid": BASE,
                "expected_merged_by_login": "attacker",
                "expected_tree_oid": MERGE_TREE,
            },
        ]
        for extra in cases:
            with self.subTest(extra=extra):
                with self.assertRaises(ReleaseGitHubLiveError):
                    client.validate_merge_readback(
                        readback,
                        expected_head_oid=HEAD,
                        expected_merge_oid=MERGE,
                        **extra,
                    )

    def test_release_boundary_does_not_import_routine_broker(self):
        for name in (
            "john_lomein_release_broker_github_app.py",
            "john_lomein_release_broker_github_live.py",
        ):
            source = (ROOT / "release_broker" / name).read_text(
                encoding="utf-8"
            )
            self.assertNotIn("from broker", source)
            self.assertNotIn("import broker", source)


if __name__ == "__main__":
    unittest.main()
