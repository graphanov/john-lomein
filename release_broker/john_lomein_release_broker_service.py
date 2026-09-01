#!/usr/bin/env python3
"""End-to-end lifecycle for the isolated protected release broker.

This service is deliberately separate from the routine protected-action
broker.  It accepts one owner-signed, exact-head, squash-only release packet,
charges durable authority before the sole GitHub mutation, fences the default
branch immediately before that mutation, and emits an append-chained signed
receipt after read-back.

There is no automatic rollback and no blind mutation retry.  A charged attempt
is retried only after a read-only reconciliation proves that the prior attempt
was absent and the exact same packet is replayed while still fresh.
"""

from __future__ import annotations

import os
import re
import secrets
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .john_lomein_release_broker_actions import (
    ReleaseActionError,
    ReleasePreflight,
    validate_immediate_base_fence,
    validate_preflight,
)
from .john_lomein_release_broker_github_app import (
    ReleaseGitHubAppClient,
    ReleaseGitHubAppError,
)
from .john_lomein_release_broker_github_live import (
    ReleaseDefaultBranchState,
    ReleaseGitHubLiveClient,
    ReleaseGitHubLiveError,
    ReleaseMergeReadback,
)
from .john_lomein_release_broker_protocol import (
    ReleaseBrokerProtocolError,
    config_digest,
    normalize_config,
    normalize_configured_submission,
    sha256_json,
    validate_requester_uid,
)
from .john_lomein_release_broker_receipts import (
    ZERO_DIGEST,
    ReleaseBrokerReceiptError,
    build_configured_receipt_payload,
    sign_configured_receipt,
    verify_configured_receipt,
)
from .john_lomein_release_broker_store import (
    ActiveBundleError,
    BudgetExceeded,
    BudgetLimits,
    BundleConflictError,
    CircuitOpenError,
    NonceReplayError,
    PacketConflictError,
    PendingRecovery,
    PendingRecoveryError,
    ReleaseBrokerStore,
    ReleaseBrokerStoreError,
    SemanticTerminalReplayError,
    StateTransitionError,
    StoreBindingError,
)


UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
REASON_COMPONENT_RE = re.compile(r"[^a-z0-9_]+")
MAX_RECEIPT_CHAIN_CAS_ATTEMPTS = 3


class ReleaseBrokerServiceError(RuntimeError):
    """The service could not safely produce a terminal signed outcome."""


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime(
        UTC_FORMAT
    )


def _parse_utc(value: str) -> datetime:
    try:
        return datetime.strptime(value, UTC_FORMAT).replace(
            tzinfo=timezone.utc
        )
    except (TypeError, ValueError) as exc:
        raise ReleaseBrokerServiceError(
            "persisted release timestamp is invalid"
        ) from exc


def _reason(prefix: str, value: str) -> str:
    component = REASON_COMPONENT_RE.sub(
        "_", str(value).lower()
    ).strip("_")
    maximum = max(1, 127 - len(prefix) - 1)
    return f"{prefix}_{(component or 'unspecified')[:maximum]}"


def _as_mapping(value: Any) -> Mapping[str, Any]:
    if hasattr(value, "as_dict") and callable(value.as_dict):
        value = value.as_dict()
    if not isinstance(value, Mapping):
        raise ReleaseBrokerServiceError(
            "release live result is not an object"
        )
    return value


def _branch_mapping(value: Any) -> Mapping[str, Any]:
    return _as_mapping(value)


def _readback_mapping(value: Any) -> Mapping[str, Any]:
    return _as_mapping(value)


class ProtectedReleaseBrokerService:
    """Credential-bearing orchestrator for one exact release merge."""

    def __init__(
        self,
        config: Mapping[str, Any],
        *,
        store: ReleaseBrokerStore | None = None,
        live_factory: Callable[[datetime], Any] | None = None,
        signer: Callable[
            [Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]],
            Mapping[str, Any],
        ]
        | None = None,
        verifier: Callable[
            [
                Mapping[str, Any],
                Mapping[str, Any],
                Mapping[str, Any],
                datetime,
            ],
            Mapping[str, Any],
        ]
        | None = None,
        clock: Callable[[], datetime] | None = None,
        trusted_key_root: Path | None = None,
    ) -> None:
        self.config = normalize_config(config)
        if self.config["enabled"] is not True:
            raise ReleaseBrokerServiceError(
                "protected release broker is disabled"
            )
        if (
            os.getuid() != self.config["broker_uid"]
            or (
                hasattr(os, "geteuid")
                and os.geteuid() != self.config["broker_uid"]
            )
        ):
            raise ReleaseBrokerServiceError(
                "release service OS identity does not match config"
            )
        private_gid = self.config.get("broker_private_gid")
        if private_gid is not None and (
            os.getgid() != private_gid
            or (
                hasattr(os, "getegid")
                and os.getegid() != private_gid
            )
        ):
            raise ReleaseBrokerServiceError(
                "release service private-key group does not match config"
            )
        self._owns_store = store is None
        self.store = store or ReleaseBrokerStore(
            self.config["state"]["database_path"]
        )
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._live_factory = live_factory or self._build_live_client
        self._signer = signer or self._sign
        self._verifier = verifier or self._verify
        self._trusted_key_root = trusted_key_root
        repository = self.config["instance"]["repository"]
        binding = {
            "schema_version": (
                "john-lomein.release-broker-runtime-binding.v1"
            ),
            "broker_id": self.config["broker_id"],
            "broker_uid": self.config["broker_uid"],
            "broker_private_gid": self.config["broker_private_gid"],
            "config_sha256": config_digest(self.config),
            "instance_slug": self.config["instance"]["slug"],
            "repository_id": repository["id"],
            "repository_full_name": repository["full_name"],
            "default_branch": repository["default_branch"],
            "github_app_id": self.config["github_app"]["app_id"],
            "github_installation_id": self.config["github_app"][
                "installation_id"
            ],
        }
        try:
            self.store.bind_runtime(binding, now=self._now())
        except ReleaseBrokerStoreError as exc:
            if self._owns_store:
                self.store.close()
            raise ReleaseBrokerServiceError(
                "release broker state is not bound to the active config"
            ) from exc
        budgets = self.config["instance"]["budgets"]
        self.limits = BudgetLimits(
            unique_requests_per_hour=budgets[
                "unique_requests_per_hour"
            ],
            owner_assertions_per_hour=budgets[
                "owner_assertions_per_hour"
            ],
            bundles_per_day=budgets["bundles_per_day"],
            mutation_attempts_per_day=budgets[
                "mutation_attempts_per_day"
            ],
            confirmed_merges_per_day=budgets[
                "confirmed_merges_per_day"
            ],
            consecutive_indeterminate_limit=budgets[
                "consecutive_indeterminate_limit"
            ],
            max_prs_per_bundle=self.config["instance"]["policy"][
                "max_prs_per_bundle"
            ],
        )

    def close(self) -> None:
        self.store.close()

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ReleaseBrokerServiceError(
                "release broker clock is invalid"
            )
        return value.astimezone(timezone.utc).replace(microsecond=0)

    @property
    def _trusted_key_owners(self) -> frozenset[int]:
        return frozenset({0, self.config["broker_uid"]})

    def _normalize_submission(
        self,
        raw: Any,
        *,
        now: datetime,
        allow_expired: bool,
    ) -> dict[str, Any]:
        return normalize_configured_submission(
            raw,
            self.config,
            now=now,
            allow_expired=allow_expired,
            allow_expired_assertion=allow_expired,
            key_owner_uids=self._trusted_key_owners,
            parent_owner_uids=self._trusted_key_owners,
            trusted_path_root=self._trusted_key_root,
        )

    def _sign(
        self,
        payload: Mapping[str, Any],
        config: Mapping[str, Any],
        packet: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return sign_configured_receipt(
            payload,
            config,
            key_owner_uids=self._trusted_key_owners,
            parent_owner_uids=self._trusted_key_owners,
            trusted_path_root=self._trusted_key_root,
            packet=packet,
        )

    def _verify(
        self,
        receipt: Mapping[str, Any],
        config: Mapping[str, Any],
        packet: Mapping[str, Any],
        now: datetime,
    ) -> Mapping[str, Any]:
        return verify_configured_receipt(
            receipt,
            config,
            public_key_owner_uids=self._trusted_key_owners,
            parent_owner_uids=self._trusted_key_owners,
            trusted_path_root=self._trusted_key_root,
            packet=packet,
            now=now,
        )

    def _build_live_client(self, now: datetime) -> ReleaseGitHubLiveClient:
        github = self.config["github_app"]
        repository = self.config["instance"]["repository"]
        policy = self.config["instance"]["policy"]
        app = ReleaseGitHubAppClient(
            app_id=github["app_id"],
            installation_id=github["installation_id"],
            app_slug=github["app_slug"],
            private_key_path=Path(github["private_key_path"]),
            private_key_owner_uid=0,
            private_key_gid=self.config["broker_private_gid"],
            private_key_mode=0o640,
            repository_id=repository["id"],
            timeout_seconds=self.config["transport"][
                "request_timeout_seconds"
            ],
        )
        credential = app.authenticate_installation(now=now)
        return ReleaseGitHubLiveClient(
            app=app,
            credential=credential,
            repository=repository["full_name"],
            repository_id=repository["id"],
            default_branch=repository["default_branch"],
            minimum_rate_limit_remaining=policy[
                "minimum_rate_limit_remaining"
            ],
            maximum_changed_files=policy[
                "maximum_changed_files_per_pr"
            ],
        )

    def _execution_expired(self, started: datetime) -> bool:
        maximum = self.config["instance"]["policy"][
            "maximum_execution_seconds"
        ]
        return (self._now() - started).total_seconds() > maximum

    @staticmethod
    def _default_final_branch(
        config: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "name": config["instance"]["repository"]["default_branch"],
            "head_sha": None,
            "tree_sha": None,
            "observed_at": None,
        }

    @staticmethod
    def _final_branch_from_readback(
        readback: Any,
        *,
        observed_at: datetime | str,
    ) -> dict[str, Any]:
        mapped = _readback_mapping(readback)
        branch = _as_mapping(mapped.get("default_branch"))
        commit = _as_mapping(branch.get("commit"))
        return {
            "name": branch.get("name"),
            "head_sha": commit.get("oid"),
            "tree_sha": commit.get("tree_oid"),
            "observed_at": observed_at,
        }

    @staticmethod
    def _packet_expired(packet: Mapping[str, Any], now: datetime) -> bool:
        return now >= _parse_utc(str(packet["expires_at"]))

    def _assert_exact_receipt(
        self,
        receipt: Mapping[str, Any],
        packet: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        verified = self._verifier(
            receipt, self.config, packet, self._now()
        )
        payload = verified.get("payload")
        binding = (
            payload.get("packet")
            if isinstance(payload, Mapping)
            else None
        )
        if (
            not isinstance(binding, Mapping)
            or binding.get("packet_id") != packet["packet_id"]
            or binding.get("request_digest")
            != packet["request_digest"]
        ):
            raise ReleaseBrokerProtocolError(
                "release receipt is bound to another packet"
            )
        return verified

    @staticmethod
    def _deterministic_precondition_digest(
        packet: Mapping[str, Any],
        reason_code: str,
        evidence: Mapping[str, Any] | None = None,
    ) -> str:
        return sha256_json(
            {
                "schema_version": (
                    "john-lomein.release-rejection-evidence.v1"
                ),
                "packet_id": packet["packet_id"],
                "request_digest": packet["request_digest"],
                "reason_code": reason_code,
                "evidence": dict(evidence or {}),
            }
        )

    def _build_rejected_step(
        self,
        packet: Mapping[str, Any],
        *,
        precondition_digest: str,
        reason_code: str,
        started_at: datetime | str,
        completed_at: datetime | str,
    ) -> dict[str, Any]:
        bundle = packet["request"]["bundle"]
        pr = bundle["ordered_prs"][0]
        return {
            "position": 0,
            "pr_number": pr["number"],
            "authorized_head_sha": pr["head_sha"],
            "expected_base_sha": bundle["initial_base_sha"],
            "precondition_digest": precondition_digest,
            "attempt_id": None,
            "outcome": "rejected",
            "reason_code": reason_code,
            "merge_sha": None,
            "parent_sha": None,
            "tree_sha": None,
            "merged_by": None,
            "started_at": started_at,
            "attempted_at": None,
            "completed_at": completed_at,
        }

    def _build_indeterminate_step(
        self,
        packet: Mapping[str, Any],
        *,
        attempt_id: str,
        precondition_digest: str,
        reason_code: str,
        started_at: datetime | str,
        attempted_at: datetime | str,
        completed_at: datetime | str,
        merge_sha: str | None = None,
        parent_sha: str | None = None,
        tree_sha: str | None = None,
        merged_by: str | None = None,
    ) -> dict[str, Any]:
        bundle = packet["request"]["bundle"]
        pr = bundle["ordered_prs"][0]
        evidence = (merge_sha, parent_sha, tree_sha, merged_by)
        if any(item is None for item in evidence):
            merge_sha = parent_sha = tree_sha = merged_by = None
        if parent_sha is not None and parent_sha != bundle["initial_base_sha"]:
            merge_sha = parent_sha = tree_sha = merged_by = None
        return {
            "position": 0,
            "pr_number": pr["number"],
            "authorized_head_sha": pr["head_sha"],
            "expected_base_sha": bundle["initial_base_sha"],
            "precondition_digest": precondition_digest,
            "attempt_id": attempt_id,
            "outcome": "indeterminate",
            "reason_code": reason_code,
            "merge_sha": merge_sha,
            "parent_sha": parent_sha,
            "tree_sha": tree_sha,
            "merged_by": merged_by,
            "started_at": started_at,
            "attempted_at": attempted_at,
            "completed_at": completed_at,
        }

    def _build_merged_step(
        self,
        packet: Mapping[str, Any],
        *,
        attempt_id: str,
        precondition_digest: str,
        started_at: datetime | str,
        attempted_at: datetime | str,
        completed_at: datetime | str,
        merge_sha: str,
        parent_sha: str,
        tree_sha: str,
        merged_by: str,
    ) -> dict[str, Any]:
        bundle = packet["request"]["bundle"]
        pr = bundle["ordered_prs"][0]
        return {
            "position": 0,
            "pr_number": pr["number"],
            "authorized_head_sha": pr["head_sha"],
            "expected_base_sha": bundle["initial_base_sha"],
            "precondition_digest": precondition_digest,
            "attempt_id": attempt_id,
            "outcome": "merged",
            "reason_code": "merge_confirmed",
            "merge_sha": merge_sha,
            "parent_sha": parent_sha,
            "tree_sha": tree_sha,
            "merged_by": merged_by,
            "started_at": started_at,
            "attempted_at": attempted_at,
            "completed_at": completed_at,
        }

    def _terminalize(
        self,
        *,
        bundle_key: str,
        packet: Mapping[str, Any],
        outcome: str,
        reason_code: str,
        steps: list[Mapping[str, Any]],
        final_branch: Mapping[str, Any],
        started_at: datetime | str,
        completed_at: datetime | str,
        circuit_mode: str = "none",
        circuit_reason: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        last_error: Exception | None = None
        for _ in range(MAX_RECEIPT_CHAIN_CAS_ATTEMPTS):
            previous_receipt = self.store.latest_receipt_digest()
            previous_chain = self.store.latest_receipt_chain_digest()
            payload = build_configured_receipt_payload(
                self.config,
                packet,
                steps=steps,
                final_branch=final_branch,
                outcome=outcome,
                reason_code=reason_code,
                started_at=started_at,
                completed_at=completed_at,
                previous_receipt_sha256=previous_receipt or ZERO_DIGEST,
            )
            signed = self._signer(payload, self.config, packet)
            try:
                terminal = self.store.terminalize_bundle(
                    bundle_key,
                    packet["packet_id"],
                    outcome,  # type: ignore[arg-type]
                    signed,
                    self.limits,
                    circuit_mode=circuit_mode,  # type: ignore[arg-type]
                    circuit_reason=circuit_reason,
                    expected_previous_chain_digest=previous_chain,
                    now=(
                        completed_at
                        if isinstance(completed_at, datetime)
                        else _parse_utc(completed_at)
                    ),
                )
                return self._assert_exact_receipt(
                    terminal.receipt, packet
                )
            except StateTransitionError as exc:
                last_error = exc
                if "receipt-chain head changed" not in str(exc):
                    raise
        raise ReleaseBrokerServiceError(
            "release receipt-chain head changed repeatedly"
        ) from last_error

    def _stop_and_reject(
        self,
        *,
        bundle_key: str,
        packet: Mapping[str, Any],
        started_at: datetime,
        reason_code: str,
        precondition_digest: str,
        detail: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        completed = self._now()
        terminal_detail = {
            "schema_version": "john-lomein.release-stop-detail.v1",
            "reason_code": reason_code,
            "precondition_digest": precondition_digest,
            "started_at": utc_text(started_at),
            "completed_at": utc_text(completed),
            "evidence": dict(detail or {}),
        }
        self.store.stop_step(
            bundle_key,
            0,
            packet["packet_id"],
            "rejected",
            terminal_detail,
            now=completed,
        )
        step = self._build_rejected_step(
            packet,
            precondition_digest=precondition_digest,
            reason_code=reason_code,
            started_at=started_at,
            completed_at=completed,
        )
        return self._terminalize(
            bundle_key=bundle_key,
            packet=packet,
            outcome="rejected",
            reason_code=reason_code,
            steps=[step],
            final_branch=self._default_final_branch(self.config),
            started_at=started_at,
            completed_at=completed,
        )

    def _record_known_absent(
        self,
        *,
        bundle_key: str,
        packet: Mapping[str, Any],
        attempt_id: str,
        evidence: Mapping[str, Any],
    ) -> None:
        self.store.record_recovery(
            bundle_key,
            0,
            packet["packet_id"],
            attempt_id,
            "jlrr-" + secrets.token_hex(16),
            "absent",
            evidence,
            self.limits,
            now=self._now(),
        )

    def _record_and_terminalize_indeterminate(
        self,
        *,
        bundle_key: str,
        packet: Mapping[str, Any],
        attempt_id: str,
        precondition_digest: str,
        attempt_started_at: datetime | str,
        reason_code: str,
        evidence: Mapping[str, Any],
        circuit_mode: str,
        merge_sha: str | None = None,
        parent_sha: str | None = None,
        tree_sha: str | None = None,
        merged_by: str | None = None,
        final_branch: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        completed = self._now()
        recovery_evidence = {
            "schema_version": (
                "john-lomein.release-recovery-evidence.v1"
            ),
            "reason_code": reason_code,
            **dict(evidence),
        }
        self.store.record_recovery(
            bundle_key,
            0,
            packet["packet_id"],
            attempt_id,
            "jlrr-" + secrets.token_hex(16),
            "indeterminate",
            recovery_evidence,
            self.limits,
            circuit_mode=circuit_mode,  # type: ignore[arg-type]
            now=completed,
        )
        step = self._build_indeterminate_step(
            packet,
            attempt_id=attempt_id,
            precondition_digest=precondition_digest,
            reason_code=reason_code,
            started_at=attempt_started_at,
            attempted_at=attempt_started_at,
            completed_at=completed,
            merge_sha=merge_sha,
            parent_sha=parent_sha,
            tree_sha=tree_sha,
            merged_by=merged_by,
        )
        return self._terminalize(
            bundle_key=bundle_key,
            packet=packet,
            outcome="indeterminate",
            reason_code=reason_code,
            steps=[step],
            final_branch=(
                final_branch
                if final_branch is not None
                else self._default_final_branch(self.config)
            ),
            started_at=(
                attempt_started_at
                if isinstance(attempt_started_at, datetime)
                else _parse_utc(attempt_started_at)
            ),
            completed_at=completed,
            circuit_mode=circuit_mode,
            circuit_reason=recovery_evidence,
        )

    def _validate_readback(
        self,
        live: Any,
        readback: Any,
        *,
        expected_head: str,
        expected_base: str,
        expected_merge: str,
        expected_tree: str,
    ) -> tuple[str, str, str, str]:
        mapped = _readback_mapping(readback)
        branch = _as_mapping(mapped.get("default_branch"))
        commit = _as_mapping(branch.get("commit"))
        tree = commit.get("tree_oid")
        if not isinstance(tree, str):
            raise ReleaseGitHubLiveError(
                "merge readback tree identity is missing"
            )
        merge_actor = self.config["instance"]["policy"][
            "expected_merge_actor_login"
        ]
        live.validate_merge_readback(
            readback,
            expected_head_oid=expected_head,
            expected_previous_default_oid=expected_base,
            expected_merge_oid=expected_merge,
            expected_merged_by_login=merge_actor,
            expected_tree_oid=expected_tree,
        )
        return expected_merge, expected_base, tree, merge_actor

    def _readback_is_exactly_absent(
        self,
        readback: Any,
        recovery: PendingRecovery,
    ) -> bool:
        mapped = _readback_mapping(readback)
        pr = _as_mapping(mapped.get("pr"))
        branch = _as_mapping(mapped.get("default_branch"))
        commit = _as_mapping(branch.get("commit"))
        repository = self.config["instance"]["repository"]
        return (
            mapped.get("repository") == recovery.repository_full_name
            and mapped.get("repository_id") == recovery.repository_id
            and pr.get("number") == recovery.pr_number
            and pr.get("head_oid") == recovery.head_sha
            and pr.get("state") == "OPEN"
            and pr.get("merged") is False
            and pr.get("merge_commit_oid") is None
            and branch.get("name") == repository["default_branch"]
            and branch.get("qualified_name")
            == f"refs/heads/{repository['default_branch']}"
            and commit.get("oid") == recovery.expected_base_sha
        )

    def _terminalize_confirmed(
        self,
        *,
        bundle_key: str,
        packet: Mapping[str, Any],
        attempt_id: str,
        precondition_digest: str,
        attempt_started_at: datetime | str,
        merge_sha: str,
        parent_sha: str,
        tree_sha: str,
        merged_by: str,
        observed_at: datetime,
    ) -> Mapping[str, Any]:
        step = self._build_merged_step(
            packet,
            attempt_id=attempt_id,
            precondition_digest=precondition_digest,
            started_at=attempt_started_at,
            attempted_at=attempt_started_at,
            completed_at=observed_at,
            merge_sha=merge_sha,
            parent_sha=parent_sha,
            tree_sha=tree_sha,
            merged_by=merged_by,
        )
        return self._terminalize(
            bundle_key=bundle_key,
            packet=packet,
            outcome="succeeded",
            reason_code="release_merged",
            steps=[step],
            final_branch={
                "name": self.config["instance"]["repository"][
                    "default_branch"
                ],
                "head_sha": merge_sha,
                "tree_sha": tree_sha,
                "observed_at": observed_at,
            },
            started_at=(
                attempt_started_at
                if isinstance(attempt_started_at, datetime)
                else _parse_utc(attempt_started_at)
            ),
            completed_at=observed_at,
        )

    def _recover_one(
        self,
        recovery: PendingRecovery,
        *,
        retry_packet_id: str | None,
    ) -> None:
        packet = self.store.load_packet(recovery.packet_id)
        expected_tree = packet["request"]["bundle"]["ordered_prs"][
            recovery.position
        ]["expected_merge_tree_sha"]
        now = self._now()
        try:
            live = self._live_factory(now)
            readback = live.fetch_merge_readback(
                pr_number=recovery.pr_number
            )
        except (
            ReleaseGitHubAppError,
            ReleaseGitHubLiveError,
            ReleaseActionError,
        ) as exc:
            self._record_and_terminalize_indeterminate(
                bundle_key=recovery.bundle_key,
                packet=packet,
                attempt_id=recovery.attempt_id,
                precondition_digest=recovery.precondition_digest,
                attempt_started_at=recovery.started_at,
                reason_code="indeterminate_recovery_unavailable",
                evidence={"error_class": type(exc).__name__},
                circuit_mode="threshold",
            )
            return

        mapped = _readback_mapping(readback)
        pr = _as_mapping(mapped.get("pr"))
        merge_oid = pr.get("merge_commit_oid")
        if pr.get("state") == "MERGED" or pr.get("merged") is True:
            try:
                if not isinstance(merge_oid, str):
                    raise ReleaseGitHubLiveError(
                        "recovery merge identity is missing"
                    )
                merge_sha, parent_sha, tree_sha, merged_by = (
                    self._validate_readback(
                        live,
                        readback,
                        expected_head=recovery.head_sha,
                        expected_base=recovery.expected_base_sha,
                        expected_merge=merge_oid,
                        expected_tree=expected_tree,
                    )
                )
            except ReleaseGitHubLiveError as exc:
                branch = _as_mapping(mapped.get("default_branch"))
                commit = _as_mapping(branch.get("commit"))
                self._record_and_terminalize_indeterminate(
                    bundle_key=recovery.bundle_key,
                    packet=packet,
                    attempt_id=recovery.attempt_id,
                    precondition_digest=recovery.precondition_digest,
                    attempt_started_at=recovery.started_at,
                    reason_code=(
                        "indeterminate_recovery_readback_mismatch"
                    ),
                    evidence={
                        "error_class": type(exc).__name__,
                        "readback": dict(mapped),
                    },
                    circuit_mode="immediate",
                    merge_sha=(
                        merge_oid if isinstance(merge_oid, str) else None
                    ),
                    parent_sha=(
                        commit.get("parent_oids", [None])[0]
                        if isinstance(commit.get("parent_oids"), list)
                        and len(commit.get("parent_oids")) == 1
                        else None
                    ),
                    tree_sha=(
                        commit.get("tree_oid")
                        if isinstance(commit.get("tree_oid"), str)
                        else None
                    ),
                    merged_by=(
                        pr.get("merged_by_login")
                        if isinstance(pr.get("merged_by_login"), str)
                        else None
                    ),
                )
                return
            self.store.record_recovery(
                recovery.bundle_key,
                recovery.position,
                recovery.packet_id,
                recovery.attempt_id,
                "jlrr-" + secrets.token_hex(16),
                "confirmed",
                {
                    "schema_version": (
                        "john-lomein.release-recovery-evidence.v1"
                    ),
                    "reason_code": "recovery_merge_confirmed",
                    "readback": dict(mapped),
                },
                self.limits,
                merge_sha=merge_sha,
                parent_sha=parent_sha,
                tree_sha=tree_sha,
                merged_by=merged_by,
                now=now,
            )
            self._terminalize_confirmed(
                bundle_key=recovery.bundle_key,
                packet=packet,
                attempt_id=recovery.attempt_id,
                precondition_digest=recovery.precondition_digest,
                attempt_started_at=recovery.started_at,
                merge_sha=merge_sha,
                parent_sha=parent_sha,
                tree_sha=tree_sha,
                merged_by=merged_by,
                observed_at=now,
            )
            return

        if self._readback_is_exactly_absent(readback, recovery):
            if retry_packet_id != recovery.packet_id:
                return
            self.store.record_recovery(
                recovery.bundle_key,
                recovery.position,
                recovery.packet_id,
                recovery.attempt_id,
                "jlrr-" + secrets.token_hex(16),
                "absent",
                {
                    "schema_version": (
                        "john-lomein.release-recovery-evidence.v1"
                    ),
                    "reason_code": "recovery_merge_absent",
                    "readback": dict(mapped),
                },
                self.limits,
                now=now,
            )
            return

        self._record_and_terminalize_indeterminate(
            bundle_key=recovery.bundle_key,
            packet=packet,
            attempt_id=recovery.attempt_id,
            precondition_digest=recovery.precondition_digest,
            attempt_started_at=recovery.started_at,
            reason_code="indeterminate_recovery_state_mismatch",
            evidence={"readback": dict(mapped)},
            circuit_mode="immediate",
        )

    def _snapshot_terminal_receipt(
        self,
        bundle_key: str,
    ) -> Mapping[str, Any] | None:
        snapshot = self.store.bundle_snapshot(bundle_key)
        steps = snapshot["steps"]
        if len(steps) != 1:
            raise ReleaseBrokerServiceError(
                "live release snapshot does not contain exactly one step"
            )
        step_state = steps[0]["state"]
        if step_state in {"pending", "mutation_pending"}:
            return None
        packet_id = snapshot["last_packet_id"]
        packet = self.store.load_packet(packet_id)
        latest_attempt = steps[0].get("latest_attempt")
        terminal_detail = steps[0].get("terminal_detail") or {}
        now = self._now()
        if step_state == "confirmed":
            if not isinstance(latest_attempt, Mapping):
                raise ReleaseBrokerServiceError(
                    "confirmed release step lacks attempt evidence"
                )
            return self._terminalize_confirmed(
                bundle_key=bundle_key,
                packet=packet,
                attempt_id=str(latest_attempt["attempt_id"]),
                precondition_digest=str(
                    latest_attempt["precondition_digest"]
                ),
                attempt_started_at=str(latest_attempt["started_at"]),
                merge_sha=str(latest_attempt["merge_sha"]),
                parent_sha=str(latest_attempt["parent_sha"]),
                tree_sha=str(latest_attempt["tree_sha"]),
                merged_by=str(latest_attempt["merged_by"]),
                observed_at=(
                    _parse_utc(str(latest_attempt["terminal_at"]))
                    if latest_attempt.get("terminal_at")
                    else now
                ),
            )
        if step_state == "rejected":
            reason_code = str(
                terminal_detail.get("reason_code")
                or "precondition_rejected"
            )
            precondition_digest = str(
                terminal_detail.get("precondition_digest")
                or self._deterministic_precondition_digest(
                    packet, reason_code
                )
            )
            started = (
                _parse_utc(str(terminal_detail["started_at"]))
                if terminal_detail.get("started_at")
                else _parse_utc(packet["created_at"])
            )
            completed = (
                _parse_utc(str(terminal_detail["completed_at"]))
                if terminal_detail.get("completed_at")
                else now
            )
            step = self._build_rejected_step(
                packet,
                precondition_digest=precondition_digest,
                reason_code=reason_code,
                started_at=started,
                completed_at=completed,
            )
            return self._terminalize(
                bundle_key=bundle_key,
                packet=packet,
                outcome="rejected",
                reason_code=reason_code,
                steps=[step],
                final_branch=self._default_final_branch(self.config),
                started_at=started,
                completed_at=completed,
            )
        if step_state == "indeterminate":
            if not isinstance(latest_attempt, Mapping):
                raise ReleaseBrokerServiceError(
                    "indeterminate release step lacks attempt evidence"
                )
            detail = latest_attempt.get("terminal_detail")
            detail = detail if isinstance(detail, Mapping) else {}
            reason_code = str(
                detail.get("reason_code")
                or "indeterminate_recovered_state"
            )
            completed = (
                _parse_utc(str(latest_attempt["terminal_at"]))
                if latest_attempt.get("terminal_at")
                else now
            )
            indeterminate_step = self._build_indeterminate_step(
                packet,
                attempt_id=str(latest_attempt["attempt_id"]),
                precondition_digest=str(
                    latest_attempt["precondition_digest"]
                ),
                reason_code=reason_code,
                started_at=str(latest_attempt["started_at"]),
                attempted_at=str(latest_attempt["started_at"]),
                completed_at=completed,
                merge_sha=latest_attempt.get("merge_sha"),
                parent_sha=latest_attempt.get("parent_sha"),
                tree_sha=latest_attempt.get("tree_sha"),
                merged_by=latest_attempt.get("merged_by"),
            )
            return self._terminalize(
                bundle_key=bundle_key,
                packet=packet,
                outcome="indeterminate",
                reason_code=reason_code,
                steps=[indeterminate_step],
                final_branch=self._default_final_branch(self.config),
                started_at=_parse_utc(str(latest_attempt["started_at"])),
                completed_at=completed,
                circuit_mode="threshold",
                circuit_reason=dict(detail),
            )
        raise ReleaseBrokerServiceError(
            "release step has an unsupported durable state"
        )

    def recover_pending(
        self,
        *,
        retry_packet_id: str | None = None,
    ) -> None:
        """Read back charged attempts; only an exact replay unlocks absence."""

        for recovery in self.store.pending_recovery():
            self._recover_one(
                recovery, retry_packet_id=retry_packet_id
            )
        for bundle_key in self.store.bundles_awaiting_terminal_receipt():
            self._snapshot_terminal_receipt(bundle_key)

    def _handle_reserved(
        self,
        *,
        packet: Mapping[str, Any],
        bundle_key: str,
        started: datetime,
    ) -> Mapping[str, Any]:
        if self._packet_expired(packet, started):
            reason = "request_packet_expired_before_retry"
            digest = self._deterministic_precondition_digest(
                packet, reason
            )
            return self._stop_and_reject(
                bundle_key=bundle_key,
                packet=packet,
                started_at=started,
                reason_code=reason,
                precondition_digest=digest,
            )

        bundle = packet["request"]["bundle"]
        pr = bundle["ordered_prs"][0]
        try:
            live = self._live_factory(started)
            snapshot = live.fetch_merge_snapshot(
                pr_number=pr["number"]
            )
            preflight = validate_preflight(
                snapshot,
                bundle,
                self.config["instance"]["policy"],
            )
        except ReleaseActionError as exc:
            reason = _reason("precondition", exc.code)
            digest = self._deterministic_precondition_digest(
                packet, reason, {"action_code": exc.code}
            )
            return self._stop_and_reject(
                bundle_key=bundle_key,
                packet=packet,
                started_at=started,
                reason_code=reason,
                precondition_digest=digest,
            )
        except (ReleaseGitHubAppError, ReleaseGitHubLiveError) as exc:
            reason = "precondition_live_state_unavailable"
            digest = self._deterministic_precondition_digest(
                packet, reason, {"error_class": type(exc).__name__}
            )
            return self._stop_and_reject(
                bundle_key=bundle_key,
                packet=packet,
                started_at=started,
                reason_code=reason,
                precondition_digest=digest,
            )

        attempt_id = "jlra-" + secrets.token_hex(16)
        mutation_started = self._now()
        try:
            mutation = self.store.begin_mutation(
                bundle_key,
                0,
                packet["packet_id"],
                attempt_id,
                self.limits,
                expected_base_sha=preflight.expected_base_sha,
                precondition_digest=preflight.precondition_digest,
                now=mutation_started,
            )
        except BudgetExceeded as exc:
            return self._stop_and_reject(
                bundle_key=bundle_key,
                packet=packet,
                started_at=started,
                reason_code=_reason("budget", exc.budget),
                precondition_digest=preflight.precondition_digest,
            )
        except CircuitOpenError:
            return self._stop_and_reject(
                bundle_key=bundle_key,
                packet=packet,
                started_at=started,
                reason_code="circuit_release_open",
                precondition_digest=preflight.precondition_digest,
            )
        if mutation.disposition == "terminal_replay":
            if mutation.receipt is None:
                raise ReleaseBrokerServiceError(
                    "terminal release replay has no receipt"
                )
            return self._assert_exact_receipt(
                mutation.receipt, packet
            )
        if mutation.disposition == "step_confirmed":
            recovered = self._snapshot_terminal_receipt(bundle_key)
            if recovered is None:
                raise ReleaseBrokerServiceError(
                    "confirmed release step lacks terminal receipt"
                )
            return recovered
        if mutation.attempt_id is None:
            raise ReleaseBrokerServiceError(
                "charged release attempt identity is missing"
            )
        attempt_id = mutation.attempt_id
        attempt_started = mutation.charged_at or utc_text(mutation_started)

        try:
            if self._execution_expired(started):
                raise ReleaseActionError(
                    "execution_window_expired",
                    "release execution window expired before merge",
                )
            immediate_branch = live.fetch_default_branch_state()
            validate_immediate_base_fence(
                immediate_branch,
                expected_branch=bundle["repository"]["default_branch"],
                expected_base_sha=preflight.expected_base_sha,
            )
        except (ReleaseActionError, ReleaseGitHubLiveError) as exc:
            self._record_known_absent(
                bundle_key=bundle_key,
                packet=packet,
                attempt_id=attempt_id,
                evidence={
                    "schema_version": (
                        "john-lomein.release-known-absent-evidence.v1"
                    ),
                    "reason_code": "immediate_base_fence_failed",
                    "error_class": type(exc).__name__,
                    "put_sent": False,
                },
            )
            return self._stop_and_reject(
                bundle_key=bundle_key,
                packet=packet,
                started_at=started,
                reason_code="precondition_immediate_base_fence_failed",
                precondition_digest=preflight.precondition_digest,
            )

        try:
            mutation_result = live.merge_pull_request(
                pr_number=preflight.pr_number,
                expected_head_oid=preflight.head_sha,
            )
        except (ReleaseGitHubAppError, ReleaseGitHubLiveError) as exc:
            return self._record_and_terminalize_indeterminate(
                bundle_key=bundle_key,
                packet=packet,
                attempt_id=attempt_id,
                precondition_digest=preflight.precondition_digest,
                attempt_started_at=attempt_started,
                reason_code="indeterminate_merge_transport",
                evidence={"error_class": type(exc).__name__},
                circuit_mode="threshold",
            )

        merge_result = _as_mapping(mutation_result)
        merge_oid = merge_result.get("merge_commit_oid")
        if not isinstance(merge_oid, str):
            return self._record_and_terminalize_indeterminate(
                bundle_key=bundle_key,
                packet=packet,
                attempt_id=attempt_id,
                precondition_digest=preflight.precondition_digest,
                attempt_started_at=attempt_started,
                reason_code="indeterminate_merge_response",
                evidence={"mutation_result": dict(merge_result)},
                circuit_mode="threshold",
            )

        try:
            readback = live.fetch_merge_readback(
                pr_number=preflight.pr_number
            )
        except (ReleaseGitHubAppError, ReleaseGitHubLiveError) as exc:
            return self._record_and_terminalize_indeterminate(
                bundle_key=bundle_key,
                packet=packet,
                attempt_id=attempt_id,
                precondition_digest=preflight.precondition_digest,
                attempt_started_at=attempt_started,
                reason_code="indeterminate_merge_readback_unavailable",
                evidence={
                    "error_class": type(exc).__name__,
                    "merge_commit_oid": merge_oid,
                },
                circuit_mode="threshold",
            )

        mapped = _readback_mapping(readback)
        try:
            merge_sha, parent_sha, tree_sha, merged_by = (
                self._validate_readback(
                    live,
                    readback,
                    expected_head=preflight.head_sha,
                    expected_base=preflight.expected_base_sha,
                    expected_merge=merge_oid,
                    expected_tree=preflight.expected_merge_tree_sha,
                )
            )
        except ReleaseGitHubLiveError as exc:
            branch = _as_mapping(mapped.get("default_branch"))
            commit = _as_mapping(branch.get("commit"))
            pr_readback = _as_mapping(mapped.get("pr"))
            return self._record_and_terminalize_indeterminate(
                bundle_key=bundle_key,
                packet=packet,
                attempt_id=attempt_id,
                precondition_digest=preflight.precondition_digest,
                attempt_started_at=attempt_started,
                reason_code="indeterminate_merge_readback_mismatch",
                evidence={
                    "error_class": type(exc).__name__,
                    "readback": dict(mapped),
                },
                circuit_mode="immediate",
                merge_sha=merge_oid,
                parent_sha=(
                    commit.get("parent_oids", [None])[0]
                    if isinstance(commit.get("parent_oids"), list)
                    and len(commit.get("parent_oids")) == 1
                    else None
                ),
                tree_sha=(
                    commit.get("tree_oid")
                    if isinstance(commit.get("tree_oid"), str)
                    else None
                ),
                merged_by=(
                    pr_readback.get("merged_by_login")
                    if isinstance(
                        pr_readback.get("merged_by_login"), str
                    )
                    else None
                ),
                final_branch=self._final_branch_from_readback(
                    readback, observed_at=self._now()
                ),
            )

        completed = self._now()
        self.store.confirm_step(
            bundle_key,
            0,
            packet["packet_id"],
            attempt_id,
            merge_sha=merge_sha,
            parent_sha=parent_sha,
            tree_sha=tree_sha,
            merged_by=merged_by,
            now=completed,
        )
        return self._terminalize_confirmed(
            bundle_key=bundle_key,
            packet=packet,
            attempt_id=attempt_id,
            precondition_digest=preflight.precondition_digest,
            attempt_started_at=attempt_started,
            merge_sha=merge_sha,
            parent_sha=parent_sha,
            tree_sha=tree_sha,
            merged_by=merged_by,
            observed_at=completed,
        )

    def handle(
        self,
        submission: Mapping[str, Any],
        peer: Any = None,
    ) -> Mapping[str, Any]:
        """Validate, reserve, execute once, read back, and sign the outcome."""

        started = self._now()
        if peer is not None:
            uid = getattr(peer, "uid", None)
            validate_requester_uid(self.config, uid)

        replay = self._normalize_submission(
            submission, now=started, allow_expired=True
        )
        packet = replay["packet"]
        packet_id = packet["packet_id"]
        existing = self.store.receipt_for_packet(packet_id)
        if existing is not None:
            if self.store.load_packet(packet_id) != packet:
                raise ReleaseBrokerServiceError(
                    "release receipt replay packet does not match"
                )
            return self._assert_exact_receipt(existing, packet)

        accepted = False
        try:
            accepted = self.store.load_packet(packet_id) == packet
        except StateTransitionError:
            accepted = False
        if accepted:
            self.recover_pending(retry_packet_id=packet_id)
            recovered = self.store.receipt_for_packet(packet_id)
            if recovered is not None:
                return self._assert_exact_receipt(
                    recovered, packet
                )
            reservation = self.store.reserve(
                packet, self.limits, now=started
            )
        else:
            fresh = self._normalize_submission(
                submission, now=started, allow_expired=False
            )
            packet = fresh["packet"]
            try:
                reservation = self.store.reserve(
                    packet, self.limits, now=started
                )
            except (
                ActiveBundleError,
                BudgetExceeded,
                BundleConflictError,
                CircuitOpenError,
                NonceReplayError,
                PacketConflictError,
                SemanticTerminalReplayError,
            ) as exc:
                raise ReleaseBrokerProtocolError(
                    "release reservation was rejected"
                ) from exc

        if reservation.disposition == "exact_terminal_replay":
            if (
                reservation.receipt is None
                or reservation.receipt_packet_id != packet_id
            ):
                raise ReleaseBrokerServiceError(
                    "release terminal replay is not exact"
                )
            return self._assert_exact_receipt(
                reservation.receipt, packet
            )
        if reservation.receipt is not None:
            raise ReleaseBrokerServiceError(
                "active release reservation unexpectedly has a receipt"
            )
        try:
            return self._handle_reserved(
                packet=packet,
                bundle_key=reservation.bundle_key,
                started=started,
            )
        except (
            PendingRecoveryError,
            ReleaseBrokerReceiptError,
            StoreBindingError,
        ) as exc:
            repository = self.config["instance"]["repository"]
            self.store.open_circuit(
                instance_slug=self.config["instance"]["slug"],
                repository_id=repository["id"],
                repository_full_name=repository["full_name"],
                reason={
                    "reason": "release_service_invariant_failure",
                    "error_class": type(exc).__name__,
                    "packet_id": packet_id,
                },
                now=self._now(),
            )
            raise ReleaseBrokerServiceError(
                "release service invariant failed"
            ) from exc


def build_service(
    config: Mapping[str, Any],
) -> ProtectedReleaseBrokerService:
    return ProtectedReleaseBrokerService(config)


# Concise package-local aliases.
ReleaseBrokerService = ProtectedReleaseBrokerService
