"""End-to-end protected broker request lifecycle."""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from .john_lomein_broker_actions import (
    BrokerActionError,
    EvaluatedAction,
    MutationIndeterminate,
    desired_state_observed,
    digest_json,
    evaluate_snapshot,
    execute_evaluated_action,
)
from .john_lomein_broker_protocol import (
    BrokerProtocolError,
    config_digest,
    normalize_config,
    normalize_submission,
)
from .john_lomein_broker_receipts import (
    ZERO_HASH,
    build_receipt_payload,
    sign_receipt,
)
from .john_lomein_broker_store import (
    BrokerStore,
    BrokerStoreError,
    BudgetExceeded,
    BudgetLimits,
    CircuitOpenError,
    PendingRecovery,
    PendingRecoveryError,
)
from .john_lomein_github_app import GitHubAppClient, GitHubAppError
from .john_lomein_github_live import (
    GitHubLiveClient,
    GitHubLiveError,
    LiveSnapshot,
)


UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
REASON_COMPONENT_RE = re.compile(r"[^a-z0-9_]+")


class BrokerServiceError(RuntimeError):
    """The broker could not safely produce a terminal signed outcome."""


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime(UTC_FORMAT)


def _reason(prefix: str, value: str) -> str:
    component = REASON_COMPONENT_RE.sub(
        "_", str(value).lower()
    ).strip("_")
    component = component[: max(1, 127 - len(prefix) - 1)]
    return f"{prefix}_{component or 'unspecified'}"


def _snapshot_mapping(
    snapshot: LiveSnapshot | Mapping[str, Any],
) -> Mapping[str, Any]:
    return snapshot.as_dict() if isinstance(snapshot, LiveSnapshot) else snapshot


class ProtectedBrokerService:
    def __init__(
        self,
        config: Mapping[str, Any],
        *,
        store: BrokerStore | None = None,
        live_factory: Callable[[datetime], Any] | None = None,
        signer: Callable[
            [Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]],
            Mapping[str, Any],
        ]
        | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = normalize_config(config)
        self.store = store or BrokerStore(
            self.config["state"]["database_path"]
        )
        try:
            self.store.bind_runtime(
                {
                    "schema_version": "john-lomein.broker-runtime-binding.v1",
                    "broker_id": self.config["broker_id"],
                    "broker_config_sha256": config_digest(self.config),
                }
            )
        except BrokerStoreError as exc:
            if store is None:
                self.store.close()
            raise BrokerServiceError(
                "broker state is not bound to the active config"
            ) from exc
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._live_factory = live_factory or self._build_live_client
        self._signer = signer or self._sign
        budgets = self.config["instance"]["budgets"]
        self.limits = BudgetLimits(
            requests_per_hour=budgets["requests_per_hour"],
            daily_mutations=budgets["mutation_attempts_per_day"],
            mark_pr_ready_per_day=budgets["daily_mark_pr_ready"],
            review_threads_per_day=budgets[
                "daily_resolve_review_thread"
            ],
            consecutive_indeterminate_limit=budgets[
                "consecutive_indeterminate_limit"
            ],
        )

    def close(self) -> None:
        self.store.close()

    def _now(self) -> datetime:
        value = self._clock().astimezone(timezone.utc)
        return value.replace(microsecond=0)

    def _sign(
        self,
        payload: Mapping[str, Any],
        config: Mapping[str, Any],
        submission: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return sign_receipt(payload, config, submission)

    def _build_live_client(self, now: datetime) -> GitHubLiveClient:
        github = self.config["github_app"]
        repository = self.config["instance"]["repository"]
        policy = self.config["instance"]["policy"]
        app = GitHubAppClient(
            app_id=github["app_id"],
            installation_id=github["installation_id"],
            app_slug=github["app_slug"],
            private_key_path=github["private_key_path"],
            repository_id=repository["id"],
            timeout_seconds=self.config["transport"][
                "request_timeout_seconds"
            ],
        )
        credential = app.authenticate_installation(now=now)
        return GitHubLiveClient(
            app=app,
            credential=credential,
            repository=repository["full_name"],
            repository_id=repository["id"],
            minimum_rate_limit_remaining=policy[
                "minimum_rate_limit_remaining"
            ],
            maximum_changed_files=policy["maximum_changed_files"],
        )

    def _signed_receipt(
        self,
        submission: Mapping[str, Any],
        *,
        precondition_digest: str,
        outcome: str,
        reason_code: str,
        mutation_status: str,
        readback_status: str,
        started_at: datetime | str,
        completed_at: datetime | str,
        mutation_attempted_at: datetime | str | None = None,
        operation_id: str = "",
        readback_observed_at: datetime | str | None = None,
        readback_head_sha: str | None = None,
        readback_pr_is_draft: bool | None = None,
        resolved_thread_node_ids: tuple[str, ...] = (),
    ) -> Mapping[str, Any]:
        payload = build_receipt_payload(
            self.config,
            submission,
            precondition_digest=precondition_digest,
            outcome=outcome,
            reason_code=reason_code,
            mutation_status=mutation_status,
            readback_status=readback_status,
            started_at=started_at,
            completed_at=completed_at,
            mutation_attempted_at=mutation_attempted_at,
            operation_id=operation_id,
            readback_observed_at=readback_observed_at,
            readback_head_sha=readback_head_sha,
            readback_pr_is_draft=readback_pr_is_draft,
            resolved_thread_node_ids=resolved_thread_node_ids,
            previous_receipt_sha256=(
                self.store.latest_receipt_digest() or ZERO_HASH
            ),
        )
        return self._signer(payload, self.config, submission)

    @staticmethod
    def _readback_fields(
        packet: Mapping[str, Any],
        snapshot: LiveSnapshot | Mapping[str, Any],
    ) -> tuple[str | None, bool | None, tuple[str, ...]]:
        live = _snapshot_mapping(snapshot)
        pr = live.get("pr")
        head = pr.get("head_sha") if isinstance(pr, Mapping) else None
        draft = pr.get("is_draft") if isinstance(pr, Mapping) else None
        if not isinstance(head, str):
            head = None
        if type(draft) is not bool:
            draft = None
        resolved: tuple[str, ...] = ()
        if packet["request"]["action"] == "resolve_review_thread":
            target = packet["request"]["targets"]["thread_node_ids"][0]
            threads = live.get("threads")
            if isinstance(threads, list) and any(
                isinstance(item, Mapping)
                and item.get("id") == target
                and item.get("is_resolved") is True
                for item in threads
            ):
                resolved = (target,)
        return head, draft, resolved

    def _record_rejection(
        self,
        submission: Mapping[str, Any],
        *,
        effect_key: str | None,
        started_at: datetime,
        reason_code: str,
        precondition_digest: str,
    ) -> Mapping[str, Any]:
        completed = self._now()
        receipt = self._signed_receipt(
            submission,
            precondition_digest=precondition_digest,
            outcome="rejected",
            reason_code=reason_code,
            mutation_status="not_attempted",
            readback_status="not_attempted",
            started_at=started_at,
            completed_at=completed,
        )
        packet_id = submission["packet"]["packet_id"]
        return self.store.record_packet_receipt(
            packet_id,
            "rejected",
            receipt,
            effect_key=effect_key,
            now=completed,
        ).receipt

    def _record_already_satisfied(
        self,
        submission: Mapping[str, Any],
        *,
        evaluated: EvaluatedAction,
        snapshot: LiveSnapshot | Mapping[str, Any],
        effect_key: str,
        started_at: datetime,
    ) -> Mapping[str, Any]:
        completed = self._now()
        head, draft, resolved = self._readback_fields(
            submission["packet"], snapshot
        )
        receipt = self._signed_receipt(
            submission,
            precondition_digest=evaluated.before_digest,
            outcome="succeeded",
            reason_code="already_satisfied",
            mutation_status="already_satisfied",
            readback_status="confirmed",
            started_at=started_at,
            completed_at=completed,
            readback_observed_at=completed,
            readback_head_sha=head,
            readback_pr_is_draft=draft,
            resolved_thread_node_ids=resolved,
        )
        return self.store.record_packet_receipt(
            submission["packet"]["packet_id"],
            "reconciled",
            receipt,
            effect_key=effect_key,
            now=completed,
        ).receipt

    def _record_indeterminate(
        self,
        submission: Mapping[str, Any],
        *,
        recovery: PendingRecovery | None,
        effect_key: str,
        attempt_id: str,
        precondition_digest: str,
        started_at: datetime | str,
        mutation_attempted_at: datetime | str,
        reason_code: str,
        readback: LiveSnapshot | Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        completed = self._now()
        head: str | None = None
        draft: bool | None = None
        resolved: tuple[str, ...] = ()
        if readback is not None:
            head, draft, resolved = self._readback_fields(
                submission["packet"], readback
            )
        receipt = self._signed_receipt(
            submission,
            precondition_digest=precondition_digest,
            outcome="indeterminate",
            reason_code=reason_code,
            mutation_status="indeterminate",
            readback_status="indeterminate",
            started_at=started_at,
            completed_at=completed,
            mutation_attempted_at=mutation_attempted_at,
            operation_id=attempt_id,
            readback_observed_at=completed,
            readback_head_sha=head,
            readback_pr_is_draft=draft,
            resolved_thread_node_ids=resolved,
        )
        return self.store.terminalize(
            effect_key,
            submission["packet"]["packet_id"],
            attempt_id,
            "indeterminate",
            receipt,
            self.limits,
            now=completed,
        ).receipt

    def _recover_one(
        self,
        recovery: PendingRecovery,
        *,
        retry_packet_id: str | None,
    ) -> None:
        packet = self.store.load_packet(recovery.packet_id)
        submission = {
            "schema_version": "john-lomein.protected-broker-submit.v1",
            "packet": packet,
        }
        attempted_at = recovery.attempt_started_at
        try:
            live = self._live_factory(self._now())
            snapshot = live.fetch_snapshot(
                pr_number=recovery.pr_number,
                evidence_comment_url=packet["request"]["preconditions"][
                    "evidence_comment_url"
                ],
            )
        except (GitHubAppError, GitHubLiveError, BrokerActionError):
            self._record_indeterminate(
                submission,
                recovery=recovery,
                effect_key=recovery.effect_key,
                attempt_id=recovery.attempt_key,
                precondition_digest=recovery.precondition_digest,
                started_at=attempted_at,
                mutation_attempted_at=attempted_at,
                reason_code="indeterminate_recovery_unavailable",
            )
            return

        if desired_state_observed(packet=packet, snapshot=snapshot):
            try:
                evaluated = evaluate_snapshot(
                    config=self.config,
                    packet=packet,
                    snapshot=snapshot,
                    allow_already_satisfied=True,
                )
            except BrokerActionError:
                self._record_indeterminate(
                    submission,
                    recovery=recovery,
                    effect_key=recovery.effect_key,
                    attempt_id=recovery.attempt_key,
                    precondition_digest=recovery.precondition_digest,
                    started_at=attempted_at,
                    mutation_attempted_at=attempted_at,
                    reason_code="indeterminate_recovery_state_mismatch",
                    readback=snapshot,
                )
                return
            if not evaluated.already_satisfied:
                raise BrokerServiceError(
                    "recovery desired-state evaluation is inconsistent"
                )
            completed = self._now()
            head, draft, resolved = self._readback_fields(packet, snapshot)
            receipt = self._signed_receipt(
                submission,
                precondition_digest=recovery.precondition_digest,
                outcome="succeeded",
                reason_code="reconciled_readback_verified",
                mutation_status="reconciled",
                readback_status="confirmed",
                started_at=attempted_at,
                completed_at=completed,
                mutation_attempted_at=attempted_at,
                operation_id=recovery.attempt_key,
                readback_observed_at=completed,
                readback_head_sha=head,
                readback_pr_is_draft=draft,
                resolved_thread_node_ids=resolved,
            )
            self.store.terminalize(
                recovery.effect_key,
                recovery.packet_id,
                recovery.attempt_key,
                "reconciled",
                receipt,
                self.limits,
                now=completed,
            )
            return

        try:
            evaluate_snapshot(
                config=self.config,
                packet=packet,
                snapshot=snapshot,
            )
        except BrokerActionError:
            self._record_indeterminate(
                submission,
                recovery=recovery,
                effect_key=recovery.effect_key,
                attempt_id=recovery.attempt_key,
                precondition_digest=recovery.precondition_digest,
                started_at=attempted_at,
                mutation_attempted_at=attempted_at,
                reason_code="indeterminate_recovery_head_or_state_changed",
                readback=snapshot,
            )
            return
        packet_expires = datetime.strptime(
            packet["expires_at"], UTC_FORMAT
        ).replace(tzinfo=timezone.utc)
        if self._now() >= packet_expires:
            self._record_indeterminate(
                submission,
                recovery=recovery,
                effect_key=recovery.effect_key,
                attempt_id=recovery.attempt_key,
                precondition_digest=recovery.precondition_digest,
                started_at=attempted_at,
                mutation_attempted_at=attempted_at,
                reason_code="indeterminate_packet_expired_before_retry",
                readback=snapshot,
            )
            return
        if recovery.mutation_attempts >= 2:
            self._record_indeterminate(
                submission,
                recovery=recovery,
                effect_key=recovery.effect_key,
                attempt_id=recovery.attempt_key,
                precondition_digest=recovery.precondition_digest,
                started_at=attempted_at,
                mutation_attempted_at=attempted_at,
                reason_code="indeterminate_retry_exhausted",
                readback=snapshot,
            )
            return
        if recovery.packet_id != retry_packet_id:
            return
        self.store.reconcile_absent(
            recovery.effect_key,
            recovery.packet_id,
            recovery.attempt_key,
            {
                "head_sha": recovery.head_sha,
                "desired_state_observed": False,
            },
            now=self._now(),
        )

    def recover_pending(
        self,
        *,
        retry_packet_id: str | None = None,
    ) -> None:
        for recovery in self.store.pending_recovery():
            self._recover_one(
                recovery,
                retry_packet_id=retry_packet_id,
            )

    def handle(
        self,
        submission: Mapping[str, Any],
        _peer: Any = None,
    ) -> Mapping[str, Any]:
        started = self._now()
        replay_now = started
        if isinstance(submission, Mapping):
            candidate_packet = submission.get("packet")
            if isinstance(candidate_packet, Mapping):
                created_at = candidate_packet.get("created_at")
                if isinstance(created_at, str):
                    try:
                        replay_now = datetime.strptime(
                            created_at, UTC_FORMAT
                        ).replace(tzinfo=timezone.utc)
                    except ValueError:
                        pass
        replay_normalized = normalize_submission(
            submission,
            self.config,
            now=replay_now,
        )
        replay_packet = replay_normalized["packet"]
        existing = self.store.receipt_for_packet(
            replay_packet["packet_id"]
        )
        if existing is not None:
            if self.store.load_packet(
                replay_packet["packet_id"]
            ) != replay_packet:
                raise BrokerServiceError(
                    "persisted receipt packet does not match the replay"
                )
            return existing

        self.recover_pending(
            retry_packet_id=replay_packet["packet_id"]
        )
        recovered = self.store.receipt_for_packet(
            replay_packet["packet_id"]
        )
        if recovered is not None:
            if self.store.load_packet(
                replay_packet["packet_id"]
            ) != replay_packet:
                raise BrokerServiceError(
                    "recovered receipt packet does not match the replay"
                )
            return recovered

        normalized = normalize_submission(
            submission, self.config, now=started
        )
        packet = normalized["packet"]

        thread_id = (
            packet["request"]["targets"]["thread_node_ids"][0]
            if packet["request"]["action"] == "resolve_review_thread"
            else None
        )
        try:
            reservation = self.store.reserve(
                packet,
                self.limits,
                thread_node_id=thread_id,
                now=started,
            )
        except BudgetExceeded as exc:
            raise BrokerProtocolError(
                "broker request budget is exhausted"
            ) from exc
        except CircuitOpenError as exc:
            raise BrokerProtocolError(
                "broker action circuit is open"
            ) from exc
        if reservation.disposition == "receipt_replay":
            assert reservation.receipt is not None
            return reservation.receipt
        if reservation.disposition == "indeterminate":
            return self._record_rejection(
                normalized,
                effect_key=reservation.effect_key,
                started_at=started,
                reason_code="circuit_semantic_indeterminate",
                precondition_digest=digest_json(
                    {
                        "effect_key": reservation.effect_key,
                        "state": "indeterminate",
                    }
                ),
            )

        try:
            live = self._live_factory(started)
            snapshot = live.fetch_snapshot(
                pr_number=packet["request"]["pr"]["number"],
                evidence_comment_url=packet["request"]["preconditions"][
                    "evidence_comment_url"
                ],
            )
            evaluated = evaluate_snapshot(
                config=self.config,
                packet=packet,
                snapshot=snapshot,
                allow_already_satisfied=True,
            )
        except BrokerActionError as exc:
            return self._record_rejection(
                normalized,
                effect_key=reservation.effect_key,
                started_at=started,
                reason_code=_reason("precondition", exc.reason_code),
                precondition_digest=digest_json(
                    {
                        "packet": packet["request_digest"],
                        "reason": exc.reason_code,
                    }
                ),
            )
        except (GitHubAppError, GitHubLiveError) as exc:
            return self._record_rejection(
                normalized,
                effect_key=reservation.effect_key,
                started_at=started,
                reason_code="precondition_live_state_unavailable",
                precondition_digest=digest_json(
                    {
                        "packet": packet["request_digest"],
                        "reason": type(exc).__name__,
                    }
                ),
            )

        if (
            reservation.disposition == "semantic_completed"
            and not evaluated.already_satisfied
        ):
            return self._record_rejection(
                normalized,
                effect_key=reservation.effect_key,
                started_at=started,
                reason_code="precondition_semantic_state_drift",
                precondition_digest=evaluated.before_digest,
            )
        if evaluated.already_satisfied:
            return self._record_already_satisfied(
                normalized,
                evaluated=evaluated,
                snapshot=snapshot,
                effect_key=reservation.effect_key,
                started_at=started,
            )

        attempt_id = secrets.token_hex(16)
        mutation_started = self._now()
        try:
            mutation = self.store.begin_mutation(
                reservation.effect_key,
                packet["packet_id"],
                attempt_id,
                self.limits,
                precondition_digest=evaluated.before_digest,
                now=mutation_started,
            )
        except BudgetExceeded as exc:
            return self._record_rejection(
                normalized,
                effect_key=reservation.effect_key,
                started_at=started,
                reason_code=_reason("budget", exc.budget),
                precondition_digest=digest_json(
                    {
                        "budget": exc.budget,
                        "effect_key": reservation.effect_key,
                        "state": "exhausted",
                    }
                ),
            )
        except CircuitOpenError:
            return self._record_rejection(
                normalized,
                effect_key=reservation.effect_key,
                started_at=started,
                reason_code="circuit_action_open",
                precondition_digest=digest_json(
                    {
                        "action": packet["request"]["action"],
                        "effect_key": reservation.effect_key,
                        "state": "open",
                    }
                ),
            )
        except PendingRecoveryError:
            return self._record_rejection(
                normalized,
                effect_key=None,
                started_at=started,
                reason_code="circuit_semantic_pending",
                precondition_digest=digest_json(
                    {
                        "effect_key": reservation.effect_key,
                        "state": "pending_recovery",
                    }
                ),
            )
        except BrokerStoreError as exc:
            raise BrokerServiceError(
                "broker mutation reservation failed"
            ) from exc
        if mutation.disposition == "receipt_replay":
            assert mutation.receipt is not None
            return mutation.receipt
        if mutation.disposition == "indeterminate":
            return self._record_rejection(
                normalized,
                effect_key=reservation.effect_key,
                started_at=started,
                reason_code="circuit_semantic_indeterminate",
                precondition_digest=digest_json(
                    {
                        "effect_key": reservation.effect_key,
                        "state": "indeterminate",
                    }
                ),
            )
        if mutation.disposition == "semantic_completed":
            return self._record_rejection(
                normalized,
                effect_key=reservation.effect_key,
                started_at=started,
                reason_code="precondition_semantic_state_drift",
                precondition_digest=evaluated.before_digest,
            )
        try:
            result = execute_evaluated_action(
                live=live,
                config=self.config,
                packet=packet,
                evaluated=evaluated,
                attempt_id=attempt_id,
            )
        except MutationIndeterminate as exc:
            return self._record_indeterminate(
                normalized,
                recovery=None,
                effect_key=reservation.effect_key,
                attempt_id=attempt_id,
                precondition_digest=evaluated.before_digest,
                started_at=started,
                mutation_attempted_at=mutation_started,
                reason_code=_reason("indeterminate", exc.reason_code),
            )

        completed = self._now()
        after = result["after"]
        after_pr = after["pr"]
        target = after.get("target_thread")
        resolved = (
            (target["id"],)
            if isinstance(target, Mapping)
            and target.get("is_resolved") is True
            else ()
        )
        receipt = self._signed_receipt(
            normalized,
            precondition_digest=evaluated.before_digest,
            outcome="succeeded",
            reason_code="readback_verified",
            mutation_status="applied",
            readback_status="confirmed",
            started_at=started,
            completed_at=completed,
            mutation_attempted_at=mutation_started,
            operation_id=attempt_id,
            readback_observed_at=completed,
            readback_head_sha=after_pr["head_sha"],
            readback_pr_is_draft=after_pr["is_draft"],
            resolved_thread_node_ids=resolved,
        )
        return self.store.terminalize(
            reservation.effect_key,
            packet["packet_id"],
            attempt_id,
            "completed",
            receipt,
            self.limits,
            now=completed,
        ).receipt


def build_service(config: Mapping[str, Any]) -> ProtectedBrokerService:
    return ProtectedBrokerService(config)
