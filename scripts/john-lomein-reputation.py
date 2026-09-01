#!/usr/bin/env python3
"""Verify externally signed outcomes and build a public-safe reputation report.

John can aggregate this ledger, but cannot mint its evidence. Every event must be
signed by a pinned external observer such as a GitHub App or protected broker.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import median
from typing import Any


EVENT_SCHEMA = "john-lomein.reputation-event.v1"
ENVELOPE_SCHEMA = "john-lomein.signed-reputation-event.v1"
REPORT_SCHEMA = "john-lomein.reputation-report.v1"
OBSERVER_POLICY_SCHEMA = "john-lomein.reputation-observer-policy.v1"
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_EVENTS = 50_000
MAX_POLICY_BYTES = 64 * 1024
MAX_CLOCK_SKEW_SECONDS = 300
REPORT_FRESHNESS_SECONDS = 30 * 24 * 3600
ZERO_HASH = "0" * 64
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,191}$")
REPO_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SOURCE_KINDS = frozenset(
    {"github_app", "protected_broker", "independent_evaluator"}
)
SUBJECT_KINDS = frozenset(
    {
        "pull_request",
        "review",
        "incident",
        "persona_evaluation",
        "capability_evaluation",
    }
)
OUTCOME_KINDS = frozenset(
    {
        "pr_merged",
        "pr_closed_unmerged",
        "review_finding_accepted",
        "repair_completed",
        "rollback",
        "escaped_defect",
        "owner_intervention",
        "persona_eval_pass",
        "capability_eval_pass",
        "incident_resolved",
    }
)
SOURCE_OUTCOMES = {
    "github_app": frozenset(
        {
            "pr_merged",
            "pr_closed_unmerged",
            "review_finding_accepted",
            "repair_completed",
            "rollback",
            "escaped_defect",
            "owner_intervention",
            "incident_resolved",
        }
    ),
    "protected_broker": frozenset(
        {
            "pr_merged",
            "pr_closed_unmerged",
            "repair_completed",
            "rollback",
            "owner_intervention",
            "incident_resolved",
        }
    ),
    "independent_evaluator": frozenset(
        {"persona_eval_pass", "capability_eval_pass"}
    ),
}
OUTCOME_SUBJECTS = {
    "pr_merged": frozenset({"pull_request"}),
    "pr_closed_unmerged": frozenset({"pull_request"}),
    "review_finding_accepted": frozenset({"review"}),
    "repair_completed": frozenset({"pull_request", "incident"}),
    "rollback": frozenset({"pull_request", "incident"}),
    "escaped_defect": frozenset({"pull_request", "incident"}),
    "owner_intervention": frozenset(
        {"pull_request", "review", "incident"}
    ),
    "persona_eval_pass": frozenset({"persona_evaluation"}),
    "capability_eval_pass": frozenset({"capability_evaluation"}),
    "incident_resolved": frozenset({"incident"}),
}
REPORT_INTERPRETATION = (
    "These are externally attested historical outcome counters, not a "
    "composite quality score or proof of current capability. Missing events "
    "must not be interpreted as success."
)


class ReputationError(ValueError):
    """A public-safe validation failure."""


class VerifiedLedger:
    """Events whose signatures, observer policy, chain, and uniqueness passed."""

    def __init__(
        self,
        events: tuple[dict[str, Any], ...],
        observer_policy: dict[str, Any],
    ) -> None:
        self.events = events
        self.observer_policy = observer_policy

    def __iter__(self):
        return iter(self.events)

    def __len__(self) -> int:
        return len(self.events)

    def __getitem__(self, index: int) -> dict[str, Any]:
        return self.events[index]


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReputationError("JSON object contains duplicate fields")
        result[key] = value
    return result


def _reject_nonfinite(_: str) -> None:
    raise ReputationError("JSON contains a non-finite number")


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReputationError(f"{field} must be an object")
    return value


def _strict_keys(value: dict[str, Any], *, field: str, allowed: set[str]) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ReputationError(f"{field} contains unknown fields")


def _token(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not TOKEN_RE.fullmatch(value):
        raise ReputationError(f"{field} must be a public-safe token")
    return value


def _positive_int(value: Any, *, field: str, maximum: int = 2**31 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReputationError(f"{field} must be an integer")
    if value <= 0 or value > maximum:
        raise ReputationError(f"{field} is outside the allowed range")
    return value


def _nonnegative_int(
    value: Any,
    *,
    field: str,
    maximum: int = 2**31 - 1,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReputationError(f"{field} must be an integer")
    if value < 0 or value > maximum:
        raise ReputationError(f"{field} is outside the allowed range")
    return value


def _parse_timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise ReputationError(f"{field} must be a UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ReputationError(f"{field} must be a UTC timestamp") from exc
    if parsed.year < 2020:
        raise ReputationError(f"{field} is outside the allowed range")
    return parsed


def _timestamp(value: Any, *, field: str) -> str:
    _parse_timestamp(value, field=field)
    return value


def _read_regular_file(
    path: Path,
    *,
    field: str,
    maximum_bytes: int,
    reject_writable: bool = False,
) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ReputationError(f"{field} is unreadable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ReputationError(
                f"{field} must be a regular non-symlink file"
            )
        if reject_writable and info.st_mode & 0o222:
            raise ReputationError(f"{field} must not be writable")
        if info.st_size > maximum_bytes:
            raise ReputationError(f"{field} exceeds its size limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise ReputationError(f"{field} exceeds its size limit")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _load_public_key(path: Path, expected_sha256: str) -> bytes:
    if not SHA256_RE.fullmatch(expected_sha256):
        raise ReputationError("public key fingerprint is invalid")
    raw = _read_regular_file(
        path,
        field="public key",
        maximum_bytes=MAX_POLICY_BYTES,
        reject_writable=True,
    )
    if b"PUBLIC KEY" not in raw:
        raise ReputationError("public key is not a PEM public key")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ReputationError("public key fingerprint mismatch")
    return raw


def _token_set(
    value: Any,
    *,
    field: str,
    allowed: frozenset[str] | None = None,
) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ReputationError(f"{field} must be a non-empty array")
    normalized = [_token(item, field=f"{field} item") for item in value]
    if len(set(normalized)) != len(normalized):
        raise ReputationError(f"{field} contains duplicate values")
    if normalized != sorted(normalized):
        raise ReputationError(f"{field} must be sorted")
    if allowed is not None and not set(normalized).issubset(allowed):
        raise ReputationError(f"{field} contains unsupported values")
    return normalized


def normalize_observer_policy(raw: Any) -> dict[str, Any]:
    policy = _mapping(raw, field="observer policy")
    _strict_keys(
        policy,
        field="observer policy",
        allowed={
            "schema_version",
            "observer_id",
            "public_key_sha256",
            "allowed_source_kinds",
            "allowed_outcomes",
            "allowed_repositories",
            "public_repository_allowlist",
        },
    )
    if policy.get("schema_version") != OBSERVER_POLICY_SCHEMA:
        raise ReputationError("observer policy schema is unsupported")
    observer_id = _token(
        policy.get("observer_id"), field="observer policy observer_id"
    )
    public_key_sha256 = str(policy.get("public_key_sha256") or "")
    if not SHA256_RE.fullmatch(public_key_sha256):
        raise ReputationError("observer policy public key fingerprint is invalid")
    source_kinds = _token_set(
        policy.get("allowed_source_kinds"),
        field="observer policy allowed_source_kinds",
        allowed=SOURCE_KINDS,
    )
    outcomes = _token_set(
        policy.get("allowed_outcomes"),
        field="observer policy allowed_outcomes",
        allowed=OUTCOME_KINDS,
    )
    repositories = policy.get("allowed_repositories")
    if not isinstance(repositories, list) or not repositories:
        raise ReputationError(
            "observer policy allowed_repositories must be a non-empty array"
        )
    normalized_repositories: list[str] = []
    for value in repositories:
        if not isinstance(value, str) or not REPO_RE.fullmatch(value):
            raise ReputationError(
                "observer policy allowed_repositories contains an invalid repository"
            )
        normalized_repositories.append(value)
    if (
        len(set(normalized_repositories)) != len(normalized_repositories)
        or normalized_repositories != sorted(normalized_repositories)
    ):
        raise ReputationError(
            "observer policy allowed_repositories must be sorted and unique"
        )
    public_repositories = policy.get("public_repository_allowlist")
    if not isinstance(public_repositories, list):
        raise ReputationError(
            "observer policy public_repository_allowlist must be an array"
        )
    normalized_public: list[str] = []
    for value in public_repositories:
        if not isinstance(value, str) or not REPO_RE.fullmatch(value):
            raise ReputationError(
                "observer policy public_repository_allowlist contains an invalid repository"
            )
        normalized_public.append(value)
    if (
        len(set(normalized_public)) != len(normalized_public)
        or normalized_public != sorted(normalized_public)
    ):
        raise ReputationError(
            "observer policy public_repository_allowlist must be sorted and unique"
        )
    if not set(normalized_public).issubset(normalized_repositories):
        raise ReputationError(
            "observer policy public repositories must be allowed repositories"
        )
    return {
        "schema_version": OBSERVER_POLICY_SCHEMA,
        "observer_id": observer_id,
        "public_key_sha256": public_key_sha256,
        "allowed_source_kinds": source_kinds,
        "allowed_outcomes": outcomes,
        "allowed_repositories": normalized_repositories,
        "public_repository_allowlist": normalized_public,
    }


def load_observer_policy(path: Path) -> dict[str, Any]:
    raw = _read_regular_file(
        path,
        field="observer policy",
        maximum_bytes=MAX_POLICY_BYTES,
        reject_writable=True,
    )
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except ReputationError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReputationError("observer policy is invalid JSON") from exc
    return normalize_observer_policy(value)


def _openssl() -> str:
    for candidate in (
        "/opt/homebrew/bin/openssl",
        "/usr/local/bin/openssl",
        "/usr/bin/openssl",
    ):
        if Path(candidate).is_file():
            return candidate
    raise ReputationError("openssl is unavailable")


def verify_signature(
    public_key: bytes,
    payload: dict[str, Any],
    signature: str,
) -> None:
    try:
        raw_signature = base64.b64decode(signature.encode("ascii"), validate=True)
    except (UnicodeError, ValueError) as exc:
        raise ReputationError("event signature is not valid base64") from exc
    if not raw_signature or len(raw_signature) > 16_384:
        raise ReputationError("event signature size is invalid")
    with tempfile.TemporaryDirectory(prefix="john-lomein-reputation-") as tmp:
        root = Path(tmp)
        public_key_path = root / "observer-public-key.pem"
        body_path = root / "payload.json"
        signature_path = root / "payload.sig"
        public_key_path.write_bytes(public_key)
        os.chmod(public_key_path, 0o400)
        body_path.write_bytes(canonical_json(payload))
        signature_path.write_bytes(raw_signature)
        proc = subprocess.run(
            [
                _openssl(),
                "dgst",
                "-sha256",
                "-verify",
                str(public_key_path),
                "-signature",
                str(signature_path),
                str(body_path),
            ],
            env={
                "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
                "HOME": str(root),
            },
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    if proc.returncode != 0:
        raise ReputationError("event signature verification failed")


def claim_id_for_event(payload: dict[str, Any]) -> str:
    source = _mapping(payload.get("source"), field="claim source")
    subject = _mapping(payload.get("subject"), field="claim subject")
    outcome = _mapping(payload.get("outcome"), field="claim outcome")
    material = {
        "actor": payload.get("actor"),
        "persona_version": payload.get("persona_version"),
        "observer_id": source.get("observer_id"),
        "subject": subject,
        "outcome_kind": outcome.get("kind"),
    }
    return f"claim-{sha256_json(material)[:40]}"


def _normalize_payload(raw: Any, *, index: int) -> dict[str, Any]:
    field = f"ledger event {index}"
    payload = _mapping(raw, field=field)
    _strict_keys(
        payload,
        field=field,
        allowed={
            "schema_version",
            "ledger_id",
            "sequence",
            "previous_event_sha256",
            "event_id",
            "claim_id",
            "observed_at",
            "actor",
            "persona_version",
            "source",
            "subject",
            "outcome",
        },
    )
    if payload.get("schema_version") != EVENT_SCHEMA:
        raise ReputationError(f"{field} schema is unsupported")
    ledger_id = _token(payload.get("ledger_id"), field=f"{field}.ledger_id")
    sequence = _positive_int(payload.get("sequence"), field=f"{field}.sequence")
    previous = str(payload.get("previous_event_sha256") or "")
    if not SHA256_RE.fullmatch(previous):
        raise ReputationError(f"{field}.previous_event_sha256 is invalid")
    event_id = _token(payload.get("event_id"), field=f"{field}.event_id")
    claim_id = _token(payload.get("claim_id"), field=f"{field}.claim_id")
    observed_at = _timestamp(
        payload.get("observed_at"), field=f"{field}.observed_at"
    )
    if payload.get("actor") != "john-lomein":
        raise ReputationError(f"{field}.actor must be john-lomein")
    persona_version = _token(
        payload.get("persona_version"), field=f"{field}.persona_version"
    )

    source = _mapping(payload.get("source"), field=f"{field}.source")
    _strict_keys(
        source,
        field=f"{field}.source",
        allowed={
            "observer_id",
            "kind",
            "delivery_id",
            "occurrence_id",
        },
    )
    observer_id = _token(
        source.get("observer_id"),
        field=f"{field}.source.observer_id",
    )
    source_kind = _token(source.get("kind"), field=f"{field}.source.kind")
    if source_kind not in SOURCE_KINDS:
        raise ReputationError(f"{field}.source.kind is unsupported")
    delivery_id = _token(
        source.get("delivery_id"), field=f"{field}.source.delivery_id"
    )
    occurrence_id = _token(
        source.get("occurrence_id"),
        field=f"{field}.source.occurrence_id",
    )

    subject = _mapping(payload.get("subject"), field=f"{field}.subject")
    _strict_keys(
        subject,
        field=f"{field}.subject",
        allowed={
            "id",
            "kind",
            "repo",
            "number",
            "head_sha",
            "visibility",
        },
    )
    subject_id = _token(
        subject.get("id"), field=f"{field}.subject.id"
    )
    subject_kind = _token(
        subject.get("kind"), field=f"{field}.subject.kind"
    )
    if subject_kind not in SUBJECT_KINDS:
        raise ReputationError(f"{field}.subject.kind is unsupported")
    repo = str(subject.get("repo") or "")
    if not REPO_RE.fullmatch(repo):
        raise ReputationError(f"{field}.subject.repo is invalid")
    visibility = str(subject.get("visibility") or "")
    if visibility not in {"public", "private"}:
        raise ReputationError(f"{field}.subject.visibility is invalid")
    number = subject.get("number")
    if subject_kind in {"pull_request", "review"}:
        number = _positive_int(number, field=f"{field}.subject.number")
    elif number is not None:
        raise ReputationError(
            f"{field}.subject.number is only valid for PR/review evidence"
        )
    head_sha = str(subject.get("head_sha") or "")
    if head_sha and not OID_RE.fullmatch(head_sha):
        raise ReputationError(f"{field}.subject.head_sha is invalid")
    if subject_kind in {"pull_request", "review"} and not head_sha:
        raise ReputationError(
            f"{field}.subject.head_sha is required for PR/review evidence"
        )

    outcome = _mapping(payload.get("outcome"), field=f"{field}.outcome")
    _strict_keys(
        outcome,
        field=f"{field}.outcome",
        allowed={"kind", "duration_seconds"},
    )
    outcome_kind = _token(
        outcome.get("kind"), field=f"{field}.outcome.kind"
    )
    if outcome_kind not in OUTCOME_KINDS:
        raise ReputationError(f"{field}.outcome.kind is unsupported")
    if subject_kind not in OUTCOME_SUBJECTS[outcome_kind]:
        raise ReputationError(
            f"{field}.outcome.kind is incompatible with subject kind {subject_kind}"
        )
    if outcome_kind not in SOURCE_OUTCOMES[source_kind]:
        raise ReputationError(
            f"{field}.outcome.kind is incompatible with source kind {source_kind}"
        )
    duration = outcome.get("duration_seconds")
    if outcome_kind == "repair_completed":
        duration = _positive_int(
            duration,
            field=f"{field}.outcome.duration_seconds",
            maximum=365 * 24 * 3600,
        )
    elif duration is not None:
        raise ReputationError(
            f"{field}.outcome.duration_seconds is only valid for repairs"
        )

    normalized = {
        "schema_version": EVENT_SCHEMA,
        "ledger_id": ledger_id,
        "sequence": sequence,
        "previous_event_sha256": previous,
        "event_id": event_id,
        "claim_id": claim_id,
        "observed_at": observed_at,
        "actor": "john-lomein",
        "persona_version": persona_version,
        "source": {
            "observer_id": observer_id,
            "kind": source_kind,
            "delivery_id": delivery_id,
            "occurrence_id": occurrence_id,
        },
        "subject": {
            "id": subject_id,
            "kind": subject_kind,
            "repo": repo,
            "visibility": visibility,
        },
        "outcome": {"kind": outcome_kind},
    }
    if number is not None:
        normalized["subject"]["number"] = number
    if head_sha:
        normalized["subject"]["head_sha"] = head_sha
    if duration is not None:
        normalized["outcome"]["duration_seconds"] = duration
    expected_claim_id = claim_id_for_event(normalized)
    if claim_id != expected_claim_id:
        raise ReputationError(f"{field}.claim_id is not canonical")
    if normalized != payload:
        raise ReputationError(f"{field} is not in canonical normalized form")
    return normalized


def load_signed_ledger(
    path: Path,
    *,
    public_key: Path,
    observer_policy: dict[str, Any],
    now: datetime | None = None,
) -> VerifiedLedger:
    policy = normalize_observer_policy(observer_policy)
    key = _load_public_key(
        public_key,
        str(policy["public_key_sha256"]),
    )
    raw_ledger = _read_regular_file(
        path,
        field="ledger",
        maximum_bytes=MAX_LEDGER_BYTES,
    )
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    events: list[dict[str, Any]] = []
    event_ids: set[str] = set()
    claim_ids: set[str] = set()
    deliveries: set[tuple[str, str]] = set()
    occurrences: set[tuple[str, str]] = set()
    visibility_by_repo: dict[str, str] = {}
    previous_digest = ZERO_HASH
    ledger_id = ""
    previous_timestamp = ""
    for line_number, raw_line in enumerate(
        raw_ledger.splitlines(keepends=True),
        1,
    ):
        if len(raw_line) > MAX_LINE_BYTES:
            raise ReputationError(f"ledger line {line_number} is too large")
        if not raw_line.endswith(b"\n"):
            raise ReputationError(
                f"ledger line {line_number} is a partial record"
            )
        if not raw_line.strip():
            raise ReputationError(f"ledger line {line_number} is empty")
        try:
            envelope = json.loads(
                raw_line,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite,
            )
        except ReputationError:
            raise
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ReputationError(
                f"ledger line {line_number} is invalid JSON"
            ) from exc
        envelope = _mapping(
            envelope, field=f"ledger envelope {line_number}"
        )
        _strict_keys(
            envelope,
            field=f"ledger envelope {line_number}",
            allowed={"schema_version", "payload", "signature"},
        )
        if envelope.get("schema_version") != ENVELOPE_SCHEMA:
            raise ReputationError(
                f"ledger envelope {line_number} schema is unsupported"
            )
        payload = _normalize_payload(
            envelope.get("payload"), index=line_number
        )
        signature = envelope.get("signature")
        if not isinstance(signature, str):
            raise ReputationError(
                f"ledger envelope {line_number}.signature is invalid"
            )
        if payload["sequence"] != len(events) + 1:
            raise ReputationError("ledger sequence is not contiguous")
        if payload["previous_event_sha256"] != previous_digest:
            raise ReputationError("ledger hash chain is invalid")
        if ledger_id and payload["ledger_id"] != ledger_id:
            raise ReputationError("ledger id changed inside the ledger")
        if previous_timestamp and payload["observed_at"] < previous_timestamp:
            raise ReputationError("ledger timestamps are not monotonic")
        observed = _parse_timestamp(
            payload["observed_at"],
            field=f"ledger event {line_number}.observed_at",
        )
        if observed > now + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
            raise ReputationError("ledger event timestamp is in the future")

        source = payload["source"]
        subject = payload["subject"]
        outcome = payload["outcome"]
        if source["observer_id"] != policy["observer_id"]:
            raise ReputationError("ledger observer id is not authorized")
        if source["kind"] not in policy["allowed_source_kinds"]:
            raise ReputationError("ledger source kind is not authorized")
        if outcome["kind"] not in policy["allowed_outcomes"]:
            raise ReputationError("ledger outcome kind is not authorized")
        repo = subject["repo"]
        if repo not in policy["allowed_repositories"]:
            raise ReputationError("ledger repository is not authorized")
        if (
            subject["visibility"] == "public"
            and repo not in policy["public_repository_allowlist"]
        ):
            raise ReputationError(
                "public repository evidence is not allowlisted for disclosure"
            )
        prior_visibility = visibility_by_repo.get(repo)
        if (
            prior_visibility is not None
            and prior_visibility != subject["visibility"]
        ):
            raise ReputationError(
                "ledger repository visibility changed inside the ledger"
            )

        event_id = payload["event_id"]
        claim_id = payload["claim_id"]
        delivery = (
            source["observer_id"],
            source["delivery_id"],
        )
        occurrence = (
            source["observer_id"],
            source["occurrence_id"],
        )
        if event_id in event_ids:
            raise ReputationError("ledger contains a duplicate event id")
        if claim_id in claim_ids:
            raise ReputationError("ledger contains a duplicate semantic claim")
        if delivery in deliveries:
            raise ReputationError(
                "ledger contains a duplicate source delivery"
            )
        if occurrence in occurrences:
            raise ReputationError(
                "ledger contains a duplicate source occurrence"
            )
        verify_signature(key, payload, signature)
        events.append(payload)
        event_ids.add(event_id)
        claim_ids.add(claim_id)
        deliveries.add(delivery)
        occurrences.add(occurrence)
        visibility_by_repo[repo] = subject["visibility"]
        ledger_id = payload["ledger_id"]
        previous_timestamp = payload["observed_at"]
        previous_digest = sha256_json(payload)
        if len(events) > MAX_EVENTS:
            raise ReputationError("ledger event limit exceeded")
    return VerifiedLedger(tuple(events), policy)


def build_report(
    ledger: VerifiedLedger,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(ledger, VerifiedLedger):
        raise ReputationError(
            "reputation reports require a verified signed ledger"
        )
    events = list(ledger.events)
    policy = normalize_observer_policy(ledger.observer_policy)
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    generated_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    counts = {kind: 0 for kind in sorted(OUTCOME_KINDS)}
    repair_durations: list[int] = []
    public_repositories: set[str] = set()
    private_repositories: set[str] = set()
    personas: set[str] = set()
    sources: set[str] = set()
    event_digests: list[str] = []
    for event in events:
        outcome = str(event["outcome"]["kind"])
        counts[outcome] += 1
        duration = event["outcome"].get("duration_seconds")
        if duration is not None:
            repair_durations.append(int(duration))
        repo = str(event["subject"]["repo"])
        if (
            event["subject"]["visibility"] == "public"
            and repo in policy["public_repository_allowlist"]
        ):
            public_repositories.add(repo)
        else:
            private_repositories.add(repo)
        personas.add(str(event["persona_version"]))
        sources.add(str(event["source"]["kind"]))
        event_digests.append(sha256_json(event))

    repair_mean = (
        round(sum(repair_durations) / len(repair_durations), 3)
        if repair_durations
        else None
    )
    repair_median = (
        float(median(repair_durations)) if repair_durations else None
    )
    shipped = counts["pr_merged"]
    latest_age: int | None = None
    freshness = "no_evidence"
    if events:
        latest = _parse_timestamp(
            events[-1]["observed_at"],
            field="latest ledger event observed_at",
        )
        latest_age = max(0, int((now - latest).total_seconds()))
        freshness = (
            "current"
            if latest_age <= REPORT_FRESHNESS_SECONDS
            else "historical"
        )
    current_capability_evidence = freshness == "current"
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "summary": {
            "status": (
                "externally_attested"
                if events
                else "no_attested_evidence"
            ),
            "signed_events": len(events),
            "public_repositories": sorted(public_repositories),
            "private_repository_count": len(private_repositories),
            "persona_versions": sorted(personas),
            "source_kinds": sorted(sources),
            "observer_id": str(policy["observer_id"]),
        },
        "metrics": {
            "shipped_prs": shipped,
            "closed_unmerged_prs": counts["pr_closed_unmerged"],
            "accepted_review_findings": counts[
                "review_finding_accepted"
            ],
            "repairs_completed": counts["repair_completed"],
            "mean_repair_seconds": repair_mean,
            "median_repair_seconds": repair_median,
            "rollbacks": counts["rollback"],
            "escaped_defects": counts["escaped_defect"],
            "owner_interventions": counts["owner_intervention"],
            "incidents_resolved": counts["incident_resolved"],
            "persona_eval_passes": counts["persona_eval_pass"],
            "capability_eval_passes": counts["capability_eval_pass"],
            "rollbacks_per_shipped_pr": (
                round(counts["rollback"] / shipped, 6)
                if shipped
                else None
            ),
            "owner_interventions_per_shipped_pr": (
                round(counts["owner_intervention"] / shipped, 6)
                if shipped
                else None
            ),
        },
        "evidence": {
            "public_reputation_eligible": bool(events),
            "current_capability_evidence": current_capability_evidence,
            "external_signatures_required": True,
            "observer_id": str(policy["observer_id"]),
            "observer_policy_sha256": sha256_json(policy),
            "public_key_sha256": str(policy["public_key_sha256"]),
            "ledger_id": str(events[0]["ledger_id"]) if events else "",
            "chain_head": event_digests[-1] if event_digests else ZERO_HASH,
            "event_digests": event_digests,
            "first_observed_at": (
                str(events[0]["observed_at"]) if events else ""
            ),
            "latest_observed_at": (
                str(events[-1]["observed_at"]) if events else ""
            ),
            "generated_at": generated_at,
            "latest_event_age_seconds": latest_age,
            "freshness": freshness,
            "freshness_window_seconds": REPORT_FRESHNESS_SECONDS,
        },
        "privacy": {
            "raw_signatures_included": False,
            "private_repository_names_included": False,
            "raw_comments_or_code_included": False,
        },
        "interpretation": REPORT_INTERPRETATION,
    }
    report["report_digest"] = sha256_json(report)
    return report


def _sorted_string_list(
    value: Any,
    *,
    field: str,
    validator: re.Pattern[str] | None = None,
    allowed: frozenset[str] | None = None,
) -> list[str]:
    if not isinstance(value, list):
        raise ReputationError(f"{field} must be an array")
    if any(not isinstance(item, str) for item in value):
        raise ReputationError(f"{field} contains a non-string value")
    if value != sorted(value) or len(set(value)) != len(value):
        raise ReputationError(f"{field} must be sorted and unique")
    if validator is not None and any(
        not validator.fullmatch(item) for item in value
    ):
        raise ReputationError(f"{field} contains an invalid value")
    if allowed is not None and not set(value).issubset(allowed):
        raise ReputationError(f"{field} contains an unsupported value")
    return value


def _optional_nonnegative_number(value: Any, *, field: str) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReputationError(f"{field} must be a number or null")
    if value < 0:
        raise ReputationError(f"{field} must not be negative")


def _validate_report(report: Any) -> dict[str, Any]:
    value = _mapping(report, field="reputation report")
    _strict_keys(
        value,
        field="reputation report",
        allowed={
            "schema_version",
            "summary",
            "metrics",
            "evidence",
            "privacy",
            "interpretation",
            "report_digest",
        },
    )
    if value.get("schema_version") != REPORT_SCHEMA:
        raise ReputationError("reputation report schema is unsupported")

    summary = _mapping(value.get("summary"), field="reputation report summary")
    _strict_keys(
        summary,
        field="reputation report summary",
        allowed={
            "status",
            "signed_events",
            "public_repositories",
            "private_repository_count",
            "persona_versions",
            "source_kinds",
            "observer_id",
        },
    )
    signed_events = _nonnegative_int(
        summary.get("signed_events"),
        field="reputation report signed_events",
        maximum=MAX_EVENTS,
    )
    expected_status = (
        "externally_attested" if signed_events else "no_attested_evidence"
    )
    if summary.get("status") != expected_status:
        raise ReputationError("reputation report summary status is inconsistent")
    _sorted_string_list(
        summary.get("public_repositories"),
        field="reputation report public_repositories",
        validator=REPO_RE,
    )
    _nonnegative_int(
        summary.get("private_repository_count"),
        field="reputation report private_repository_count",
        maximum=MAX_EVENTS,
    )
    _sorted_string_list(
        summary.get("persona_versions"),
        field="reputation report persona_versions",
        validator=TOKEN_RE,
    )
    _sorted_string_list(
        summary.get("source_kinds"),
        field="reputation report source_kinds",
        allowed=SOURCE_KINDS,
    )
    observer_id = _token(
        summary.get("observer_id"),
        field="reputation report observer_id",
    )

    metrics = _mapping(value.get("metrics"), field="reputation report metrics")
    count_fields = {
        "shipped_prs",
        "closed_unmerged_prs",
        "accepted_review_findings",
        "repairs_completed",
        "rollbacks",
        "escaped_defects",
        "owner_interventions",
        "incidents_resolved",
        "persona_eval_passes",
        "capability_eval_passes",
    }
    optional_number_fields = {
        "mean_repair_seconds",
        "median_repair_seconds",
        "rollbacks_per_shipped_pr",
        "owner_interventions_per_shipped_pr",
    }
    _strict_keys(
        metrics,
        field="reputation report metrics",
        allowed=count_fields | optional_number_fields,
    )
    for field in count_fields:
        _nonnegative_int(
            metrics.get(field),
            field=f"reputation report metrics.{field}",
            maximum=MAX_EVENTS,
        )
    for field in optional_number_fields:
        _optional_nonnegative_number(
            metrics.get(field),
            field=f"reputation report metrics.{field}",
        )

    evidence = _mapping(
        value.get("evidence"), field="reputation report evidence"
    )
    _strict_keys(
        evidence,
        field="reputation report evidence",
        allowed={
            "public_reputation_eligible",
            "current_capability_evidence",
            "external_signatures_required",
            "observer_id",
            "observer_policy_sha256",
            "public_key_sha256",
            "ledger_id",
            "chain_head",
            "event_digests",
            "first_observed_at",
            "latest_observed_at",
            "generated_at",
            "latest_event_age_seconds",
            "freshness",
            "freshness_window_seconds",
        },
    )
    for field in (
        "public_reputation_eligible",
        "current_capability_evidence",
        "external_signatures_required",
    ):
        if type(evidence.get(field)) is not bool:
            raise ReputationError(
                f"reputation report evidence.{field} must be boolean"
            )
    if evidence["external_signatures_required"] is not True:
        raise ReputationError("reputation report must require external signatures")
    if evidence.get("observer_id") != observer_id:
        raise ReputationError("reputation report observer ids do not match")
    for field in (
        "observer_policy_sha256",
        "public_key_sha256",
        "chain_head",
    ):
        if not isinstance(evidence.get(field), str) or not SHA256_RE.fullmatch(
            evidence[field]
        ):
            raise ReputationError(
                f"reputation report evidence.{field} is invalid"
            )
    ledger_id = evidence.get("ledger_id")
    if not isinstance(ledger_id, str) or (
        ledger_id and not TOKEN_RE.fullmatch(ledger_id)
    ):
        raise ReputationError("reputation report ledger_id is invalid")
    event_digests = _sorted_string_list(
        sorted(evidence.get("event_digests") or []),
        field="reputation report event_digests",
        validator=SHA256_RE,
    )
    if event_digests != evidence.get("event_digests"):
        # Event order is chain order, not lexical order. Validate uniqueness only.
        raw_digests = evidence.get("event_digests")
        if (
            not isinstance(raw_digests, list)
            or any(
                not isinstance(item, str) or not SHA256_RE.fullmatch(item)
                for item in raw_digests
            )
            or len(set(raw_digests)) != len(raw_digests)
        ):
            raise ReputationError(
                "reputation report event_digests are invalid"
            )
        event_digests = raw_digests
    if len(event_digests) != signed_events:
        raise ReputationError(
            "reputation report event digest count is inconsistent"
        )
    if evidence["chain_head"] != (
        event_digests[-1] if event_digests else ZERO_HASH
    ):
        raise ReputationError("reputation report chain head is inconsistent")
    generated = _parse_timestamp(
        evidence.get("generated_at"),
        field="reputation report generated_at",
    )
    freshness_window = _positive_int(
        evidence.get("freshness_window_seconds"),
        field="reputation report freshness_window_seconds",
        maximum=365 * 24 * 3600,
    )
    if freshness_window != REPORT_FRESHNESS_SECONDS:
        raise ReputationError(
            "reputation report freshness window is unsupported"
        )
    first_observed = evidence.get("first_observed_at")
    latest_observed = evidence.get("latest_observed_at")
    latest_age = evidence.get("latest_event_age_seconds")
    if signed_events:
        first = _parse_timestamp(
            first_observed,
            field="reputation report first_observed_at",
        )
        latest = _parse_timestamp(
            latest_observed,
            field="reputation report latest_observed_at",
        )
        if latest < first:
            raise ReputationError(
                "reputation report evidence timestamps are inconsistent"
            )
        expected_age = max(0, int((generated - latest).total_seconds()))
        if latest_age != expected_age:
            raise ReputationError(
                "reputation report latest event age is inconsistent"
            )
        expected_freshness = (
            "current"
            if expected_age <= REPORT_FRESHNESS_SECONDS
            else "historical"
        )
    else:
        if first_observed != "" or latest_observed != "" or latest_age is not None:
            raise ReputationError(
                "empty reputation report contains event timestamps"
            )
        expected_freshness = "no_evidence"
    if evidence.get("freshness") != expected_freshness:
        raise ReputationError("reputation report freshness is inconsistent")
    if evidence["public_reputation_eligible"] != bool(signed_events):
        raise ReputationError(
            "reputation report eligibility is inconsistent"
        )
    if evidence["current_capability_evidence"] != (
        expected_freshness == "current"
    ):
        raise ReputationError(
            "reputation report current-capability evidence is inconsistent"
        )

    privacy = _mapping(
        value.get("privacy"), field="reputation report privacy"
    )
    expected_privacy = {
        "raw_signatures_included": False,
        "private_repository_names_included": False,
        "raw_comments_or_code_included": False,
    }
    if privacy != expected_privacy:
        raise ReputationError("reputation report privacy contract is invalid")
    if value.get("interpretation") != REPORT_INTERPRETATION:
        raise ReputationError("reputation report interpretation is invalid")
    digest = value.get("report_digest")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise ReputationError("reputation report digest is invalid")
    body = {key: item for key, item in value.items() if key != "report_digest"}
    if digest != sha256_json(body):
        raise ReputationError("reputation report digest does not match")
    return value


def verify_report(report: Any) -> bool:
    try:
        _validate_report(report)
        return True
    except ReputationError:
        return False


def load_json(path: Path, *, field: str) -> Any:
    raw = _read_regular_file(
        path,
        field=field,
        maximum_bytes=MAX_LEDGER_BYTES,
    )
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except ReputationError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReputationError(f"{field} is invalid JSON") from exc


def atomic_write(path: Path, payload: dict[str, Any], *, pretty: bool) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
    ) + "\n"
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=str(path.parent),
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        Path(temporary).unlink(missing_ok=True)
        raise


def _render(value: dict[str, Any], *, pretty: bool) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--ledger", required=True)
    build.add_argument("--public-key", required=True)
    build.add_argument("--observer-policy", required=True)
    build.add_argument("--output")
    build.add_argument("--pretty", action="store_true")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--report", required=True)
    verify.add_argument("--ledger", required=True)
    verify.add_argument("--public-key", required=True)
    verify.add_argument("--observer-policy", required=True)
    verify.add_argument("--pretty", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            policy = load_observer_policy(Path(args.observer_policy))
            ledger = load_signed_ledger(
                Path(args.ledger),
                public_key=Path(args.public_key),
                observer_policy=policy,
            )
            report = build_report(ledger)
            if args.output:
                atomic_write(Path(args.output), report, pretty=args.pretty)
            else:
                print(_render(report, pretty=args.pretty))
            return 0

        report = load_json(Path(args.report), field="reputation report")
        digest_valid = verify_report(report)
        source_reproducible = False
        if digest_valid:
            policy = load_observer_policy(Path(args.observer_policy))
            ledger = load_signed_ledger(
                Path(args.ledger),
                public_key=Path(args.public_key),
                observer_policy=policy,
                now=_parse_timestamp(
                    report["evidence"]["generated_at"],
                    field="reputation report generated_at",
                ),
            )
            rebuilt = build_report(
                ledger,
                now=_parse_timestamp(
                    report["evidence"]["generated_at"],
                    field="reputation report generated_at",
                ),
            )
            source_reproducible = rebuilt == report
        result = {
            "schema_version": "john-lomein.reputation-verification.v1",
            "digest_valid": digest_valid,
            "source_reproducible": source_reproducible,
            "valid": digest_valid and source_reproducible,
        }
        print(_render(result, pretty=args.pretty))
        return 0 if result["valid"] else 1
    except ReputationError as exc:
        print(f"john-lomein reputation blocked: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
