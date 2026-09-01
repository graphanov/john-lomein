#!/usr/bin/env python3
"""Deterministic public comment/body templates for john-lomein runtimes.

The role prompts still decide *when* to comment, but public text should come from
these helpers so GitHub/Discord surfaces stay compact, evidence-shaped, and free
of hidden runtime chatter.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Iterable, Sequence

NO_AUTHORITY = "john-lomein did not merge, publish, release, dispatch workflows, change settings, force-push, rewrite history, or touch secrets."
PROTECTED_EVIDENCE_SCHEMA = "john-lomein-protected-evidence:v1"
PROTECTED_ACTIONS = frozenset({"mark_pr_ready", "resolve_review_thread"})
INSTANCE_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
OID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def clean(value: object) -> str:
    return str(value or "").replace("\r\n", "\n").replace("\r", "\n").strip()


def sentence(value: object) -> str:
    text = clean(value)
    if not text:
        return "not specified."
    if text[-1:] in {".", "!", "?", ")"}:
        return text
    return text + "."


def as_list(values: object) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        return [line.strip() for line in values.splitlines() if line.strip()]
    if isinstance(values, Iterable):
        out: list[str] = []
        for value in values:
            text = clean(value)
            if text:
                out.append(text)
        return out
    text = clean(values)
    return [text] if text else []


def bullet_lines(values: object, *, empty: str = "not observed") -> list[str]:
    items = as_list(values)
    if not items:
        items = [empty]
    lines: list[str] = []
    for item in items:
        parts = item.split("\n")
        lines.append(f"- {parts[0]}")
        for continuation in parts[1:]:
            lines.append(f"  {continuation}")
    return lines


def with_marker(marker: str | None, body: str) -> str:
    marker = clean(marker)
    return f"{marker}\n{body}" if marker else body


def format_status_evidence_next(status: str, evidence: Sequence[str] | str, next_text: str, *, marker: str | None = None, next_label: str = "Next") -> str:
    body = "\n".join(
        [
            f"Status: {sentence(status)}",
            "",
            "Evidence:",
            *bullet_lines(evidence),
            "",
            f"{next_label}: {sentence(next_text)}",
        ]
    )
    return with_marker(marker, body)


def format_review_reply(status: str, evidence: Sequence[str] | str, next_text: str, *, marker: str | None = None) -> str:
    return format_status_evidence_next(status, evidence, next_text, marker=marker)


def protected_evidence_marker(
    *,
    instance_slug: str,
    action: str,
    head_sha: str,
    commands_sha256: str,
    result_sha256: str,
) -> str:
    instance_slug = clean(instance_slug)
    action = clean(action)
    head_sha = clean(head_sha).lower()
    commands_sha256 = clean(commands_sha256).lower()
    result_sha256 = clean(result_sha256).lower()
    if not INSTANCE_SLUG_RE.fullmatch(instance_slug):
        raise ValueError("protected evidence instance slug is invalid")
    if action not in PROTECTED_ACTIONS:
        raise ValueError("protected evidence action is invalid")
    if not OID_RE.fullmatch(head_sha):
        raise ValueError("protected evidence head SHA is invalid")
    if not SHA256_RE.fullmatch(commands_sha256):
        raise ValueError("protected evidence command digest is invalid")
    if not SHA256_RE.fullmatch(result_sha256):
        raise ValueError("protected evidence result digest is invalid")
    return (
        f"<!-- {PROTECTED_EVIDENCE_SCHEMA}"
        f" instance={instance_slug}"
        f" action={action}"
        f" head={head_sha}"
        f" commands={commands_sha256}"
        f" result={result_sha256} -->"
    )


def format_protected_evidence(
    *,
    instance_slug: str,
    action: str,
    head_sha: str,
    commands_sha256: str,
    result_sha256: str,
    status: str,
    evidence: Sequence[str] | str,
    next_text: str,
) -> str:
    return format_status_evidence_next(
        status,
        evidence,
        next_text,
        marker=protected_evidence_marker(
            instance_slug=instance_slug,
            action=action,
            head_sha=head_sha,
            commands_sha256=commands_sha256,
            result_sha256=result_sha256,
        ),
    )


def format_blocker(reason: str, evidence: Sequence[str] | str, needed: str, *, marker: str | None = None) -> str:
    body = "\n".join(
        [
            f"Status: blocked — {sentence(reason)}",
            "",
            "Evidence:",
            *bullet_lines(evidence),
            "",
            f"Needed: {sentence(needed)}",
        ]
    )
    return with_marker(marker, body)


def format_issue_intake(request: str, *, next_text: str = "triage follows the configured labels, forge capacity, and owner gates") -> str:
    request = clean(request)
    return "\n".join(
        [
            "Status: issue intake captured.",
            "",
            "Evidence:",
            "- Public-safe request recorded below.",
            "",
            "Request:",
            request or "(empty)",
            "",
            f"Next: {sentence(next_text)}",
        ]
    )


def format_pr_draft_body(
    *,
    summary: Sequence[str] | str,
    scope: Sequence[str] | str,
    out_of_scope: Sequence[str] | str,
    verification: Sequence[str] | str,
    risk: Sequence[str] | str,
    linked_issue: str,
    authority: str = NO_AUTHORITY,
) -> str:
    lines = [
        "## Summary",
        *bullet_lines(summary),
        "",
        "## Scope",
        *bullet_lines(scope),
        "",
        "## Out of scope",
        *bullet_lines(out_of_scope),
        "",
        "## Verification",
        *bullet_lines(verification),
        "",
        "## Risk",
        *bullet_lines(risk, empty="standard PR review risk only"),
        "",
        "## Linked issue",
        clean(linked_issue) or "not linked",
        "",
        "## Authority boundary",
        sentence(authority),
    ]
    return "\n".join(lines)


def codex_review_request() -> str:
    return "@codex review"


def pr_label(pr: dict) -> str:
    number = pr.get("number")
    title = clean(pr.get("title")) or "untitled"
    head = clean(pr.get("headRefOid"))
    suffix = f" — head `{head}`" if head else ""
    return f"#{number} — {title} — latest-head clean: yes{suffix}"


def format_release_bundle(
    *,
    bundle_id: str,
    clean_prs: Sequence[dict],
    blockers: Sequence[str],
    publish_readiness: dict,
    approval_text: str,
    trusted_approver_required: bool = False,
) -> str:
    verification = [
        f"clean PR candidates: {len(clean_prs)}",
        f"non-bundle blockers: {len(blockers)}",
        f"publish ready after merge: `{bool(publish_readiness.get('publish_ready_after_merge'))}`",
    ]
    blocker = clean(publish_readiness.get("blocker"))
    if blocker:
        verification.append(f"publish blocker: `{blocker}`")
    note = clean(publish_readiness.get("premerge_note"))
    if note:
        verification.append(f"publish condition: {note}")
    lines = [
        f"Release bundle ready: {clean(bundle_id)}.",
        "",
        "Included PRs:",
    ]
    lines.extend([f"- {pr_label(pr)}" for pr in clean_prs] or ["- none"])
    lines.extend(["", "Verification:"])
    lines.extend(f"- {item}" for item in verification)
    if blockers:
        lines.extend(["", "Non-bundle blockers:"])
        lines.extend(f"- {clean(item)}" for item in blockers)
    lines.extend(
        [
            "",
            "Owner gate required:",
            sentence(approval_text),
        ]
    )
    if trusted_approver_required:
        lines.extend(
            [
                "",
                "Trusted approver required:",
                "- configured owner approver identity must accompany the exact approval text",
            ]
        )
    return "\n".join(lines)


def parse_json_list_or_lines(value: str) -> list[str]:
    value = value or ""
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return [clean(x) for x in parsed if clean(x)]
    except Exception:
        pass
    return as_list(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render deterministic john-lomein public comment templates.")
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="Render Status/Evidence/Next")
    status.add_argument("--status", required=True)
    status.add_argument("--evidence", action="append", default=[])
    status.add_argument("--next", required=True, dest="next_text")
    status.add_argument("--marker")

    review = sub.add_parser("review-reply", help="Render a review reply")
    review.add_argument("--status", required=True)
    review.add_argument("--evidence", action="append", default=[])
    review.add_argument("--next", required=True, dest="next_text")
    review.add_argument("--marker")

    protected = sub.add_parser(
        "protected-evidence",
        help="Render broker-verifiable Status/Evidence/Next",
    )
    protected.add_argument("--instance-slug", required=True)
    protected.add_argument(
        "--action",
        required=True,
        choices=sorted(PROTECTED_ACTIONS),
    )
    protected.add_argument("--head-sha", required=True)
    protected.add_argument("--commands-sha256", required=True)
    protected.add_argument("--result-sha256", required=True)
    protected.add_argument("--status", required=True)
    protected.add_argument("--evidence", action="append", default=[])
    protected.add_argument("--next", required=True, dest="next_text")

    blocker = sub.add_parser("blocker", help="Render a blocker comment")
    blocker.add_argument("--reason", required=True)
    blocker.add_argument("--evidence", action="append", default=[])
    blocker.add_argument("--needed", required=True)
    blocker.add_argument("--marker")

    issue = sub.add_parser("issue-intake", help="Render an issue-intake body/comment")
    issue.add_argument("--request", help="Request text. Defaults to stdin.")
    issue.add_argument("--next", dest="next_text", default="triage follows the configured labels, forge capacity, and owner gates")

    pr = sub.add_parser("pr-draft-body", help="Render a draft PR body")
    pr.add_argument("--summary", action="append", default=[])
    pr.add_argument("--scope", action="append", default=[])
    pr.add_argument("--out-of-scope", action="append", default=[])
    pr.add_argument("--verification", action="append", default=[])
    pr.add_argument("--risk", action="append", default=[])
    pr.add_argument("--linked-issue", required=True)
    pr.add_argument("--authority", default=NO_AUTHORITY)

    sub.add_parser("codex-review", help="Render the exact Codex review trigger")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "status":
        print(format_status_evidence_next(args.status, args.evidence, args.next_text, marker=args.marker))
    elif args.command == "review-reply":
        print(format_review_reply(args.status, args.evidence, args.next_text, marker=args.marker))
    elif args.command == "protected-evidence":
        print(
            format_protected_evidence(
                instance_slug=args.instance_slug,
                action=args.action,
                head_sha=args.head_sha,
                commands_sha256=args.commands_sha256,
                result_sha256=args.result_sha256,
                status=args.status,
                evidence=args.evidence,
                next_text=args.next_text,
            )
        )
    elif args.command == "blocker":
        print(format_blocker(args.reason, args.evidence, args.needed, marker=args.marker))
    elif args.command == "issue-intake":
        request = args.request if args.request is not None else sys.stdin.read()
        print(format_issue_intake(request, next_text=args.next_text))
    elif args.command == "pr-draft-body":
        print(
            format_pr_draft_body(
                summary=args.summary,
                scope=args.scope,
                out_of_scope=args.out_of_scope,
                verification=args.verification,
                risk=args.risk,
                linked_issue=args.linked_issue,
                authority=args.authority,
            )
        )
    elif args.command == "codex-review":
        print(codex_review_request())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
