#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_autonomy import AutonomyError, deployed_runtime_control
from john_lomein_comment_templates import format_issue_intake
from john_lomein_owner_actions import normalize_trust_tier, route_allowed_for_trust, split_csv, trusted_route_identity_from_assertion
from john_lomein_profile_contract import canonical_role_profiles

MAX_TITLE_CHARS = 180
MAX_BODY_CHARS = 12000

SECRETISH_PATTERNS = [
    re.compile(r"(?i)\b(GH_TOKEN|GITHUB_TOKEN|DISCORD_BOT_TOKEN|BOT_DISCORD_TOKEN|GLM_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|API_KEY|SECRET|PASSWORD)\s*="),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{20,}"),
    re.compile(r"\bgh[opsu]_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"),
]
PRIVATE_PATH_PATTERNS = [
    re.compile(r"/Users/[^\s)\]}>]+"),
    re.compile(r"(?<![\w.-])~/(?:\.hermes|\.john-lomein|mnemosyne|Projects|" + re.escape("Dan" + "iel-AI-Command-Center") + r")\b"),
]
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.: /+\-]{0,80}$")
DEFAULT_READINESS_LABELS = ["maintainer-ready", "forge-ready", "ready-for-implementation"]
ROUTE_LABELS = {
    "forge": "forge-ready",
    "pr": "ready-for-implementation",
    "implementation": "ready-for-implementation",
    "maintainer": "maintainer-ready",
}
CONTROLLED_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"


class IntakeError(Exception):
    def __init__(self, code: str, message: str, *, status: int = 2):
        super().__init__(message)
        self.code = code
        self.status = status


def strict_boolean(
    value: Any,
    *,
    field: str,
    default: bool,
) -> bool:
    if value is None:
        return default
    if type(value) is not bool:
        raise ValueError(f"{field} must be true or false")
    return value


def runtime_home() -> Path:
    deployed_env = SCRIPT_DIR / "john-lomein-instance.env"
    if deployed_env.exists():
        return SCRIPT_DIR.parent.resolve()
    raise IntakeError("non_deployed_issue_intake", "issue-intake must run from a deployed instance scripts directory")


def gh_env() -> dict[str, str]:
    home = runtime_home()
    try:
        manifest = load_manifest(home)
        profile = canonical_role_profiles(manifest)["guide"]
    except ValueError as exc:
        raise IntakeError(
            "unsafe_profile_contract",
            "deployed instance profile bindings are invalid",
            status=3,
        ) from exc
    profile_home = home / "profiles" / profile / "home"
    gh_config = profile_home / ".config" / "gh"
    env = {
        "PATH": CONTROLLED_PATH,
        "HERMES_HOME": str(home),
        "BOT_HERMES_HOME": str(home),
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
    }
    if profile_home.exists():
        env["HOME"] = str(profile_home)
    if gh_config.exists():
        env["GH_CONFIG_DIR"] = str(gh_config)
    return env


def _parse_scalar(raw: str) -> Any:
    value = raw.strip()
    if not value:
        return ""
    if value[0:1] in {"'", '"'} and value[-1:] == value[0]:
        return value[1:-1]
    lowered = value.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    return value


def load_manifest(home: Path) -> dict[str, Any]:
    """Load the small subset of instance.yaml this helper needs.

    Keep this dependency-free because guide-profile terminal shells can resolve to
    system Python without PyYAML. The generated instance manifests use simple
    top-level mappings for `target.repo` and `runtime.mutation_enabled`, so a
    minimal parser is safer than adding a package-install requirement to issue intake.
    """
    path = home / "instance.yaml"
    if not path.exists():
        return {}
    data: dict[str, Any] = {}
    section: str | None = None
    pending_list_key: str | None = None
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()
        if raw_line[:1] not in {" ", "\t"} and raw_line.rstrip().endswith(":"):
            section = stripped[:-1]
            data.setdefault(section, {})
            pending_list_key = None
            continue
        if section and indent >= 2 and stripped.startswith("- ") and pending_list_key:
            bucket = data.setdefault(section, {}).setdefault(pending_list_key, [])
            if isinstance(bucket, list):
                bucket.append(_parse_scalar(stripped[2:]))
            continue
        if section and raw_line.startswith("  ") and ":" in stripped:
            key, value = stripped.split(":", 1)
            key = key.strip()
            if value.strip() == "":
                data.setdefault(section, {})[key] = []
                pending_list_key = key
            else:
                data.setdefault(section, {})[key] = _parse_scalar(value)
                pending_list_key = None
    return data


def runtime_config(home: Path | None = None) -> dict[str, Any]:
    home = home or runtime_home()
    manifest = load_manifest(home)
    target = manifest.get("target") or {}
    runtime = manifest.get("runtime") or {}
    gates = manifest.get("gates") or {}
    authority = manifest.get("authority") or {}
    discord = manifest.get("discord") or {}
    repo = target.get("repo") or ""
    try:
        canonical_role_profiles(manifest)
        mutation_enabled = strict_boolean(
            runtime.get("mutation_enabled"),
            field="runtime.mutation_enabled",
            default=False,
        )
    except ValueError as exc:
        raise IntakeError(
            "unsafe_instance_manifest",
            "deployed instance manifest contains an unsafe profile or boolean field",
            status=3,
        ) from exc
    try:
        control = deployed_runtime_control(home)
    except AutonomyError as exc:
        raise IntakeError(
            "unsafe_runtime_control",
            str(exc),
            status=3,
        ) from exc
    deployed_repo = control.get("BOT_REPO") or ""
    if repo and repo != deployed_repo:
        raise IntakeError(
            "runtime_control_mismatch",
            "deployed target repository does not match the instance manifest",
            status=3,
        )
    readiness = gates.get("readiness_labels")
    if isinstance(readiness, list):
        readiness_labels = [str(x) for x in readiness]
    else:
        raw_readiness = str(readiness or "").strip()
        if raw_readiness.startswith("[") and raw_readiness.endswith("]"):
            raw_readiness = raw_readiness[1:-1]
        readiness_labels = split_csv(raw_readiness)
    owner_approvers = split_csv(authority.get("owner_approvers") or discord.get("owner_user_ids") or [])
    collaborators = split_csv(discord.get("trusted_collaborator_user_ids") or [])
    trust_public_key_sha256 = str(authority.get("trust_public_key_sha256") or discord.get("trust_public_key_sha256") or "").strip()
    return {
        "home": str(home),
        "repo": repo,
        "mutation_enabled": (
            mutation_enabled
            and control.get("BOT_MISSION_COMPLETE") == "1"
            and control.get("BOT_MUTATION_ENABLED") == "1"
        ),
        "readiness_labels": normalize_labels([str(x) for x in readiness_labels]),
        "owner_approvers": owner_approvers,
        "trusted_collaborators": collaborators,
        "trust_public_key_sha256": trust_public_key_sha256,
    }


def normalize_title(title: str) -> str:
    title = " ".join((title or "").strip().split())
    if len(title) < 5:
        raise IntakeError("title_too_short", "issue title must be at least 5 characters")
    if len(title) > MAX_TITLE_CHARS:
        raise IntakeError("title_too_long", f"issue title must be <= {MAX_TITLE_CHARS} characters")
    return title


def normalize_issue_number(issue: str | int | None) -> int | None:
    if issue in (None, ""):
        return None
    try:
        number = int(str(issue).lstrip("#"))
    except ValueError as exc:
        raise IntakeError("invalid_issue_number", "issue number must be a positive integer") from exc
    if number <= 0:
        raise IntakeError("invalid_issue_number", "issue number must be a positive integer")
    return number


def validate_public_safe(text: str, field: str) -> None:
    for pattern in SECRETISH_PATTERNS:
        if pattern.search(text or ""):
            raise IntakeError("secretish_content", f"{field} appears to contain a secret/token; redact before filing")
    for pattern in PRIVATE_PATH_PATTERNS:
        if pattern.search(text or ""):
            raise IntakeError("private_path_content", f"{field} appears to contain a private local path; redact before filing")


def normalize_body(body: str) -> str:
    body = (body or "").strip()
    if len(body) < 20:
        raise IntakeError("body_too_short", "issue body/comment must be at least 20 characters")
    if len(body) > MAX_BODY_CHARS:
        raise IntakeError("body_too_long", f"issue body/comment must be <= {MAX_BODY_CHARS} characters")
    validate_public_safe(body, "issue body/comment")
    if any(
        line.lstrip().startswith(("/", "@"))
        for line in body.splitlines()
    ):
        raise IntakeError(
            "command_like_content",
            "public issue intake cannot contain command-like / or @ lines",
        )
    return body


def normalize_labels(labels: list[str]) -> list[str]:
    out: list[str] = []
    for raw in labels:
        for part in str(raw).split(","):
            label = part.strip()
            if not label:
                continue
            if not LABEL_RE.match(label):
                raise IntakeError("invalid_label", f"invalid label: {label!r}")
            if label not in out:
                out.append(label)
    return out


def configured_readiness_labels(cfg: dict[str, Any]) -> list[str]:
    labels = normalize_labels([str(x) for x in (cfg.get("readiness_labels") or [])])
    return labels or list(DEFAULT_READINESS_LABELS)


def route_labels(route: str, cfg: dict[str, Any]) -> list[str]:
    route = (route or "").strip().lower()
    label = ROUTE_LABELS.get(route)
    if not label:
        raise IntakeError("invalid_route", f"unsupported route: {route!r}")
    allowed = configured_readiness_labels(cfg)
    if label not in allowed:
        raise IntakeError("route_label_not_configured", f"route {route!r} maps to {label!r}, which is not in configured readiness_labels: {allowed}")
    return [label]


def route_trust_blockers(tier: str, actor: str, cfg: dict[str, Any]) -> list[str]:
    tier = normalize_trust_tier(tier)
    actor = (actor or "").strip()
    owners = [str(x) for x in (cfg.get("owner_approvers") or [])]
    collaborators = [str(x) for x in (cfg.get("trusted_collaborators") or [])]
    if not route_allowed_for_trust(tier):
        return ["route_requires_trusted_input"]
    if not owners and not collaborators:
        return ["route_trusted_actor_registry_missing"]
    if not actor:
        return ["route_trusted_actor_identity_missing"]
    if tier == "owner" and actor not in owners:
        return ["route_actor_not_trusted_owner"]
    if tier == "collaborator" and actor not in set(owners + collaborators):
        return ["route_actor_not_trusted_collaborator"]
    return []


def route_identity_from_gateway(repo: str, issue: int | str, route: str, cfg: dict[str, Any]) -> tuple[str, str, str]:
    """Return signed trusted route identity from gateway/runtime metadata only.

    CLI flags are not authentication: public text can ask a model to pass
    `--trust-tier owner --actor <id>`, or to set plain environment variables.
    Route authority therefore requires a signed gateway assertion generated
    outside the model command surface. The verifier key fingerprint and actor
    registry come from deployed instance manifest/runtime config, not caller env.
    """
    assertion_env = {
        "BOT_HERMES_HOME": str(cfg.get("home") or ""),
        "HERMES_HOME": str(cfg.get("home") or ""),
        "BOT_TRUST_PUBLIC_KEY_SHA256": str(cfg.get("trust_public_key_sha256") or ""),
        "JOHN_LOMEIN_TRUST_ASSERTION": os.environ.get("JOHN_LOMEIN_TRUST_ASSERTION", ""),
    }
    return trusted_route_identity_from_assertion(assertion_env, repo=str(repo), issue=str(issue), route=str(route))


def build_create_command(repo: str, title: str, labels: list[str]) -> list[str]:
    if not repo or "/" not in repo:
        raise IntakeError("missing_repo", "target repo is missing or invalid")
    cmd = ["gh", "issue", "create", "--repo", repo, "--title", title, "--body-file", "-"]
    for label in labels:
        cmd.extend(["--label", label])
    return cmd


def build_comment_command(repo: str, issue_number: int) -> list[str]:
    if not repo or "/" not in repo:
        raise IntakeError("missing_repo", "target repo is missing or invalid")
    return ["gh", "issue", "comment", str(issue_number), "--repo", repo, "--body-file", "-"]


def build_route_command(repo: str, issue_number: int, labels: list[str]) -> list[str]:
    if not repo or "/" not in repo:
        raise IntakeError("missing_repo", "target repo is missing or invalid")
    if not labels:
        raise IntakeError("missing_route_label", "route must resolve to at least one label")
    cmd = ["gh", "issue", "edit", str(issue_number), "--repo", repo]
    for label in labels:
        cmd.extend(["--add-label", label])
    return cmd


def create_issue(repo: str, title: str, body: str, labels: list[str]) -> dict[str, Any]:
    cmd = build_create_command(repo, title, labels)
    proc = subprocess.run(cmd, input=body, capture_output=True, text=True, timeout=90, env=gh_env())
    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    if proc.returncode != 0:
        raise IntakeError("gh_issue_create_failed", stderr or stdout or f"gh exited {proc.returncode}", status=1)
    url_match = re.search(r"https://github\.com/[^\s]+/issues/(\d+)", stdout)
    result: dict[str, Any] = {"ok": True, "action": "create", "repo": repo, "title": title, "labels": labels, "url": stdout}
    if url_match:
        result["number"] = int(url_match.group(1))
        result["url"] = url_match.group(0)
    return result


def comment_issue(repo: str, issue_number: int, body: str) -> dict[str, Any]:
    cmd = build_comment_command(repo, issue_number)
    proc = subprocess.run(cmd, input=body, capture_output=True, text=True, timeout=90, env=gh_env())
    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    if proc.returncode != 0:
        raise IntakeError("gh_issue_comment_failed", stderr or stdout or f"gh exited {proc.returncode}", status=1)
    result: dict[str, Any] = {"ok": True, "action": "comment", "repo": repo, "number": issue_number, "url": stdout}
    if stdout.startswith("https://github.com/"):
        result["url"] = stdout
    return result


def route_issue(repo: str, issue_number: int, labels: list[str]) -> dict[str, Any]:
    cmd = build_route_command(repo, issue_number, labels)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90, env=gh_env())
    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    if proc.returncode != 0:
        raise IntakeError("gh_issue_route_failed", stderr or stdout or f"gh exited {proc.returncode}", status=1)
    return {
        "ok": True,
        "action": "route",
        "repo": repo,
        "number": issue_number,
        "labels": labels,
        "url": f"https://github.com/{repo}/issues/{issue_number}",
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create, comment, or route public-safe GitHub issues for a john-lomein instance target repo.")
    parser.add_argument("--issue", help="Existing issue number to comment on or route. Omit to create a new issue.")
    parser.add_argument("--title", help="Issue title for new issue creation")
    parser.add_argument("--body", help="Issue body/comment. If omitted, read from stdin for create/comment actions.")
    parser.add_argument("--body-file", help="Read issue body/comment from file instead of --body/stdin.")
    parser.add_argument("--label", action="append", default=[], help="Optional non-readiness GitHub label for new issue creation. Readiness labels require --route plus a signed gateway trust assertion.")
    parser.add_argument("--route", choices=sorted(ROUTE_LABELS), help="Route an existing issue by adding the configured readiness label for this lane; use `pr`/`implementation` for issue-to-draft-PR pickup, or `forge` for softer forge consideration.")
    parser.add_argument("--trust-tier", default="public", choices=["owner", "collaborator", "public", "untrusted"], help="Trust tier of the input that requested this action. Public/untrusted input can create/comment but cannot route readiness labels.")
    parser.add_argument("--actor", help="Stable configured actor identity for trusted route requests")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print the issue payload without mutating GitHub.")
    return parser.parse_args(argv)


def read_body(args: argparse.Namespace) -> str:
    sources = [bool(args.body), bool(args.body_file)]
    if sum(sources) > 1:
        raise IntakeError("body_source_conflict", "use only one of --body or --body-file")
    if args.body_file:
        return Path(args.body_file).read_text(encoding="utf-8")
    if args.body:
        return args.body
    return sys.stdin.read()


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv or sys.argv[1:])
        cfg = runtime_config()
        repo = str(cfg.get("repo") or "")
        if not repo or "/" not in repo:
            raise IntakeError("missing_repo", "target.repo is missing or invalid in deployed instance manifest", status=3)
        if not cfg.get("mutation_enabled"):
            raise IntakeError("issue_intake_disabled", "issue intake requires runtime.mutation_enabled=true", status=3)
        issue_number = normalize_issue_number(args.issue)
        trust_tier = normalize_trust_tier(args.trust_tier)
        if args.route:
            if issue_number is None:
                raise IntakeError("route_requires_issue", "--route requires --issue N")
            trusted_tier, trusted_actor, trust_error = route_identity_from_gateway(repo, issue_number, args.route, cfg)
            if trust_error:
                raise IntakeError(trust_error, "--route requires a signed gateway trust assertion; public/untrusted Discord text, plain env vars, and CLI actor flags are data only")
            route_blockers = route_trust_blockers(trusted_tier, trusted_actor, cfg)
            if route_blockers:
                raise IntakeError(route_blockers[0], "--route requires gateway-supplied trusted owner or collaborator identity; public/untrusted Discord text and CLI actor flags are data only")
            labels = route_labels(args.route, cfg)
            if args.title or args.label or args.body or args.body_file:
                raise IntakeError("route_action_conflict", "--route may only be combined with --issue and --dry-run")
            if args.dry_run:
                print(json.dumps({"ok": True, "dry_run": True, "action": "route", "repo": repo, "number": issue_number, "route": args.route, "labels": labels, "trust_tier": trusted_tier, "actor": trusted_actor, "requested_trust_tier": trust_tier, "requested_actor": args.actor or ""}, sort_keys=True))
                return 0
            raise IntakeError(
                "route_requires_protected_broker",
                "signed readiness routes require the external intake broker",
                status=3,
            )

        body = normalize_body(read_body(args))
        if issue_number is not None:
            body = format_issue_intake(body, next_text="repo maintainers can use this comment as public context for the existing issue")
            if args.dry_run:
                print(json.dumps({"ok": True, "dry_run": True, "action": "comment", "repo": repo, "number": issue_number, "body_chars": len(body), "trust_tier": trust_tier}, sort_keys=True))
                return 0
            print(json.dumps(comment_issue(repo, issue_number, body), sort_keys=True))
            return 0

        title = normalize_title(args.title or "")
        validate_public_safe(title, "issue title")
        labels = normalize_labels(args.label)
        env_readiness_labels = normalize_labels(split_csv(os.environ.get("BOT_READINESS_LABELS") or ""))
        readiness_labels = {label.casefold() for label in (set(configured_readiness_labels(cfg)) | set(DEFAULT_READINESS_LABELS) | set(env_readiness_labels))}
        blocked_readiness = [label for label in labels if label.casefold() in readiness_labels]
        if blocked_readiness:
            raise IntakeError("readiness_label_requires_signed_route", f"readiness labels require --route with a signed gateway trust assertion: {blocked_readiness}")
        if labels:
            raise IntakeError(
                "issue_labels_require_protected_broker",
                "public issue intake cannot attach GitHub labels",
                status=3,
            )
        body = format_issue_intake(body, next_text="triage follows the issue labels, forge capacity, and owner gates")
        if args.dry_run:
            print(json.dumps({"ok": True, "dry_run": True, "action": "create", "repo": repo, "title": title, "labels": labels, "body_chars": len(body), "trust_tier": trust_tier}, sort_keys=True))
            return 0
        print(json.dumps(create_issue(repo, title, body, labels), sort_keys=True))
        return 0
    except IntakeError as exc:
        print(json.dumps({"ok": False, "error": exc.code, "detail": str(exc)}, sort_keys=True))
        return exc.status
    except subprocess.TimeoutExpired:
        print(json.dumps({"ok": False, "error": "gh_issue_intake_timeout", "detail": "gh issue command timed out"}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
