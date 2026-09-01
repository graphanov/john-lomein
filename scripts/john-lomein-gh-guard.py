#!/usr/bin/env python3
"""Guard GitHub CLI calls made by john-lomein workers.

The maintainer profile is intentionally powerful enough to comment on PRs, but
it must not spam `@codex review` after Codex has already reviewed the current
head clean. This wrapper passes through to the real `gh` for everything except
obvious duplicate Codex review requests.
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_autonomy import (
    AutonomyError,
    begin_effect,
    deployed_runtime_control,
    finish_effect,
    policy_from_runtime,
    require_active_run,
    require_effective_lane,
    sha256_json,
)
from john_lomein_public_safety import (
    PublicSafetyError,
    assert_public_safe_text,
)

STDIN_BODY: bytes | None = None
MAX_BODY_BYTES = 1_048_576


def real_gh() -> str:
    explicit = os.environ.get("JOHN_LOMEIN_REAL_GH")
    deployed = (SCRIPT_DIR / "john-lomein-instance.env").exists()
    if explicit and not deployed and Path(explicit).exists():
        return explicit
    this = Path(__file__).resolve()
    skip_dirs = {str(this.parent), str(this.parent / "bin"), str(this.parent.parent / "bin")}
    search_path = (
        "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
        if deployed
        else os.environ.get("PATH", "")
    )
    for raw in search_path.split(os.pathsep):
        if not raw or raw in skip_dirs:
            continue
        candidate = Path(raw) / "gh"
        try:
            resolved = candidate.resolve()
            if (
                candidate.exists()
                and os.access(candidate, os.X_OK)
                and resolved != this
                and not (resolved.stat().st_mode & 0o022)
            ):
                return str(resolved)
        except OSError:
            continue
    raise AutonomyError("trusted GitHub CLI binary not found")


def value_after(args: list[str], names: set[str]) -> str:
    found = ""
    for i, arg in enumerate(args):
        if arg in names and i + 1 < len(args):
            found = args[i + 1]
            continue
        for name in names:
            prefix = name + "="
            if arg.startswith(prefix):
                found = arg[len(prefix):]
                break
            if (
                len(name) == 2
                and name.startswith("-")
                and arg.startswith(name)
                and len(arg) > 2
            ):
                found = arg[2:]
                break
    return found


def comment_body(args: list[str]) -> str:
    global STDIN_BODY
    if len(args) >= 2 and args[0] == "api":
        if value_after(args, {"--input"}):
            raise AutonomyError(
                "API comment input files are not inspectable"
            )
        bodies: list[str] = []
        for field in _api_fields(args):
            key, separator, value = field.partition("=")
            if separator and key == "body":
                if value.startswith("@"):
                    raise AutonomyError(
                        "API comment body files are not inspectable"
                    )
                bodies.append(value)
        if len(bodies) != 1:
            raise AutonomyError(
                "API comments require exactly one inline body field"
            )
        return bodies[0]
    body = value_after(args, {"--body", "-b"})
    if body:
        return body
    body_file = value_after(args, {"--body-file", "-F"})
    if body_file == "-":
        if STDIN_BODY is None:
            STDIN_BODY = sys.stdin.buffer.read(MAX_BODY_BYTES + 1)
            if len(STDIN_BODY) > MAX_BODY_BYTES:
                raise AutonomyError("GitHub body exceeds the inspection limit")
        return (STDIN_BODY or b"").decode("utf-8", errors="replace")
    if body_file:
        raise AutonomyError(
            "GitHub body files must be captured before policy evaluation"
        )
    return ""


def capture_body_file(
    original_args: list[str],
    command_args: list[str],
) -> list[str]:
    """Capture a non-API body once and make gh consume those exact bytes."""
    global STDIN_BODY
    if not command_args or command_args[0] == "api":
        return original_args
    body_files = _option_values(command_args, {"--body-file", "-F"})
    if not body_files:
        return original_args
    if len(body_files) != 1:
        raise AutonomyError("duplicate GitHub body-file options are forbidden")
    body_file = body_files[0]
    try:
        if body_file == "-":
            captured = sys.stdin.buffer.read(MAX_BODY_BYTES + 1)
        else:
            path = Path(body_file)
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(info.st_mode):
                raise AutonomyError(
                    "GitHub body file must be a non-symlink regular file"
                )
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_dev != info.st_dev
                or opened.st_ino != info.st_ino
            ):
                os.close(descriptor)
                raise AutonomyError(
                    "GitHub body file changed during capture"
                )
            with os.fdopen(descriptor, "rb") as handle:
                captured = handle.read(MAX_BODY_BYTES + 1)
    except AutonomyError:
        raise
    except OSError as exc:
        raise AutonomyError("GitHub body file cannot be read safely") from exc
    if len(captured) > MAX_BODY_BYTES:
        raise AutonomyError("GitHub body exceeds the inspection limit")
    STDIN_BODY = captured

    rewritten: list[str] = []
    index = 0
    replaced = False
    while index < len(original_args):
        arg = original_args[index]
        if arg in {"--body-file", "-F"}:
            if index + 1 >= len(original_args):
                raise AutonomyError("GitHub body-file option lacks a value")
            if replaced:
                raise AutonomyError(
                    "duplicate GitHub body-file options are forbidden"
                )
            rewritten.extend(["--body-file", "-"])
            replaced = True
            index += 2
            continue
        if arg.startswith("--body-file="):
            if replaced:
                raise AutonomyError(
                    "duplicate GitHub body-file options are forbidden"
                )
            rewritten.append("--body-file=-")
            replaced = True
            index += 1
            continue
        if arg.startswith("-F") and len(arg) > 2:
            if replaced:
                raise AutonomyError(
                    "duplicate GitHub body-file options are forbidden"
                )
            rewritten.append("-F-")
            replaced = True
            index += 1
            continue
        rewritten.append(arg)
        index += 1
    if not replaced:
        raise AutonomyError("GitHub body-file option could not be canonicalized")
    return rewritten


def pr_number(args: list[str]) -> str:
    if len(args) >= 3 and args[0] == "pr" and args[1] == "comment":
        return args[2]
    return ""


def reviewed_commit(body: str) -> str:
    match = re.search(r"Reviewed commit:\*\*\s*`([0-9a-fA-F]{7,40})`", body or "", re.I)
    return match.group(1).lower() if match else ""


CODEX_AUTHORS = {"chatgpt-codex-connector", "chatgpt-codex-connector[bot]"}


def is_codex_login(login: str) -> bool:
    return str(login or "") in CODEX_AUTHORS


def gh_json(gh: str, cmd: list[str]) -> object:
    out = subprocess.check_output(
        [gh, *cmd],
        text=True,
        stderr=subprocess.DEVNULL,
        env=gh_env(),
    )
    return json.loads(out or "null")


def codex_state(gh: str, repo: str, pr: str) -> dict:
    view = gh_json(gh, ["pr", "view", pr, "--repo", repo, "--json", "headRefOid"])
    head = str((view or {}).get("headRefOid") or "").lower()
    if not head:
        raise RuntimeError("missing_pr_head")
    head10 = head[:10]
    comments = gh_json(gh, ["api", f"repos/{repo}/issues/{pr}/comments", "--paginate"]) or []
    artifacts: list[dict] = []
    triggers: list[str] = []
    for item in comments:
        body = item.get("body") or ""
        login = ((item.get("user") or {}).get("login") or "")
        created = item.get("created_at") or ""
        if is_codex_login(login):
            lowered = body.lower()
            clean = "didn't find any major issues" in lowered and "automated review suggestions" not in lowered
            artifacts.append({"kind": "issue_comment", "created_at": created, "commit": reviewed_commit(body), "clean": clean, "reviewed": clean})
        elif "@codex review" in body.lower():
            triggers.append(created)
    reviews = gh_json(gh, ["api", f"repos/{repo}/pulls/{pr}/reviews", "--paginate"]) or []
    for item in reviews:
        body = item.get("body") or ""
        login = ((item.get("user") or {}).get("login") or "")
        if not is_codex_login(login):
            continue
        commit = str(item.get("commit_id") or reviewed_commit(body) or "").lower()
        lowered = body.lower()
        clean = "didn't find any major issues" in lowered and "automated review suggestions" not in lowered
        artifacts.append({"kind": "formal_review", "created_at": item.get("submitted_at") or "", "commit": commit, "clean": clean, "reviewed": bool(commit)})
    current_artifacts = [a for a in artifacts if head10 and (a.get("commit") or "").startswith(head10)]
    latest_current = max(current_artifacts, key=lambda a: a.get("created_at") or "", default={})
    clean_current = bool(latest_current.get("clean"))
    current_review = clean_current
    latest_artifact = max([a["created_at"] for a in artifacts] or [""])
    latest_trigger = max(triggers or [""])
    pending = bool(latest_trigger and latest_trigger > latest_artifact and not current_review)
    return {"head": head10, "clean_current": clean_current, "current_review": current_review, "pending": pending, "latest_artifact": latest_artifact, "latest_trigger": latest_trigger}


def should_guard(args: list[str]) -> bool:
    return (
        len(args) >= 3
        and args[0] == "pr"
        and args[1] == "comment"
        and comment_body(args).strip().casefold() == "@codex review"
    )


def canonical_command_args(args: list[str]) -> list[str]:
    value_flags = {"--repo", "-R", "--hostname"}
    boolean_flags = {"--debug", "--help", "-h", "--version"}
    index = 0
    while index < len(args) and args[index].startswith("-"):
        arg = args[index]
        if arg in value_flags:
            if index + 1 >= len(args):
                raise AutonomyError(f"missing value for root gh option {arg}")
            index += 2
            continue
        if any(arg.startswith(flag + "=") for flag in value_flags):
            index += 1
            continue
        if arg.startswith("-R") and len(arg) > 2:
            index += 1
            continue
        if arg in boolean_flags:
            index += 1
            continue
        raise AutonomyError(f"unsupported root-level gh option: {arg}")
    return args[index:]


def validate_cli_shape(
    original_args: list[str],
    command_args: list[str],
) -> None:
    repo_values = _option_values(original_args, {"--repo", "-R"})
    if len(repo_values) > 1:
        raise AutonomyError("duplicate GitHub --repo options are forbidden")
    host_values = _option_values(original_args, {"--hostname"})
    if len(host_values) > 1 or (
        host_values and host_values[0].casefold() != "github.com"
    ):
        raise AutonomyError("protected GitHub host must be github.com")
    method_values = _option_values(command_args, {"--method", "-X"})
    if len(method_values) > 1:
        raise AutonomyError("duplicate GitHub API methods are forbidden")
    if command_args[:2] == ["pr", "create"]:
        draft_flags = [
            arg
            for arg in command_args
            if arg == "--draft" or arg.startswith("--draft=")
        ]
        if len(draft_flags) > 1 or any(
            arg != "--draft" for arg in draft_flags
        ):
            raise AutonomyError("ambiguous PR draft flags are forbidden")
        for names, label in (
            ({"--base", "-B"}, "base"),
            ({"--head", "-H"}, "head"),
        ):
            if len(_option_values(command_args, names)) > 1:
                raise AutonomyError(
                    f"duplicate PR {label} options are forbidden"
                )


def _api_fields(args: list[str]) -> list[str]:
    values: list[str] = []
    index = 2
    names = {"-f", "-F", "--field", "--raw-field"}
    while index < len(args):
        arg = args[index]
        if arg in names:
            if index + 1 < len(args):
                values.append(args[index + 1])
                index += 2
                continue
            break
        matched = False
        for name in names:
            if arg.startswith(name + "="):
                values.append(arg[len(name) + 1 :])
                matched = True
                break
            if (
                len(name) == 2
                and arg.startswith(name)
                and len(arg) > 2
            ):
                values.append(arg[2:])
                matched = True
                break
        index += 1
        if matched:
            continue
    return values


def _deployed_gh_config_dir(
    runtime: Path,
    control: dict[str, str],
    lane: str,
) -> Path:
    profile_key = (
        "BOT_FORGE_PROFILE"
        if lane == "forge"
        else "BOT_MAINTAINER_PROFILE"
    )
    profile = control.get(profile_key) or ""
    if not profile:
        raise AutonomyError(
            "deployed GitHub auth profile is unavailable"
        )
    expected = (
        runtime
        / "profiles"
        / profile
        / "home"
        / ".config"
        / "gh"
    )
    try:
        gh_config = expected.resolve(strict=True)
    except OSError as exc:
        raise AutonomyError(
            "deployed GitHub auth directory is unavailable"
        ) from exc
    if not gh_config.is_dir() or gh_config != expected:
        raise AutonomyError(
            "deployed GitHub auth directory does not match "
            "the deployed lane profile"
        )
    return gh_config


def gh_env() -> dict[str, str]:
    deployed = (SCRIPT_DIR / "john-lomein-instance.env").exists()
    if not deployed:
        env = dict(os.environ)
        for key in (
            "ALL_PROXY",
            "GH_ENTERPRISE_HOST",
            "GH_ENTERPRISE_TOKEN",
            "GH_HOST",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "SSL_CERT_DIR",
            "SSL_CERT_FILE",
            "all_proxy",
            "http_proxy",
            "https_proxy",
            "no_proxy",
        ):
            env.pop(key, None)
        env["GH_HOST"] = "github.com"
        env["GH_PROMPT_DISABLED"] = "1"
        return env
    runtime = SCRIPT_DIR.parent.resolve()
    control = deployed_runtime_control(runtime)
    lane = os.environ.get("JOHN_LOMEIN_AUTONOMY_LANE") or ""
    gh_config = _deployed_gh_config_dir(
        runtime,
        control,
        lane,
    )
    return {
        "PATH": (
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
        ),
        "HOME": str(gh_config.parent.parent),
        "LANG": "C",
        "LC_ALL": "C",
        "GH_CONFIG_DIR": str(gh_config),
        "GH_HOST": "github.com",
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
    }


def _label_only_edit(args: list[str]) -> bool:
    value_flags = {
        "--add-label",
        "--remove-label",
        "--repo",
        "-R",
    }
    target_seen = False
    label_seen = False
    index = 2
    while index < len(args):
        arg = args[index]
        if arg in value_flags:
            if index + 1 >= len(args):
                return False
            if arg in {"--add-label", "--remove-label"}:
                label_seen = True
            index += 2
            continue
        if any(arg.startswith(flag + "=") for flag in value_flags):
            if arg.startswith(("--add-label=", "--remove-label=")):
                label_seen = True
            index += 1
            continue
        if arg.startswith("-R") and len(arg) > 2:
            index += 1
            continue
        if arg.startswith("-"):
            return False
        if target_seen:
            return False
        target_seen = True
        index += 1
    return target_seen and label_seen


def effect_kind(args: list[str]) -> str | None:
    if len(args) < 2:
        return None
    group, action = args[0], args[1]
    exact = {
        ("pr", "comment"): "public_comments",
        ("issue", "comment"): "public_comments",
        ("issue", "create"): "issues",
        ("pr", "create"): "pull_requests",
        ("pr", "ready"): "pull_request_updates",
        ("pr", "merge"): "merges",
        ("workflow", "run"): "workflow_dispatches",
        ("release", "create"): "publishes",
        ("release", "upload"): "publishes",
        ("release", "edit"): "publishes",
        ("release", "delete"): "publishes",
    }
    if (group, action) in exact:
        return exact[(group, action)]
    if (group, action) in {("pr", "edit"), ("issue", "edit")}:
        return "labels" if _label_only_edit(args) else "github_writes"
    generic_writes = {
        ("pr", "review"),
        ("pr", "close"),
        ("pr", "reopen"),
        ("issue", "close"),
        ("issue", "reopen"),
        ("issue", "delete"),
        ("repo", "edit"),
        ("label", "create"),
        ("label", "edit"),
        ("label", "delete"),
        ("variable", "set"),
        ("variable", "delete"),
        ("secret", "set"),
        ("secret", "delete"),
    }
    if (group, action) in generic_writes:
        return "github_writes"
    if group != "api":
        return None
    method = value_after(args, {"--method", "-X"}).upper()
    has_input = bool(
        value_after(args, {"--input"})
        or any(
            arg in {"-f", "-F", "--field", "--raw-field"}
            or arg.startswith(
                (
                    "-f=",
                    "-F=",
                    "--field=",
                    "--raw-field=",
                )
            )
            or (
                (arg.startswith("-f") or arg.startswith("-F"))
                and len(arg) > 2
            )
            for arg in args
        )
    )
    graphql_mutation = action == "graphql" and any(
        "mutation" in arg.lower() for arg in args[2:]
    )
    joined = " ".join(args[2:]).lower()
    if action == "graphql":
        return "github_writes" if (graphql_mutation or has_input) else None
    effective_method = method or ("POST" if has_input else "GET")
    if (
        effective_method == "POST"
        and re.search(
            r"/(?:issues/\d+/comments|pulls/comments/\d+/replies)(?:\s|$)",
            f"{action} ",
        )
    ):
        return "github_writes"
    if method == "GET":
        return None
    if method and method != "GET":
        return "github_writes"
    if has_input or graphql_mutation:
        return "github_writes"
    return None


def enforce_effect_authority(
    lane: str,
    args: list[str],
    kind: str,
) -> None:
    protected = {
        "merges",
        "pull_request_updates",
        "workflow_dispatches",
        "publishes",
        "github_writes",
    }
    if kind in protected:
        command = " ".join(args[:2])
        raise AutonomyError(
            f"GitHub action '{command}' requires a protected broker"
        )
    allowed_lanes = {
        "public_comments": {"maintainer", "forge", "portfolio", "release"},
        "issues": {"forge", "portfolio"},
        "labels": {"maintainer", "forge", "portfolio", "triage"},
        "pull_requests": {"forge", "portfolio"},
    }
    if lane not in allowed_lanes.get(kind, set()):
        raise AutonomyError(
            f"lane {lane!r} lacks authority for GitHub effect {kind!r}"
        )


def _option_values(args: list[str], names: set[str]) -> list[str]:
    values: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in names:
            if index + 1 < len(args):
                values.append(args[index + 1])
                index += 2
                continue
            return values
        matched = False
        for name in names:
            if arg.startswith(name + "="):
                values.append(arg[len(name) + 1 :])
                matched = True
                break
            if (
                len(name) == 2
                and arg.startswith(name)
                and len(arg) > 2
            ):
                values.append(arg[2:])
                matched = True
                break
        index += 1
        if matched:
            continue
    return values


def _parse_canonical_write(
    args: list[str],
    *,
    value_flags: set[str],
    boolean_flags: set[str] = frozenset(),
) -> tuple[list[str], dict[str, list[str]], dict[str, int]]:
    positionals: list[str] = []
    values = {flag: [] for flag in value_flags}
    booleans = {flag: 0 for flag in boolean_flags}
    index = 2
    while index < len(args):
        arg = args[index]
        if arg in value_flags:
            if index + 1 >= len(args):
                raise AutonomyError(f"missing value for GitHub option {arg}")
            values[arg].append(args[index + 1])
            index += 2
            continue
        if arg in boolean_flags:
            booleans[arg] += 1
            index += 1
            continue
        if arg.startswith("-"):
            raise AutonomyError(
                f"unsupported protected GitHub write option: {arg}"
            )
        positionals.append(arg)
        index += 1
    if any(len(items) > 1 for items in values.values()):
        raise AutonomyError(
            "duplicate protected GitHub write options are forbidden"
        )
    if any(count > 1 for count in booleans.values()):
        raise AutonomyError(
            "duplicate protected GitHub write flags are forbidden"
        )
    return positionals, values, booleans


def _required_value(values: dict[str, list[str]], flag: str) -> str:
    found = values.get(flag) or []
    if len(found) != 1 or not found[0]:
        raise AutonomyError(
            f"protected GitHub write requires exactly one {flag}"
        )
    return found[0]


def _validate_numeric_target(positionals: list[str]) -> None:
    if len(positionals) != 1 or not re.fullmatch(
        r"[1-9][0-9]*",
        positionals[0],
    ):
        raise AutonomyError(
            "protected GitHub write requires one positive numeric target"
        )


def _validate_body_source(
    args: list[str],
    values: dict[str, list[str]],
) -> None:
    body_count = len(values.get("--body") or []) + len(
        values.get("--body-file") or []
    )
    if body_count != 1:
        raise AutonomyError(
            "protected GitHub write requires exactly one body source"
        )
    body = comment_body(args)
    if not body.strip():
        raise AutonomyError("protected GitHub write body cannot be empty")
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise AutonomyError("GitHub body exceeds the inspection limit")
    try:
        assert_public_safe_text(
            body,
            field="protected GitHub write body",
        )
    except PublicSafetyError as exc:
        raise AutonomyError(str(exc)) from exc


def _validate_public_title(value: str) -> None:
    if (
        not value.strip()
        or len(value) > 256
        or "\n" in value
        or "\r" in value
        or value.lstrip().startswith(("/", "@"))
    ):
        raise AutonomyError(
            "protected GitHub write title is not a safe single line"
        )
    try:
        assert_public_safe_text(
            value,
            field="protected GitHub write title",
        )
    except PublicSafetyError as exc:
        raise AutonomyError(str(exc)) from exc


def validate_write_grammar(
    original_args: list[str],
    command_args: list[str],
) -> None:
    if original_args != command_args:
        raise AutonomyError(
            "protected GitHub writes do not accept root-level options"
        )
    command = tuple(command_args[:2])
    if command in {("issue", "comment"), ("pr", "comment")}:
        positionals, values, _ = _parse_canonical_write(
            command_args,
            value_flags={"--repo", "--body", "--body-file"},
        )
        _validate_numeric_target(positionals)
        _required_value(values, "--repo")
        _validate_body_source(command_args, values)
        return
    if command == ("issue", "create"):
        positionals, values, _ = _parse_canonical_write(
            command_args,
            value_flags={
                "--repo",
                "--title",
                "--body",
                "--body-file",
            },
        )
        if positionals:
            raise AutonomyError(
                "autonomous issue creation accepts no positional target"
            )
        _required_value(values, "--repo")
        _validate_public_title(_required_value(values, "--title"))
        _validate_body_source(command_args, values)
        return
    if command == ("pr", "create"):
        positionals, values, booleans = _parse_canonical_write(
            command_args,
            value_flags={
                "--repo",
                "--base",
                "--head",
                "--title",
                "--body",
                "--body-file",
            },
            boolean_flags={"--draft"},
        )
        if positionals:
            raise AutonomyError(
                "autonomous PR creation accepts no positional target"
            )
        for flag in ("--repo", "--base", "--head"):
            _required_value(values, flag)
        _validate_public_title(_required_value(values, "--title"))
        if booleans["--draft"] != 1:
            raise AutonomyError("autonomous PR creation must remain draft")
        _validate_body_source(command_args, values)
        return
    if command in {("issue", "edit"), ("pr", "edit")}:
        positionals, values, _ = _parse_canonical_write(
            command_args,
            value_flags={
                "--repo",
                "--add-label",
                "--remove-label",
            },
        )
        _validate_numeric_target(positionals)
        _required_value(values, "--repo")
        label_values = (values["--add-label"] + values["--remove-label"])
        if len(label_values) != 1 or "," in label_values[0]:
            raise AutonomyError(
                "label mutation requires exactly one non-CSV label"
            )
        return
    if command == ("pr", "ready"):
        positionals, values, _ = _parse_canonical_write(
            command_args,
            value_flags={"--repo"},
        )
        _validate_numeric_target(positionals)
        _required_value(values, "--repo")
        return
    raise AutonomyError(
        "GitHub write has no canonical autonomous command grammar"
    )


def _readiness_labels(control: dict[str, str]) -> set[str]:
    raw = control.get("BOT_READINESS_LABELS") or ""
    labels = {
        part.strip().casefold()
        for part in raw.split(",")
        if part.strip()
    }
    labels.update(
        {
            "maintainer-ready",
            "forge-ready",
            "ready-for-implementation",
        }
    )
    return labels


def _autonomous_safe_labels(control: dict[str, str]) -> set[str]:
    return {
        part.strip().casefold()
        for part in (
            control.get("BOT_AUTONOMOUS_SAFE_LABELS") or ""
        ).split(",")
        if part.strip()
    } - _readiness_labels(control)


def _command_positionals(command_args: list[str]) -> list[str]:
    value_flags = {
        "--add-assignee",
        "--add-label",
        "--assignee",
        "-a",
        "--base",
        "-B",
        "--body",
        "-b",
        "--body-file",
        "-F",
        "--head",
        "-H",
        "--label",
        "-l",
        "--match-head-commit",
        "--milestone",
        "-m",
        "--project",
        "-p",
        "--recover",
        "--remove-assignee",
        "--remove-label",
        "--repo",
        "-R",
        "--reviewer",
        "-r",
        "--subject",
        "--template",
        "-T",
        "--title",
        "-t",
    }
    positionals: list[str] = []
    index = 2
    while index < len(command_args):
        arg = command_args[index]
        if arg == "--":
            positionals.extend(command_args[index + 1 :])
            break
        if arg in value_flags:
            if index + 1 >= len(command_args):
                raise AutonomyError(f"missing value for GitHub option {arg}")
            index += 2
            continue
        if any(
            arg.startswith(name + "=")
            for name in value_flags
            if name.startswith("--")
        ):
            index += 1
            continue
        if any(
            arg.startswith(name) and len(arg) > 2
            for name in value_flags
            if len(name) == 2 and name.startswith("-")
        ):
            index += 1
            continue
        if arg.startswith("-"):
            index += 1
            continue
        positionals.append(arg)
        index += 1
    return positionals


def _target_url_repo(value: str) -> str | None:
    parsed = urlsplit(value)
    if parsed.scheme.casefold() not in {"http", "https"}:
        return None
    if (
        parsed.scheme.casefold() != "https"
        or (parsed.hostname or "").casefold() != "github.com"
        or parsed.username
        or parsed.password
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise AutonomyError("protected GitHub target URL is not canonical")
    match = re.fullmatch(
        r"/([^/]+/[^/]+)/(?:issues|pull)/\d+/?",
        parsed.path,
        flags=re.I,
    )
    if not match:
        raise AutonomyError("protected GitHub target URL is not canonical")
    return match.group(1).removesuffix(".git")


def _require_target_repo(
    original_args: list[str],
    command_args: list[str],
    control: dict[str, str],
) -> None:
    expected = str(control["BOT_REPO"]).casefold()
    if command_args[0] == "api":
        endpoint = command_args[1] if len(command_args) > 1 else ""
        match = re.match(r"^repos/([^/]+/[^/]+)/", endpoint, flags=re.I)
        if not match or match.group(1).casefold() != expected:
            raise AutonomyError(
                "GitHub API write is outside the configured target repo"
            )
        return
    supplied = _option_values(original_args, {"--repo", "-R"})
    if len(supplied) != 1 or supplied[0].casefold() != expected:
        raise AutonomyError(
            "protected GitHub write requires the exact configured target repo"
        )
    target_commands = {
        ("issue", "comment"),
        ("issue", "edit"),
        ("pr", "comment"),
        ("pr", "edit"),
        ("pr", "merge"),
        ("pr", "ready"),
    }
    if tuple(command_args[:2]) not in target_commands:
        return
    for target in _command_positionals(command_args):
        url_repo = _target_url_repo(target)
        if url_repo is None:
            continue
        if url_repo.casefold() != expected:
            raise AutonomyError(
                "protected GitHub target URL is outside the configured repo"
            )
        raise AutonomyError(
            "protected GitHub writes cannot combine a target URL with --repo"
        )


def validate_effect_semantics(
    lane: str,
    original_args: list[str],
    command_args: list[str],
    kind: str,
    control: dict[str, str],
) -> None:
    validate_write_grammar(original_args, command_args)
    _require_target_repo(original_args, command_args, control)
    readiness = _readiness_labels(control)
    if kind == "issues":
        requested = _option_values(command_args, {"--label", "-l"})
        labels = {
            part.strip().casefold()
            for value in requested
            for part in value.split(",")
            if part.strip()
        }
        if labels & readiness:
            raise AutonomyError(
                "issue creation cannot self-grant a readiness label"
            )
    elif kind == "labels":
        requested = _option_values(
            command_args,
            {"--add-label", "--remove-label"},
        )
        labels = {
            part.strip().casefold()
            for value in requested
            for part in value.split(",")
            if part.strip()
        }
        if labels & readiness:
            raise AutonomyError(
                "readiness labels require the signed intake route broker"
            )
        safe_labels = _autonomous_safe_labels(control)
        if len(labels) != 1 or not labels <= safe_labels:
            raise AutonomyError(
                "label mutation is outside the deployed autonomous "
                "safe-label allowlist"
            )
    elif kind == "pull_requests":
        if "--draft" not in command_args:
            raise AutonomyError("autonomous PR creation must remain draft")
        base = value_after(command_args, {"--base", "-B"})
        if base != control["BOT_DEFAULT_BRANCH"]:
            raise AutonomyError(
                "autonomous PR base must be the configured default branch"
            )
        head = value_after(command_args, {"--head", "-H"})
        if not head or ":" in head:
            raise AutonomyError(
                "autonomous PR creation requires an explicit local head"
            )
        if lane == "forge" and not head.startswith("forge/"):
            raise AutonomyError("forge PR head must use forge/*")
        if lane == "portfolio":
            prefix = (
                control.get("BOT_OSC_PORTFOLIO_BRANCH_PREFIX")
                or "portfolio/"
            )
            if not head.startswith(prefix):
                raise AutonomyError(
                    "portfolio PR head must use its configured prefix"
                )
    elif kind == "public_comments":
        body = comment_body(command_args)
        lowered = body.casefold()
        if lowered.strip() != "@codex review" and any(
            line.lstrip().startswith(("/", "@"))
            for line in body.splitlines()
        ):
            raise AutonomyError(
                "public comment contains a command-like line"
            )
        protected_patterns = (
            r"(?m)^\s*bors\s+r\+",
            r"(?m)^\s*@dependabot\s+(?:merge|rebase)\b",
            r"(?m)^\s*@github-actions\b",
        )
        if any(re.search(pattern, lowered) for pattern in protected_patterns):
            raise AutonomyError(
                "public comment contains a protected automation command"
            )


def is_explicit_read_only(args: list[str]) -> bool:
    if not args:
        return True
    group = args[0]
    action = args[1] if len(args) > 1 else ""
    allowed_pairs = {
        ("auth", "status"),
        ("cache", "list"),
        ("config", "get"),
        ("config", "list"),
        ("issue", "list"),
        ("issue", "status"),
        ("issue", "view"),
        ("label", "list"),
        ("pr", "checks"),
        ("pr", "diff"),
        ("pr", "list"),
        ("pr", "status"),
        ("pr", "view"),
        ("release", "list"),
        ("release", "view"),
        ("repo", "list"),
        ("repo", "view"),
        ("run", "list"),
        ("run", "view"),
        ("run", "watch"),
        ("workflow", "list"),
        ("workflow", "view"),
    }
    if (group, action) in allowed_pairs:
        return True
    if group in {"completion", "help", "search", "status"}:
        return True
    if group == "api":
        return effect_kind(args) is None
    return False


def autonomy_runtime() -> Path | None:
    deployed_env = SCRIPT_DIR / "john-lomein-instance.env"
    explicit = (
        os.environ.get("BOT_HERMES_HOME")
        or os.environ.get("HERMES_HOME")
        or ""
    )
    if deployed_env.exists():
        runtime = SCRIPT_DIR.parent.resolve()
        for key in ("BOT_HERMES_HOME", "HERMES_HOME"):
            supplied = os.environ.get(key)
            if (
                supplied
                and Path(supplied).expanduser().resolve() != runtime
            ):
                raise AutonomyError(
                    f"caller {key} does not match deployed runtime"
                )
        return runtime
    runtime = (
        Path(explicit).expanduser().resolve()
        if explicit
        else SCRIPT_DIR.parent.resolve()
    )
    stamp = runtime / "state" / "john-lomein-autonomy-policy.json"
    runtime_env = runtime / "scripts" / "john-lomein-instance.env"
    if not stamp.exists() and not runtime_env.exists():
        return None
    if not stamp.exists():
        raise AutonomyError("deployed autonomy policy stamp is missing")
    return runtime


def run_effect_guarded(
    gh: str,
    args: list[str],
    command_args: list[str],
    kind: str,
) -> int:
    runtime = autonomy_runtime()
    if runtime is None:
        if STDIN_BODY is not None:
            return subprocess.run(
                [gh, *args],
                input=STDIN_BODY,
                check=False,
            ).returncode
        os.execv(gh, [gh, *args])
        return 127
    policy = policy_from_runtime(runtime)
    control = deployed_runtime_control(runtime)
    lane = os.environ.get("JOHN_LOMEIN_AUTONOMY_LANE") or ""
    run_id = os.environ.get("JOHN_LOMEIN_AUTONOMY_RUN_ID") or ""
    if not lane or not run_id:
        raise AutonomyError(
            "protected GitHub write is missing an active autonomy run"
        )
    require_effective_lane(control, lane)
    require_active_run(runtime, policy, lane, run_id)
    enforce_effect_authority(lane, command_args, kind)
    validate_effect_semantics(
        lane,
        args,
        command_args,
        kind,
        control,
    )
    body_bearing = kind in {
        "public_comments",
        "issues",
        "pull_requests",
    }
    body_digest = (
        sha256_json({"body": comment_body(args)})
        if body_bearing
        else None
    )
    operation_digest = sha256_json(
        {
            "tool": "gh",
            "effect_kind": kind,
            "args": args,
            "body_sha256": body_digest,
        }
    )
    decision = begin_effect(
        runtime,
        policy,
        lane,
        run_id,
        kind,
        idempotency_key=f"gh:{kind}:{operation_digest}",
        before_sha256=operation_digest,
    )
    if not decision["allowed"]:
        reason = str(decision["reason"])
        print(
            f"john-lomein gh guard: protected write blocked reason={reason}",
            file=sys.stderr,
        )
        if reason == "effect_idempotency_completed":
            receipt = decision.get("receipt")
            if isinstance(receipt, dict):
                stdout = receipt.get("stdout")
                if isinstance(stdout, str) and stdout:
                    sys.stdout.write(stdout)
                    sys.stdout.flush()
            return 0
        return 75
    try:
        proc = subprocess.run(
            [gh, *args],
            input=STDIN_BODY,
            capture_output=True,
            check=False,
            env=gh_env(),
        )
    except OSError as exc:
        try:
            finish_effect(
                runtime,
                str(decision["effect_id"]),
                success=False,
            )
        except AutonomyError:
            pass
        raise AutonomyError(
            "protected GitHub write could not launch"
        ) from exc
    receipt: dict[str, object] | None = None
    if proc.returncode == 0:
        receipt = _github_effect_receipt(
            kind,
            command_args,
            proc.stdout or b"",
            control,
        )
    if proc.stdout:
        sys.stdout.buffer.write(proc.stdout)
        sys.stdout.buffer.flush()
    if proc.stderr:
        sys.stderr.buffer.write(proc.stderr)
        sys.stderr.buffer.flush()
    try:
        finish_effect(
            runtime,
            str(decision["effect_id"]),
            success=proc.returncode == 0,
            after_sha256=(
                sha256_json(receipt)
                if receipt is not None
                else None
            ),
            receipt=receipt,
        )
    except AutonomyError as exc:
        print(
            f"john-lomein gh guard: write outcome is journal-ambiguous: {exc}",
            file=sys.stderr,
        )
        return 75
    return proc.returncode


def _github_effect_receipt(
    kind: str,
    command_args: list[str],
    stdout_bytes: bytes,
    control: dict[str, str],
) -> dict[str, object]:
    if len(stdout_bytes) > 2_048:
        raise AutonomyError(
            "protected GitHub write receipt output is too large"
        )
    try:
        stdout = stdout_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AutonomyError(
            "protected GitHub write receipt is not UTF-8"
        ) from exc
    try:
        assert_public_safe_text(
            stdout,
            field="protected GitHub write receipt",
        )
    except PublicSafetyError as exc:
        raise AutonomyError(str(exc)) from exc
    receipt: dict[str, object] = {
        "action": " ".join(command_args[:2]),
        "repo": control["BOT_REPO"],
        "stdout": stdout,
        "verified": True,
    }
    urls = re.findall(
        r"https://github\.com/"
        + re.escape(control["BOT_REPO"])
        + r"/(?:issues|pull)/[1-9][0-9]*"
        r"(?:#[A-Za-z0-9._:-]+)?",
        stdout,
    )
    if urls:
        url = urls[-1]
        receipt["url"] = url
        match = re.search(r"/(?:issues|pull)/([1-9][0-9]*)", url)
        if match:
            receipt["number"] = int(match.group(1))
    if kind in {"issues", "pull_requests"} and "url" not in receipt:
        raise AutonomyError(
            "protected GitHub create succeeded without a typed URL receipt"
        )
    if kind == "labels":
        receipt["target"] = (
            _command_positionals(command_args)[0]
            if _command_positionals(command_args)
            else ""
        )
        labels = _option_values(
            command_args,
            {"--add-label", "--remove-label"},
        )
        if labels:
            receipt["label"] = labels[0]
    return receipt


def main() -> int:
    args = sys.argv[1:]
    try:
        gh = real_gh()
    except AutonomyError as exc:
        print(f"john-lomein gh guard: {exc}", file=sys.stderr)
        return 75
    try:
        command_args = canonical_command_args(args)
        validate_cli_shape(args, command_args)
        args = capture_body_file(args, command_args)
        command_args = canonical_command_args(args)
    except AutonomyError as exc:
        print(f"john-lomein gh guard: {exc}", file=sys.stderr)
        return 75
    if should_guard(command_args):
        repo = value_after(args, {"--repo", "-R"}) or os.environ.get("BOT_REPO") or ""
        pr = pr_number(command_args)
        if not repo or not pr:
            print("john-lomein gh guard: refusing guarded @codex review without repo/pr metadata", file=sys.stderr)
            return 2
        try:
            state = codex_state(gh, repo, pr)
            if state["current_review"] or state["pending"]:
                reason = "already_clean" if state["clean_current"] else ("already_reviewed" if state["current_review"] else "request_already_pending")
                print(
                    f"john-lomein gh guard: skipped duplicate @codex review for {repo}#{pr} "
                    f"head={state['head']} reason={reason}",
                    file=sys.stderr,
                )
                return 0
        except Exception as exc:
            print(f"john-lomein gh guard: unable to verify Codex state, refusing guarded @codex review: {exc}", file=sys.stderr)
            return 2
    kind = effect_kind(command_args)
    if kind:
        try:
            return run_effect_guarded(
                gh,
                args,
                command_args,
                kind,
            )
        except AutonomyError as exc:
            print(
                f"john-lomein gh guard: protected write refused: {exc}",
                file=sys.stderr,
            )
            return 75
    try:
        runtime = autonomy_runtime()
        if runtime is not None:
            deployed_runtime_control(runtime)
            if not is_explicit_read_only(command_args):
                raise AutonomyError(
                    "GitHub command is not on the deployed read-only allowlist"
                )
    except AutonomyError as exc:
        print(
            f"john-lomein gh guard: command refused: {exc}",
            file=sys.stderr,
        )
        return 75
    runtime = autonomy_runtime()
    if runtime is not None:
        proc = subprocess.run(
            [gh, *args],
            input=STDIN_BODY,
            env=gh_env(),
        )
        return proc.returncode
    if STDIN_BODY is not None:
        proc = subprocess.run([gh, *args], input=STDIN_BODY)
        return proc.returncode
    os.execv(gh, [gh, *args])
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
