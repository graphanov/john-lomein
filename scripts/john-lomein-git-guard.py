#!/usr/bin/env python3
"""Journal and bound remote git mutations made by John Lomein workers.

This wrapper does not grant authority. It permits only ordinary non-force
branch pushes from explicitly authorized worker lanes, and it records a
before/after outcome through the autonomy journal. Destructive, tag, broad,
or force pushes fail closed.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_autonomy import (
    AutonomyError,
    begin_effect,
    deployed_runtime_control,
    finish_effect,
    policy_from_runtime,
    reconcile_effect,
    require_active_run,
    require_effective_lane,
    sha256_json,
)

SAFE_ROOT_CONFIGS = frozenset(
    {
        "core.hooksPath=/dev/null",
        "core.fsmonitor=false",
        "core.untrackedCache=false",
        "commit.gpgSign=false",
        "tag.gpgSign=false",
        "core.pager=cat",
        "pager.status=false",
        "diff.external=",
        "interactive.diffFilter=",
        "submodule.recurse=false",
        "push.followTags=false",
        "push.gpgSign=false",
        "push.recurseSubmodules=no",
        "http.followRedirects=false",
    }
)
HARD_FORBIDDEN_PUSH_PATHS = frozenset(
    {
        ".env",
        ".env.*",
        ".github/CODEOWNERS",
        ".github/actions/**",
        ".github/workflows/**",
        ".gitmodules",
        ".npmrc",
    }
)


def real_git() -> str:
    explicit = os.environ.get("JOHN_LOMEIN_REAL_GIT")
    deployed = (SCRIPT_DIR / "john-lomein-instance.env").exists()
    if explicit and not deployed and Path(explicit).exists():
        return explicit
    this = Path(__file__).resolve()
    skip_dirs = {
        str(this.parent),
        str(this.parent / "bin"),
        str(this.parent.parent / "bin"),
    }
    search_path = (
        "/usr/bin:/opt/homebrew/bin:/usr/local/bin:/bin"
        if deployed
        else os.environ.get("PATH", "")
    )
    for raw in search_path.split(os.pathsep):
        if not raw or raw in skip_dirs:
            continue
        candidate = Path(raw) / "git"
        try:
            if (
                candidate.exists()
                and os.access(candidate, os.X_OK)
                and candidate.resolve() != this
                and not (candidate.resolve().stat().st_mode & 0o022)
            ):
                return str(candidate)
        except OSError:
            continue
    raise AutonomyError("trusted git binary not found")


def real_gh() -> str:
    explicit = os.environ.get("JOHN_LOMEIN_REAL_GH")
    deployed = (SCRIPT_DIR / "john-lomein-instance.env").exists()
    if explicit and not deployed and Path(explicit).exists():
        return explicit
    skip_dirs = {
        str(SCRIPT_DIR),
        str(SCRIPT_DIR / "bin"),
        str(SCRIPT_DIR.parent / "bin"),
    }
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
            if (
                candidate.exists()
                and os.access(candidate, os.X_OK)
                and not (candidate.resolve().stat().st_mode & 0o022)
            ):
                return str(candidate.resolve())
        except OSError:
            continue
    raise AutonomyError("trusted GitHub credential helper not found")


def split_command(args: list[str]) -> tuple[list[str], list[str]]:
    value_options = {
        "-C",
        "--git-dir",
        "--work-tree",
        "--namespace",
    }
    boolean_options = {
        "--bare",
        "--no-pager",
        "--no-optional-locks",
        "--paginate",
        "--literal-pathspecs",
        "--glob-pathspecs",
        "--noglob-pathspecs",
        "--icase-pathspecs",
    }
    index = 0
    prefix: list[str] = []
    while index < len(args) and args[index].startswith("-"):
        arg = args[index]
        if arg in value_options:
            if index + 1 >= len(args):
                raise AutonomyError(f"missing value for root git option {arg}")
            prefix.extend(args[index : index + 2])
            index += 2
            continue
        if any(arg.startswith(option + "=") for option in value_options):
            prefix.append(arg)
            index += 1
            continue
        if arg == "-c":
            if index + 1 >= len(args):
                raise AutonomyError("missing value for root git option -c")
            config = args[index + 1]
            if config not in SAFE_ROOT_CONFIGS:
                raise AutonomyError(
                    f"unsupported root-level git configuration: {config}"
                )
            prefix.extend(args[index : index + 2])
            index += 2
            continue
        if arg in boolean_options:
            prefix.append(arg)
            index += 1
            continue
        if arg in {"--help", "--version"}:
            return args, []
        raise AutonomyError(f"unsupported root-level git option: {arg}")
    return prefix, args[index:]


def is_allowed_nonpush(args: list[str]) -> bool:
    if not args:
        return True
    command = args[0]
    allowed = {
        "add",
        "am",
        "apply",
        "archive",
        "bisect",
        "blame",
        "branch",
        "cat-file",
        "check-attr",
        "check-ref-format",
        "checkout",
        "cherry-pick",
        "clean",
        "commit",
        "commit-tree",
        "diff",
        "diff-tree",
        "fetch",
        "for-each-ref",
        "format-patch",
        "fsck",
        "grep",
        "hash-object",
        "log",
        "ls-files",
        "ls-remote",
        "merge",
        "merge-base",
        "merge-tree",
        "mv",
        "pull",
        "range-diff",
        "read-tree",
        "rebase",
        "reflog",
        "request-pull",
        "reset",
        "restore",
        "rev-list",
        "rev-parse",
        "rm",
        "show",
        "show-ref",
        "sparse-checkout",
        "status",
        "switch",
        "tag",
        "update-index",
        "update-ref",
        "verify-commit",
        "verify-tag",
        "whatchanged",
        "worktree",
        "write-tree",
    }
    if command in allowed:
        return True
    if command == "config":
        return len(args) > 1 and (
            args[1] in {
                "--get",
                "--get-all",
                "--get-regexp",
                "--list",
                "-l",
            }
            or args[1].startswith(
                ("--get=", "--get-all=", "--get-regexp=")
            )
        )
    if command == "remote":
        return len(args) == 1 or (
            len(args) > 1
            and args[1] in {"-v", "get-url", "show"}
        )
    return False


def is_mutating_nonpush(args: list[str]) -> bool:
    """Conservatively classify allowed Git commands that can change state."""

    if not args:
        return False
    command = args[0]
    read_only = {
        "archive",
        "blame",
        "cat-file",
        "check-attr",
        "check-ref-format",
        "diff",
        "diff-tree",
        "for-each-ref",
        "fsck",
        "grep",
        "log",
        "ls-files",
        "ls-remote",
        "merge-base",
        "range-diff",
        "request-pull",
        "rev-list",
        "rev-parse",
        "show",
        "show-ref",
        "status",
        "verify-commit",
        "verify-tag",
        "whatchanged",
    }
    if command in read_only or command in {"config", "remote"}:
        return False
    if command == "branch":
        mutation_flags = {
            "-d",
            "-D",
            "-m",
            "-M",
            "-c",
            "-C",
            "--delete",
            "--move",
            "--copy",
            "--edit-description",
            "--set-upstream-to",
            "--unset-upstream",
        }
        return any(
            token in mutation_flags
            or token.startswith(
                (
                    "--set-upstream-to=",
                    "--track=",
                )
            )
            for token in args[1:]
        ) or any(not token.startswith("-") for token in args[1:])
    if command == "tag":
        return any(
            token in {"-a", "-s", "-u", "-d", "-f", "--delete", "--force"}
            or not token.startswith("-")
            for token in args[1:]
        )
    if command == "reflog":
        return len(args) < 2 or args[1] not in {"show", "exists"}
    if command == "worktree":
        return len(args) < 2 or args[1] != "list"
    return True


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


def validate_push_authority(
    git: str,
    lane: str,
    root_options: list[str],
    command_args: list[str],
    control: dict[str, str],
    runtime: Path,
) -> tuple[str, str, str, list[str]]:
    if lane not in {"maintainer", "forge", "portfolio"}:
        raise AutonomyError(f"lane {lane!r} lacks branch-push authority")
    index = 0
    while index < len(root_options):
        option = root_options[index]
        if option == "-C":
            index += 2
            continue
        if option == "-c":
            if (
                index + 1 >= len(root_options)
                or root_options[index + 1] not in SAFE_ROOT_CONFIGS
            ):
                raise AutonomyError(
                    "guarded git push received an unsafe root configuration"
                )
            index += 2
            continue
        if option == "--no-optional-locks":
            index += 1
            continue
        raise AutonomyError(
            f"unsupported guarded git push root option: {option}"
        )
    push_args = command_args[1:]
    if "--no-follow-tags" not in push_args:
        raise AutonomyError(
            "guarded git push requires --no-follow-tags"
        )
    denied_flags = {
        "--all",
        "--delete",
        "-d",
        "--dry-run",
        "-n",
        "--follow-tags",
        "--force",
        "-f",
        "--mirror",
        "--no-dry-run",
        "--prune",
        "--tags",
    }
    allowed_flags = {
        "--atomic",
        "--no-follow-tags",
        "--porcelain",
        "--quiet",
        "-q",
        "--verbose",
        "-v",
    }
    positional: list[str] = []
    normalized_flags: set[str] = set()
    for arg in push_args:
        if (
            arg in denied_flags
            or arg.startswith("--force-with-lease")
            or arg.startswith("--force-if-includes")
        ):
            raise AutonomyError(
                f"destructive or broad git push option is forbidden: {arg}"
            )
        if arg.startswith("+"):
            raise AutonomyError("force-update git refspec is forbidden")
        if ":" in arg:
            source, destination = arg.split(":", 1)
            if not source:
                raise AutonomyError("deleting git refspec is forbidden")
            if destination.startswith("refs/tags/"):
                raise AutonomyError("tag publication requires a broker")
        if arg.startswith("-"):
            if arg not in allowed_flags:
                raise AutonomyError(
                    f"unsupported guarded git push option: {arg}"
                )
            if arg in {"--quiet", "-q"}:
                normalized_flags.add("--quiet")
            elif arg in {"--verbose", "-v"}:
                normalized_flags.add("--verbose")
            elif arg != "--no-follow-tags":
                normalized_flags.add(arg)
            continue
        positional.append(arg)
    if {"--quiet", "--verbose"} <= normalized_flags:
        raise AutonomyError(
            "guarded git push cannot be both quiet and verbose"
        )
    if not positional:
        raise AutonomyError(
            "guarded git push requires an explicit verified remote"
        )
    remote = positional[0]
    refspecs = positional[1:]
    if len(refspecs) != 1 or "tag" in refspecs:
        raise AutonomyError(
            "guarded git push requires exactly one explicit branch refspec"
        )
    branch, head_oid = _push_branch(git, root_options, refspecs)
    canonical_remote = _validate_target_remote(
        git,
        root_options,
        remote,
        control,
    )
    _validate_lane_branch(
        git,
        root_options,
        lane,
        branch,
        control,
    )
    _validate_source_repository(
        git,
        root_options,
        lane=lane,
        branch=branch,
        head_oid=head_oid,
        control=control,
        runtime=runtime,
    )
    flags = ["--no-follow-tags"]
    flags.extend(
        flag
        for flag in ("--atomic", "--porcelain", "--quiet", "--verbose")
        if flag in normalized_flags
    )
    return canonical_remote, branch, head_oid, flags


def git_env() -> dict[str, str]:
    env = dict(os.environ)
    for key in list(env):
        if key.startswith("GIT_"):
            env.pop(key, None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _git_command(git: str, *args: str) -> list[str]:
    return [git, "-c", "core.hooksPath=/dev/null", *args]


def _git_text(git: str, root_options: list[str], *args: str) -> str:
    try:
        return subprocess.check_output(
            _git_command(git, *root_options, *args),
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=20,
            env=git_env(),
        ).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise AutonomyError(
            f"guarded git inspection failed: {' '.join(args)}"
        ) from exc


def _push_branch(
    git: str,
    root_options: list[str],
    refspecs: list[str],
) -> tuple[str, str]:
    refspec = refspecs[0]
    if "refs/tags/" in refspec:
        raise AutonomyError("tag publication requires a broker")
    if ":" not in refspec:
        raise AutonomyError(
            "guarded git push requires SOURCE:refs/heads/BRANCH"
        )
    source, destination = refspec.split(":", 1)
    prefix = "refs/heads/"
    if not destination.startswith(prefix):
        raise AutonomyError(
            "guarded git push destination must be refs/heads/<branch>"
        )
    head = _git_text(git, root_options, "rev-parse", "HEAD").lower()
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", head):
        raise AutonomyError("guarded git push HEAD is not a full commit OID")
    if source != "HEAD" and source.lower() != head:
        raise AutonomyError(
            "guarded git push source must be HEAD or the exact HEAD OID"
        )
    return destination[len(prefix) :], head


def _normalized_github_repo(remote_url: str) -> str:
    patterns = (
        r"^https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$",
        r"^git@github\.com:([^/]+/[^/]+?)(?:\.git)?$",
        r"^ssh://git@github\.com/([^/]+/[^/]+?)(?:\.git)?/?$",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, remote_url.strip(), flags=re.I)
        if match:
            return match.group(1).lower()
    return ""


def _validate_target_remote(
    git: str,
    root_options: list[str],
    remote: str,
    control: dict[str, str],
) -> str:
    repo = str(control.get("BOT_REPO") or "").strip().lower()
    if not repo or "/" not in repo:
        raise AutonomyError("guarded git push lacks configured target repo")
    if re.fullmatch(r"[A-Za-z0-9._-]+", remote):
        remote_url = _git_text(
            git,
            root_options,
            "remote",
            "get-url",
            "--push",
            remote,
        )
    else:
        remote_url = remote
    if _normalized_github_repo(remote_url) != repo:
        raise AutonomyError(
            "guarded git push remote is not the configured target repo"
        )
    rewrite_probe = subprocess.run(
        _git_command(
            git,
            *root_options,
            "config",
            "--get-regexp",
            r"^url\..*\.(insteadOf|pushInsteadOf)$",
        ),
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
        env=git_env(),
    )
    if rewrite_probe.returncode == 0 and rewrite_probe.stdout.strip():
        raise AutonomyError("git URL rewrite configuration is forbidden")
    return f"https://github.com/{repo}.git"


def _validate_lane_branch(
    git: str,
    root_options: list[str],
    lane: str,
    branch: str,
    control: dict[str, str],
) -> None:
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", branch):
        raise AutonomyError("guarded git push branch is unsafe")
    default_branch = control["BOT_DEFAULT_BRANCH"]
    if branch == default_branch:
        raise AutonomyError("direct push to the default branch is forbidden")
    if lane == "forge" and not branch.startswith("forge/"):
        raise AutonomyError("forge may push only forge/* branches")
    if lane == "portfolio":
        prefix = (
            control.get("BOT_OSC_PORTFOLIO_BRANCH_PREFIX")
            or "portfolio/"
        )
        if not branch.startswith(prefix):
            raise AutonomyError(
                "portfolio may push only its configured branch prefix"
            )


def _absolute_git_path(
    git: str,
    root_options: list[str],
    *args: str,
) -> Path:
    raw = _git_text(
        git,
        root_options,
        "rev-parse",
        "--path-format=absolute",
        *args,
    )
    path = Path(raw)
    if not path.is_absolute():
        raise AutonomyError(
            "guarded git repository path is not absolute"
        )
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise AutonomyError(
            "guarded git repository path is unavailable"
        ) from exc


def _registered_worktrees(
    git: str,
    managed: Path,
) -> set[Path]:
    raw = _git_text(
        git,
        ["-C", str(managed)],
        "worktree",
        "list",
        "--porcelain",
    )
    registered: set[Path] = set()
    for line in raw.splitlines():
        if not line.startswith("worktree "):
            continue
        try:
            registered.add(
                Path(line.split(" ", 1)[1]).resolve(strict=True)
            )
        except OSError as exc:
            raise AutonomyError(
                "registered git worktree is unavailable"
            ) from exc
    return registered


def _validate_source_repository(
    git: str,
    root_options: list[str],
    *,
    lane: str,
    branch: str,
    head_oid: str,
    control: dict[str, str],
    runtime: Path,
) -> None:
    try:
        managed = Path(control["BOT_LOCAL"]).expanduser().resolve(
            strict=True
        )
    except OSError as exc:
        raise AutonomyError(
            "configured managed checkout is unavailable"
        ) from exc
    source_top = _absolute_git_path(
        git,
        root_options,
        "--show-toplevel",
    )
    source_common = _absolute_git_path(
        git,
        root_options,
        "--git-common-dir",
    )
    managed_common = _absolute_git_path(
        git,
        ["-C", str(managed)],
        "--git-common-dir",
    )
    try:
        same_repository = os.path.samefile(
            source_common,
            managed_common,
        )
    except OSError:
        same_repository = False
    if not same_repository:
        raise AutonomyError(
            "guarded push source is not the configured repository"
        )
    if source_top not in _registered_worktrees(git, managed):
        raise AutonomyError(
            "guarded push source is not a registered managed worktree"
        )
    if lane == "maintainer":
        allowed_root = managed
        if source_top != managed:
            raise AutonomyError(
                "maintainer push must originate in the managed checkout"
            )
    else:
        allowed_root = (
            runtime
            / "state"
            / "worktrees"
            / ("forge" if lane == "forge" else "portfolio")
        ).resolve()
        if (
            source_top == allowed_root
            or not source_top.is_relative_to(allowed_root)
        ):
            raise AutonomyError(
                f"{lane} push must originate in its runtime worktree root"
            )
    current_branch = _git_text(
        git,
        root_options,
        "branch",
        "--show-current",
    )
    if current_branch != branch:
        raise AutonomyError(
            "guarded push branch does not match the source worktree"
        )
    branch_oid = _git_text(
        git,
        root_options,
        "rev-parse",
        f"refs/heads/{branch}",
    ).lower()
    if branch_oid != head_oid:
        raise AutonomyError(
            "guarded push HEAD is not the exact local branch tip"
        )


def _forbidden_push_patterns(
    control: dict[str, str],
) -> set[str]:
    try:
        configured = json.loads(
            control.get("BOT_FORBIDDEN_PATHS_JSON") or "[]"
        )
    except json.JSONDecodeError as exc:
        raise AutonomyError(
            "guarded push forbidden-path policy is invalid"
        ) from exc
    patterns = set(HARD_FORBIDDEN_PUSH_PATHS)
    for value in configured:
        pattern = str(value).split(":", 1)[0].strip()
        if pattern:
            patterns.add(pattern)
    return patterns


def _changed_paths(
    git: str,
    root_options: list[str],
    base_oid: str,
    head_oid: str,
) -> list[str]:
    try:
        raw = subprocess.check_output(
            _git_command(
                git,
                *root_options,
                "diff",
                "--name-only",
                "-z",
                base_oid,
                head_oid,
                "--",
            ),
            stderr=subprocess.DEVNULL,
            timeout=30,
            env=git_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AutonomyError(
            "guarded push changed-path inspection failed"
        ) from exc
    paths: list[str] = []
    for item in raw.decode("utf-8", errors="strict").split("\0"):
        if not item:
            continue
        path = item.replace("\\", "/")
        if (
            path.startswith("/")
            or path.startswith("../")
            or "/../" in path
            or "\n" in path
            or "\r" in path
        ):
            raise AutonomyError(
                "guarded push contains an unsafe changed path"
            )
        paths.append(path)
    return paths


def _validate_commit_delta(
    git: str,
    root_options: list[str],
    *,
    lane: str,
    base_oid: str,
    head_oid: str,
    control: dict[str, str],
) -> list[str]:
    if base_oid == head_oid:
        return []
    ancestry = subprocess.run(
        _git_command(
            git,
            *root_options,
            "merge-base",
            "--is-ancestor",
            base_oid,
            head_oid,
        ),
        capture_output=True,
        check=False,
        timeout=30,
        env=git_env(),
    )
    if ancestry.returncode != 0:
        raise AutonomyError(
            "guarded push is not a fast-forward from the live remote base"
        )
    changed = _changed_paths(
        git,
        root_options,
        base_oid,
        head_oid,
    )
    if not changed:
        raise AutonomyError(
            "guarded push has no changed paths above the remote base"
        )
    patterns = _forbidden_push_patterns(control)
    blocked = sorted(
        path
        for path in changed
        if any(
            path == pattern
            or fnmatch.fnmatchcase(path, pattern)
            for pattern in patterns
        )
    )
    if blocked:
        raise AutonomyError(
            "guarded push touches forbidden paths: "
            + ",".join(blocked[:8])
        )
    if lane == "portfolio" and any(
        not path.startswith(".osc/plans/backlog/")
        for path in changed
    ):
        raise AutonomyError(
            "portfolio push may change only .osc/plans/backlog/*"
        )
    return changed


def _repository_objects_path(
    git: str,
    root_options: list[str],
) -> Path:
    raw = _git_text(
        git,
        root_options,
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        "objects",
    )
    path = Path(raw)
    if not path.is_absolute():
        top = Path(
            _git_text(
                git,
                root_options,
                "rev-parse",
                "--show-toplevel",
            )
        )
        path = top / path
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise AutonomyError(
            "guarded git push object database is unavailable"
        ) from exc
    if not resolved.is_dir():
        raise AutonomyError(
            "guarded git push object database is not a directory"
        )
    return resolved


def _validated_gh_config_dir(
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
            "guarded git push lacks a deployed GitHub auth profile"
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
        path = expected.resolve(strict=True)
    except OSError as exc:
        raise AutonomyError(
            "guarded git push GitHub auth directory is unavailable"
        ) from exc
    if (
        not path.is_dir()
        or path != expected
    ):
        raise AutonomyError(
            "guarded git push GitHub auth directory does not match "
            "the deployed lane profile"
        )
    return path


def _isolated_gh_env(gh_config_dir: Path) -> dict[str, str]:
    return {
        "PATH": (
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
        ),
        "HOME": str(gh_config_dir.parent.parent),
        "LANG": "C",
        "LC_ALL": "C",
        "GH_CONFIG_DIR": str(gh_config_dir),
        "GH_HOST": "github.com",
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
        "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
    }


def _isolated_push_env(
    *,
    objects: Path,
    gh_config_dir: Path,
) -> dict[str, str]:
    env = _isolated_gh_env(gh_config_dir)
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(objects),
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return env


def _gh_result(
    gh: str,
    args: list[str],
    *,
    env: dict[str, str],
    failure: str,
) -> str:
    try:
        result = subprocess.run(
            [gh, *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AutonomyError(failure) from exc
    if result.returncode != 0:
        raise AutonomyError(failure)
    return result.stdout.strip()


def _authenticated_gh_login(
    gh: str,
    *,
    env: dict[str, str],
) -> str:
    login = _gh_result(
        gh,
        ["api", "user", "--jq", ".login"],
        env=env,
        failure="maintainer push cannot authenticate the GitHub bot",
    )
    if (
        not login
        or len(login) > 100
        or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9-]{0,98}(?:\[bot\])?",
            login,
        )
    ):
        raise AutonomyError(
            "maintainer push received an invalid authenticated GitHub login"
        )
    return login


def _json_login(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    login = value.get("login")
    return login if isinstance(login, str) else ""


def _validate_maintainer_pr_authority(
    gh: str,
    *,
    env: dict[str, str],
    repo: str,
    branch: str,
    authenticated_login: str,
    remote_branch_oid: str | None,
) -> dict[str, object]:
    if remote_branch_oid is None:
        raise AutonomyError(
            "maintainer may push only an existing remote PR branch"
        )
    raw = _gh_result(
        gh,
        [
            "pr",
            "list",
            "--repo",
            repo,
            "--state",
            "open",
            "--head",
            branch,
            "--limit",
            "2",
            "--json",
            (
                "number,author,headRefName,headRefOid,"
                "headRepositoryOwner,isCrossRepository"
            ),
        ],
        env=env,
        failure="maintainer push cannot verify the target PR",
    )
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AutonomyError(
            "maintainer push received malformed target PR data"
        ) from exc
    if not isinstance(values, list):
        raise AutonomyError(
            "maintainer push received malformed target PR data"
        )
    if len(values) != 1:
        raise AutonomyError(
            "maintainer requires exactly one same-repository open PR "
            "for the branch authored by the authenticated GitHub bot"
        )
    repo_owner = repo.split("/", 1)[0]
    candidates = [
        value
        for value in values
        if (
            isinstance(value, dict)
            and type(value.get("number")) is int
            and int(value["number"]) > 0
            and value.get("headRefName") == branch
            and value.get("isCrossRepository") is False
            and _json_login(value.get("headRepositoryOwner")).lower()
            == repo_owner.lower()
            and _json_login(value.get("author")).lower()
            == authenticated_login.lower()
        )
    ]
    if len(candidates) != 1:
        raise AutonomyError(
            "maintainer requires exactly one same-repository open PR "
            "for the branch authored by the authenticated GitHub bot"
        )
    candidate = candidates[0]
    pr_head_oid = candidate.get("headRefOid")
    if pr_head_oid not in {None, ""}:
        if (
            not isinstance(pr_head_oid, str)
            or not re.fullmatch(
                r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})",
                pr_head_oid,
            )
        ):
            raise AutonomyError(
                "maintainer push received a malformed PR head OID"
            )
        if pr_head_oid.lower() != remote_branch_oid:
            raise AutonomyError(
                "maintainer PR head OID does not match the live remote branch"
            )
    return {
        "number": int(candidate["number"]),
        "author": authenticated_login,
        "head_oid": (
            str(pr_head_oid).lower()
            if isinstance(pr_head_oid, str) and pr_head_oid
            else remote_branch_oid
        ),
    }


def _prepare_isolated_git_dir(
    path: Path,
    *,
    head_oid: str,
    credential_helper: str,
) -> None:
    (path / "objects" / "info").mkdir(parents=True, mode=0o700)
    (path / "objects" / "pack").mkdir(mode=0o700)
    (path / "refs" / "heads").mkdir(parents=True, mode=0o700)
    (path / "refs" / "tags").mkdir(mode=0o700)
    (path / "HEAD").write_text(
        "ref: refs/heads/john-lomein-isolated\n",
        encoding="utf-8",
    )
    config = [
        "[core]",
        (
            "\trepositoryformatversion = 1"
            if len(head_oid) == 64
            else "\trepositoryformatversion = 0"
        ),
        "\tbare = true",
        "\tlogallrefupdates = false",
        "[credential]",
        f"\thelper = {credential_helper}",
    ]
    if len(head_oid) == 64:
        config.extend(
            [
                "[extensions]",
                "\tobjectFormat = sha256",
            ]
        )
    (path / "config").write_text(
        "\n".join(config) + "\n",
        encoding="utf-8",
    )


def _exact_git_prefix(
    git: str,
    *,
    git_dir: Path,
) -> list[str]:
    prefix = [git, "--git-dir", str(git_dir)]
    for config in sorted(SAFE_ROOT_CONFIGS):
        prefix.extend(["-c", config])
    return prefix


def _remote_branch_oid(
    prefix: list[str],
    *,
    remote: str,
    branch: str,
    env: dict[str, str],
) -> str | None:
    try:
        result = subprocess.run(
            [
                *prefix,
                "ls-remote",
                "--heads",
                remote,
                f"refs/heads/{branch}",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AutonomyError(
            "guarded git remote readback is unavailable"
        ) from exc
    if result.returncode != 0:
        raise AutonomyError(
            "guarded git remote readback failed"
        )
    if not result.stdout.strip():
        return None
    fields = result.stdout.split()
    if (
        len(fields) < 2
        or not re.fullmatch(
            r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})",
            fields[0],
        )
    ):
        raise AutonomyError(
            "guarded git remote readback is malformed"
        )
    return fields[0].lower()


def run_guarded_push(
    git: str,
    args: list[str],
    root_options: list[str],
    command_args: list[str],
) -> int:
    runtime = autonomy_runtime()
    if runtime is None:
        os.execv(git, [git, *args])
        return 127
    policy = policy_from_runtime(runtime)
    control = deployed_runtime_control(runtime)
    lane = os.environ.get("JOHN_LOMEIN_AUTONOMY_LANE") or ""
    run_id = os.environ.get("JOHN_LOMEIN_AUTONOMY_RUN_ID") or ""
    if not lane or not run_id:
        raise AutonomyError(
            "protected git push is missing an active autonomy run"
        )
    require_effective_lane(control, lane)
    require_active_run(runtime, policy, lane, run_id)
    canonical_remote, branch, head_oid, flags = validate_push_authority(
        git,
        lane,
        root_options,
        command_args,
        control,
        runtime,
    )
    objects = _repository_objects_path(git, root_options)
    gh = real_gh()
    gh_config_dir = _validated_gh_config_dir(
        runtime,
        control,
        lane,
    )
    isolated_gh_env = _isolated_gh_env(gh_config_dir)
    authenticated_login = (
        _authenticated_gh_login(
            gh,
            env=isolated_gh_env,
        )
        if lane == "maintainer"
        else ""
    )
    isolated_env = _isolated_push_env(
        objects=objects,
        gh_config_dir=gh_config_dir,
    )
    helper = f"!{shlex.quote(gh)} auth git-credential"
    with tempfile.TemporaryDirectory(
        prefix="john-lomein-git-broker-"
    ) as tmp:
        git_dir = Path(tmp)
        _prepare_isolated_git_dir(
            git_dir,
            head_oid=head_oid,
            credential_helper=helper,
        )
        exact_prefix = _exact_git_prefix(git, git_dir=git_dir)
        remote_branch_oid = _remote_branch_oid(
            exact_prefix,
            remote=canonical_remote,
            branch=branch,
            env=isolated_env,
        )
        default_oid = _remote_branch_oid(
            exact_prefix,
            remote=canonical_remote,
            branch=control["BOT_DEFAULT_BRANCH"],
            env=isolated_env,
        )
        if default_oid is None:
            raise AutonomyError(
                "guarded git push cannot verify the live default branch"
            )
        maintainer_pr: dict[str, object] | None = None
        if lane == "maintainer":
            maintainer_pr = _validate_maintainer_pr_authority(
                gh,
                env=isolated_gh_env,
                repo=control["BOT_REPO"],
                branch=branch,
                authenticated_login=authenticated_login,
                remote_branch_oid=remote_branch_oid,
            )
        base_oid = remote_branch_oid or default_oid
        changed_paths = _validate_commit_delta(
            git,
            root_options,
            lane=lane,
            base_oid=base_oid,
            head_oid=head_oid,
            control=control,
        )
        operation_fields: dict[str, object] = {
            "tool": "git",
            "operation": "push_exact_oid",
            "remote_sha256": sha256_json(
                {"remote": canonical_remote}
            ),
            "branch_sha256": sha256_json({"branch": branch}),
            "cwd_sha256": sha256_json({"cwd": str(Path.cwd())}),
            "head_sha256": sha256_json({"head": head_oid}),
            "flags": flags,
        }
        operation_digest = sha256_json(operation_fields)
        receipt = {
            "action": "push_exact_oid",
            "repo": control["BOT_REPO"],
            "branch": branch,
            "oid": head_oid,
            "verified": True,
        }
        if maintainer_pr is not None:
            receipt["number"] = maintainer_pr["number"]
        decision = begin_effect(
            runtime,
            policy,
            lane,
            run_id,
            "branches",
            idempotency_key=f"git:branches:{operation_digest}",
            before_sha256=operation_digest,
        )
        if not decision["allowed"]:
            reason = str(decision["reason"])
            if reason in {
                "effect_idempotency_pending",
                "effect_idempotency_failed",
            }:
                effect_id = str(decision.get("effect_id") or "")
                if remote_branch_oid == head_oid:
                    reconcile_effect(
                        runtime,
                        effect_id,
                        observed="completed",
                        receipt=receipt,
                    )
                    print(
                        "john-lomein git guard: reconciled prior "
                        "push from live remote state",
                        file=sys.stderr,
                    )
                    return 0
                reconcile_effect(
                    runtime,
                    effect_id,
                    observed="absent",
                )
                decision = begin_effect(
                    runtime,
                    policy,
                    lane,
                    run_id,
                    "branches",
                    idempotency_key=(
                        f"git:branches:{operation_digest}"
                    ),
                    before_sha256=operation_digest,
                )
                if not decision["allowed"]:
                    reason = str(decision["reason"])
                else:
                    reason = "allowed_after_reconciliation"
            if reason == "effect_idempotency_completed":
                print(
                    "john-lomein git guard: protected push blocked "
                    f"reason={reason}",
                    file=sys.stderr,
                )
                return 0
            if decision["allowed"] and remote_branch_oid == head_oid:
                reconcile_effect(
                    runtime,
                    str(decision["effect_id"]),
                    observed="completed",
                    receipt=receipt,
                )
                return 0
            if decision["allowed"]:
                pass
            else:
                print(
                    "john-lomein git guard: protected push blocked "
                    f"reason={reason}",
                    file=sys.stderr,
                )
                return 75
        if remote_branch_oid == head_oid:
            reconcile_effect(
                runtime,
                str(decision["effect_id"]),
                observed="completed",
                receipt=receipt,
            )
            return 0
        if not changed_paths:
            print(
                "john-lomein git guard: exact remote OID has no "
                "journaled completion",
                file=sys.stderr,
            )
            return 75
        try:
            proc = subprocess.run(
                [
                    *exact_prefix,
                    "push",
                    *flags,
                    canonical_remote,
                    f"{head_oid}:refs/heads/{branch}",
                ],
                check=False,
                env=isolated_env,
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
                "guarded git push could not launch"
            ) from exc
        observed = _remote_branch_oid(
            exact_prefix,
            remote=canonical_remote,
            branch=branch,
            env=isolated_env,
        )
        if observed == head_oid:
            proc_returncode = 0
        elif proc.returncode == 0:
            raise AutonomyError(
                "guarded git push remote readback does not match "
                "the captured OID"
            )
        else:
            proc_returncode = proc.returncode
        try:
            finish_effect(
                runtime,
                str(decision["effect_id"]),
                success=proc_returncode == 0,
                receipt=receipt if proc_returncode == 0 else None,
            )
        except AutonomyError as exc:
            print(
                "john-lomein git guard: push outcome is "
                f"journal-ambiguous: {exc}",
                file=sys.stderr,
            )
            return 75
        return proc_returncode


def main() -> int:
    args = sys.argv[1:]
    try:
        git = real_git()
        root_options, command_args = split_command(args)
        if command_args and (
            command_args[0] == "send-pack"
            or (
                command_args[0] == "lfs"
                and len(command_args) > 1
                and command_args[1]
                in {"push", "prune", "lock", "unlock"}
            )
        ):
            raise AutonomyError(
                "remote git mutation requires the guarded push broker"
            )
        if not command_args or command_args[0] != "push":
            runtime = autonomy_runtime()
            if runtime is not None:
                control = deployed_runtime_control(runtime)
                if not is_allowed_nonpush(command_args):
                    raise AutonomyError(
                        "git command is not on the deployed local/read allowlist"
                    )
                if is_mutating_nonpush(command_args):
                    lane = (
                        os.environ.get("JOHN_LOMEIN_AUTONOMY_LANE")
                        or ""
                    )
                    run_id = (
                        os.environ.get("JOHN_LOMEIN_AUTONOMY_RUN_ID")
                        or ""
                    )
                    require_effective_lane(control, lane)
                    require_active_run(
                        runtime,
                        policy_from_runtime(runtime),
                        lane,
                        run_id,
                    )
            os.execv(git, [git, *args])
            return 127
        return run_guarded_push(
            git,
            args,
            root_options,
            command_args,
        )
    except AutonomyError as exc:
        print(
            f"john-lomein git guard: protected operation refused: {exc}",
            file=sys.stderr,
        )
        return 75


if __name__ == "__main__":
    raise SystemExit(main())
