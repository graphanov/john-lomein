#!/usr/bin/env python3
"""Trusted-parent publication for an owner-scoped Forge implementation.

The coding executor is allowed to leave a dirty implementation worktree, but it
is not trusted with Git or GitHub publication authority.  This module validates
an explicit, structured owner scope and performs the commit, non-force push,
and draft-PR creation in the parent process.  Every externally visible step is
checkpointed atomically so a retry can resume without rewriting history or
creating a duplicate PR.

The module deliberately has no CLI.  Callers must supply separately scoped Git
and GitHub command runners; this keeps credentials out of executor processes
and makes the mutation boundary straightforward to test.
"""
from __future__ import annotations

import fnmatch
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping, Sequence
from urllib.parse import urlsplit

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from john_lomein_comment_templates import format_pr_draft_body


SCOPE_SCHEMA = "john-lomein.forge-owner-scope.v1"
ARTIFACT_SCHEMA = "john-lomein.scoped-publication.v1"
SCOPE_ENV_KEY = "BOT_FORGE_OWNER_SCOPE_JSON"
SCOPE_FILE_ENV_KEY = "BOT_FORGE_OWNER_SCOPE_FILE"
ARTIFACT_NAME = "parent-publication.json"
BODY_NAME = "draft-pr-body.md"
LOCK_NAME = "parent-publication.lock"
MAX_SCOPE_BYTES = 64 * 1024
COMMIT_OID_RE = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
REPO_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})\Z"
)
PHASE_ORDER = {
    "initialized": 0,
    "validated": 1,
    "committed": 2,
    "pushed": 3,
    "complete": 4,
}
SAFE_REGULAR_MODES = {"000000", "100644", "100755"}
SAFE_GIT_PREFIX = [
    "--no-optional-locks",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "commit.gpgSign=false",
    "-c",
    "tag.gpgSign=false",
    "-c",
    "core.pager=cat",
    "-c",
    "pager.status=false",
    "-c",
    "diff.external=",
    "-c",
    "interactive.diffFilter=",
    "-c",
    "submodule.recurse=false",
    "-c",
    "push.followTags=false",
    "-c",
    "push.gpgSign=false",
    "-c",
    "push.recurseSubmodules=no",
    "-c",
    "http.followRedirects=false",
]


class ScopedPublicationError(RuntimeError):
    """A fail-closed publication error with a stable machine code."""

    def __init__(self, code: str, message: str, *, stage: str = "validation") -> None:
        super().__init__(message)
        self.code = code
        self.stage = stage


@dataclass(frozen=True)
class OwnerScope:
    repo: str
    issue: int
    branch: str
    default_branch: str
    base_sha: str
    allowed_paths: tuple[str, ...]
    draft_only: bool
    source_kind: str = "inline_env"

    def canonical_payload(self) -> dict:
        return {
            "schema_version": SCOPE_SCHEMA,
            "repo": self.repo,
            "issue": self.issue,
            "branch": self.branch,
            "default_branch": self.default_branch,
            "base_sha": self.base_sha,
            "allowed_paths": list(self.allowed_paths),
            "draft_only": self.draft_only,
        }

    @property
    def digest(self) -> str:
        raw = json.dumps(self.canonical_payload(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


CommandRunner = Callable[[Sequence[str], Path | None], CommandResult]


@dataclass(frozen=True)
class PublicationResult:
    repo: str
    issue: int
    branch: str
    base_sha: str
    head_sha: str
    changed_paths: tuple[str, ...]
    pr_number: int
    pr_url: str
    artifact_path: Path
    idempotent: bool


class SubprocessRunner:
    """Small injectable runner for callers that already prepared a minimal env."""

    def __init__(self, executable: str | Path, *, env: Mapping[str, str], timeout: int = 180) -> None:
        path = Path(executable)
        if not path.is_absolute() or not path.is_file():
            raise ValueError("command executable must be an existing absolute path")
        self.executable = str(path)
        self.env = dict(env)
        self.timeout = timeout

    def __call__(self, args: Sequence[str], cwd: Path | None) -> CommandResult:
        try:
            proc = subprocess.run(
                [self.executable, *[str(item) for item in args]],
                cwd=str(cwd) if cwd else None,
                env=self.env,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            return CommandResult(proc.returncode, proc.stdout or "", proc.stderr or "")
        except Exception as exc:
            return CommandResult(999, "", type(exc).__name__)


def utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ScopedPublicationError("scope_duplicate_key", f"duplicate owner-scope key: {key}")
        result[key] = value
    return result


def _valid_branch(value: str) -> bool:
    if not value or len(value.encode("utf-8")) > 255:
        return False
    if value.startswith(("-", ".", "/")) or value.endswith(("/", ".", ".lock")):
        return False
    if ".." in value or "@{" in value or "//" in value:
        return False
    if any(ord(char) < 33 or char in "~^:?*[\\" for char in value):
        return False
    return all(part not in {"", ".", ".."} and not part.endswith(".lock") for part in value.split("/"))


def _canonical_repo(value: object) -> str:
    if not isinstance(value, str) or not REPO_RE.fullmatch(value):
        raise ScopedPublicationError("scope_repo_invalid", "owner scope repo must be an exact owner/repo slug")
    if ".." in value or value.endswith(".git"):
        raise ScopedPublicationError("scope_repo_invalid", "owner scope repo is not canonical")
    return value


def _canonical_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 1024:
        raise ScopedPublicationError("scope_path_invalid", "owner-scope paths must be non-empty strings")
    if any(ord(char) < 32 for char in value) or "\\" in value or "\x00" in value:
        raise ScopedPublicationError("scope_path_invalid", f"unsafe owner-scope path: {value!r}")
    if any(char in value for char in "*?[]"):
        raise ScopedPublicationError("scope_path_not_exact", f"owner-scope paths cannot contain globs: {value}")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ScopedPublicationError("scope_path_invalid", f"owner-scope path must be relative: {value}")
    if path.as_posix() != value or any(part.casefold() == ".git" for part in path.parts):
        raise ScopedPublicationError("scope_path_not_canonical", f"owner-scope path is not canonical: {value}")
    return value


def parse_owner_scope(text: str, *, source_kind: str = "inline_env") -> OwnerScope:
    if not isinstance(text, str) or not text.strip():
        raise ScopedPublicationError("scope_missing", "explicit owner-scope JSON is required")
    if len(text.encode("utf-8")) > MAX_SCOPE_BYTES:
        raise ScopedPublicationError("scope_too_large", "owner-scope JSON exceeds the size limit")
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except ScopedPublicationError:
        raise
    except Exception as exc:
        raise ScopedPublicationError("scope_json_invalid", "owner-scope JSON is invalid") from exc
    if not isinstance(data, dict):
        raise ScopedPublicationError("scope_shape_invalid", "owner-scope JSON must be an object")
    required = {
        "schema_version",
        "repo",
        "issue",
        "branch",
        "default_branch",
        "base_sha",
        "allowed_paths",
        "draft_only",
    }
    if set(data) != required:
        missing = sorted(required - set(data))
        extra = sorted(set(data) - required)
        raise ScopedPublicationError(
            "scope_keys_invalid",
            f"owner scope has missing={missing} extra={extra}",
        )
    if data["schema_version"] != SCOPE_SCHEMA:
        raise ScopedPublicationError("scope_schema_invalid", "owner-scope schema_version is not supported")
    repo = _canonical_repo(data["repo"])
    issue = data["issue"]
    if isinstance(issue, bool) or not isinstance(issue, int) or issue <= 0:
        raise ScopedPublicationError("scope_issue_invalid", "owner-scope issue must be a positive integer")
    branch = data["branch"]
    if not isinstance(branch, str) or not _valid_branch(branch):
        raise ScopedPublicationError("scope_branch_invalid", "owner-scope branch is not a valid Git branch")
    if not branch.startswith(f"forge/issue-{issue}-"):
        raise ScopedPublicationError("scope_branch_issue_mismatch", "owner-scope branch is not canonical for its issue")
    default_branch = data["default_branch"]
    if not isinstance(default_branch, str) or not _valid_branch(default_branch):
        raise ScopedPublicationError("scope_default_branch_invalid", "owner-scope default_branch is invalid")
    if default_branch == branch:
        raise ScopedPublicationError("scope_default_branch_invalid", "owner-scope default branch cannot equal the Forge branch")
    base_sha = data["base_sha"]
    if not isinstance(base_sha, str) or not COMMIT_OID_RE.fullmatch(base_sha):
        raise ScopedPublicationError("scope_base_invalid", "owner-scope base_sha must be a full commit OID")
    paths = data["allowed_paths"]
    if not isinstance(paths, list) or not paths:
        raise ScopedPublicationError("scope_paths_missing", "owner scope must contain at least one exact path")
    normalized = tuple(_canonical_path(path) for path in paths)
    if len(set(normalized)) != len(normalized) or len({path.casefold() for path in normalized}) != len(normalized):
        raise ScopedPublicationError("scope_paths_duplicate", "owner-scope paths must be unique")
    if data["draft_only"] is not True:
        raise ScopedPublicationError("scope_not_draft_only", "owner scope must set draft_only to true")
    return OwnerScope(
        repo=repo,
        issue=issue,
        branch=branch,
        default_branch=default_branch,
        base_sha=base_sha.lower(),
        allowed_paths=tuple(sorted(normalized)),
        draft_only=True,
        source_kind=source_kind,
    )


def _revalidate_scope(scope: OwnerScope) -> OwnerScope:
    if not isinstance(scope, OwnerScope):
        raise ScopedPublicationError("scope_object_invalid", "publisher requires a parsed OwnerScope")
    normalized = parse_owner_scope(
        json.dumps(scope.canonical_payload(), sort_keys=True, separators=(",", ":")),
        source_kind=scope.source_kind,
    )
    if normalized.canonical_payload() != scope.canonical_payload():
        raise ScopedPublicationError("scope_object_not_canonical", "OwnerScope object bypassed canonical parsing")
    return normalized


def _read_scope_file(path: Path) -> str:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ScopedPublicationError("scope_file_symlink", "owner-scope file cannot be a symlink")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(expanded, flags)
    except OSError as exc:
        raise ScopedPublicationError("scope_file_unreadable", "owner-scope file cannot be opened safely") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ScopedPublicationError("scope_file_not_regular", "owner-scope file must be regular")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise ScopedPublicationError("scope_file_wrong_owner", "owner-scope file is not owned by the current user")
        if info.st_mode & 0o022:
            raise ScopedPublicationError("scope_file_writable_by_others", "owner-scope file is group/world writable")
        chunks: list[bytes] = []
        remaining = MAX_SCOPE_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_SCOPE_BYTES:
            raise ScopedPublicationError("scope_too_large", "owner-scope file exceeds the size limit")
        try:
            return raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ScopedPublicationError("scope_file_encoding", "owner-scope file must be UTF-8") from exc
    finally:
        os.close(fd)


def load_owner_scope(
    env: Mapping[str, str],
    *,
    inline_key: str = SCOPE_ENV_KEY,
    file_key: str = SCOPE_FILE_ENV_KEY,
) -> OwnerScope:
    inline = str(env.get(inline_key) or "").strip()
    file_value = str(env.get(file_key) or "").strip()
    if bool(inline) == bool(file_value):
        code = "scope_source_conflict" if inline else "scope_missing"
        raise ScopedPublicationError(code, "set exactly one explicit owner-scope JSON source")
    if inline:
        return parse_owner_scope(inline, source_kind="inline_env")
    return parse_owner_scope(_read_scope_file(Path(file_value)), source_kind="owner_file")


def _atomic_write(path: Path, data: str) -> None:
    if path.exists() and path.is_symlink():
        raise ScopedPublicationError("artifact_symlink", f"refusing symlink artifact: {path.name}")
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY | directory_flag)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # The rename is still atomic on platforms that do not allow a
            # directory fsync; supported production macOS does.
            pass
    finally:
        if tmp.exists():
            tmp.unlink()


def _write_artifact(path: Path, state: dict) -> None:
    state["schema_version"] = ARTIFACT_SCHEMA
    state["recorded_at"] = utc()
    _atomic_write(path, json.dumps(state, indent=2, sort_keys=True) + "\n")


def _safe_cycle(cycle: Path) -> Path:
    cycle = Path(os.path.abspath(os.path.expanduser(str(cycle))))
    if cycle.is_symlink():
        raise ScopedPublicationError("cycle_symlink", "publication cycle directory cannot be a symlink")
    if not cycle.exists():
        raise ScopedPublicationError("cycle_missing", "publication cycle directory must already exist")
    if not cycle.is_dir():
        raise ScopedPublicationError("cycle_not_directory", "publication cycle path is not a directory")
    info = cycle.stat()
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ScopedPublicationError("cycle_wrong_owner", "publication cycle directory is not owned by the current user")
    if info.st_mode & 0o022:
        raise ScopedPublicationError("cycle_writable_by_others", "publication cycle directory is group/world writable")
    return cycle


@contextmanager
def _publication_lock(cycle: Path):
    path = cycle / LOCK_NAME
    if path.is_symlink():
        raise ScopedPublicationError("publication_lock_symlink", "publication lock cannot be a symlink")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ScopedPublicationError("publication_lock_open_failed", "publication lock cannot be opened safely") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ScopedPublicationError("publication_lock_not_regular", "publication lock is not a regular file")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise ScopedPublicationError("publication_lock_wrong_owner", "publication lock has the wrong owner")
        if info.st_mode & 0o077:
            raise ScopedPublicationError("publication_lock_permissions", "publication lock must be owner-only")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ScopedPublicationError("publication_lock_busy", "another scoped publisher owns this cycle") from exc
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)


def _binding(scope: OwnerScope) -> dict:
    return {
        "scope_digest": scope.digest,
        "repo": scope.repo,
        "issue": scope.issue,
        "branch": scope.branch,
        "default_branch": scope.default_branch,
        "base_sha": scope.base_sha,
        "allowed_paths": list(scope.allowed_paths),
        "draft_only": True,
    }


def _initial_state(scope: OwnerScope) -> dict:
    return {
        "status": "in_progress",
        "checkpoint": "initialized",
        "binding": _binding(scope),
        "head_sha": "",
        "changed_paths": [],
        "pr": {},
        "error": {},
    }


def _load_state(path: Path, scope: OwnerScope) -> tuple[dict, bool]:
    if not path.exists():
        return _initial_state(scope), False
    if path.is_symlink() or not path.is_file():
        raise ScopedPublicationError("artifact_unsafe", "publication artifact is not a safe regular file")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ScopedPublicationError("artifact_invalid", "publication artifact is unreadable") from exc
    if not isinstance(state, dict) or state.get("schema_version") != ARTIFACT_SCHEMA:
        raise ScopedPublicationError("artifact_schema_invalid", "publication artifact schema is invalid")
    if state.get("binding") != _binding(scope):
        raise ScopedPublicationError("artifact_scope_mismatch", "publication artifact does not match owner scope")
    checkpoint = str(state.get("checkpoint") or "")
    if checkpoint not in PHASE_ORDER:
        raise ScopedPublicationError("artifact_checkpoint_invalid", "publication artifact checkpoint is invalid")
    return state, True


def _run(
    runner: CommandRunner,
    args: Sequence[str],
    cwd: Path | None,
    *,
    code: str,
    stage: str,
) -> CommandResult:
    result = runner([str(item) for item in args], cwd)
    if not isinstance(result, CommandResult):
        raise ScopedPublicationError("runner_contract_invalid", "command runner returned an invalid result", stage=stage)
    if result.returncode != 0:
        raise ScopedPublicationError(code, f"{stage} command failed with exit {result.returncode}", stage=stage)
    return result


def _git_args(*args: str) -> list[str]:
    return [*SAFE_GIT_PREFIX, *args]


def _run_git(
    runner: CommandRunner,
    cwd: Path,
    *args: str,
    code: str = "git_command_failed",
    stage: str = "validation",
) -> CommandResult:
    return _run(runner, _git_args(*args), cwd, code=code, stage=stage)


def _git_text(runner: CommandRunner, cwd: Path, *args: str, stage: str = "validation") -> str:
    return _run_git(runner, cwd, *args, stage=stage).stdout.strip()


def _split_z(value: str) -> tuple[str, ...]:
    return tuple(item for item in value.split("\0") if item)


def _git_z_paths(runner: CommandRunner, cwd: Path, *args: str, stage: str = "validation") -> set[str]:
    return set(_split_z(_run_git(runner, cwd, *args, stage=stage).stdout))


def _resolve_git_path(raw: str, cwd: Path) -> Path:
    value = Path(raw)
    if not value.is_absolute():
        value = cwd / value
    return value.resolve(strict=False)


def _first_symlink_component(path: Path) -> Path | None:
    absolute = Path(os.path.abspath(str(path)))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            return current
    return None


def _require_owned_directory(path: Path, code: str) -> None:
    if _first_symlink_component(path) is not None or not path.is_dir():
        raise ScopedPublicationError(code, "trusted publication directory is missing or traverses a symlink")
    info = path.stat()
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ScopedPublicationError(code, "trusted publication directory has the wrong owner")
    if info.st_mode & 0o022:
        raise ScopedPublicationError(code, "trusted publication directory is group/world writable")


def _require_owned_regular(path: Path, code: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ScopedPublicationError(code, "trusted Git control file is missing, non-regular, or a symlink")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ScopedPublicationError(code, "trusted Git control file has an unsafe type or link count")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise ScopedPublicationError(code, "trusted Git control file has the wrong owner")
    if info.st_mode & 0o022:
        raise ScopedPublicationError(code, "trusted Git control file is group/world writable")


def _validate_owned_worktree(
    *,
    git_runner: CommandRunner,
    worktree: Path,
    expected_worktree: Path,
    worktree_root: Path,
    managed_checkout: Path,
    branch: str,
) -> tuple[Path, Path]:
    worktree = Path(os.path.abspath(os.path.expanduser(str(worktree))))
    expected = Path(os.path.abspath(os.path.expanduser(str(expected_worktree))))
    root = Path(os.path.abspath(os.path.expanduser(str(worktree_root))))
    managed = Path(os.path.abspath(os.path.expanduser(str(managed_checkout))))
    if worktree != expected:
        raise ScopedPublicationError("worktree_path_mismatch", "implementation worktree is not the deterministic expected path")
    try:
        worktree.relative_to(root)
    except ValueError as exc:
        raise ScopedPublicationError("worktree_outside_owned_root", "implementation worktree is outside its owned root") from exc
    _require_owned_directory(root, "worktree_root_unsafe")
    _require_owned_directory(managed, "managed_checkout_invalid")
    current = root
    for part in worktree.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise ScopedPublicationError("worktree_symlink", "implementation worktree contains a symlink component")
    _require_owned_directory(worktree, "worktree_directory_unsafe")
    dot_git = worktree / ".git"
    if not worktree.is_dir() or dot_git.is_symlink() or not dot_git.is_file():
        raise ScopedPublicationError("worktree_not_linked", "implementation path is not a linked Git worktree")
    _require_owned_regular(dot_git, "worktree_git_pointer_unsafe")
    if (managed / ".git").is_symlink() or not (managed / ".git").is_dir():
        raise ScopedPublicationError("managed_checkout_invalid", "managed checkout is not a canonical Git checkout")
    top = _git_text(git_runner, worktree, "rev-parse", "--show-toplevel")
    managed_top = _git_text(git_runner, managed, "rev-parse", "--show-toplevel")
    if _resolve_git_path(top, worktree) != worktree.resolve() or _resolve_git_path(managed_top, managed) != managed.resolve():
        raise ScopedPublicationError("checkout_root_mismatch", "Git top-level path is not canonical")
    common = _resolve_git_path(_git_text(git_runner, worktree, "rev-parse", "--git-common-dir"), worktree)
    managed_common = _resolve_git_path(_git_text(git_runner, managed, "rev-parse", "--git-common-dir"), managed)
    expected_common = (managed / ".git").resolve()
    if common != managed_common or common != expected_common:
        raise ScopedPublicationError("worktree_common_git_mismatch", "implementation worktree is not owned by the managed checkout")
    _require_owned_directory(common, "worktree_common_git_unsafe")
    raw_git_dir = _git_text(git_runner, worktree, "rev-parse", "--git-dir")
    git_dir = _resolve_git_path(raw_git_dir, worktree)
    try:
        git_dir.relative_to(common / "worktrees")
    except ValueError as exc:
        raise ScopedPublicationError("worktree_git_dir_mismatch", "linked worktree Git directory is outside common Git ownership") from exc
    _require_owned_directory(git_dir, "worktree_git_dir_unsafe")
    try:
        dot_git_lines = dot_git.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ScopedPublicationError("worktree_git_pointer_invalid", "linked worktree .git pointer is unreadable") from exc
    if len(dot_git_lines) != 1 or not dot_git_lines[0].startswith("gitdir: "):
        raise ScopedPublicationError("worktree_git_pointer_invalid", "linked worktree .git pointer is malformed")
    if _resolve_git_path(dot_git_lines[0].split(": ", 1)[1], worktree) != git_dir:
        raise ScopedPublicationError("worktree_git_pointer_mismatch", "linked worktree .git pointer does not match Git")
    commondir_file = git_dir / "commondir"
    backlink_file = git_dir / "gitdir"
    if (
        commondir_file.is_symlink()
        or backlink_file.is_symlink()
        or not commondir_file.is_file()
        or not backlink_file.is_file()
    ):
        raise ScopedPublicationError("worktree_git_backlink_invalid", "linked worktree ownership files are unsafe")
    for control_file in [commondir_file, backlink_file, git_dir / "HEAD", git_dir / "index"]:
        _require_owned_regular(control_file, "worktree_git_control_unsafe")
    for optional_control in [common / "config", common / "HEAD", common / "packed-refs"]:
        if optional_control.exists():
            _require_owned_regular(optional_control, "worktree_common_control_unsafe")
    _require_owned_directory(common / "refs", "worktree_branch_ref_unsafe")
    _require_owned_directory(common / "refs" / "heads", "worktree_branch_ref_unsafe")
    branch_ref = common / "refs" / "heads"
    for part in PurePosixPath(branch).parts:
        branch_ref = branch_ref / part
        if branch_ref.is_dir():
            _require_owned_directory(branch_ref, "worktree_branch_ref_unsafe")
    if branch_ref.exists():
        _require_owned_regular(branch_ref, "worktree_branch_ref_unsafe")
    if _resolve_git_path(commondir_file.read_text(encoding="utf-8").strip(), git_dir) != common:
        raise ScopedPublicationError("worktree_commondir_mismatch", "linked worktree commondir does not match managed Git")
    if _resolve_git_path(backlink_file.read_text(encoding="utf-8").strip(), git_dir) != dot_git.resolve():
        raise ScopedPublicationError("worktree_backlink_mismatch", "linked worktree backlink does not match its .git file")
    actual_branch = _git_text(git_runner, worktree, "branch", "--show-current")
    if actual_branch != branch:
        raise ScopedPublicationError("worktree_branch_mismatch", "implementation worktree is on the wrong branch")
    _run_git(git_runner, worktree, "check-ref-format", "--branch", branch)
    return worktree, managed


def canonical_github_origin(url: str) -> str:
    try:
        parsed = urlsplit(url.strip())
        parsed_port = parsed.port
    except Exception as exc:
        raise ScopedPublicationError("origin_invalid", "origin URL is invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed_port is not None
        or parsed.query
        or parsed.fragment
        or "%" in parsed.path
    ):
        raise ScopedPublicationError("origin_not_canonical_https", "origin must be canonical GitHub HTTPS without credentials")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        raise ScopedPublicationError("origin_invalid", "origin URL must identify exactly one owner/repo")
    if parts[1].endswith(".git"):
        parts[1] = parts[1][:-4]
    repo = _canonical_repo("/".join(parts))
    if url.strip() not in {f"https://github.com/{repo}", f"https://github.com/{repo}.git"}:
        raise ScopedPublicationError("origin_not_canonical_https", "origin URL spelling is not canonical")
    return repo


def _validate_remote_endpoint(git_runner: CommandRunner, worktree: Path, repo: str) -> str:
    rewrite = git_runner(_git_args("config", "--get-regexp", r"^url\."), worktree)
    if not isinstance(rewrite, CommandResult):
        raise ScopedPublicationError("runner_contract_invalid", "Git runner returned an invalid result", stage="push")
    if rewrite.returncode == 0 and rewrite.stdout.strip():
        raise ScopedPublicationError("git_url_rewrite_forbidden", "Git URL rewrite configuration is forbidden", stage="push")
    if rewrite.returncode not in {0, 1}:
        raise ScopedPublicationError("git_url_rewrite_lookup_failed", "Git URL rewrite lookup failed", stage="push")

    fetch_urls = [
        line.strip()
        for line in _run_git(git_runner, worktree, "remote", "get-url", "--all", "origin", stage="push").stdout.splitlines()
        if line.strip()
    ]
    push_urls = [
        line.strip()
        for line in _run_git(
            git_runner,
            worktree,
            "remote",
            "get-url",
            "--push",
            "--all",
            "origin",
            stage="push",
        ).stdout.splitlines()
        if line.strip()
    ]
    if len(fetch_urls) != 1 or len(push_urls) != 1 or fetch_urls != push_urls:
        raise ScopedPublicationError("origin_push_endpoint_mismatch", "origin must have one identical fetch/push endpoint", stage="push")
    canonical = canonical_github_origin(fetch_urls[0])
    if canonical.casefold() != repo.casefold():
        raise ScopedPublicationError("origin_repo_mismatch", "origin does not match the bound owner-scope repo", stage="push")
    return fetch_urls[0]


def _forbidden_pattern(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScopedPublicationError("forbidden_pattern_invalid", "forbidden path patterns must be non-empty strings")
    raw = value.strip().split(":", 1)[0]
    if not raw or raw.startswith("/") or "\\" in raw or any(ord(char) < 32 for char in raw):
        raise ScopedPublicationError("forbidden_pattern_invalid", f"invalid forbidden path pattern: {value!r}")
    parts = PurePosixPath(raw).parts
    if any(part in {"", ".", ".."} for part in parts):
        raise ScopedPublicationError("forbidden_pattern_invalid", f"invalid forbidden path pattern: {value!r}")
    return raw


def path_is_forbidden(path: str, forbidden_paths: Sequence[str]) -> bool:
    folded = path.casefold()
    for item in forbidden_paths:
        pattern = _forbidden_pattern(item).casefold()
        if folded == pattern or fnmatch.fnmatchcase(folded, pattern):
            return True
        if pattern.endswith("/**") and folded.startswith(pattern[:-3].rstrip("/") + "/"):
            return True
        if pattern.endswith("/") and folded.startswith(pattern):
            return True
    return False


def _collect_dirty_paths(git_runner: CommandRunner, worktree: Path) -> tuple[str, ...]:
    paths = set()
    paths.update(
        _git_z_paths(
            git_runner,
            worktree,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--name-only",
            "-z",
            "--",
        )
    )
    paths.update(
        _git_z_paths(
            git_runner,
            worktree,
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--no-renames",
            "--name-only",
            "-z",
            "--",
        )
    )
    paths.update(_git_z_paths(git_runner, worktree, "ls-files", "--others", "--exclude-standard", "-z", "--"))
    normalized = tuple(sorted(_canonical_path(path) for path in paths))
    if len(set(normalized)) != len(normalized):
        raise ScopedPublicationError("dirty_paths_ambiguous", "dirty Git paths are ambiguous")
    return normalized


def _validate_filesystem_path(worktree: Path, rel: str) -> None:
    root = worktree.resolve()
    current = worktree
    for part in PurePosixPath(rel).parts:
        current = current / part
        if current.is_symlink():
            raise ScopedPublicationError("changed_path_symlink", f"changed path is or traverses a symlink: {rel}")
    if not current.exists():
        return  # deletion of a regular tracked file is checked from the staged raw modes
    try:
        current.resolve().relative_to(root)
    except ValueError as exc:
        raise ScopedPublicationError("changed_path_escape", f"changed path escapes the worktree: {rel}") from exc
    info = current.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ScopedPublicationError("changed_path_not_regular", f"changed path is not a regular file: {rel}")
    if info.st_nlink != 1:
        raise ScopedPublicationError("changed_path_hardlink", f"changed path has multiple hard links: {rel}")


def _validate_no_clean_filters(git_runner: CommandRunner, worktree: Path, paths: Sequence[str]) -> None:
    result = _run_git(git_runner, worktree, "check-attr", "-z", "filter", "--", *paths)
    fields = _split_z(result.stdout)
    if len(fields) % 3 != 0:
        raise ScopedPublicationError("git_attributes_ambiguous", "Git attribute output is malformed")
    for index in range(0, len(fields), 3):
        value = fields[index + 2]
        if value not in {"unspecified", "unset"}:
            raise ScopedPublicationError("clean_filter_forbidden", f"changed path uses a configured clean filter: {fields[index]}")


def _validate_staged_modes(raw: str) -> None:
    fields = _split_z(raw)
    if len(fields) % 2 != 0:
        raise ScopedPublicationError("staged_diff_ambiguous", "staged raw diff is malformed", stage="commit")
    for index in range(0, len(fields), 2):
        header = fields[index]
        bits = header.split()
        if len(bits) != 5 or not bits[0].startswith(":"):
            raise ScopedPublicationError("staged_diff_ambiguous", "staged raw diff header is malformed", stage="commit")
        old_mode = bits[0][1:]
        new_mode = bits[1]
        if old_mode not in SAFE_REGULAR_MODES or new_mode not in SAFE_REGULAR_MODES:
            raise ScopedPublicationError("staged_type_forbidden", "symlink, gitlink, or special-file change is forbidden", stage="commit")
        if old_mode != "000000" and new_mode != "000000" and old_mode != new_mode:
            raise ScopedPublicationError("staged_type_change", "file mode/type changes are forbidden", stage="commit")


def _validate_tree_snapshot(
    git_runner: CommandRunner,
    worktree: Path,
    *,
    base_sha: str,
    tree_sha: str,
    changed_paths: Sequence[str],
) -> None:
    if not COMMIT_OID_RE.fullmatch(tree_sha):
        raise ScopedPublicationError("tree_oid_invalid", "staged tree does not have a full OID", stage="commit")
    _run_git(
        git_runner,
        worktree,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--check",
        base_sha,
        tree_sha,
        "--",
        stage="commit",
    )
    tree_paths = _git_z_paths(
        git_runner,
        worktree,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "--name-only",
        "-z",
        base_sha,
        tree_sha,
        "--",
        stage="commit",
    )
    if tree_paths != set(changed_paths):
        raise ScopedPublicationError("tree_paths_mismatch", "staged tree paths do not exactly match owner scope", stage="commit")
    raw = _run_git(
        git_runner,
        worktree,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--raw",
        "--no-renames",
        "-z",
        base_sha,
        tree_sha,
        "--",
        stage="commit",
    ).stdout
    _validate_staged_modes(raw)


def _verify_exact_commit(
    git_runner: CommandRunner,
    worktree: Path,
    *,
    branch: str,
    base_sha: str,
    head_sha: str,
    tree_sha: str,
    changed_paths: Sequence[str],
) -> None:
    if not COMMIT_OID_RE.fullmatch(head_sha):
        raise ScopedPublicationError("commit_head_invalid", "publication commit lacks a full OID", stage="commit")
    if _git_text(git_runner, worktree, "branch", "--show-current", stage="commit") != branch:
        raise ScopedPublicationError("committed_branch_mismatch", "publication branch changed during commit", stage="commit")
    if _git_text(git_runner, worktree, "rev-parse", "HEAD", stage="commit").lower() != head_sha:
        raise ScopedPublicationError("committed_head_mismatch", "worktree HEAD differs from publication checkpoint", stage="commit")
    if _git_text(git_runner, worktree, "rev-parse", "HEAD^", stage="commit").lower() != base_sha:
        raise ScopedPublicationError("commit_parent_mismatch", "publication commit parent differs from bound base", stage="commit")
    if _git_text(git_runner, worktree, "rev-list", "--count", f"{base_sha}..HEAD", stage="commit") != "1":
        raise ScopedPublicationError("commit_count_mismatch", "publication branch must contain exactly one commit", stage="commit")
    committed_tree = _git_text(git_runner, worktree, "rev-parse", "HEAD^{tree}", stage="commit").lower()
    if committed_tree != tree_sha:
        raise ScopedPublicationError("commit_tree_mismatch", "publication commit tree differs from the validated index tree", stage="commit")
    _validate_tree_snapshot(
        git_runner,
        worktree,
        base_sha=base_sha,
        tree_sha=committed_tree,
        changed_paths=changed_paths,
    )
    if _run_git(
        git_runner,
        worktree,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        stage="commit",
    ).stdout:
        raise ScopedPublicationError("worktree_not_clean", "worktree is not clean after trusted-parent commit", stage="commit")


def _remote_ref_head(git_runner: CommandRunner, worktree: Path, remote_url: str, ref: str) -> str:
    result = git_runner(_git_args("ls-remote", "--heads", remote_url, ref), worktree)
    if not isinstance(result, CommandResult):
        raise ScopedPublicationError("runner_contract_invalid", "Git runner returned an invalid result", stage="push")
    if result.returncode != 0:
        raise ScopedPublicationError("remote_branch_lookup_failed", "remote branch lookup failed", stage="push")
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return ""
    if len(lines) != 1:
        raise ScopedPublicationError("remote_branch_ambiguous", "remote branch lookup returned multiple refs", stage="push")
    parts = lines[0].split()
    if len(parts) != 2 or parts[1] != ref or not COMMIT_OID_RE.fullmatch(parts[0]):
        raise ScopedPublicationError("remote_branch_ambiguous", "remote branch lookup returned malformed evidence", stage="push")
    return parts[0].lower()


def _deterministic_pr(scope: OwnerScope, changed_paths: Sequence[str]) -> tuple[str, str]:
    title = f"chore: owner-scoped implementation for #{scope.issue}"
    body = format_pr_draft_body(
        summary=[f"Implements the explicitly owner-scoped draft slice for issue #{scope.issue}."],
        scope=[f"Update `{path}` within the bound owner scope." for path in changed_paths],
        out_of_scope=[
            "Merge, release, publish, workflow dispatch, force-push, repository settings, branch protection, and secrets access.",
        ],
        verification=[
            "Trusted-parent `git diff --cached --check` passed before commit.",
            "Independent configured verification and Codex review remain required before any owner gate.",
        ],
        risk=["Draft-only publication; the exact changed path set is bound to an explicit owner scope."],
        linked_issue=f"Closes #{scope.issue}",
        authority="Draft PR only. This does not authorize merge, release, publish, workflow dispatch, force-push, settings changes, branch-protection changes, or secrets access.",
    )
    return title, body


def _gh_json(
    runner: CommandRunner,
    args: Sequence[str],
    cwd: Path,
    *,
    code: str,
    stage: str,
) -> object:
    result = _run(runner, args, cwd, code=code, stage=stage)
    try:
        return json.loads(result.stdout or "null")
    except Exception as exc:
        raise ScopedPublicationError(code, f"{stage} returned invalid JSON", stage=stage) from exc


def _list_prs_for_branch(gh_runner: CommandRunner, worktree: Path, scope: OwnerScope) -> list[dict]:
    data = _gh_json(
        gh_runner,
        [
            "pr",
            "list",
            "--repo",
            scope.repo,
            "--head",
            scope.branch,
            "--state",
            "all",
            "--json",
            "number,url,state,isDraft,headRefName,headRefOid,baseRefName,baseRefOid,headRepository,headRepositoryOwner,isCrossRepository,title,body",
        ],
        worktree,
        code="pr_lookup_failed",
        stage="pr",
    )
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise ScopedPublicationError("pr_lookup_invalid", "branch PR lookup did not return a list", stage="pr")
    return data


def _view_pr(gh_runner: CommandRunner, worktree: Path, scope: OwnerScope, number: int) -> dict:
    data = _gh_json(
        gh_runner,
        [
            "pr",
            "view",
            str(number),
            "--repo",
            scope.repo,
            "--json",
            "number,url,state,isDraft,headRefName,headRefOid,baseRefName,baseRefOid,headRepository,headRepositoryOwner,isCrossRepository,title,body",
        ],
        worktree,
        code="pr_readback_failed",
        stage="pr",
    )
    if not isinstance(data, dict):
        raise ScopedPublicationError("pr_readback_invalid", "PR readback did not return an object", stage="pr")
    return data


def _verify_pr(
    pr: dict,
    *,
    scope: OwnerScope,
    default_branch: str,
    head_sha: str,
    title: str,
    body: str,
) -> tuple[int, str]:
    number = pr.get("number")
    if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
        raise ScopedPublicationError("pr_number_invalid", "PR readback lacks a valid number", stage="pr")
    expected = {
        "state": "OPEN",
        "isDraft": True,
        "headRefName": scope.branch,
        "headRefOid": head_sha,
        "baseRefName": default_branch,
        "baseRefOid": scope.base_sha,
        "isCrossRepository": False,
        "title": title,
        "body": body,
    }
    for key, value in expected.items():
        actual = pr.get(key)
        if key in {"state", "headRefOid", "baseRefOid"} and isinstance(actual, str) and isinstance(value, str):
            matches = actual.upper() == value.upper()
        else:
            matches = actual == value
        if not matches:
            raise ScopedPublicationError("pr_readback_mismatch", f"draft PR readback mismatch: {key}", stage="pr")
    head_repository = pr.get("headRepository")
    head_owner = pr.get("headRepositoryOwner")
    expected_owner, expected_name = scope.repo.split("/", 1)
    if (
        not isinstance(head_repository, dict)
        or str(head_repository.get("name") or "").casefold() != expected_name.casefold()
        or not isinstance(head_owner, dict)
        or str(head_owner.get("login") or "").casefold() != expected_owner.casefold()
    ):
        raise ScopedPublicationError("pr_head_repository_mismatch", "draft PR head repository is not the bound repo", stage="pr")
    name_with_owner = str(head_repository.get("nameWithOwner") or "")
    if name_with_owner and name_with_owner.casefold() != scope.repo.casefold():
        raise ScopedPublicationError("pr_head_repository_mismatch", "draft PR head repository identity conflicts with the bound repo", stage="pr")
    url = str(pr.get("url") or "")
    if url != f"https://github.com/{scope.repo}/pull/{number}":
        raise ScopedPublicationError("pr_url_invalid", "PR readback URL is not canonical", stage="pr")
    return number, url


def _publish_scoped_draft_locked(
    scope: OwnerScope,
    *,
    expected_repo: str,
    expected_issue: int,
    expected_branch: str,
    expected_base_sha: str,
    default_branch: str,
    worktree: Path,
    expected_worktree: Path,
    worktree_root: Path,
    managed_checkout: Path,
    cycle: Path,
    forbidden_paths: Sequence[str],
    git_runner: CommandRunner,
    github_runner: CommandRunner,
) -> PublicationResult:
    """Validate, commit, push, and create/read back one exact draft PR.

    No force-push, checkout, reset, merge, publish, release, or workflow
    dispatch command exists in this state machine.  A failed retry resumes only
    from an atomically recorded checkpoint bound to the same owner scope.
    """

    scope = _revalidate_scope(scope)
    cycle = _safe_cycle(cycle)
    artifact = cycle / ARTIFACT_NAME
    state, existed = _load_state(artifact, scope)
    artifact_writable = True
    try:
        if scope.repo != expected_repo or scope.issue != expected_issue or scope.branch != expected_branch:
            raise ScopedPublicationError("scope_binding_mismatch", "owner scope does not match the selected Forge candidate")
        if not COMMIT_OID_RE.fullmatch(expected_base_sha) or scope.base_sha != expected_base_sha.lower():
            raise ScopedPublicationError("scope_base_mismatch", "owner scope does not match the selected base commit")
        if not _valid_branch(default_branch) or default_branch != scope.default_branch:
            raise ScopedPublicationError("default_branch_mismatch", "configured default branch does not match owner scope")
        if scope.draft_only is not True:
            raise ScopedPublicationError("scope_not_draft_only", "only draft publication is supported")
        for path in scope.allowed_paths:
            if path_is_forbidden(path, forbidden_paths):
                raise ScopedPublicationError("scope_contains_forbidden_path", f"owner scope includes forbidden path: {path}")

        worktree, managed = _validate_owned_worktree(
            git_runner=git_runner,
            worktree=worktree,
            expected_worktree=expected_worktree,
            worktree_root=worktree_root,
            managed_checkout=managed_checkout,
            branch=scope.branch,
        )
        remote_url = _validate_remote_endpoint(git_runner, worktree, scope.repo)
        live_base = _remote_ref_head(
            git_runner,
            worktree,
            remote_url,
            f"refs/heads/{default_branch}",
        )
        if live_base != scope.base_sha:
            raise ScopedPublicationError("live_remote_base_mismatch", "live default branch no longer matches the owner-scoped base", stage="push")
        remote_base = _git_text(
            git_runner,
            worktree,
            "rev-parse",
            "--verify",
            f"origin/{default_branch}^{{commit}}",
        ).lower()
        if remote_base != scope.base_sha:
            raise ScopedPublicationError("remote_base_mismatch", "origin default branch no longer matches the bound base")
        managed_head = _git_text(git_runner, managed, "rev-parse", "HEAD").lower()
        if managed_head != scope.base_sha:
            raise ScopedPublicationError("managed_base_mismatch", "managed checkout is not at the bound base")

        checkpoint = str(state["checkpoint"])
        local_head = _git_text(git_runner, worktree, "rev-parse", "HEAD").lower()
        if checkpoint == "validated" and local_head != scope.base_sha:
            recovery_tree = str(state.get("expected_tree") or "").lower()
            recovery_paths = tuple(str(path) for path in state.get("changed_paths") or [])
            if not COMMIT_OID_RE.fullmatch(recovery_tree) or not recovery_paths:
                raise ScopedPublicationError("worktree_base_mismatch", "validated checkpoint cannot prove an interrupted commit")
            _verify_exact_commit(
                git_runner,
                worktree,
                branch=scope.branch,
                base_sha=scope.base_sha,
                head_sha=local_head,
                tree_sha=recovery_tree,
                changed_paths=recovery_paths,
            )
            state.update(
                {
                    "status": "in_progress",
                    "checkpoint": "committed",
                    "head_sha": local_head,
                    "error": {},
                }
            )
            _write_artifact(artifact, state)
            checkpoint = "committed"

        if PHASE_ORDER[checkpoint] < PHASE_ORDER["committed"]:
            local_head = _git_text(git_runner, worktree, "rev-parse", "HEAD").lower()
            if local_head != scope.base_sha:
                raise ScopedPublicationError("worktree_base_mismatch", "fresh publication branch is not at the bound base")
            if _remote_ref_head(git_runner, worktree, remote_url, f"refs/heads/{scope.branch}"):
                raise ScopedPublicationError("remote_branch_collision", "remote branch already exists before a recorded commit", stage="push")
            if _list_prs_for_branch(github_runner, worktree, scope):
                raise ScopedPublicationError("existing_pr_collision", "a PR already exists before a recorded commit", stage="pr")
            changed_paths = _collect_dirty_paths(git_runner, worktree)
            if not changed_paths:
                raise ScopedPublicationError("dirty_paths_missing", "publication requires a non-empty dirty path set")
            outside = sorted(set(changed_paths) - set(scope.allowed_paths))
            if outside:
                raise ScopedPublicationError("dirty_paths_outside_scope", f"dirty paths outside owner scope: {outside}")
            for path in changed_paths:
                if path_is_forbidden(path, forbidden_paths):
                    raise ScopedPublicationError("dirty_path_forbidden", f"dirty path is forbidden: {path}")
                _validate_filesystem_path(worktree, path)
            _validate_no_clean_filters(git_runner, worktree, changed_paths)
            state.update(
                {
                    "status": "in_progress",
                    "checkpoint": "validated",
                    "changed_paths": list(changed_paths),
                    "expected_tree": "",
                    "error": {},
                }
            )
            _write_artifact(artifact, state)

            _run_git(git_runner, worktree, "add", "--", *changed_paths, stage="commit")
            staged = _git_z_paths(
                git_runner,
                worktree,
                "diff",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--name-only",
                "-z",
                scope.base_sha,
                "--",
                stage="commit",
            )
            if staged != set(changed_paths):
                raise ScopedPublicationError("staged_paths_mismatch", "staged paths do not exactly match validated paths", stage="commit")
            unstaged = _git_z_paths(
                git_runner,
                worktree,
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--name-only",
                "-z",
                "--",
                stage="commit",
            )
            untracked = _git_z_paths(
                git_runner,
                worktree,
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
                stage="commit",
            )
            if unstaged or untracked:
                raise ScopedPublicationError("worktree_changed_during_stage", "worktree changed while staging", stage="commit")
            _run_git(
                git_runner,
                worktree,
                "diff",
                "--cached",
                "--no-ext-diff",
                "--no-textconv",
                "--check",
                scope.base_sha,
                "--",
                stage="commit",
            )
            raw = _run_git(
                git_runner,
                worktree,
                "diff",
                "--cached",
                "--raw",
                "--no-renames",
                "-z",
                scope.base_sha,
                "--",
                stage="commit",
            ).stdout
            _validate_staged_modes(raw)
            expected_tree = _git_text(git_runner, worktree, "write-tree", stage="commit").lower()
            _validate_tree_snapshot(
                git_runner,
                worktree,
                base_sha=scope.base_sha,
                tree_sha=expected_tree,
                changed_paths=changed_paths,
            )
            state.update({"expected_tree": expected_tree, "error": {}})
            _write_artifact(artifact, state)
            head_sha = _git_text(
                git_runner,
                worktree,
                "commit-tree",
                expected_tree,
                "-p",
                scope.base_sha,
                "-m",
                f"chore(forge): implement issue #{scope.issue}",
                stage="commit",
            ).lower()
            if not COMMIT_OID_RE.fullmatch(head_sha) or head_sha == scope.base_sha:
                raise ScopedPublicationError("commit_head_invalid", "trusted-parent commit did not produce a new full OID", stage="commit")
            _run_git(
                git_runner,
                worktree,
                "update-ref",
                f"refs/heads/{scope.branch}",
                head_sha,
                scope.base_sha,
                stage="commit",
            )
            _verify_exact_commit(
                git_runner,
                worktree,
                branch=scope.branch,
                base_sha=scope.base_sha,
                head_sha=head_sha,
                tree_sha=expected_tree,
                changed_paths=changed_paths,
            )
            state.update(
                {
                    "status": "in_progress",
                    "checkpoint": "committed",
                    "head_sha": head_sha,
                    "error": {},
                }
            )
            _write_artifact(artifact, state)

        head_sha = str(state.get("head_sha") or "").lower()
        expected_tree = str(state.get("expected_tree") or "").lower()
        changed_paths = tuple(str(path) for path in state.get("changed_paths") or [])
        if not COMMIT_OID_RE.fullmatch(head_sha) or not COMMIT_OID_RE.fullmatch(expected_tree) or not changed_paths:
            raise ScopedPublicationError("artifact_commit_invalid", "committed checkpoint lacks valid head/path evidence", stage="commit")
        if set(changed_paths) - set(scope.allowed_paths):
            raise ScopedPublicationError("artifact_paths_outside_scope", "artifact changed paths exceed owner scope", stage="commit")
        _verify_exact_commit(
            git_runner,
            worktree,
            branch=scope.branch,
            base_sha=scope.base_sha,
            head_sha=head_sha,
            tree_sha=expected_tree,
            changed_paths=changed_paths,
        )

        checkpoint = str(state["checkpoint"])
        push_remote_url = _validate_remote_endpoint(git_runner, worktree, scope.repo)
        if push_remote_url != remote_url:
            raise ScopedPublicationError("origin_changed_before_push", "origin endpoint changed during publication", stage="push")
        if _remote_ref_head(
            git_runner,
            worktree,
            push_remote_url,
            f"refs/heads/{default_branch}",
        ) != scope.base_sha:
            raise ScopedPublicationError("live_remote_base_changed", "live default branch changed before push", stage="push")
        remote_head = _remote_ref_head(git_runner, worktree, push_remote_url, f"refs/heads/{scope.branch}")
        if PHASE_ORDER[checkpoint] < PHASE_ORDER["pushed"]:
            if remote_head and remote_head != head_sha:
                raise ScopedPublicationError("remote_branch_collision", "remote branch has an unexpected head", stage="push")
            if not remote_head:
                _run_git(
                    git_runner,
                    worktree,
                    "push",
                    "--porcelain",
                    "--no-follow-tags",
                    push_remote_url,
                    f"{head_sha}:refs/heads/{scope.branch}",
                    code="push_failed",
                    stage="push",
                )
            if _remote_ref_head(git_runner, worktree, push_remote_url, f"refs/heads/{scope.branch}") != head_sha:
                raise ScopedPublicationError("push_readback_mismatch", "remote branch does not match committed head", stage="push")
            state.update({"status": "in_progress", "checkpoint": "pushed", "error": {}})
            _write_artifact(artifact, state)
            checkpoint = "pushed"
        elif remote_head != head_sha:
            raise ScopedPublicationError("remote_head_mismatch", "recorded remote branch no longer matches committed head", stage="push")

        _verify_exact_commit(
            git_runner,
            worktree,
            branch=scope.branch,
            base_sha=scope.base_sha,
            head_sha=head_sha,
            tree_sha=expected_tree,
            changed_paths=changed_paths,
        )

        if _remote_ref_head(
            git_runner,
            worktree,
            push_remote_url,
            f"refs/heads/{default_branch}",
        ) != scope.base_sha:
            raise ScopedPublicationError("live_remote_base_changed", "live default branch changed before PR creation", stage="pr")
        title, body = _deterministic_pr(scope, changed_paths)
        body_path = cycle / BODY_NAME
        body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        _atomic_write(body_path, body)
        if checkpoint == "complete":
            recorded_pr = state.get("pr") or {}
            pr_number = recorded_pr.get("number") if isinstance(recorded_pr, dict) else None
            if isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number <= 0:
                raise ScopedPublicationError("artifact_pr_invalid", "complete checkpoint lacks a bound PR number", stage="pr")
        else:
            prs = _list_prs_for_branch(github_runner, worktree, scope)
            if len(prs) > 1:
                raise ScopedPublicationError("multiple_branch_prs", "multiple PRs exist for the exact branch", stage="pr")
            if prs:
                pr_number = prs[0].get("number")
                if isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number <= 0:
                    raise ScopedPublicationError("pr_number_invalid", "existing PR lacks a valid number", stage="pr")
            else:
                create = _run(
                    github_runner,
                    [
                        "pr",
                        "create",
                        "--repo",
                        scope.repo,
                        "--draft",
                        "--base",
                        default_branch,
                        "--head",
                        scope.branch,
                        "--title",
                        title,
                        "--body-file",
                        str(body_path),
                    ],
                    worktree,
                    code="pr_create_failed",
                    stage="pr",
                )
                match = re.search(r"/pull/(\d+)(?:\s|$)", create.stdout.strip())
                if not match:
                    prs = _list_prs_for_branch(github_runner, worktree, scope)
                    if len(prs) != 1 or not isinstance(prs[0].get("number"), int):
                        raise ScopedPublicationError("pr_create_readback_missing", "created PR could not be identified", stage="pr")
                    pr_number = int(prs[0]["number"])
                else:
                    pr_number = int(match.group(1))
        pr = _view_pr(github_runner, worktree, scope, int(pr_number))
        verified_number, pr_url = _verify_pr(
            pr,
            scope=scope,
            default_branch=default_branch,
            head_sha=head_sha,
            title=title,
            body=body,
        )
        state.update(
            {
                "status": "complete",
                "checkpoint": "complete",
                "pr": {
                    "number": verified_number,
                    "url": pr_url,
                    "draft": True,
                    "head_sha": head_sha,
                    "body_sha256": body_hash,
                },
                "error": {},
            }
        )
        _write_artifact(artifact, state)
        return PublicationResult(
            repo=scope.repo,
            issue=scope.issue,
            branch=scope.branch,
            base_sha=scope.base_sha,
            head_sha=head_sha,
            changed_paths=changed_paths,
            pr_number=verified_number,
            pr_url=pr_url,
            artifact_path=artifact,
            idempotent=existed,
        )
    except ScopedPublicationError as exc:
        # Never overwrite an artifact whose binding/schema could not be trusted.
        if exc.code.startswith("artifact_"):
            artifact_writable = False
        if artifact_writable:
            state.update(
                {
                    "status": "repair_due",
                    "error": {"code": exc.code, "stage": exc.stage},
                }
            )
            _write_artifact(artifact, state)
        raise
    except Exception as exc:
        wrapped = ScopedPublicationError("publication_internal_error", "trusted-parent publication failed closed", stage="internal")
        state.update(
            {
                "status": "repair_due",
                "error": {"code": wrapped.code, "stage": wrapped.stage, "exception": type(exc).__name__},
            }
        )
        _write_artifact(artifact, state)
        raise wrapped from exc


def publish_scoped_draft(
    scope: OwnerScope,
    *,
    expected_repo: str,
    expected_issue: int,
    expected_branch: str,
    expected_base_sha: str,
    default_branch: str,
    worktree: Path,
    expected_worktree: Path,
    worktree_root: Path,
    managed_checkout: Path,
    cycle: Path,
    forbidden_paths: Sequence[str],
    git_runner: CommandRunner,
    github_runner: CommandRunner,
) -> PublicationResult:
    """Serialize and execute one owner-scoped trusted-parent publication."""

    validated_scope = _revalidate_scope(scope)
    safe_cycle = _safe_cycle(cycle)
    with _publication_lock(safe_cycle):
        return _publish_scoped_draft_locked(
            validated_scope,
            expected_repo=expected_repo,
            expected_issue=expected_issue,
            expected_branch=expected_branch,
            expected_base_sha=expected_base_sha,
            default_branch=default_branch,
            worktree=worktree,
            expected_worktree=expected_worktree,
            worktree_root=worktree_root,
            managed_checkout=managed_checkout,
            cycle=safe_cycle,
            forbidden_paths=forbidden_paths,
            git_runner=git_runner,
            github_runner=github_runner,
        )


__all__ = [
    "ARTIFACT_NAME",
    "ARTIFACT_SCHEMA",
    "BODY_NAME",
    "LOCK_NAME",
    "CommandResult",
    "CommandRunner",
    "OwnerScope",
    "PublicationResult",
    "SCOPE_ENV_KEY",
    "SCOPE_FILE_ENV_KEY",
    "SCOPE_SCHEMA",
    "ScopedPublicationError",
    "SubprocessRunner",
    "canonical_github_origin",
    "load_owner_scope",
    "parse_owner_scope",
    "path_is_forbidden",
    "publish_scoped_draft",
]
