#!/usr/bin/env python3
"""Detached john-lomein worker supervisor.

Cron/no-agent scripts must exit quickly; real maintainer/forge work can take a
long time. This supervisor owns the durable pidfile/state/log contract:

- spawn <lane> starts a detached worker when one is not already running;
- run <lane> performs the lane within its configured hard runtime budget;
- state JSON + line logs let overwatch detect stalled-but-not-killed workers;
- completion/failure summaries are routed through john-lomein-overwatch-post.sh.
"""
from __future__ import annotations

import codecs
from collections import deque
import json
import os
import re
import select
import shlex
import signal
import subprocess
import sys
import time
import uuid
from contextlib import nullcontext
from pathlib import Path
from typing import Iterable

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_owner_actions import ACTION_AUTOMATION_BLOCKER, notification_seen, stable_fingerprint
from john_lomein_autonomy import (
    AutonomyError,
    autonomy_lock,
    begin_run,
    deployed_runtime_control,
    finish_run,
    mutation_lease,
    policy_from_env,
    policy_from_runtime,
    require_effective_lane,
)
from john_lomein_public_safety import sanitize_public_text
from john_lomein_model_isolation import isolated_command, isolated_environment

LANES = {"maintainer", "forge", "portfolio", "release"}
MUTATING_LANES = {"maintainer", "forge", "portfolio"}
NON_ALERT_STATUSES = {"ok", "success", "clean", "clean_idle", "no_action_needed"}
OWNER_GATE_STATUSES = {"owner_gate"}
BLOCKED_STATUSES = {
    "blocked",
    "blocked_external",
    "blocked_checkout",
    "blocked_implementation",
    "budget_exhausted",
}
STALL_WARN_AFTER_SECONDS = 10 * 60
HEARTBEAT_SECONDS = 60
SUMMARY_LIMIT = 1400
MAX_CAPTURED_OUTPUT_CHARS = 256 * 1024
MAX_STREAMED_LOG_CHARS = 4 * 1024 * 1024
MAX_WORKER_LOG_FILES = 96
MAX_WORKER_LOG_TOTAL_BYTES = 128 * 1024 * 1024
WORKER_LOG_MAX_AGE_SECONDS = 30 * 24 * 60 * 60
CONTROLLED_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
TRIGGER_FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")


def utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def parse_shell_env(path: Path) -> dict[str, str]:
    vals: dict[str, str] = {}
    if not path.exists():
        return vals
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        try:
            parts = shlex.split(value, posix=True)
            vals[key] = parts[0] if parts else ""
        except Exception:
            vals[key] = value.strip().strip("'").strip('"')
    return vals


def runtime_home_from_script_or_env() -> Path:
    deployed_env = SCRIPT_DIR / "john-lomein-instance.env"
    if deployed_env.exists():
        return SCRIPT_DIR.parent.resolve()
    raw = os.environ.get("BOT_HERMES_HOME") or os.environ.get("HERMES_HOME") or ""
    if not raw:
        raise RuntimeError("worker_missing_runtime_home")
    return Path(raw).expanduser().resolve()


def load_env() -> dict[str, str]:
    home = runtime_home_from_script_or_env()
    expected_env = (home / "scripts" / "john-lomein-instance.env").resolve()
    requested_raw = os.environ.get("JOHN_LOMEIN_INSTANCE_ENV")
    if requested_raw:
        requested = Path(requested_raw).expanduser().resolve()
        if requested != expected_env:
            raise RuntimeError("worker_refuses_non_deployed_instance_env")
    if not expected_env.exists():
        raise RuntimeError(f"worker_missing_instance_env:{expected_env}")
    vals = parse_shell_env(expected_env)
    vals["BOT_HERMES_HOME"] = str(home)
    vals["HERMES_HOME"] = str(home)
    # Model-facing lanes never receive deterministic indexer state through
    # their environment. The steward subprocess gets an explicit injection.
    vals.pop("MNEMOSYNE_DATA_DIR", None)
    vals.setdefault("BOT_HERMES_MANAGED_ROOT", str(home / "managed-policy"))
    vals.setdefault("BOT_MODEL_MEMORY_ISOLATION", "required")
    vals.setdefault(
        "BOT_STEWARD_PRIVATE_ROOT",
        str(home / "private" / "learning-steward"),
    )
    vals.setdefault(
        "BOT_STEWARD_PROJECTION_ROOT",
        str(home / "state" / "learning"),
    )
    trigger_fingerprint = os.environ.get(
        "JOHN_LOMEIN_TRIGGER_FINGERPRINT",
        "",
    )
    if trigger_fingerprint:
        if not TRIGGER_FINGERPRINT_RE.fullmatch(trigger_fingerprint):
            raise RuntimeError("worker_refuses_unsafe_trigger_fingerprint")
        vals["JOHN_LOMEIN_TRIGGER_FINGERPRINT"] = trigger_fingerprint
    return vals


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def process_command(pid: int) -> str:
    if not pid_alive(pid):
        return ""
    try:
        proc = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True, timeout=5, env={"PATH": CONTROLLED_PATH})
    except Exception:
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def pid_is_lane_worker(pid: int, lane: str) -> bool:
    """Return true only for this supervisor running the requested lane.

    `kill(pid, 0)` is not enough for a durable pidfile: PIDs can be reused and
    zombies can remain observable briefly. A stale pidfile must not block future
    cron ticks from picking work back up.
    """
    cmd = process_command(pid)
    if not cmd:
        return False
    return "john-lomein-worker.py" in cmd and re.search(rf"\brun\s+{re.escape(lane)}\b", cmd) is not None


def state_root(env: dict[str, str]) -> Path:
    root = Path(env["BOT_HERMES_HOME"]).expanduser() / "state" / "workers"
    root.mkdir(parents=True, exist_ok=True)
    return root


def log_root(env: dict[str, str]) -> Path:
    root = Path(env["BOT_HERMES_HOME"]).expanduser() / "logs" / "workers"
    root.mkdir(parents=True, exist_ok=True)
    return root


def state_path(env: dict[str, str], lane: str) -> Path:
    return state_root(env) / f"{lane}.json"


def pid_path(env: dict[str, str], lane: str) -> Path:
    return state_root(env) / f"{lane}.pid"


def read_state(env: dict[str, str], lane: str) -> dict:
    path = state_path(env, lane)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_state(env: dict[str, str], lane: str, **updates) -> None:
    data = read_state(env, lane)
    data.update(updates)
    data.setdefault("lane", lane)
    data["updated_at"] = utc()
    path = state_path(env, lane)
    tmp = path.with_name(
        f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def replace_state(env: dict[str, str], lane: str, **updates) -> None:
    """Write a fresh lane state, clearing stale fields from previous runs."""
    data = dict(updates)
    data.setdefault("lane", lane)
    data["updated_at"] = utc()
    path = state_path(env, lane)
    tmp = path.with_name(
        f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def state_pid(env: dict[str, str], lane: str) -> int | None:
    pidfile = pid_path(env, lane)
    candidates: list[int] = []
    if pidfile.exists():
        try:
            candidates.append(int(pidfile.read_text(encoding="utf-8").strip()))
        except Exception:
            pass
    data = read_state(env, lane)
    try:
        if data.get("pid"):
            candidates.append(int(data["pid"]))
    except Exception:
        pass
    for pid in candidates:
        if pid_is_lane_worker(pid, lane):
            return pid
    if pidfile.exists():
        try:
            stale = int(pidfile.read_text(encoding="utf-8").strip())
        except Exception:
            stale = -1
        if stale <= 0 or not pid_is_lane_worker(stale, lane):
            pidfile.unlink(missing_ok=True)
    return None


def real_home(env: dict[str, str]) -> Path:
    explicit = env.get("HERMES_REAL_HOME") or env.get("BOT_REAL_HOME")
    if explicit:
        return Path(explicit).expanduser()
    home = env.get("BOT_HERMES_HOME") or ""
    marker = "/.john-lomein/instances/"
    if marker in home:
        return Path(home.split(marker, 1)[0]).expanduser()
    return Path.home()


def resolve_hermes_python(env: dict[str, str]) -> str:
    explicit = env.get("HERMES_PYTHON")
    if explicit and Path(explicit).exists():
        return explicit
    hermes_bin = shutil_which("hermes")
    if hermes_bin:
        hermes_dir = Path(hermes_bin).expanduser().parent
        for name in ("python3", "python"):
            candidate = hermes_dir / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        try:
            first = Path(hermes_bin).read_text(encoding="utf-8", errors="ignore").splitlines()[0]
            if first.startswith("#!"):
                candidate = first[2:].strip()
                path = Path(candidate).expanduser()
                if path.name.startswith("python") and path.is_file() and os.access(path, os.X_OK):
                    return candidate
        except Exception:
            pass
    owner = real_home(env)
    for rel in [".hermes/hermes-agent/venv/bin/python3", ".hermes/hermes-agent/venv/bin/python"]:
        candidate = owner / rel
        if candidate.exists():
            return str(candidate)
    return sys.executable


def shutil_which(name: str) -> str | None:
    for directory in CONTROLLED_PATH.split(os.pathsep):
        if not directory:
            continue
        candidate = Path(directory) / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def base_env(env: dict[str, str]) -> dict[str, str]:
    H = env["BOT_HERMES_HOME"]
    out = dict(env)
    out.pop("GH_CONFIG_DIR", None)
    out.pop("MNEMOSYNE_DATA_DIR", None)
    out.update(
        {
            "HERMES_HOME": H,
            "BOT_HERMES_HOME": H,
            "JOHN_LOMEIN_INSTANCE_HERMES_HOME": H,
            "JOHN_LOMEIN_HERMES_HOME": H,
        }
    )
    py = resolve_hermes_python(env)
    venv = str(Path(py).resolve().parent.parent)
    out["VIRTUAL_ENV"] = venv
    guard_bin = str(Path(H) / "scripts" / "bin")
    out["PATH"] = f"{guard_bin}:{Path(py).resolve().parent}:{CONTROLLED_PATH}"
    # Prefer profile-local gh auth when present.
    profile = env.get("BOT_MAINTAINER_PROFILE", "john-lomein-maintainer")
    profile_home = Path(H) / "profiles" / profile / "home"
    gh_config = profile_home / ".config" / "gh"
    if profile_home.exists():
        out["HOME"] = str(profile_home)
    if gh_config.exists():
        out["GH_CONFIG_DIR"] = str(gh_config)
    out["GH_PROMPT_DISABLED"] = "1"
    out["GH_NO_UPDATE_NOTIFIER"] = "1"
    out["GH_NO_EXTENSION_UPDATE_NOTIFIER"] = "1"
    return out


def model_process_env(
    env: dict[str, str],
    profile: str,
) -> dict[str, str]:
    """Build the exact no-indexer, managed-policy environment for a model."""

    out = base_env(env)
    for key in ("GH_TOKEN", "GITHUB_TOKEN", "GH_CONFIG_DIR"):
        out.pop(key, None)
    out.pop("MNEMOSYNE_DATA_DIR", None)
    managed_root = Path(
        env.get("BOT_HERMES_MANAGED_ROOT")
        or Path(env["BOT_HERMES_HOME"]) / "managed-policy"
    )
    out["HERMES_MANAGED_DIR"] = str(managed_root / profile)
    return out


def steward_process_env(env: dict[str, str]) -> dict[str, str]:
    """Build the deterministic steward environment with explicit index access."""

    out = base_env(env)
    out["MNEMOSYNE_DATA_DIR"] = str(
        Path(env["BOT_HERMES_HOME"])
        / "private"
        / "learning-steward"
        / "mnemosyne"
        / "data"
    )
    return out


def truncate(text: str, limit: int = SUMMARY_LIMIT) -> str:
    text = text.strip()
    return text if len(text) <= limit else text[: limit - 20] + "… [truncated]"


def prune_worker_logs(
    env: dict[str, str],
    *,
    now: float | None = None,
) -> None:
    root = log_root(env)
    current = time.time() if now is None else now
    entries: list[tuple[float, int, Path]] = []
    for path in root.glob("*.log"):
        try:
            if path.is_symlink() or not path.is_file():
                continue
            info = path.stat()
        except OSError:
            continue
        if current - info.st_mtime > WORKER_LOG_MAX_AGE_SECONDS:
            try:
                path.unlink()
            except OSError:
                pass
            continue
        entries.append((info.st_mtime, info.st_size, path))
    entries.sort(key=lambda item: item[0], reverse=True)
    retained = 0
    retained_bytes = 0
    for _mtime, size, path in entries:
        if (
            retained < MAX_WORKER_LOG_FILES
            and retained_bytes + size <= MAX_WORKER_LOG_TOTAL_BYTES
        ):
            retained += 1
            retained_bytes += size
            continue
        try:
            path.unlink()
        except OSError:
            pass


def post(env: dict[str, str], label: str, body: str) -> None:
    public_body = sanitize_public_text(body, limit=SUMMARY_LIMIT)
    fingerprint = stable_fingerprint({"label": label, "body": public_body, "class": ACTION_AUTOMATION_BLOCKER})
    if notification_seen(env, label, fingerprint):
        return
    script = Path(env["BOT_HERMES_HOME"]) / "scripts" / "john-lomein-overwatch-post.sh"
    if not script.exists():
        print(f"[{utc()}] {label}: {public_body}", flush=True)
        return
    try:
        subprocess.run(
            ["bash", str(script), label],
            input=public_body,
            text=True,
            env=base_env(env),
            timeout=60,
            check=False,
        )
    except Exception as exc:
        print(f"[{utc()}] notification failed: {exc}", flush=True)


def learning_status_for_output(lane: str, process_status: str, output: str) -> tuple[str, str]:
    """Convert raw worker output into a learning pattern.

    A lane can exit 0 while still surfacing a durable learning blocker: for
    example a forge implementation handoff can return a clean wrapper exit with
    `JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED`, and a maintainer tick can safely
    stop on an interrupted dirty checkout. Candidate learning should see those
    domain blockers instead of only the process exit code.
    """
    if process_status not in {"ok", "success", "clean"}:
        return process_status, f"{lane}:post_flight:{process_status}"
    text = (output or "").lower()
    compact = re.sub(r"[^a-z0-9#]+", " ", text)
    if "john_lomein_autonomy_status: budget_exhausted" in text:
        return "budget_exhausted", f"{lane}:budget_exhausted"
    if "john_lomein_implement_status: blocked" in text or "implement_status\": \"blocked" in text:
        return "blocked_implementation", f"{lane}:blocked_implementation"
    if "john_lomein_implement_status: failed" in text or "implement_status\": \"failed" in text:
        return "failed", f"{lane}:implementation:failed"
    if any(token in text for token in ("clean_owner_gate", "owner gate", "owner-gated", "owner_gated", "owner approval", "approval required", "human gate", "needs owner")):
        return "owner_gate", f"{lane}:owner_gate"
    if any(token in text for token in ("no safe mutation", "no safe repo/github mutation", "no safe maintainer mutation", "nothing to move", "nothing to mutate", "no movement needed", "no repo movement", "no pr movement needed", "no prs to move", "no open prs to maintain", "zero open prs to maintain", "steady-state quiescent", "clean no-op", "no-op clean")):
        return "no_action_needed", f"{lane}:no_action_needed"
    if any(token in text for token in ("queue is clean", "queue clean", "clean idle", "idle clean")) or (process_status in {"ok", "success", "clean"} and "empty bundle" in text and "blockers=0" in text):
        return "clean_idle", f"{lane}:clean_idle"
    if "recovery blocker" in text or "managed checkout dirty" in text or "dirty checkout" in text or ("interrupted" in text and "checkout" in text):
        return "blocked_checkout", f"{lane}:blocked_checkout"
    if "exhausted_in_cycle_revisions" in text or "deferred status=revise" in text or ("ship gate" in text and "revise" in text):
        return "blocked_implementation", f"{lane}:ship_gate_revise_blocker"
    if any(token in text for token in ("rate limit", "permission denied", "authentication failed", "auth failed", "github unavailable", "network error", "dependency blocked", "blocked by #")) or "blocked by" in compact:
        return "blocked_external", f"{lane}:blocked_external"
    return process_status, f"{lane}:post_flight:{process_status}"


def lane_status_for_output(lane: str, process_status: str, output: str) -> str:
    return learning_status_for_output(lane, process_status, output)[0]


def emit_learning(env: dict[str, str], lane: str, status: str, exit_code: int, output: str) -> None:
    """Emit a post-flight observation and let the steward update memory.

    Operational lanes never write Mnemosyne directly. They only leave a
    structured observation; the central learning steward performs the memory
    upsert and candidate-improvement quarantine.
    """
    if env.get("BOT_LEARNING_ENABLED", "1") != "1":
        return
    script = Path(env["BOT_HERMES_HOME"]) / "scripts" / "john-lomein-learning-steward.py"
    if not script.exists():
        return
    benv = steward_process_env(env)
    summary = truncate(output, 1800)
    learning_status, pattern = learning_status_for_output(lane, status, output)
    source_ref = os.environ.get("JOHN_LOMEIN_WORKER_LOG") or str(state_path(env, lane))
    py = resolve_hermes_python(env)
    try:
        subprocess.run(
            [
                py,
                str(script),
                "observe",
                "--role",
                lane,
                "--event",
                "post_flight",
                "--status",
                learning_status,
                "--summary",
                summary,
                "--pattern-key",
                pattern,
                "--source-ref",
                source_ref,
                "--metadata-json",
                json.dumps({"exit_code": exit_code, "process_status": status}),
            ],
            env=benv,
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
        subprocess.run(
            [py, str(script), "reconcile", "--mode", "post-flight", "--json"],
            env=benv,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except Exception as exc:
        write_state(env, lane, learning_observation_error=f"{type(exc).__name__}: {exc}")


def stream_command(
    env: dict[str, str],
    lane: str,
    cmd: list[str],
    *,
    cwd: str | None = None,
    deadline_monotonic: float | None = None,
) -> tuple[int, str]:
    print(f"[{utc()}] lane={lane} command={' '.join(shlex.quote(x) for x in cmd)}", flush=True)
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=base_env(env),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=False,
        bufsize=0,
        start_new_session=True,
    )
    write_state(env, lane, child_pid=proc.pid, heartbeat_at=utc(), status="running")
    chunks: deque[str] = deque()
    captured_chars = 0
    capture_truncated = False
    streamed_chars = 0
    stream_truncated = False
    saw_output = False
    last_heartbeat = time.time()
    last_output = time.time()
    warned = False
    timed_out = False
    assert proc.stdout is not None
    fd = proc.stdout.fileno()
    os.set_blocking(fd, False)
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    stdout_eof = False

    def emit_text(text: str) -> None:
        nonlocal capture_truncated, captured_chars, last_output
        nonlocal saw_output, stream_truncated, streamed_chars
        if not text:
            return
        saw_output = True
        if streamed_chars < MAX_STREAMED_LOG_CHARS:
            remaining = MAX_STREAMED_LOG_CHARS - streamed_chars
            visible = text[:remaining]
            if visible:
                print(visible, end="", flush=True)
                streamed_chars += len(visible)
            if len(visible) < len(text) and not stream_truncated:
                print(
                    "\n[worker child output log limit reached; "
                    "further bytes omitted]\n",
                    end="",
                    flush=True,
                )
                stream_truncated = True
        elif not stream_truncated:
            print(
                "\n[worker child output log limit reached; "
                "further bytes omitted]\n",
                end="",
                flush=True,
            )
            stream_truncated = True
        chunks.append(text)
        captured_chars += len(text)
        while captured_chars > MAX_CAPTURED_OUTPUT_CHARS and chunks:
            overflow = captured_chars - MAX_CAPTURED_OUTPUT_CHARS
            oldest = chunks[0]
            if len(oldest) <= overflow:
                chunks.popleft()
                captured_chars -= len(oldest)
                capture_truncated = True
                continue
            chunks[0] = oldest[overflow:]
            captured_chars -= overflow
            capture_truncated = True
            break
        last_output = time.time()

    def drain_stdout() -> None:
        nonlocal stdout_eof
        while not stdout_eof:
            try:
                raw = os.read(fd, 8192)
            except BlockingIOError:
                break
            if not raw:
                stdout_eof = True
                break
            emit_text(decoder.decode(raw))

    while True:
        now = time.time()
        if stdout_eof:
            time.sleep(1.0)
            ready: list[int] = []
        else:
            ready, _, _ = select.select([fd], [], [], 1.0)
        if ready:
            drain_stdout()
        if proc.poll() is not None:
            drain_stdout()
            emit_text(decoder.decode(b"", final=True))
            break
        now = time.time()
        if (
            deadline_monotonic is not None
            and time.monotonic() >= deadline_monotonic
        ):
            timed_out = True
            marker = (
                f"\nJOHN_LOMEIN_AUTONOMY_STATUS: budget_exhausted "
                f"lane={lane}\n"
            )
            emit_text(marker)
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=10)
            drain_stdout()
            emit_text(decoder.decode(b"", final=True))
            break
        if now - last_heartbeat >= HEARTBEAT_SECONDS:
            write_state(env, lane, heartbeat_at=utc(), last_output_at=utc() if saw_output else None)
            last_heartbeat = now
        if not warned and now - last_output > STALL_WARN_AFTER_SECONDS:
            warned = True
            msg = f"lane={lane} child_pid={proc.pid} has produced no output for {int((now-last_output)/60)}m; monitoring continues, not killing"
            write_state(env, lane, stalled_since=utc(), stall_warning=msg)
            post(env, f"{lane.upper()}_STALLING", msg)
    code = proc.wait()
    if timed_out:
        code = 124
    proc.stdout.close()
    output = "".join(chunks)
    if capture_truncated:
        output = (
            "[earlier child output omitted by worker capture limit]\n"
            + output
        )
    process_status = "ok" if code == 0 else "failed"
    final_status = lane_status_for_output(lane, process_status, output)
    write_state(env, lane, status=final_status, child_pid=None, exit_code=code, finished_child_at=utc(), heartbeat_at=utc())
    return code, output


def run_hermes_chat(
    env: dict[str, str],
    lane: str,
    profile: str,
    prompt_file: Path,
    *,
    deadline_monotonic: float | None = None,
) -> tuple[int, str]:
    prompt = prompt_file.read_text(encoding="utf-8")
    py = resolve_hermes_python(env)
    cmd = [
        py,
        "-I",
        "-m",
        "hermes_cli.main",
        "--profile",
        profile,
        "chat",
        "-q",
        prompt,
        "-Q",
    ]
    child_env = model_process_env(env, profile)
    cmd = isolated_command(
        child_env,
        cmd,
        allow_projection=profile != env.get(
            "BOT_GUIDE_PROFILE",
            "john-lomein-guide",
        ),
        profile=profile,
    )
    child_env = isolated_environment(child_env, profile=profile)
    return stream_command(
        child_env,
        lane,
        cmd,
        cwd=env.get("BOT_LOCAL") or None,
        deadline_monotonic=deadline_monotonic,
    )


def run_lane(env: dict[str, str], lane: str) -> int:
    H = Path(env["BOT_HERMES_HOME"])
    deployed = (H / "scripts" / "john-lomein-instance.env").exists()
    policy = policy_from_runtime(H) if deployed else policy_from_env(env)
    trigger_fingerprint = env.get("JOHN_LOMEIN_TRIGGER_FINGERPRINT")
    idempotency_key = (
        f"{lane}:{trigger_fingerprint}"
        if trigger_fingerprint
        else None
    )
    started_monotonic = time.monotonic()
    autonomy_run_id: str | None = None
    max_run_seconds: int | None = None
    final_status = "crashed"
    final_code = 2
    return_code = 2
    output = ""
    lease = (
        mutation_lease(H, lane)
        if lane in MUTATING_LANES
        else nullcontext()
    )
    try:
        if lane in MUTATING_LANES:
            control = deployed_runtime_control(H) if deployed else env
            require_effective_lane(control, lane)
        with lease:
            decision = begin_run(
                H,
                policy,
                lane,
                idempotency_key=idempotency_key,
            )
            if not decision["allowed"]:
                reason = str(decision["reason"])
                quiet_skip = reason in {
                    "idempotency_completed",
                    "idempotency_in_progress",
                }
                status = "no_action_needed" if quiet_skip else "autonomy_blocked"
                replace_state(
                    env,
                    lane,
                    status=status,
                    pid=os.getpid(),
                    autonomy_reason=reason,
                    autonomy=decision,
                    finished_at=utc(),
                )
                if not quiet_skip:
                    post(
                        env,
                        f"{lane.upper()}_AUTONOMY_BLOCKED",
                        f"lane={lane} autonomy gate={reason}",
                    )
                    return 75
                return 0

            autonomy_run_id = str(decision["run_id"])
            env = dict(env)
            env["JOHN_LOMEIN_AUTONOMY_RUN_ID"] = autonomy_run_id
            env["JOHN_LOMEIN_AUTONOMY_LANE"] = lane
            max_run_seconds = int(decision["allowed_run_seconds"])
            deadline = time.monotonic() + max_run_seconds
            started = utc()
            replace_state(
                env,
                lane,
                status="running",
                pid=os.getpid(),
                child_pid=None,
                exit_code=None,
                started_at=started,
                heartbeat_at=started,
                log=os.environ.get("JOHN_LOMEIN_WORKER_LOG"),
                autonomy_run_id=autonomy_run_id,
                autonomy_idempotency_sha256=decision[
                    "idempotency_key_sha256"
                ],
                autonomy_max_run_seconds=max_run_seconds,
            )
            pid_path(env, lane).write_text(
                str(os.getpid()),
                encoding="utf-8",
            )

            if lane == "maintainer":
                final_code, output = run_hermes_chat(
                    env,
                    lane,
                    env.get(
                        "BOT_MAINTAINER_PROFILE",
                        "john-lomein-maintainer",
                    ),
                    H / "scripts" / "john-lomein-maintainer-prompt.txt",
                    deadline_monotonic=deadline,
                )
                # After PR-maintenance, refresh release bundle evidence while
                # preserving the same total per-run wall-clock budget.
                bundler = H / "scripts" / "john-lomein-release-bundler.py"
                if (
                    bundler.exists()
                    and final_code != 124
                    and time.monotonic() < deadline
                ):
                    bcode, bout = stream_command(
                        env,
                        "release",
                        [sys.executable, str(bundler), "--signal"],
                        cwd=env.get("BOT_LOCAL") or None,
                        deadline_monotonic=deadline,
                    )
                    output = output + "\n" + bout
                    final_code = (
                        final_code if final_code != 0 else bcode
                    )
            elif lane == "forge":
                orch = H / "scripts" / "john-lomein-forge-orchestrator.py"
                final_code, output = stream_command(
                    env,
                    lane,
                    [sys.executable, str(orch)],
                    cwd=env.get("BOT_LOCAL") or None,
                    deadline_monotonic=deadline,
                )
            elif lane == "portfolio":
                steward = (
                    H / "scripts" / "john-lomein-osc-portfolio-steward.py"
                )
                final_code, output = stream_command(
                    env,
                    lane,
                    [sys.executable, str(steward), "--apply", "--json"],
                    cwd=env.get("BOT_LOCAL") or None,
                    deadline_monotonic=deadline,
                )
            elif lane == "release":
                bundler = H / "scripts" / "john-lomein-release-bundler.py"
                final_code, output = stream_command(
                    env,
                    lane,
                    [sys.executable, str(bundler), "--signal"],
                    cwd=env.get("BOT_LOCAL") or None,
                    deadline_monotonic=deadline,
                )
            else:  # pragma: no cover - protected by CLI validation
                raise RuntimeError(f"unknown lane: {lane}")

            process_status = "ok" if final_code == 0 else "failed"
            final_status = lane_status_for_output(
                lane,
                process_status,
                output,
            )
            write_state(
                env,
                lane,
                status=final_status,
                exit_code=final_code,
                finished_at=utc(),
                summary=truncate(output),
            )
            emit_learning(
                env,
                lane,
                final_status,
                final_code,
                output,
            )
            if final_status in BLOCKED_STATUSES:
                label = f"{lane.upper()}_BLOCKED"
            elif final_status in OWNER_GATE_STATUSES:
                label = f"{lane.upper()}_OWNER_GATE"
            elif final_status in NON_ALERT_STATUSES:
                label = lane.upper()
            else:
                label = f"{lane.upper()}_FAILED"
            if final_status not in NON_ALERT_STATUSES:
                post(env, label, truncate(output))
            return_code = (
                1
                if final_status in BLOCKED_STATUSES and final_code == 0
                else final_code
            )
    except AutonomyError as exc:
        msg = f"lane={lane} autonomy blocked: {exc}"
        if "mutation lease is already held" in str(exc):
            print(msg, flush=True)
            return_code = 0
        else:
            final_status = "autonomy_blocked"
            final_code = 75
            return_code = final_code
            replace_state(
                env,
                lane,
                status=final_status,
                error=msg,
                finished_at=utc(),
            )
            post(env, f"{lane.upper()}_AUTONOMY_BLOCKED", msg)
            print(msg, flush=True)
    except Exception as exc:
        msg = f"lane={lane} crashed: {exc}"
        final_status = "crashed"
        final_code = 2
        return_code = 2
        output = msg
        write_state(env, lane, status="crashed", error=msg, finished_at=utc())
        emit_learning(env, lane, "crashed", 2, msg)
        post(env, f"{lane.upper()}_CRASHED", msg)
        print(msg, flush=True)
    finally:
        if autonomy_run_id:
            try:
                finish_run(
                    H,
                    autonomy_run_id,
                    status=final_status,
                    exit_code=final_code,
                    duration_seconds=min(
                        max(
                            0,
                            int(
                                time.monotonic()
                                - started_monotonic
                            ),
                        ),
                        max_run_seconds
                        if max_run_seconds is not None
                        else 0,
                    ),
                )
            except Exception as exc:
                final_status = "autonomy_control_failed"
                final_code = 75
                return_code = 75
                msg = (
                    "lane="
                    f"{lane} autonomy journal finalization failed: "
                    f"{type(exc).__name__}"
                )
                replace_state(
                    env,
                    lane,
                    status=final_status,
                    exit_code=final_code,
                    error=msg,
                    autonomy_journal_error=msg,
                    finished_at=utc(),
                )
                try:
                    post(
                        env,
                        f"{lane.upper()}_AUTONOMY_CONTROL_FAILED",
                        msg,
                    )
                except Exception:
                    pass
        try:
            if pid_path(env, lane).read_text(encoding="utf-8").strip() == str(os.getpid()):
                pid_path(env, lane).unlink()
        except Exception:
            pass
    return return_code


def spawn_lane(
    env: dict[str, str],
    lane: str,
    *,
    quiet: bool = False,
    trigger_fingerprint: str | None = None,
) -> int:
    if trigger_fingerprint and not TRIGGER_FINGERPRINT_RE.fullmatch(
        trigger_fingerprint
    ):
        raise RuntimeError("unsafe worker trigger fingerprint")
    if lane in MUTATING_LANES:
        H = Path(env["BOT_HERMES_HOME"])
        deployed = (H / "scripts" / "john-lomein-instance.env").exists()
        try:
            control = deployed_runtime_control(H) if deployed else env
            require_effective_lane(control, lane)
        except AutonomyError as exc:
            replace_state(
                env,
                lane,
                status="autonomy_blocked",
                error=str(exc),
                finished_at=utc(),
            )
            if not quiet:
                print(f"john-lomein worker: lane={lane} {exc}")
            return 75
    with autonomy_lock(env["BOT_HERMES_HOME"]):
        return _spawn_lane_locked(
            env,
            lane,
            quiet=quiet,
            trigger_fingerprint=trigger_fingerprint,
        )


def _spawn_lane_locked(
    env: dict[str, str],
    lane: str,
    *,
    quiet: bool,
    trigger_fingerprint: str | None,
) -> int:
    existing = state_pid(env, lane)
    if existing:
        write_state(env, lane, status="running", pid=existing, spawn_skipped_at=utc(), spawn_skip_reason="same_lane_running")
        if not quiet:
            print(f"john-lomein worker already running lane={lane} pid={existing}")
        return 0
    if lane in MUTATING_LANES:
        for other in sorted(MUTATING_LANES - {lane}):
            other_pid = state_pid(env, other)
            if other_pid:
                write_state(env, lane, spawn_skipped_at=utc(), spawn_skip_reason=f"{other}_running", blocked_by_lane=other, blocked_by_pid=other_pid)
                if not quiet:
                    print(f"john-lomein worker not spawned lane={lane}; {other} already running pid={other_pid}")
                return 0
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    prune_worker_logs(env)
    log_path = log_root(env) / f"{lane}-{ts}.log"
    run_env = base_env(env)
    run_env["JOHN_LOMEIN_WORKER_LOG"] = str(log_path)
    if trigger_fingerprint:
        run_env["JOHN_LOMEIN_TRIGGER_FINGERPRINT"] = trigger_fingerprint
    cmd = [sys.executable, str(Path(__file__).resolve()), "run", lane]
    with log_path.open("a", encoding="utf-8") as log:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=run_env, cwd=env.get("BOT_LOCAL") or None, start_new_session=True)
    pid_path(env, lane).write_text(str(proc.pid), encoding="utf-8")
    replace_state(
        env,
        lane,
        status="spawned",
        pid=proc.pid,
        log=str(log_path),
        spawned_at=utc(),
        heartbeat_at=utc(),
        autonomy_triggered=bool(trigger_fingerprint),
    )
    if not quiet:
        print(f"john-lomein worker spawned lane={lane} pid={proc.pid} log={log_path}")
    return 0


def worker_status(env: dict[str, str]) -> int:
    rows = []
    for lane in sorted(LANES):
        data = read_state(env, lane)
        pid = data.get("pid")
        alive = pid_is_lane_worker(int(pid), lane) if pid else False
        rows.append({"lane": lane, "pid": pid, "alive": alive, "status": data.get("status"), "updated_at": data.get("updated_at"), "log": data.get("log")})
    print(json.dumps(rows, indent=2))
    return 0


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in {"spawn", "run", "status"}:
        print(
            "usage: john-lomein-worker.py spawn|run "
            "<maintainer|forge|portfolio|release> "
            "[--quiet] [--fingerprint KEY] | status",
            file=sys.stderr,
        )
        return 2
    env = load_env()
    action = argv[1]
    if action == "status":
        return worker_status(env)
    if len(argv) < 3 or argv[2] not in LANES:
        print(f"lane must be one of: {', '.join(sorted(LANES))}", file=sys.stderr)
        return 2
    lane = argv[2]
    if action == "spawn":
        quiet = "--quiet" in argv[3:]
        trigger_fingerprint = None
        if "--fingerprint" in argv[3:]:
            index = argv.index("--fingerprint")
            if index + 1 >= len(argv):
                print("--fingerprint requires a value", file=sys.stderr)
                return 2
            trigger_fingerprint = argv[index + 1]
        return spawn_lane(
            env,
            lane,
            quiet=quiet,
            trigger_fingerprint=trigger_fingerprint,
        )
    return run_lane(env, lane)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
