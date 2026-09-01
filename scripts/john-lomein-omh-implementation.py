#!/usr/bin/env python3
"""Run the forge implementation stage through OMH handoff artifacts and Codex."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_model_isolation import isolated_command, isolated_environment

IMPLEMENT_STATUS_RE = re.compile(r"(?im)^\s*JOHN_LOMEIN_IMPLEMENT_STATUS\s*:\s*(COMPLETE|BLOCKED)\s*$")
BLOCKING_SEMANTIC_STATUSES = {
    "blocked",
    "blocked_requirements_missing",
    "blocker",
    "denied",
    "error",
    "failed",
    "failure",
    "missing",
    "missing_requirements",
    "not_ready",
    "requirements_missing",
    "unavailable",
    "unknown",
}


def utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def tail(text: str, limit: int = 3000) -> str:
    text = text or ""
    return text if len(text) <= limit else text[-limit:]


def exception_evidence(artifact: str, operation: str, exc: Exception) -> dict[str, object]:
    evidence: dict[str, object] = {
        "artifact": artifact,
        "operation": operation,
        "error_type": type(exc).__name__,
    }
    errno = getattr(exc, "errno", None)
    if isinstance(errno, int):
        evidence["errno"] = errno
    return evidence


def evidence_summary(evidence: dict[str, object]) -> str:
    summary = str(evidence.get("error_type") or "error")
    if isinstance(evidence.get("errno"), int):
        summary += f" errno={evidence['errno']}"
    return summary


def read_text_artifact(
    path: Path,
    *,
    artifact: str,
    required: bool = False,
) -> tuple[str, dict[str, object] | None]:
    try:
        if not required and not os.path.lexists(path):
            return "", None
        return path.read_text(encoding="utf-8"), None
    except Exception as exc:
        return "", exception_evidence(artifact, "read", exc)


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp = Path(raw_tmp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY | directory_flag)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        tmp.unlink(missing_ok=True)


def read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def normalize_status(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def semantic_status_blocked(value: object) -> bool:
    status = normalize_status(value)
    return bool(
        status in BLOCKING_SEMANTIC_STATUSES
        or status.startswith("blocked")
        or status.endswith("_missing")
        or status.startswith("not_ready")
    )


def readiness_available(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        status = normalize_status(value)
        if status in {"false", "0", "no", "n", "off", "unavailable", "not_available"}:
            return False
        if status in {"true", "1", "yes", "y", "on", "available", "ready"}:
            return True
    return bool(value)


def semantic_blockers(name: str, data: object) -> list[str]:
    blockers: list[str] = []

    def walk_for_command_errors(value: object, path: str) -> None:
        if isinstance(value, dict):
            schema = normalize_status(value.get("schema_version"))
            if schema == "john_lomein_omh_command_error_v1":
                blockers.append(f"{name}:{path or '$'}:command_error")
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                walk_for_command_errors(child, child_path)
            return
        if isinstance(value, list):
            for idx, child in enumerate(value):
                walk_for_command_errors(child, f"{path}[{idx}]")

    walk_for_command_errors(data, "")
    if not isinstance(data, dict):
        return blockers

    # OMH payloads can contain nested informational fields such as
    # `details.status=unknown` or `metadata.result=missing`. Treat only the
    # top-level handoff/readiness status contract, explicit top-level boolean
    # blockers, and command-error schemas as fail-closed blockers.
    for key, child in data.items():
        key_norm = normalize_status(key)
        if key_norm in {"status", "state", "readiness_status", "result", "blocker"} and semantic_status_blocked(child):
            blockers.append(f"{name}:{key}={child}")
        elif key_norm in {"blocked", "not_ready"} and child is True:
            blockers.append(f"{name}:{key}=true")
    return blockers


def prompt_has_concrete_implementation_context(prompt: str, args: object) -> bool:
    """Return True when john-lomein already supplied a concrete implementation packet."""
    text = prompt or ""
    expected = [
        f"Issue #{getattr(args, 'issue', '')}",
        str(getattr(args, "local", "")),
        str(getattr(args, "branch", "")),
        "Allowed side effects:",
        "Implementation requirements:",
        "JOHN_LOMEIN_IMPLEMENT_STATUS",
    ]
    return all(item and item in text for item in expected)


def coding_delegate_prepared_handoff_ready(data: dict, args: object, prompt: str) -> bool:
    """Accept OMH prepared handoffs that are dispatchable but unrecorded.

    OMH may report `blocked_requirements_missing` for its own generic runtime
    record while still returning a dispatchable Codex handoff. In forge
    implementation, the issue/worktree prompt is the concrete requirements and
    dispatch intent, so this precise shape should continue to observed Codex.
    """
    if not isinstance(data, dict):
        return False
    status = normalize_status(data.get("status"))
    if status not in {"blocked_requirements_missing", "requirements_missing", "missing_requirements"}:
        return False
    if not readiness_available(data.get("dispatchable", False)):
        return False
    if normalize_status(data.get("selected_executor_profile")) != normalize_status(getattr(args, "executor", "codex")):
        return False
    policy = normalize_status(data.get("dispatch_policy"))
    if policy not in {"ask_before_dispatch", "send_to_executor", "prepare_only"}:
        return False
    if not (data.get("executor_handoff_prompt") or data.get("delegation_prompt")):
        return False
    return prompt_has_concrete_implementation_context(prompt, args)


def filter_prepared_handoff_blockers(blockers: list[str], prepared_handoff: bool) -> list[str]:
    if not prepared_handoff:
        return blockers
    filtered: list[str] = []
    for blocker in blockers:
        if blocker.startswith("coding_delegate:status=") and "missing" in normalize_status(blocker):
            continue
        filtered.append(blocker)
    return filtered


def parse_implementation_marker(final_text: str, stdout: str) -> tuple[str, str, list[dict[str, str]]]:
    seen: list[dict[str, str]] = []
    for source, text in [("codex_final", final_text or ""), ("codex_stdout", stdout or "")]:
        for match in IMPLEMENT_STATUS_RE.finditer(text):
            seen.append({"source": source, "status": match.group(1).upper()})
    if not seen:
        return "BLOCKED", "missing_marker", seen
    by_source: dict[str, list[str]] = {}
    for item in seen:
        by_source.setdefault(item["source"], []).append(item["status"])
    if any(len(statuses) > 1 for statuses in by_source.values()):
        return "BLOCKED", "ambiguous_marker", seen
    statuses = {item["status"] for item in seen}
    if len(statuses) != 1:
        return "BLOCKED", "ambiguous_marker", seen
    source = seen[0]["source"]
    if len(seen) > 1:
        source = "duplicate_marker"
    return statuses.pop(), source, seen


def toml_string(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def command_env(args: argparse.Namespace) -> dict[str, str]:
    env = dict(os.environ)
    for key in (
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GH_CONFIG_DIR",
        "SSH_AUTH_SOCK",
        "GIT_ASKPASS",
        "MNEMOSYNE_DATA_DIR",
    ):
        env.pop(key, None)
    if args.hermes_home:
        env["HERMES_HOME"] = str(args.hermes_home)
        env["JOHN_LOMEIN_INSTANCE_HERMES_HOME"] = str(args.hermes_home)
        env["JOHN_LOMEIN_HERMES_HOME"] = str(args.hermes_home)
    if args.omh_home:
        env["OMH_HOME"] = str(args.omh_home)
    if args.codex_home:
        env["CODEX_HOME"] = str(args.codex_home)
    owner = owner_home_from_hermes(args.hermes_home)
    path_prefixes = [
        owner / ".local" / "bin",
        owner / ".npm-global" / "bin",
        owner / ".cargo" / "bin",
        Path("/opt/homebrew/bin"),
        Path("/usr/local/bin"),
    ]
    existing_path = env.get("PATH") or ""
    env["PATH"] = os.pathsep.join([str(p) for p in path_prefixes if p.exists()] + ([existing_path] if existing_path else []))
    env.setdefault("GH_PROMPT_DISABLED", "1")
    env.setdefault("GH_NO_UPDATE_NOTIFIER", "1")
    env.setdefault("GH_NO_EXTENSION_UPDATE_NOTIFIER", "1")
    return env


def codex_command_env(args: argparse.Namespace, base_env: dict[str, str]) -> dict[str, str]:
    """Give Codex auth/runtime essentials without forge GitHub credentials."""
    runtime_home = args.cycle / "codex-runtime-home"
    runtime_home.mkdir(parents=True, exist_ok=True, mode=0o700)
    out = {
        "PATH": base_env.get("PATH") or "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(runtime_home),
        "TMPDIR": str(runtime_home),
        "XDG_CONFIG_HOME": str(runtime_home / ".config"),
        "XDG_CACHE_HOME": str(runtime_home / ".cache"),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GH_PROMPT_DISABLED": "1",
        "NPM_CONFIG_USERCONFIG": "/dev/null",
        "PIP_CONFIG_FILE": "/dev/null",
    }
    if args.codex_home:
        out["CODEX_HOME"] = str(args.codex_home)
    for key in ("LANG", "LC_ALL", "LC_CTYPE", "TERM", "SHELL", "SSL_CERT_FILE", "SSL_CERT_DIR"):
        if base_env.get(key):
            out[key] = base_env[key]
    return out


def codex_isolation_env(
    args: argparse.Namespace,
    base_env: dict[str, str],
    process_env: dict[str, str],
) -> dict[str, str]:
    """Bind the credential-minimal Codex process to the deployed boundary."""

    out = dict(process_env)
    if args.hermes_home is None:
        return out
    home = args.hermes_home
    out.update(
        {
            "BOT_HERMES_HOME": str(home),
            "HERMES_HOME": str(home),
            "BOT_LOCAL": str(args.local),
            "BOT_MODEL_MEMORY_ISOLATION": str(
                base_env.get("BOT_MODEL_MEMORY_ISOLATION") or "required"
            ),
            "BOT_STEWARD_PRIVATE_ROOT": str(
                home / "private" / "learning-steward"
            ),
            "BOT_STEWARD_PROJECTION_ROOT": str(home / "state" / "learning"),
        }
    )
    return out


def owner_home_from_hermes(hermes_home: Path | None) -> Path:
    explicit = os.environ.get("HERMES_REAL_HOME") or os.environ.get("BOT_REAL_HOME")
    if explicit:
        return Path(explicit).expanduser()
    if hermes_home:
        marker = "/.john-lomein/instances/"
        text = str(hermes_home.expanduser())
        if marker in text:
            return Path(text.split(marker, 1)[0]).expanduser()
    return Path.home()


def resolve_command(name: str, env: dict[str, str]) -> str | None:
    return shutil.which(name, path=env.get("PATH") or None)


def run_capture(
    cmd: list[str],
    *,
    env: dict[str, str],
    cwd: Path | None = None,
    input_text: str | None = None,
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            env=env,
            cwd=str(cwd) if cwd else None,
            timeout=timeout,
        )
    except Exception as exc:
        return subprocess.CompletedProcess(cmd, 999, "", str(exc))


def run_json_artifact(
    name: str,
    cmd: list[str],
    *,
    path: Path,
    err_path: Path,
    env: dict[str, str],
    input_text: str,
) -> tuple[subprocess.CompletedProcess[str], dict]:
    proc = run_capture(cmd, env=env, input_text=input_text, timeout=240)
    err_path.write_text(proc.stderr or "", encoding="utf-8")
    data: dict
    try:
        parsed = json.loads(proc.stdout or "{}")
        if not isinstance(parsed, dict):
            raise ValueError("OMH machine envelope must be a JSON object")
        data = parsed
        write_json(path, data)
    except Exception:
        data = {
            "schema_version": "john_lomein_omh_command_error/v1",
            "command": name,
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "recorded_at": utc(),
        }
        write_json(path, data)
    return proc, data


def run_process(
    cmd: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    input_text: str,
    timeout: int,
) -> tuple[int, str, str, bool, dict[str, object] | None]:
    started = False
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            cwd=str(cwd),
            start_new_session=True,
        )
    except Exception as exc:
        evidence = exception_evidence("codex_process", "launch", exc)
        message = f"\n[{utc()}] codex process launch failed: {evidence_summary(evidence)}\n"
        return 1, "", message, False, evidence
    started = True
    try:
        stdout, stderr = proc.communicate(input=input_text, timeout=timeout)
        return proc.returncode, stdout or "", stderr or "", started, None
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except Exception:
            proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                proc.kill()
            stdout, stderr = proc.communicate()
        message = f"\n[{utc()}] codex timeout after {timeout}s; killed process group\n"
        return 124, (stdout or "") + message, stderr or "", started, None


def print_final_or_tail(final_text: str, stdout: str, stderr: str) -> None:
    final = (final_text or "").strip()
    final = IMPLEMENT_STATUS_RE.sub("", final).strip()
    stdout = IMPLEMENT_STATUS_RE.sub("", stdout or "").strip()
    stderr = IMPLEMENT_STATUS_RE.sub("", stderr or "").strip()
    chunks = []
    if final:
        chunks.append(final)
    elif stdout.strip():
        chunks.append(tail(stdout.strip()))
    if stderr.strip():
        chunks.append("--- codex stderr tail ---\n" + tail(stderr.strip(), 1800))
    if chunks:
        print("\n".join(chunks))


def build_result(args: argparse.Namespace, artifacts: dict[str, str]) -> dict:
    return {
        "schema_version": "john_lomein_omh_executor_result/v1",
        "repo": args.repo,
        "local": str(args.local),
        "branch": args.branch,
        "issue": args.issue,
        "cycle": str(args.cycle),
        "executor": args.executor,
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "observed": False,
        "readiness_status": "unknown",
        "exit_code": None,
        "status": "BLOCKED",
        "artifacts": artifacts,
        "started_at": utc(),
    }


def parse_args() -> argparse.Namespace:
    hermes_default = os.environ.get("BOT_HERMES_HOME") or os.environ.get("HERMES_HOME")
    omh_default = os.environ.get("BOT_OMH_HOME")
    codex_default = os.environ.get("BOT_CODEX_HOME") or os.environ.get("CODEX_HOME")
    parser = argparse.ArgumentParser(description="Run john-lomein forge implementation through OMH and Codex.")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--local", required=True, type=Path)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--issue", required=True, type=int)
    parser.add_argument("--cycle", required=True, type=Path)
    parser.add_argument("--prompt-file", required=True, type=Path)
    parser.add_argument("--hermes-home", type=Path, default=Path(hermes_default).expanduser() if hermes_default else None)
    parser.add_argument("--omh-home", type=Path, default=Path(omh_default).expanduser() if omh_default else None)
    parser.add_argument("--codex-home", type=Path, default=Path(codex_default).expanduser() if codex_default else None)
    parser.add_argument("--executor", default=os.environ.get("BOT_IMPLEMENTATION_EXECUTOR") or "codex")
    parser.add_argument("--model", default=os.environ.get("BOT_CODEX_MODEL") or "gpt-5.5")
    parser.add_argument("--reasoning-effort", default=os.environ.get("BOT_CODEX_REASONING_EFFORT") or "xhigh")
    parser.add_argument("--timeout", type=int, default=int(os.environ.get("BOT_CODEX_TIMEOUT_SECONDS") or os.environ.get("BOT_AGENT_TIMEOUT_SECONDS") or 3600))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.cycle.mkdir(parents=True, exist_ok=True)
    if not args.hermes_home:
        print("john-lomein OMH implementation blocked: --hermes-home or HERMES_HOME is required")
        print("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED")
        return 1
    args.hermes_home = args.hermes_home.expanduser().resolve()
    if args.omh_home:
        args.omh_home = args.omh_home.expanduser().resolve()
    else:
        args.omh_home = args.hermes_home / "omh"
    if args.codex_home:
        args.codex_home = args.codex_home.expanduser().resolve()

    artifacts = {
        "omh_chat_interact": str(args.cycle / "omh-chat-interact.json"),
        "omh_chat_interact_error": str(args.cycle / "omh-chat-interact.err"),
        "omh_coding_delegate": str(args.cycle / "omh-coding-delegate.json"),
        "omh_coding_delegate_error": str(args.cycle / "omh-coding-delegate.err"),
        "executor_readiness": str(args.cycle / "executor-readiness.json"),
        "executor_readiness_error": str(args.cycle / "executor-readiness.err"),
        "codex_stdout": str(args.cycle / "codex-stdout.log"),
        "codex_stderr": str(args.cycle / "codex-stderr.log"),
        "codex_final": str(args.cycle / "codex-final.md"),
        "executor_result": str(args.cycle / "executor-result.json"),
    }
    result = build_result(args, artifacts)
    codex_final = Path(artifacts["codex_final"])
    preexisting_artifacts = [
        name for name, value in artifacts.items() if os.path.lexists(Path(value))
    ]
    if preexisting_artifacts:
        preflight_path = args.cycle / f"executor-preflight-blocked-{time.time_ns()}-{os.getpid()}.json"
        artifacts["executor_result"] = str(preflight_path)
        result["blocker"] = (
            "codex_final_artifact_preexisting"
            if "codex_final" in preexisting_artifacts
            else "executor_artifact_preexisting"
        )
        result["artifact_preflight_errors"] = [
            {
                "artifact": name,
                "operation": "preflight",
                "condition": "preexisting",
            }
            for name in preexisting_artifacts
        ]
        result["finished_at"] = utc()
        write_json(preflight_path, result)
        print(
            "john-lomein OMH implementation blocked: executor artifacts already exist: "
            + ", ".join(preexisting_artifacts)
        )
        print("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED")
        return 1

    result_path = Path(artifacts["executor_result"])
    prompt, prompt_read_error = read_text_artifact(
        args.prompt_file,
        artifact="implementation_prompt",
        required=True,
    )
    if prompt_read_error:
        result["blocker"] = "implementation_prompt_artifact_read_failed"
        result["artifact_read_errors"] = [prompt_read_error]
        result["finished_at"] = utc()
        write_json(result_path, result)
        print(
            "john-lomein OMH implementation blocked: implementation prompt read failed: "
            + evidence_summary(prompt_read_error)
        )
        print("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED")
        return 1

    env = command_env(args)
    omh = resolve_command("omh", env)
    codex = resolve_command("codex", env)
    if args.executor != "codex":
        result["blocker"] = f"unsupported_executor={args.executor}"
        write_json(result_path, result)
        print(f"john-lomein OMH implementation blocked: unsupported executor {args.executor}")
        print("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED")
        return 1
    if not omh:
        result["blocker"] = "missing_omh"
        write_json(result_path, result)
        print("john-lomein OMH implementation blocked: omh command not found")
        print("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED")
        return 1
    if not codex:
        result["blocker"] = "missing_codex"
        write_json(result_path, result)
        print("john-lomein OMH implementation blocked: codex command not found")
        print("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED")
        return 1

    omh_prefix = [omh, "--omh-home", str(args.omh_home), "--hermes-home", str(args.hermes_home)]
    chat_proc, chat_data = run_json_artifact(
        "chat-interact",
        omh_prefix + ["chat", "interact", "--source", "hermes", "--mode", "delegate", "--executor", "codex", "--include-message", "--stdin", "--json"],
        path=Path(artifacts["omh_chat_interact"]),
        err_path=Path(artifacts["omh_chat_interact_error"]),
        env=env,
        input_text=prompt,
    )
    delegate_proc, delegate_data = run_json_artifact(
        "coding-delegate",
        omh_prefix + ["coding", "delegate", "--source", "hermes", "--executor", "codex", "--include-message", "--record", "--stdin"],
        path=Path(artifacts["omh_coding_delegate"]),
        err_path=Path(artifacts["omh_coding_delegate_error"]),
        env=env,
        input_text=prompt,
    )
    readiness_proc, readiness = run_json_artifact(
        "executor-readiness",
        omh_prefix + ["coding", "executor-readiness", "--executor", "codex"],
        path=Path(artifacts["executor_readiness"]),
        err_path=Path(artifacts["executor_readiness_error"]),
        env=env,
        input_text="",
    )
    readiness = readiness or read_json(Path(artifacts["executor_readiness"]))
    readiness_status = str(readiness.get("status") or "unknown")
    result["readiness_status"] = readiness_status
    result["omh_exit_codes"] = {
        "chat_interact": chat_proc.returncode,
        "coding_delegate": delegate_proc.returncode,
        "executor_readiness": readiness_proc.returncode,
    }
    delegate_prepared_handoff = coding_delegate_prepared_handoff_ready(delegate_data, args, prompt)
    result["coding_delegate_prepared_handoff_accepted"] = delegate_prepared_handoff
    if delegate_prepared_handoff:
        result["coding_delegate_prepared_handoff_reason"] = "dispatchable_omh_handoff_with_concrete_forge_implementation_context"

    omh_blockers = []
    omh_blockers.extend(semantic_blockers("chat_interact", chat_data))
    omh_blockers.extend(filter_prepared_handoff_blockers(semantic_blockers("coding_delegate", delegate_data), delegate_prepared_handoff))
    omh_blockers.extend(semantic_blockers("executor_readiness", readiness))
    ready = readiness_proc.returncode == 0 and readiness_status == "ready" and readiness_available(readiness.get("available", True))
    if chat_proc.returncode != 0 or delegate_proc.returncode != 0 or not ready or omh_blockers:
        result["blocker"] = "omh_handoff_or_readiness_failed"
        result["blockers"] = omh_blockers
        result["finished_at"] = utc()
        write_json(result_path, result)
        print("john-lomein OMH implementation blocked: OMH handoff/readiness did not pass")
        if omh_blockers:
            print("OMH semantic blockers: " + "; ".join(omh_blockers[:8]))
        print("JOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED")
        return 1

    codex_cmd = [
        codex,
        "exec",
        "--ignore-user-config",
        "--ignore-rules",
        "--ephemeral",
        "--model",
        args.model,
        "--sandbox",
        "workspace-write",
        "--cd",
        str(args.local),
        "-c",
        f"model_reasoning_effort={toml_string(args.reasoning_effort)}",
        "-c",
        "shell_environment_policy.inherit=none",
        "-c",
        "mcp_servers={}",
        "--color",
        "never",
        "--output-last-message",
        str(codex_final),
        "-",
    ]
    result["codex_command"] = codex_cmd
    try:
        process_env = codex_command_env(args, env)
    except Exception as exc:
        process_error = exception_evidence("codex_process", "prepare", exc)
        exit_code = 1
        stdout = ""
        stderr = f"\n[{utc()}] codex process preparation failed: {evidence_summary(process_error)}\n"
        observed = False
    else:
        isolation_env = codex_isolation_env(args, env, process_env)
        try:
            codex_cmd = isolated_command(
                isolation_env,
                codex_cmd,
                allow_projection=False,
            )
            # The outer command is already fully constructed. Do not leak the
            # runtime binding variables into the coding model itself.
            process_env = isolated_environment(isolation_env)
            for key in (
                "BOT_HERMES_HOME",
                "HERMES_HOME",
                "BOT_LOCAL",
                "BOT_MODEL_MEMORY_ISOLATION",
                "BOT_STEWARD_PRIVATE_ROOT",
                "BOT_STEWARD_PROJECTION_ROOT",
            ):
                process_env.pop(key, None)
        except Exception as exc:
            process_error = exception_evidence("codex_process", "isolation", exc)
            exit_code = 1
            stdout = ""
            stderr = (
                f"\n[{utc()}] codex isolation preparation failed: "
                f"{evidence_summary(process_error)}\n"
            )
            observed = False
        else:
            exit_code, stdout, stderr, observed, process_error = run_process(
                codex_cmd,
                env=process_env,
                cwd=args.local,
                input_text=prompt,
                timeout=args.timeout,
            )
    Path(artifacts["codex_stdout"]).write_text(stdout, encoding="utf-8")
    Path(artifacts["codex_stderr"]).write_text(stderr, encoding="utf-8")
    final_text = ""
    final_read_error = None
    if not process_error:
        final_text, final_read_error = read_text_artifact(codex_final, artifact="codex_final")
    parsed_status, parsed_source, marker_evidence = parse_implementation_marker(final_text, stdout)
    semantic_status, semantic_source = parsed_status, parsed_source
    result["observed"] = observed
    result["exit_code"] = exit_code
    result["semantic_status"] = semantic_status
    result["semantic_status_source"] = semantic_source
    result["semantic_marker_evidence"] = marker_evidence
    if process_error:
        result["process_errors"] = [process_error]
    if final_read_error:
        result["artifact_read_errors"] = [final_read_error]
    if (
        not process_error
        and not final_read_error
        and exit_code == 0
        and semantic_status == "COMPLETE"
        and semantic_source not in {"missing_marker", "ambiguous_marker"}
    ):
        result["status"] = "COMPLETE"
    else:
        result["status"] = "BLOCKED"
        blockers: list[str] = []
        if process_error:
            process_blocker = (
                "codex_process_prepare_failed"
                if process_error.get("operation") == "prepare"
                else "codex_process_launch_failed"
            )
            blockers.append(process_blocker)
        elif final_read_error:
            blockers.append("codex_final_artifact_read_failed")
            if exit_code != 0:
                blockers.append("codex_process_failed")
        else:
            blockers.append("codex_semantic_status_blocked" if exit_code == 0 else "codex_process_failed")
        result["blocker"] = blockers[0]
        result["blockers"] = blockers
    result["finished_at"] = utc()
    write_json(result_path, result)
    presentation_stderr = stderr
    if final_read_error:
        presentation_stderr += (
            f"\n[{utc()}] codex final artifact read failed: {evidence_summary(final_read_error)}\n"
        )
    print_final_or_tail(final_text, stdout, presentation_stderr)
    print(f"JOHN_LOMEIN_IMPLEMENT_STATUS: {result['status']}")
    if result["status"] != "COMPLETE":
        return exit_code or 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
