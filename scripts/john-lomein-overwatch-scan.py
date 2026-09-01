#!/usr/bin/env python3
from __future__ import annotations

import os
import json
import sys
import time
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from john_lomein_owner_actions import DIRTY_CHECKOUT_RECOVERY
from john_lomein_autonomy import (
    AutonomyError,
    autonomy_status,
    policy_from_runtime,
)


def sh(cmd, cwd=None, timeout=30):
    env = dict(os.environ)
    home = Path(env.get("BOT_HERMES_HOME") or env.get("HERMES_HOME") or "").expanduser()
    profile = env.get("BOT_MAINTAINER_PROFILE") or "john-lomein-maintainer"
    gh_config = home / "profiles" / profile / "home" / ".config" / "gh"
    if gh_config.exists():
        env.setdefault("GH_CONFIG_DIR", str(gh_config))
    env.setdefault("GH_PROMPT_DISABLED", "1")
    env.setdefault("GH_NO_UPDATE_NOTIFIER", "1")
    env.setdefault("GH_NO_EXTENSION_UPDATE_NOTIFIER", "1")
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:  # pragma: no cover - defensive runtime guard
        return 999, "", str(e)


def load_env(H: Path):
    vals = {}
    p = H / "scripts" / "john-lomein-instance.env"
    if p.exists():
        for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            if "=" in raw:
                k, v = raw.split("=", 1)
                vals[k] = v.strip().strip("'").strip('"')
    return vals


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False


def process_command(pid: int) -> str:
    if not pid_alive(pid):
        return ""
    try:
        proc = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True, timeout=5)
    except Exception:
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def pid_is_lane_worker(pid: int, lane: str) -> bool:
    cmd = process_command(pid)
    return bool(cmd and "john-lomein-worker.py" in cmd and f" run {lane}" in cmd)


def parse_utc(ts: str) -> float:
    try:
        return time.mktime(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
    except Exception:
        return 0.0


def worker_warnings(H: Path) -> list[str]:
    warnings: list[str] = []
    root = H / "state" / "workers"
    if not root.exists():
        warnings.append("worker state dir missing")
        return warnings
    now = time.time()
    for state in sorted(root.glob("*.json")):
        try:
            data = json.loads(state.read_text(encoding="utf-8"))
        except Exception as exc:
            warnings.append(f"worker state unreadable {state.name}:{exc}")
            continue
        lane = data.get("lane") or state.stem
        pid = data.get("pid")
        status = data.get("status")
        if pid and status in {"spawned", "running", "already_running"}:
            alive = pid_is_lane_worker(int(pid), str(lane))
            if not alive:
                warnings.append(f"worker {lane} stale pid={pid} status={status}")
                continue
            heartbeat = parse_utc(data.get("heartbeat_at") or data.get("updated_at") or "")
            if heartbeat and now - heartbeat > 10 * 60:
                warnings.append(f"worker {lane} heartbeat stale {int((now-heartbeat)/60)}m pid={pid}")
    return warnings


def main() -> int:
    H = Path(os.environ.get("HERMES_HOME", "")).expanduser()
    vals = load_env(H)
    slug = vals.get("BOT_SLUG", "unknown")
    repo = vals.get("BOT_REPO", "")
    local = vals.get("BOT_LOCAL", "")
    branch = vals.get("BOT_DEFAULT_BRANCH", "main")
    failures = []
    warnings = []
    domains = {
        "runtime": "ok",
        "autonomy_control": "ok",
        "managed_checkout": "ok",
        "queue_release": "ok",
        "workers": "ok",
        "discord_visibility": "ok",
    }

    if not H.exists():
        failures.append("runtime missing")
        domains["runtime"] = "fail"
    else:
        try:
            autonomy_state = autonomy_status(
                H,
                policy_from_runtime(H),
            )
            autonomy_alerts = []
            for lane, lane_state in autonomy_state["lanes"].items():
                circuit = lane_state["circuit"]
                daily = lane_state["daily"]
                if circuit["open"]:
                    autonomy_alerts.append(
                        f"{lane}_circuit_open_until={circuit['open_until']}"
                    )
                if daily["lane_runs"] >= daily["lane_run_limit"]:
                    autonomy_alerts.append(
                        f"{lane}_run_budget={daily['lane_runs']}/{daily['lane_run_limit']}"
                    )
            daily = autonomy_state["lanes"]["maintainer"]["daily"]
            if daily["runtime_seconds"] >= daily["runtime_limit_seconds"]:
                autonomy_alerts.append(
                    f"runtime_budget={daily['runtime_seconds']}/{daily['runtime_limit_seconds']}"
                )
            for effect, used in daily["effect_counts"].items():
                limit = daily["effect_limits"][effect]
                if limit > 0 and used >= limit:
                    autonomy_alerts.append(
                        f"{effect}_budget={used}/{limit}"
                    )
            if autonomy_alerts:
                warnings.extend(autonomy_alerts)
                domains["autonomy_control"] = "warn"
        except (AutonomyError, ValueError) as exc:
            failures.append(f"autonomy_control_invalid {exc}")
            domains["autonomy_control"] = "fail"
    for p in ["john-lomein-maintainer", "john-lomein-forge", "john-lomein-guide", "john-lomein-overwatch"]:
        if not (H / "profiles" / p).exists():
            failures.append(f"profile missing {p}")
            domains["runtime"] = "fail"

    if local and Path(local).exists():
        c, o, _ = sh(["git", "status", "--short", "--branch"], cwd=local)
        dirty = [x for x in o.splitlines()[1:] if x.strip()]
        if dirty:
            warnings.append(f"managed_checkout_dirty items={len(dirty)} {DIRTY_CHECKOUT_RECOVERY}")
            domains["managed_checkout"] = "warn"
        c2, o2, _ = sh(["git", "rev-list", "--left-right", "--count", f"HEAD...origin/{branch}"], cwd=local)
        if c2 == 0 and o2.strip() != "0\t0" and o2.strip() != "0 0":
            warnings.append(f"managed_checkout_not_fresh {o2}")
            domains["managed_checkout"] = "warn"
    else:
        failures.append("checkout missing")
        domains["managed_checkout"] = "fail"

    if vals.get("BOT_DISCORD_ENABLED", "0") == "1" and not vals.get("BOT_NOTIFICATIONS_CHANNEL") and not vals.get("BOT_NOTIFICATION_TARGET"):
        warnings.append("discord_visibility_enabled_without_notification_target")
        domains["discord_visibility"] = "warn"

    worker_alerts = worker_warnings(H)
    if worker_alerts:
        domains["workers"] = "warn"
        warnings.extend(worker_alerts)

    queue_script = H / "scripts" / "john-lomein-queue-health.py"
    if queue_script.exists():
        env = dict(os.environ)
        env.update(vals)
        env.setdefault("HERMES_HOME", str(H))
        env.setdefault("BOT_HERMES_HOME", str(H))
        qc, qo, qe = sh(["python3", str(queue_script)], timeout=90)
        if qc != 0:
            domains["queue_release"] = "warn" if qc == 1 else "fail"
            warnings.append(("queue_release " + (qo or qe or f"queue health exited {qc}")).replace("\n", " "))
    else:
        warnings.append("queue_release queue health script missing")
        domains["queue_release"] = "warn"

    details = "; ".join(failures + warnings) or "ok"
    domain_text = " ".join(f"{k}={v}" for k, v in sorted(domains.items()))
    print(f"john-lomein overwatch: instance={slug} repo={repo} domains={domain_text} failures={len(failures)} warnings={len(warnings)} details={details}")
    return 2 if failures else (1 if warnings else 0)


if __name__ == "__main__":
    raise SystemExit(main())
