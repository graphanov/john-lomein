#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
WORKER_PATH = ROOT / "scripts" / "john-lomein-worker.py"


def load_worker():
    spec = importlib.util.spec_from_file_location("john_lomein_worker", WORKER_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class WorkerSupervisorTest(unittest.TestCase):
    def make_env(self, tmp: str) -> dict[str, str]:
        H = Path(tmp) / "hermes"
        (H / "state" / "workers").mkdir(parents=True)
        (H / "logs" / "workers").mkdir(parents=True)
        local = Path(tmp) / "repo"
        local.mkdir()
        return {
            "BOT_HERMES_HOME": str(H),
            "HERMES_HOME": str(H),
            "BOT_LOCAL": str(local),
            "BOT_MISSION_COMPLETE": "1",
            "BOT_MUTATION_ENABLED": "1",
        }

    def test_load_env_refuses_forged_instance_env_selector(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            expected = Path(env["BOT_HERMES_HOME"]) / "scripts" / "john-lomein-instance.env"
            expected.parent.mkdir(parents=True, exist_ok=True)
            expected.write_text("BOT_LOCAL='real'\nBOT_OWNER_APPROVERS='real-owner'\n", encoding="utf-8")
            forged = Path(tmp) / "forged.env"
            forged.write_text("BOT_LOCAL='evil'\nBOT_OWNER_APPROVERS='attacker'\n", encoding="utf-8")
            old_env = os.environ.copy()
            os.environ.clear()
            os.environ.update({"HERMES_HOME": env["BOT_HERMES_HOME"], "JOHN_LOMEIN_INSTANCE_ENV": str(forged)})
            try:
                with self.assertRaises(RuntimeError):
                    worker.load_env()
            finally:
                os.environ.clear()
                os.environ.update(old_env)

    def test_parse_shell_env_does_not_seed_authority_from_caller_env(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "john-lomein-instance.env"
            path.write_text("BOT_LOCAL='real'\n", encoding="utf-8")
            old_env = os.environ.copy()
            os.environ["BOT_OWNER_APPROVERS"] = "attacker"
            try:
                vals = worker.parse_shell_env(path)
            finally:
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(vals.get("BOT_LOCAL"), "real")
            self.assertNotIn("BOT_OWNER_APPROVERS", vals)

    def test_base_env_ignores_caller_auth_and_config(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            env["HERMES_PYTHON"] = sys.executable
            gh_config = Path(env["BOT_HERMES_HOME"]) / "profiles" / "john-lomein-maintainer" / "home" / ".config" / "gh"
            gh_config.mkdir(parents=True)
            old_env = os.environ.copy()
            os.environ.clear()
            os.environ.update({"GH_CONFIG_DIR": "/tmp/evil-gh", "GH_TOKEN": "evil", "PATH": "/tmp/evil-bin"})
            try:
                result = worker.base_env(env)
            finally:
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(result.get("GH_CONFIG_DIR"), str(gh_config))
            self.assertNotIn("GH_TOKEN", result)
            self.assertNotIn("/tmp/evil-bin", result.get("PATH", ""))

    def test_model_role_environments_exclude_mnemosyne_and_pin_policy(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            env["HERMES_PYTHON"] = sys.executable
            env["MNEMOSYNE_DATA_DIR"] = "/should/not/reach/model"
            managed_root = (
                Path(env["BOT_HERMES_HOME"]) / "managed-policy"
            )
            env["BOT_HERMES_MANAGED_ROOT"] = str(managed_root)
            prompt = Path(tmp) / "prompt.txt"
            prompt.write_text("test", encoding="utf-8")
            captured: list[tuple[str, dict[str, str]]] = []

            def fake_stream(
                child_env,
                lane,
                cmd,
                *,
                cwd=None,
                deadline_monotonic=None,
            ):
                captured.append((lane, dict(child_env)))
                return 0, "ok"

            profiles = {
                "maintainer": "john-lomein-maintainer",
                "forge": "john-lomein-forge",
                "guide": "john-lomein-guide",
                "overwatch": "john-lomein-overwatch",
                "learning_steward": "john-lomein-learning-steward",
            }
            for profile in profiles.values():
                (
                    Path(env["BOT_HERMES_HOME"])
                    / "profiles"
                    / profile
                ).mkdir(parents=True)
                (managed_root / profile).mkdir(parents=True)
            with mock.patch.object(
                worker,
                "stream_command",
                side_effect=fake_stream,
            ), mock.patch.object(
                worker,
                "isolated_command",
                side_effect=lambda _env, cmd, **_kwargs: cmd,
            ):
                for lane, profile in profiles.items():
                    worker.run_hermes_chat(
                        env,
                        lane,
                        profile,
                        prompt,
                    )

            self.assertEqual(
                {lane for lane, _ in captured},
                set(profiles),
            )
            for lane, child_env in captured:
                self.assertNotIn("MNEMOSYNE_DATA_DIR", child_env)
                self.assertEqual(
                    child_env["HERMES_MANAGED_DIR"],
                    str(managed_root / profiles[lane]),
                )
            steward_env = worker.steward_process_env(env)
            self.assertEqual(
                steward_env["MNEMOSYNE_DATA_DIR"],
                str(
                    Path(env["BOT_HERMES_HOME"])
                    / "private"
                    / "learning-steward"
                    / "mnemosyne"
                    / "data"
                ),
            )

    def test_process_command_uses_absolute_ps_and_minimal_env(self):
        worker = load_worker()
        calls = []

        def fake_run(cmd, capture_output=True, text=True, timeout=5, env=None):
            calls.append((cmd, env))
            return subprocess.CompletedProcess(cmd, 0, "python john-lomein-worker.py run maintainer\n", "")

        old_run = worker.subprocess.run
        old_pid_alive = getattr(worker, "pid_alive")
        worker.subprocess.run = fake_run
        setattr(worker, "pid_alive", lambda pid: True)
        try:
            output = worker.process_command(123)
        finally:
            worker.subprocess.run = old_run
            setattr(worker, "pid_alive", old_pid_alive)
        self.assertIn("john-lomein-worker.py", output)
        cmd, env = calls[0]
        self.assertEqual(cmd[0], "/bin/ps")
        self.assertEqual(env, {"PATH": worker.CONTROLLED_PATH})

    def test_replace_state_clears_stale_run_fields(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            worker.write_state(env, "maintainer", status="ok", pid=123, finished_at="old", stalled_since="old")
            worker.replace_state(env, "maintainer", status="running", pid=456, started_at="new")
            data = json.loads(worker.state_path(env, "maintainer").read_text())
            self.assertEqual(data["status"], "running")
            self.assertEqual(data["pid"], 456)
            self.assertNotIn("finished_at", data)
            self.assertNotIn("stalled_since", data)

    def test_pid_identity_rejects_unrelated_live_process(self):
        worker = load_worker()
        self.assertFalse(worker.pid_is_lane_worker(os.getpid(), "maintainer"))

    def test_same_lane_spawn_skip_does_not_write_already_running_status(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            worker.pid_path(env, "maintainer").write_text("111", encoding="utf-8")
            worker.replace_state(env, "maintainer", status="running", pid=111, started_at="now")
            with mock.patch.object(worker, "pid_is_lane_worker", return_value=True):
                rc = worker.spawn_lane(env, "maintainer", quiet=True)
            self.assertEqual(rc, 0)
            data = json.loads(worker.state_path(env, "maintainer").read_text())
            self.assertEqual(data["status"], "running")
            self.assertEqual(data["spawn_skip_reason"], "same_lane_running")
            self.assertNotEqual(data["status"], "already_running")

    def test_mutating_lanes_do_not_spawn_concurrently(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            worker.pid_path(env, "maintainer").write_text("222", encoding="utf-8")
            worker.replace_state(env, "maintainer", status="running", pid=222, started_at="now")
            calls = []

            def fake_popen(*args, **kwargs):  # pragma: no cover - should not run
                calls.append((args, kwargs))
                raise AssertionError("forge spawned while maintainer active")

            with mock.patch.object(worker, "pid_is_lane_worker", side_effect=lambda pid, lane: lane == "maintainer"), mock.patch.object(worker.subprocess, "Popen", side_effect=fake_popen):
                rc = worker.spawn_lane(env, "forge", quiet=True)
            self.assertEqual(rc, 0)
            self.assertFalse(calls)
            data = json.loads(worker.state_path(env, "forge").read_text())
            self.assertEqual(data["spawn_skip_reason"], "maintainer_running")
            self.assertEqual(data["blocked_by_lane"], "maintainer")

    def test_runtime_kill_switch_blocks_run_and_spawn_before_work(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            env["BOT_MUTATION_ENABLED"] = "0"
            with mock.patch.object(
                worker,
                "begin_run",
                side_effect=AssertionError("begin_run must not execute"),
            ), mock.patch.object(
                worker.subprocess,
                "Popen",
                side_effect=AssertionError("worker must not spawn"),
            ):
                run_rc = worker.run_lane(env, "forge")
                spawn_rc = worker.spawn_lane(env, "forge", quiet=True)
            self.assertEqual(run_rc, 75)
            self.assertEqual(spawn_rc, 75)
            data = json.loads(
                worker.state_path(env, "forge").read_text(encoding="utf-8")
            )
            self.assertEqual(data["status"], "autonomy_blocked")
            self.assertIn("kill switch is disabled", data["error"])

    def test_incomplete_owner_mission_blocks_run_and_spawn_before_work(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            env["BOT_MISSION_COMPLETE"] = "0"
            with mock.patch.object(
                worker,
                "begin_run",
                side_effect=AssertionError("begin_run must not execute"),
            ), mock.patch.object(
                worker.subprocess,
                "Popen",
                side_effect=AssertionError("worker must not spawn"),
            ):
                run_rc = worker.run_lane(env, "forge")
                spawn_rc = worker.spawn_lane(env, "forge", quiet=True)
            self.assertEqual(run_rc, 75)
            self.assertEqual(spawn_rc, 75)
            data = json.loads(
                worker.state_path(env, "forge").read_text(encoding="utf-8")
            )
            self.assertEqual(data["status"], "autonomy_blocked")
            self.assertIn("owner mission gate is incomplete", data["error"])

    def test_forge_blocked_implementation_output_sets_blocked_state(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            posts = []
            learning = []

            def fake_stream(
                env_arg,
                lane,
                cmd,
                *,
                cwd=None,
                deadline_monotonic=None,
            ):
                return 0, "john-lomein forge cycle: {\"implement_status\": \"BLOCKED\"}\nJOHN_LOMEIN_IMPLEMENT_STATUS: BLOCKED\n"

            worker.stream_command = fake_stream
            worker.post = lambda env_arg, label, body: posts.append((label, body))
            worker.emit_learning = lambda env_arg, lane, status, exit_code, output: learning.append((lane, status, exit_code, output))

            rc = worker.run_lane(env, "forge")
            data = json.loads(worker.state_path(env, "forge").read_text())

            self.assertEqual(rc, 1)
            self.assertEqual(data["status"], "blocked_implementation")
            self.assertEqual(data["exit_code"], 0)
            self.assertEqual(posts[0][0], "FORGE_BLOCKED")
            self.assertEqual(learning[0][1], "blocked_implementation")

    def test_hard_deadline_is_not_bypassed_by_partial_stdout_line(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            env["HERMES_PYTHON"] = sys.executable
            started = time.monotonic()
            code, output = worker.stream_command(
                env,
                "maintainer",
                [
                    sys.executable,
                    "-c",
                    (
                        "import sys,time;"
                        "sys.stdout.write('partial');"
                        "sys.stdout.flush();"
                        "time.sleep(3)"
                    ),
                ],
                deadline_monotonic=started + 0.25,
            )
            elapsed = time.monotonic() - started
            self.assertEqual(code, 124)
            self.assertIn("partial", output)
            self.assertIn("budget_exhausted", output)
            self.assertLess(elapsed, 2.0)

    def test_stream_command_bounds_captured_and_logged_child_output(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            env["HERMES_PYTHON"] = sys.executable
            old_capture = worker.MAX_CAPTURED_OUTPUT_CHARS
            old_stream = worker.MAX_STREAMED_LOG_CHARS
            worker.MAX_CAPTURED_OUTPUT_CHARS = 128
            worker.MAX_STREAMED_LOG_CHARS = 96
            visible = io.StringIO()
            try:
                with redirect_stdout(visible):
                    code, output = worker.stream_command(
                        env,
                        "maintainer",
                        [
                            sys.executable,
                            "-c",
                            "print('x' * 4096)",
                        ],
                    )
            finally:
                worker.MAX_CAPTURED_OUTPUT_CHARS = old_capture
                worker.MAX_STREAMED_LOG_CHARS = old_stream
            self.assertEqual(code, 0)
            self.assertIn("earlier child output omitted", output)
            self.assertLessEqual(
                len(output),
                128 + len(
                    "[earlier child output omitted by worker "
                    "capture limit]\n"
                ),
            )
            self.assertIn(
                "worker child output log limit reached",
                visible.getvalue(),
            )
            self.assertLess(len(visible.getvalue()), 512)

    def test_worker_log_retention_bounds_age_count_and_total_size(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            root = worker.log_root(env)
            now = time.time()
            paths = []
            for index in range(5):
                path = root / f"maintainer-2026010{index}T000000Z.log"
                path.write_bytes(bytes([65 + index]) * 40)
                os.utime(path, (now - index, now - index))
                paths.append(path)
            stale = root / "stale.log"
            stale.write_text("old", encoding="utf-8")
            os.utime(
                stale,
                (
                    now - worker.WORKER_LOG_MAX_AGE_SECONDS - 1,
                    now - worker.WORKER_LOG_MAX_AGE_SECONDS - 1,
                ),
            )
            old_files = worker.MAX_WORKER_LOG_FILES
            old_bytes = worker.MAX_WORKER_LOG_TOTAL_BYTES
            worker.MAX_WORKER_LOG_FILES = 3
            worker.MAX_WORKER_LOG_TOTAL_BYTES = 90
            try:
                worker.prune_worker_logs(env, now=now)
            finally:
                worker.MAX_WORKER_LOG_FILES = old_files
                worker.MAX_WORKER_LOG_TOTAL_BYTES = old_bytes
            kept = sorted(root.glob("*.log"))
            self.assertFalse(stale.exists())
            self.assertEqual(len(kept), 2)
            self.assertEqual(
                {path.name for path in kept},
                {paths[0].name, paths[1].name},
            )

    def test_losing_mutation_lease_does_not_clobber_running_state(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            worker.replace_state(
                env,
                "maintainer",
                status="running",
                pid=4242,
                started_at="earlier",
            )

            @contextmanager
            def busy_lease(*_args, **_kwargs):
                raise worker.AutonomyError(
                    "instance mutation lease is already held"
                )
                yield

            with mock.patch.object(
                worker,
                "mutation_lease",
                side_effect=busy_lease,
            ):
                rc = worker.run_lane(env, "maintainer")

            data = json.loads(
                worker.state_path(env, "maintainer").read_text()
            )
            self.assertEqual(rc, 0)
            self.assertEqual(data["status"], "running")
            self.assertEqual(data["pid"], 4242)

    def test_clean_noop_output_is_not_posted_as_blocked_or_failed(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            posts = []
            learning = []

            def fake_chat(
                env_arg,
                lane,
                profile,
                prompt_path,
                *,
                deadline_monotonic=None,
            ):
                return 0, "Status: blocked_exact — no safe maintainer mutation exists this tick. checkout stayed clean."

            with mock.patch.object(worker, "run_hermes_chat", side_effect=fake_chat), mock.patch.object(worker, "post", side_effect=lambda env_arg, label, body: posts.append((label, body))), mock.patch.object(worker, "emit_learning", side_effect=lambda env_arg, lane, status, exit_code, output: learning.append((lane, status, exit_code, output))):
                rc = worker.run_lane(env, "maintainer")
            data = json.loads(worker.state_path(env, "maintainer").read_text())

            self.assertEqual(rc, 0)
            self.assertEqual(data["status"], "no_action_needed")
            self.assertFalse(posts)
            self.assertEqual(learning[0][1], "no_action_needed")

    def test_failure_exit_cannot_claim_success_status_through_output(self):
        worker = load_worker()
        for output in (
            "owner gate",
            "no safe maintainer mutation",
            "queue is clean",
        ):
            with self.subTest(output=output):
                self.assertEqual(
                    worker.lane_status_for_output(
                        "maintainer",
                        "failed",
                        output,
                    ),
                    "failed",
                )

    def test_autonomy_finalization_failure_forces_control_failure(self):
        worker = load_worker()
        with tempfile.TemporaryDirectory() as tmp:
            env = self.make_env(tmp)
            posts = []
            with mock.patch.object(
                worker,
                "run_hermes_chat",
                return_value=(0, "queue is clean"),
            ), mock.patch.object(
                worker,
                "finish_run",
                side_effect=worker.AutonomyError(
                    "journal unavailable"
                ),
            ), mock.patch.object(
                worker,
                "post",
                side_effect=lambda _env, label, body: posts.append(
                    (label, body)
                ),
            ), mock.patch.object(
                worker,
                "emit_learning",
            ):
                rc = worker.run_lane(env, "maintainer")
            data = json.loads(
                worker.state_path(env, "maintainer").read_text()
            )
            self.assertEqual(rc, 75)
            self.assertEqual(
                data["status"],
                "autonomy_control_failed",
            )
            self.assertEqual(
                posts[-1][0],
                "MAINTAINER_AUTONOMY_CONTROL_FAILED",
            )


if __name__ == "__main__":
    unittest.main()
