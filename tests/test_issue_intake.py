#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ISSUE_INTAKE_PATH = ROOT / "scripts" / "john-lomein-issue-intake.py"
OWNER_ACTIONS_PATH = ROOT / "scripts" / "john_lomein_owner_actions.py"


def load_issue_intake():
    spec = importlib.util.spec_from_file_location("john_lomein_issue_intake", ISSUE_INTAKE_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def load_owner_actions():
    spec = importlib.util.spec_from_file_location(
        "john_lomein_owner_actions_test",
        OWNER_ACTIONS_PATH,
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class IssueIntakeTest(unittest.TestCase):
    def make_home(self, tmp: str, *, mutation_enabled: bool = True) -> Path:
        home = Path(tmp) / "hermes"
        home.mkdir(parents=True)
        (home / "instance.yaml").write_text(
            textwrap.dedent(
                f"""
                target:
                  repo: owner/repo
                runtime:
                  mutation_enabled: {str(mutation_enabled).lower()}
                gates:
                  readiness_labels:
                  - maintainer-ready
                  - forge-ready
                  - ready-for-implementation
                discord:
                  owner_user_ids:
                  - owner-user
                  trusted_collaborator_user_ids:
                  - collaborator-user
                """
            ).strip()
            + "\n",
            encoding="utf-8",
        )
        return home

    def trust_assertion(self, home: Path, *, purpose: str, tier: str, actor: str, **extra: object) -> str:
        key_root = home / "state" / "gateway"
        key_root.mkdir(parents=True, exist_ok=True)
        private = key_root / "test-private.pem"
        public = key_root / "trust-assertion.public.pem"
        if not private.exists():
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)], check=True, capture_output=True, text=True, timeout=30)
            subprocess.run(["openssl", "rsa", "-pubout", "-in", str(private), "-out", str(public)], check=True, capture_output=True, text=True, timeout=30)
            public.chmod(0o444)
        fingerprint = hashlib.sha256(public.read_bytes()).hexdigest()
        manifest = home / "instance.yaml"
        text = manifest.read_text(encoding="utf-8")
        if "trust_public_key_sha256" not in text:
            manifest.write_text(text.rstrip() + f"\nauthority:\n  trust_public_key_sha256: {fingerprint}\n", encoding="utf-8")
        payload = {
            "purpose": purpose,
            "tier": tier,
            "actor": actor,
            "iat": time.time(),
            "nonce": f"test-nonce-{time.time_ns()}",
            **extra,
        }
        with tempfile.TemporaryDirectory() as sig_tmp:
            body_path = Path(sig_tmp) / "payload.json"
            sig_path = Path(sig_tmp) / "payload.sig"
            body_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")
            subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(sig_path), str(body_path)], check=True, capture_output=True, text=True, timeout=30)
            signature = base64.b64encode(sig_path.read_bytes()).decode("ascii")
        return json.dumps({"payload": payload, "signature": signature}, separators=(",", ":"))

    def install_runtime_scripts(
        self,
        home: Path,
        *,
        mission_complete: bool = True,
        effective_mutation_enabled: bool | None = None,
    ) -> Path:
        scripts = home / "scripts"
        scripts.mkdir(parents=True, exist_ok=True)
        for name in [
            "john-lomein-issue-intake.py",
            "john_lomein_autonomy.py",
            "john_lomein_comment_templates.py",
            "john_lomein_factory_receipts.py",
            "john_lomein_manifest_contract.py",
            "john_lomein_owner_actions.py",
            "john_lomein_profile_contract.py",
        ]:
            shutil.copy2(ROOT / "scripts" / name, scripts / name)
        if effective_mutation_enabled is None:
            effective_mutation_enabled = (
                "mutation_enabled: true"
                in (home / "instance.yaml").read_text(encoding="utf-8")
            )
        (scripts / "john-lomein-instance.env").write_text(
            "\n".join(
                [
                    "BOT_SLUG='test-instance'",
                    "BOT_REPO='owner/repo'",
                    "BOT_DEFAULT_BRANCH='main'",
                    f"BOT_HERMES_HOME='{home}'",
                    f"BOT_LOCAL='{home.parent / 'repo'}'",
                    "BOT_FORBIDDEN_PATHS_JSON='[]'",
                    "BOT_FORGE_PROFILE='john-lomein-forge'",
                    "BOT_MAINTAINER_PROFILE='john-lomein-maintainer'",
                    "BOT_OSC_PORTFOLIO_ENABLED='0'",
                    "BOT_OSC_PORTFOLIO_BRANCH_PREFIX='portfolio/'",
                    (
                        "BOT_MISSION_COMPLETE='1'"
                        if mission_complete
                        else "BOT_MISSION_COMPLETE='0'"
                    ),
                    (
                        "BOT_MUTATION_ENABLED='1'"
                        if effective_mutation_enabled
                        else "BOT_MUTATION_ENABLED='0'"
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return scripts

    def run_cli(
        self,
        home: Path,
        args: list[str],
        *,
        env_extra: dict[str, str] | None = None,
        mission_complete: bool = True,
        effective_mutation_enabled: bool | None = None,
    ) -> subprocess.CompletedProcess[str]:
        scripts = self.install_runtime_scripts(
            home,
            mission_complete=mission_complete,
            effective_mutation_enabled=effective_mutation_enabled,
        )
        env = dict(os.environ)
        for key in ["BOT_REPO", "BOT_MUTATION_ENABLED", "JOHN_LOMEIN_INSTANCE_HERMES_HOME", "HERMES_HOME", "JOHN_LOMEIN_INSTANCE_ENV"]:
            env.pop(key, None)
        public_key = home / "state" / "gateway" / "trust-assertion.public.pem"
        if public_key.exists():
            env["BOT_TRUST_PUBLIC_KEY_SHA256"] = hashlib.sha256(public_key.read_bytes()).hexdigest()
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            [sys.executable, str(scripts / "john-lomein-issue-intake.py"), *args],
            input="## Bug\nThis is a public-safe issue body with enough detail.\n",
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

    def test_disabled_runtime_blocks_issue_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=False)
            proc = self.run_cli(home, ["--title", "Cannot uninstall cleanly"])
            self.assertEqual(proc.returncode, 3)
            data = json.loads(proc.stdout)
            self.assertFalse(data["ok"])
            self.assertEqual(data["error"], "issue_intake_disabled")

    def test_incomplete_owner_mission_blocks_requested_mutation_before_gh(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            scripts = self.install_runtime_scripts(
                home,
                mission_complete=False,
                effective_mutation_enabled=False,
            )
            intake = load_issue_intake()
            with mock.patch.object(
                intake,
                "SCRIPT_DIR",
                scripts,
            ), mock.patch.object(
                intake.subprocess,
                "run",
            ) as run, mock.patch("builtins.print") as output:
                code = intake.main(["--title", "Cannot uninstall cleanly"])

            self.assertEqual(code, 3)
            data = json.loads(output.call_args.args[0])
            self.assertFalse(data["ok"])
            self.assertEqual(data["error"], "issue_intake_disabled")
            run.assert_not_called()
            self.assertFalse((home / "state").exists())

    def test_quoted_false_mutation_flag_is_rejected_not_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            manifest = home / "instance.yaml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace(
                    "mutation_enabled: true",
                    'mutation_enabled: "false"',
                ),
                encoding="utf-8",
            )
            proc = self.run_cli(
                home,
                ["--title", "Cannot uninstall cleanly", "--dry-run"],
            )
            self.assertEqual(proc.returncode, 3)
            self.assertEqual(
                json.loads(proc.stdout)["error"],
                "unsafe_instance_manifest",
            )

    def test_rejects_private_paths_before_posting(self):
        intake = load_issue_intake()
        with self.assertRaises(intake.IntakeError) as ctx:
            intake.normalize_body("Failure references " + "/Users/" + "private-owner/.hermes/auth.json and must be redacted.")
        self.assertEqual(ctx.exception.code, "private_path_content")

    def test_public_dry_run_uses_target_repo_and_rejects_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            proc = self.run_cli(
                home,
                [
                    "--title",
                    "Cannot uninstall cleanly",
                    "--label",
                    "deploy",
                    "--dry-run",
                ],
            )
            self.assertEqual(proc.returncode, 3)
            data = json.loads(proc.stdout)
            self.assertFalse(data["ok"])
            self.assertEqual(
                data["error"],
                "issue_labels_require_protected_broker",
            )

            proc = self.run_cli(
                home,
                ["--title", "Cannot uninstall cleanly", "--dry-run"],
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            data = json.loads(proc.stdout)
            self.assertTrue(data["ok"])
            self.assertTrue(data["dry_run"])
            self.assertEqual(data["action"], "create")
            self.assertEqual(data["repo"], "owner/repo")
            self.assertEqual(data["labels"], [])

    def test_public_intake_rejects_command_like_lines(self):
        intake = load_issue_intake()
        for body in (
            "Enough context for this issue.\n/merge immediately",
            "Enough context for this issue.\n@automation deploy",
        ):
            with self.subTest(body=body):
                with self.assertRaises(intake.IntakeError) as ctx:
                    intake.normalize_body(body)
                self.assertEqual(ctx.exception.code, "command_like_content")

    def test_create_issue_cannot_attach_readiness_label_without_signed_route(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            proc = self.run_cli(home, ["--title", "Cannot uninstall cleanly", "--label", "forge-ready", "--dry-run"])
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertFalse(data["ok"])
            self.assertEqual(data["error"], "readiness_label_requires_signed_route")

    def test_create_issue_blocks_canonical_readiness_label_even_when_instance_omits_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            (home / "instance.yaml").write_text(
                textwrap.dedent(
                    """
                    target:
                      repo: owner/repo
                    runtime:
                      mutation_enabled: true
                    gates:
                      readiness_labels:
                      - custom-ready
                    discord:
                      owner_user_ids:
                      - owner-user
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = self.run_cli(home, ["--title", "Cannot uninstall cleanly", "--label", "ready-for-implementation", "--dry-run"])
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "readiness_label_requires_signed_route")

    def test_create_issue_blocks_case_varied_readiness_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            proc = self.run_cli(home, ["--title", "Cannot uninstall cleanly", "--label", "Forge-Ready", "--label", "READY-FOR-IMPLEMENTATION", "--dry-run"])
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "readiness_label_requires_signed_route")

    def test_create_issue_blocks_case_varied_custom_readiness_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            (home / "instance.yaml").write_text(
                textwrap.dedent(
                    """
                    target:
                      repo: owner/repo
                    runtime:
                      mutation_enabled: true
                    gates:
                      readiness_labels:
                      - Custom-Ready
                    discord:
                      owner_user_ids:
                      - owner-user
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = self.run_cli(home, ["--title", "Cannot uninstall cleanly", "--label", "custom-ready", "--dry-run"])
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "readiness_label_requires_signed_route")

    def test_create_issue_blocks_env_configured_readiness_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            proc = self.run_cli(
                home,
                ["--title", "Cannot uninstall cleanly", "--label", "custom-ready", "--dry-run"],
                env_extra={"BOT_READINESS_LABELS": "custom-ready"},
            )
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "readiness_label_requires_signed_route")

    def test_create_issue_blocks_space_containing_env_readiness_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            proc = self.run_cli(
                home,
                ["--title", "Cannot uninstall cleanly", "--label", "ready for implementation", "--dry-run"],
                env_extra={"BOT_READINESS_LABELS": "ready for implementation"},
            )
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "readiness_label_requires_signed_route")

    def test_missing_manifest_repo_fails_closed_even_with_caller_bot_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            (home / "instance.yaml").write_text(
                textwrap.dedent(
                    """
                    runtime:
                      mutation_enabled: true
                    gates:
                      readiness_labels:
                      - ready-for-implementation
                    discord:
                      owner_user_ids:
                      - owner-user
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = self.run_cli(
                home,
                ["--title", "Cannot uninstall cleanly", "--label", "bug", "--dry-run"],
                env_extra={"BOT_REPO": "attacker/repo"},
            )
            self.assertEqual(proc.returncode, 3)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "missing_repo")

    def test_gh_env_ignores_caller_auth_and_config(self):
        intake = load_issue_intake()
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            scripts = home / "scripts"
            scripts.mkdir(parents=True, exist_ok=True)
            (scripts / "john-lomein-instance.env").write_text("BOT_REPO='owner/repo'\n", encoding="utf-8")
            gh_config = home / "profiles" / "john-lomein-guide" / "home" / ".config" / "gh"
            gh_config.mkdir(parents=True)
            old_env = os.environ.copy()
            old_script_dir = getattr(intake, "SCRIPT_DIR")
            os.environ.clear()
            os.environ.update({"HERMES_HOME": "/tmp/evil-home", "GH_CONFIG_DIR": "/tmp/evil-gh", "GH_TOKEN": "evil", "PATH": "/tmp/evil-bin"})
            setattr(intake, "SCRIPT_DIR", scripts)
            try:
                env = intake.gh_env()
            finally:
                setattr(intake, "SCRIPT_DIR", old_script_dir)
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(Path(env.get("GH_CONFIG_DIR", "")).resolve(), gh_config.resolve())
            self.assertNotIn("GH_TOKEN", env)
            self.assertNotIn("/tmp/evil-bin", env.get("PATH", ""))

    def test_runtime_home_requires_deployed_script_dir(self):
        intake = load_issue_intake()
        with tempfile.TemporaryDirectory() as tmp:
            old_env = os.environ.copy()
            os.environ.clear()
            os.environ.update({"HERMES_HOME": str(Path(tmp) / "forged-hermes")})
            try:
                with self.assertRaises(intake.IntakeError) as ctx:
                    intake.runtime_home()
            finally:
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual(ctx.exception.code, "non_deployed_issue_intake")

    def test_env_readiness_labels_cannot_hide_manifest_readiness_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            (home / "instance.yaml").write_text(
                textwrap.dedent(
                    """
                    target:
                      repo: owner/repo
                    runtime:
                      mutation_enabled: true
                    gates:
                      readiness_labels:
                      - custom-ready
                    discord:
                      owner_user_ids:
                      - owner-user
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = self.run_cli(
                home,
                ["--title", "Cannot uninstall cleanly", "--label", "custom-ready", "--dry-run"],
                env_extra={"BOT_READINESS_LABELS": "safe-looking-label"},
            )
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "readiness_label_requires_signed_route")

    def test_comment_dry_run_uses_target_repo_and_issue_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            proc = self.run_cli(home, ["--issue", "#42", "--dry-run"])
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            data = json.loads(proc.stdout)
            self.assertTrue(data["ok"])
            self.assertTrue(data["dry_run"])
            self.assertEqual(data["action"], "comment")
            self.assertEqual(data["repo"], "owner/repo")
            self.assertEqual(data["number"], 42)

    def test_create_issue_calls_gh_against_target_repo(self):
        intake = load_issue_intake()
        calls = []

        def fake_run(cmd, input=None, capture_output=True, text=True, timeout=90, env=None):
            calls.append((cmd, input, env))
            return subprocess.CompletedProcess(cmd, 0, "https://github.com/owner/repo/issues/123\n", "")

        old_run = intake.subprocess.run
        old_gh_env = getattr(intake, "gh_env")
        intake.subprocess.run = fake_run
        setattr(intake, "gh_env", lambda: {})
        try:
            data = intake.create_issue("owner/repo", "Cannot uninstall cleanly", "This is a public-safe issue body with enough detail.", ["bug"])
        finally:
            intake.subprocess.run = old_run
            setattr(intake, "gh_env", old_gh_env)
        self.assertEqual(data["url"], "https://github.com/owner/repo/issues/123")
        self.assertEqual(data["number"], 123)
        args, body, env = calls[0]
        self.assertEqual(args[:6], ["gh", "issue", "create", "--repo", "owner/repo", "--title"])
        self.assertEqual(args[6], "Cannot uninstall cleanly")
        self.assertIn("--body-file", args)
        self.assertIn("public-safe issue body", body)

    def test_comment_issue_calls_gh_against_target_repo(self):
        intake = load_issue_intake()
        calls = []

        def fake_run(cmd, input=None, capture_output=True, text=True, timeout=90, env=None):
            calls.append((cmd, input, env))
            return subprocess.CompletedProcess(cmd, 0, "https://github.com/owner/repo/issues/42#issuecomment-9\n", "")

        old_run = intake.subprocess.run
        old_gh_env = getattr(intake, "gh_env")
        intake.subprocess.run = fake_run
        setattr(intake, "gh_env", lambda: {})
        try:
            data = intake.comment_issue("owner/repo", 42, "This is a public-safe issue body with enough detail.")
        finally:
            intake.subprocess.run = old_run
            setattr(intake, "gh_env", old_gh_env)
        self.assertEqual(data["action"], "comment")
        self.assertEqual(data["number"], 42)
        self.assertEqual(data["url"], "https://github.com/owner/repo/issues/42#issuecomment-9")
        args, body, env = calls[0]
        self.assertEqual(args, ["gh", "issue", "comment", "42", "--repo", "owner/repo", "--body-file", "-"])
        self.assertIn("public-safe issue body", body)

    def test_route_issue_dry_run_adds_configured_forge_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            proc = self.run_cli(home, ["--issue", "28", "--route", "forge", "--dry-run"], env_extra={"JOHN_LOMEIN_TRUST_ASSERTION": self.trust_assertion(home, purpose="route", tier="collaborator", actor="collaborator-user", repo="owner/repo", issue="28", route="forge")})
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            data = json.loads(proc.stdout)
            self.assertEqual(data["action"], "route")
            self.assertEqual(data["repo"], "owner/repo")
            self.assertEqual(data["number"], 28)
            self.assertEqual(data["labels"], ["forge-ready"])
            self.assertEqual(data["trust_tier"], "collaborator")
            self.assertEqual(data["actor"], "collaborator-user")
            second_ok = self.run_cli(home, ["--issue", "28", "--route", "forge", "--dry-run"], env_extra={"JOHN_LOMEIN_TRUST_ASSERTION": self.trust_assertion(home, purpose="route", tier="collaborator", actor="collaborator-user", repo="owner/repo", issue="28", route="forge", nonce="test-nonce-2")})
            # A fresh gateway assertion for the same action remains valid only with a new nonce; identical nonce reuse is rejected separately.
            self.assertEqual(second_ok.returncode, 0, second_ok.stderr + second_ok.stdout)

    def test_writable_trust_public_key_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            assertion = self.trust_assertion(home, purpose="route", tier="collaborator", actor="collaborator-user", repo="owner/repo", issue="28", route="forge")
            public_key = home / "state" / "gateway" / "trust-assertion.public.pem"
            public_key.chmod(0o644)
            proc = self.run_cli(home, ["--issue", "28", "--route", "forge", "--dry-run"], env_extra={"JOHN_LOMEIN_TRUST_ASSERTION": assertion})
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "route_trust_assertion_public_key_permissions_writable")

    def test_signature_verification_uses_validated_public_key_snapshot(self):
        owner_actions = load_owner_actions()
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "hermes"
            key_root = home / "state" / "gateway"
            key_root.mkdir(parents=True)
            private_a = key_root / "private-a.pem"
            private_b = key_root / "private-b.pem"
            public_a = key_root / "public-a.pem"
            public_b = key_root / "public-b.pem"
            installed = key_root / "trust-assertion.public.pem"
            for private, public in (
                (private_a, public_a),
                (private_b, public_b),
            ):
                subprocess.run(
                    [
                        "openssl",
                        "genpkey",
                        "-algorithm",
                        "RSA",
                        "-pkeyopt",
                        "rsa_keygen_bits:2048",
                        "-out",
                        str(private),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                subprocess.run(
                    [
                        "openssl",
                        "rsa",
                        "-pubout",
                        "-in",
                        str(private),
                        "-out",
                        str(public),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            installed.write_bytes(public_a.read_bytes())
            installed.chmod(0o444)
            payload = {
                "purpose": "route",
                "tier": "owner",
                "actor": "owner-user",
                "iat": time.time(),
                "nonce": "snapshot-test",
            }
            body = key_root / "payload.json"
            signature_path = key_root / "payload.sig"
            body.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-sign",
                    str(private_a),
                    "-out",
                    str(signature_path),
                    str(body),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            signature = base64.b64encode(signature_path.read_bytes()).decode(
                "ascii"
            )
            env = {
                "BOT_HERMES_HOME": str(home),
                "BOT_TRUST_PUBLIC_KEY_SHA256": hashlib.sha256(
                    public_a.read_bytes()
                ).hexdigest(),
            }
            real_run = owner_actions.subprocess.run
            observed_verify_key: list[Path] = []

            def swapping_run(command, **kwargs):
                observed_verify_key.append(Path(command[4]))
                installed.chmod(0o600)
                installed.write_bytes(public_b.read_bytes())
                installed.chmod(0o444)
                return real_run(command, **kwargs)

            owner_actions.subprocess.run = swapping_run
            try:
                error = owner_actions.verify_trust_signature(
                    env,
                    payload,
                    signature,
                )
            finally:
                owner_actions.subprocess.run = real_run
            self.assertEqual(error, "")
            self.assertEqual(len(observed_verify_key), 1)
            self.assertNotEqual(
                observed_verify_key[0],
                installed,
                "openssl must verify against the validated key snapshot",
            )

    def test_replayed_route_assertion_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            assertion = self.trust_assertion(home, purpose="route", tier="collaborator", actor="collaborator-user", repo="owner/repo", issue="28", route="forge")
            first = self.run_cli(home, ["--issue", "28", "--route", "forge", "--dry-run"], env_extra={"JOHN_LOMEIN_TRUST_ASSERTION": assertion})
            second = self.run_cli(home, ["--issue", "28", "--route", "forge", "--dry-run"], env_extra={"JOHN_LOMEIN_TRUST_ASSERTION": assertion})
            self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
            self.assertEqual(second.returncode, 2)
            data = json.loads(second.stdout)
            self.assertEqual(data["error"], "route_trust_assertion_replay")

    def test_same_nonce_for_same_route_is_rejected_even_with_fresh_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            nonce = "same-action-nonce"
            first_assertion = self.trust_assertion(home, purpose="route", tier="collaborator", actor="collaborator-user", repo="owner/repo", issue="28", route="forge", nonce=nonce, iat=time.time())
            second_assertion = self.trust_assertion(home, purpose="route", tier="collaborator", actor="collaborator-user", repo="owner/repo", issue="28", route="forge", nonce=nonce, iat=time.time() + 1)
            self.assertNotEqual(first_assertion, second_assertion)
            first = self.run_cli(home, ["--issue", "28", "--route", "forge", "--dry-run"], env_extra={"JOHN_LOMEIN_TRUST_ASSERTION": first_assertion})
            second = self.run_cli(home, ["--issue", "28", "--route", "forge", "--dry-run"], env_extra={"JOHN_LOMEIN_TRUST_ASSERTION": second_assertion})
            self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
            self.assertEqual(second.returncode, 2)
            data = json.loads(second.stdout)
            self.assertEqual(data["error"], "route_trust_assertion_replay")

    def test_same_nonce_for_same_route_is_rejected_even_with_different_issuer(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            nonce = "same-action-different-issuer"
            first_assertion = self.trust_assertion(home, purpose="route", tier="collaborator", actor="collaborator-user", repo="owner/repo", issue="28", route="forge", nonce=nonce, issuer="gateway-a")
            second_assertion = self.trust_assertion(home, purpose="route", tier="collaborator", actor="collaborator-user", repo="owner/repo", issue="28", route="forge", nonce=nonce, issuer="gateway-b")
            first = self.run_cli(home, ["--issue", "28", "--route", "forge", "--dry-run"], env_extra={"JOHN_LOMEIN_TRUST_ASSERTION": first_assertion})
            second = self.run_cli(home, ["--issue", "28", "--route", "forge", "--dry-run"], env_extra={"JOHN_LOMEIN_TRUST_ASSERTION": second_assertion})
            self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
            self.assertEqual(second.returncode, 2)
            data = json.loads(second.stdout)
            self.assertEqual(data["error"], "route_trust_assertion_replay")

    def test_public_input_cannot_route_readiness_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            proc = self.run_cli(home, ["--issue", "28", "--route", "forge", "--dry-run"])
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertFalse(data["ok"])
            self.assertEqual(data["error"], "route_trust_assertion_missing")

    def test_signed_route_assertion_requires_pinned_public_key_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            assertion = self.trust_assertion(home, purpose="route", tier="collaborator", actor="collaborator-user", repo="owner/repo", issue="28", route="forge")
            (home / "instance.yaml").write_text(
                textwrap.dedent(
                    """
                    target:
                      repo: owner/repo
                    runtime:
                      mutation_enabled: true
                    gates:
                      readiness_labels:
                      - maintainer-ready
                      - forge-ready
                      - ready-for-implementation
                    discord:
                      owner_user_ids:
                      - owner-user
                      trusted_collaborator_user_ids:
                      - collaborator-user
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = self.run_cli(
                home,
                ["--issue", "28", "--route", "forge", "--dry-run"],
                env_extra={"JOHN_LOMEIN_TRUST_ASSERTION": assertion, "BOT_TRUST_PUBLIC_KEY_SHA256": hashlib.sha256((home / "state" / "gateway" / "trust-assertion.public.pem").read_bytes()).hexdigest()},
            )
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "route_trust_assertion_public_key_fingerprint_missing")

    def test_claimed_trusted_route_requires_gateway_actor_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            proc = self.run_cli(home, ["--issue", "28", "--route", "pr", "--trust-tier", "owner", "--actor", "owner-user", "--dry-run"])
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "route_trust_assertion_missing")

    def test_plain_env_trust_claim_cannot_spoof_route_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            proc = self.run_cli(
                home,
                ["--issue", "28", "--route", "pr", "--dry-run"],
                env_extra={"JOHN_LOMEIN_DISCORD_TRUST_TIER": "owner", "JOHN_LOMEIN_DISCORD_ACTOR_ID": "owner-user"},
            )
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "route_trust_assertion_missing")

    def test_signed_route_assertion_is_bound_to_issue_and_route(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            assertion = self.trust_assertion(home, purpose="route", tier="owner", actor="owner-user", repo="owner/repo", issue="28", route="pr")
            proc = self.run_cli(home, ["--issue", "29", "--route", "forge", "--dry-run"], env_extra={"JOHN_LOMEIN_TRUST_ASSERTION": assertion})
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "route_trust_assertion_issue_mismatch")

    def test_gateway_actor_must_match_configured_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            proc = self.run_cli(
                home,
                ["--issue", "28", "--route", "pr", "--dry-run"],
                env_extra={"JOHN_LOMEIN_TRUST_ASSERTION": self.trust_assertion(home, purpose="route", tier="owner", actor="drive-by-user", repo="owner/repo", issue="28", route="pr")},
            )
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "route_actor_not_trusted_owner")

    def test_env_owner_registry_cannot_spoof_route_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp, mutation_enabled=True)
            (home / "instance.yaml").write_text(
                textwrap.dedent(
                    """
                    target:
                      repo: owner/repo
                    runtime:
                      mutation_enabled: true
                    gates:
                      readiness_labels:
                      - ready-for-implementation
                    authority:
                      trust_public_key_sha256: PLACEHOLDER
                    discord: {}
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            assertion = self.trust_assertion(home, purpose="route", tier="owner", actor="owner-user", repo="owner/repo", issue="28", route="pr")
            public_key = home / "state" / "gateway" / "trust-assertion.public.pem"
            text = (home / "instance.yaml").read_text(encoding="utf-8")
            (home / "instance.yaml").write_text(text.replace("PLACEHOLDER", hashlib.sha256(public_key.read_bytes()).hexdigest()), encoding="utf-8")
            proc = self.run_cli(
                home,
                ["--issue", "28", "--route", "pr", "--dry-run"],
                env_extra={"JOHN_LOMEIN_TRUST_ASSERTION": assertion, "BOT_OWNER_APPROVERS": "owner-user"},
            )
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "route_trusted_actor_registry_missing")

    def test_route_issue_calls_gh_issue_edit_against_target_repo(self):
        intake = load_issue_intake()
        calls = []

        def fake_run(cmd, capture_output=True, text=True, timeout=90, env=None):
            calls.append((cmd, env))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        old_run = intake.subprocess.run
        old_gh_env = getattr(intake, "gh_env")
        intake.subprocess.run = fake_run
        setattr(intake, "gh_env", lambda: {})
        try:
            data = intake.route_issue("owner/repo", 28, ["ready-for-implementation"])
        finally:
            intake.subprocess.run = old_run
            setattr(intake, "gh_env", old_gh_env)
        self.assertEqual(data["action"], "route")
        self.assertEqual(data["labels"], ["ready-for-implementation"])
        self.assertEqual(data["url"], "https://github.com/owner/repo/issues/28")
        args, env = calls[0]
        self.assertEqual(args, ["gh", "issue", "edit", "28", "--repo", "owner/repo", "--add-label", "ready-for-implementation"])

    def test_route_rejects_unconfigured_readiness_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "hermes"
            home.mkdir(parents=True)
            (home / "instance.yaml").write_text(
                textwrap.dedent(
                    """
                    target:
                      repo: owner/repo
                    runtime:
                      mutation_enabled: true
                    gates:
                      readiness_labels:
                      - maintainer-ready
                    discord:
                      trusted_collaborator_user_ids:
                      - collaborator-user
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = self.run_cli(home, ["--issue", "28", "--route", "forge", "--dry-run"], env_extra={"JOHN_LOMEIN_TRUST_ASSERTION": self.trust_assertion(home, purpose="route", tier="collaborator", actor="collaborator-user", repo="owner/repo", issue="28", route="forge")})
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "route_label_not_configured")

    def test_env_readiness_labels_cannot_widen_signed_route_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "hermes"
            home.mkdir(parents=True)
            (home / "instance.yaml").write_text(
                textwrap.dedent(
                    """
                    target:
                      repo: owner/repo
                    runtime:
                      mutation_enabled: true
                    gates:
                      readiness_labels:
                      - maintainer-ready
                    discord:
                      trusted_collaborator_user_ids:
                      - collaborator-user
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = self.run_cli(
                home,
                ["--issue", "28", "--route", "forge", "--dry-run"],
                env_extra={
                    "BOT_READINESS_LABELS": "forge-ready",
                    "JOHN_LOMEIN_TRUST_ASSERTION": self.trust_assertion(home, purpose="route", tier="collaborator", actor="collaborator-user", repo="owner/repo", issue="28", route="forge"),
                },
            )
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["error"], "route_label_not_configured")


if __name__ == "__main__":
    unittest.main()
