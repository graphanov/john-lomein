#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from release_broker import john_lomein_release_broker_protocol as protocol


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install-protected-release-broker.sh"
UNINSTALLER = (
    ROOT / "scripts" / "uninstall-protected-release-broker.sh"
)
CONFIG_TEMPLATE = (
    ROOT / "templates" / "protected-release-broker-config.json.example"
)
CLIENT_TEMPLATE = (
    ROOT
    / "templates"
    / "protected-release-broker-client-config.json.example"
)
CLIENT_SCRIPT = ROOT / "scripts" / "john-lomein-release-submit.py"


def load_client_module():
    spec = importlib.util.spec_from_file_location(
        "john_lomein_release_submit_installer_test",
        CLIENT_SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("release client module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ProtectedReleaseBrokerInstallerAssetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.install = INSTALLER.read_text(encoding="utf-8")
        cls.uninstall = UNINSTALLER.read_text(encoding="utf-8")

    def test_shell_assets_are_executable_and_bash_syntax_valid(self) -> None:
        for path in (INSTALLER, UNINSTALLER):
            self.assertTrue(path.stat().st_mode & 0o111)
            self.assertTrue(
                path.read_text(encoding="utf-8").startswith("#!/bin/bash\n")
            )
            subprocess.run(
                ["/bin/bash", "-n", str(path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )

    def test_shellcheck_is_clean_when_available(self) -> None:
        shellcheck = shutil.which("shellcheck")
        if shellcheck is None:
            self.skipTest("shellcheck is not installed")
        subprocess.run(
            [shellcheck, "-x", str(INSTALLER), str(UNINSTALLER)],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_installer_has_complete_operator_cli_and_platform_gate(self) -> None:
        for option in (
            "--slug",
            "--config",
            "--github-app-private-key",
            "--owner-assertion-public-key",
            "--receipt-private-key",
            "--receipt-public-key",
            "--python",
            "--broker-user",
            "--requester-user",
            "--submit-group",
        ):
            self.assertIn(option, self.install)
        self.assertNotIn("--owner-assertion-private-key", self.install)
        self.assertIn('id -u)" -eq 0', self.install)
        self.assertIn('uname -s)" = "Darwin"', self.install)
        self.assertIn("macOS LaunchDaemons only", self.install)

    def test_source_and_runtime_are_root_controlled(self) -> None:
        required = (
            'validate_existing_path "$SCRIPT_PATH" 0 file "installer script"',
            'validate_root_owned_tree "$SOURCE_BROKER_DIR"',
            'validate_existing_path "$PYTHON" 0 executable',
            '"$GITHUB_KEY_SOURCE" 0 file',
            '"$OWNER_PUBLIC_SOURCE" 0 file',
            '"$RECEIPT_PRIVATE_SOURCE" 0 file',
            '"$RECEIPT_PUBLIC_SOURCE" 0 file',
            "root-controlled source snapshot",
            "group/other-writable path component",
            "has an access-control list",
            "/usr/bin/find -x",
        )
        for fragment in required:
            self.assertIn(fragment, self.install)

    def test_canonical_release_paths_are_separate_from_routine_broker(self) -> None:
        required = (
            "/private/etc/john-lomein-release-broker.d",
            "/private/etc/john-lomein-release-broker-public",
            "/private/var/db/john-lomein-release-broker",
            "/usr/local/libexec/john-lomein-protected-release-broker",
            "com.john-lomein.protected-release-broker.$SLUG",
            'RUN_DIR="$RUN_ROOT/$SLUG"',
            'STATE_DIR="$STATE_ROOT/$SLUG"',
            "release-broker.sock",
            "release-broker.sqlite",
        )
        for value in required:
            self.assertIn(value, self.install)
        self.assertNotIn(
            "/usr/local/libexec/john-lomein-protected-broker'",
            self.install,
        )
        self.assertNotIn("com.john-lomein.protected-broker.$SLUG", self.install)
        self.assertNotIn("/Users/", self.install)
        self.assertNotIn("HERMES_HOME", self.install)
        self.assertNotIn("uv run", self.install)

    def test_python_and_locked_cryptography_are_fully_trust_checked(self) -> None:
        required = (
            '"$PYTHON" -I -B -S -c',
            '"$PYTHON" -I -B -c',
            "sys.executable",
            "sys.base_prefix",
            "sys.prefix",
            "sys.exec_prefix",
            "sysconfig.get_paths()",
            "validate_runtime_path",
            'cryptography.__version__ != "50.0.1"',
            "cryptography_package",
            "cryptography_native_binding",
            "cryptography_distribution",
            "cryptography.hazmat.bindings",
            "serialization",
            "ed25519",
            "rsa",
        )
        for value in required:
            self.assertIn(value, self.install)

    def test_identity_and_kernel_socket_boundary_are_bound(self) -> None:
        required = (
            'id -u "$BROKER_USER"',
            'id -u "$REQUESTER_USER"',
            'id -G "$user"',
            'user_has_gid "$BROKER_USER" "$SUBMIT_GID"',
            'user_has_gid "$REQUESTER_USER" "$SUBMIT_GID"',
            "broker and requester must be different OS identities",
            "broker private-key group and submit group must differ",
            "requester user must not belong to the broker private-key group",
            "broker private-key group must be dedicated to the broker OS identity",
            'config["broker_uid"] == int(broker_uid)',
            'config["broker_private_gid"] == int(broker_private_gid)',
            'config["transport"]["requester_uid"] == int(requester_uid)',
            'config["transport"]["submit_gid"] == int(submit_gid)',
            "release broker socket mode is not 0660",
        )
        for value in required:
            self.assertIn(value, self.install)

    def test_inputs_are_descriptor_snapshotted_and_keys_are_verified(self) -> None:
        required = (
            "O_NOFOLLOW",
            "input changed while being snapshotted",
            "input must be a singly linked regular file",
            "parse_json_bytes",
            "normalize_config",
            "GitHub App RSA key must be at least 2048 bits",
            "owner assertion public key must be Ed25519",
            "owner assertion public-key fingerprint does not match config",
            "receipt private and public keys do not match",
            "receipt public-key fingerprint does not match config",
            '"socket path"',
            '"database path"',
            '"GitHub private-key path"',
            '"owner assertion public-key path"',
            '"receipt private-key path"',
            '"receipt public-key path"',
            "does not match installer binding",
        )
        for value in required:
            self.assertIn(value, self.install)

    def test_root_owned_credentials_and_public_assets_have_narrow_modes(
        self,
    ) -> None:
        expected = (
            '"$SECRETS_DIR" root "$BROKER_PRIMARY_GROUP" 0750',
            '"$GITHUB_KEY_SNAPSHOT" "$GITHUB_KEY_PATH" root',
            '"$BROKER_PRIMARY_GROUP" 0640',
            '"$OWNER_PUBLIC_SNAPSHOT" "$OWNER_PUBLIC_PATH" root',
            '"$BROKER_PRIMARY_GROUP" 0440',
            '"$RECEIPT_PRIVATE_SNAPSHOT" "$RECEIPT_PRIVATE_PATH" root',
            '"$RECEIPT_PUBLIC_SNAPSHOT" "$RECEIPT_PUBLIC_PATH" root wheel 0444',
            '"$CONFIG_SNAPSHOT" "$CONFIG_PATH" root "$BROKER_PRIMARY_GROUP" 0640',
            '"$CLIENT_CONFIG_SNAPSHOT" "$CLIENT_CONFIG_PATH" root wheel 0444',
            '"$PLIST_SNAPSHOT" "$PLIST_PATH" root wheel 0644',
        )
        for fragment in expected:
            self.assertIn(fragment, self.install)
        self.assertIn(
            '"$GITHUB_KEY_PATH" 0 "$BROKER_PRIMARY_GID" 640',
            self.install,
        )
        self.assertIn(
            '"$RECEIPT_PRIVATE_PATH" 0 "$BROKER_PRIMARY_GID" 640',
            self.install,
        )
        self.assertIn("must be singly linked", self.install)

    def test_config_template_matches_protocol_and_is_fail_closed(self) -> None:
        raw = json.loads(CONFIG_TEMPLATE.read_text(encoding="utf-8"))
        normalized = protocol.normalize_config(raw)
        self.assertEqual(
            normalized["schema_version"],
            "john-lomein.protected-release-broker-config.v1",
        )
        self.assertFalse(normalized["enabled"])
        self.assertEqual(normalized["broker_private_gid"], 504)
        policy = normalized["instance"]["policy"]
        self.assertEqual(policy["max_prs_per_bundle"], 1)
        self.assertEqual(policy["merge_method"], "squash")
        self.assertFalse(policy["publish"])
        self.assertFalse(policy["delete_branch"])
        self.assertTrue(policy["require_same_repository_head"])
        self.assertTrue(policy["require_codex_evidence"])
        self.assertTrue(policy["reject_unconfigured_failures"])
        self.assertEqual(
            set(policy["required_checks"][0]),
            {
                "kind",
                "name",
                "producer_app_id",
                "producer_slug",
                "producer_login",
            },
        )
        self.assertTrue(policy["codex_evidence_author_logins"])
        for section in ("owner_assertion", "receipt_signing"):
            self.assertRegex(
                raw[section]["public_key_sha256"],
                r"^sha256:[0-9a-f]{64}$",
            )
        self.assertNotIn("private_key_path", raw["owner_assertion"])

    def test_client_template_and_generated_schema_match_client(self) -> None:
        template = json.loads(CLIENT_TEMPLATE.read_text(encoding="utf-8"))
        client = load_client_module()
        normalized = client.normalize_client_config(template)
        self.assertEqual(
            normalized["schema_version"],
            "john-lomein.protected-release-broker-client-config.v1",
        )
        match = re.search(
            r"client = \{\n(?P<body>.*?)\n\}",
            self.install,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        assert match is not None
        generated_keys = set(
            re.findall(
                r'^\s{4}"([^"]+)":',
                match.group("body"),
                re.MULTILINE,
            )
        )
        self.assertEqual(generated_keys, set(template))
        self.assertIn('"connect_timeout_seconds": 5', match.group("body"))
        self.assertIn(
            '"max_response_bytes": MAX_RECEIPT_BYTES + 64 * 1024',
            match.group("body"),
        )
        self.assertIn("config_digest(config)", self.install)

    def test_release_policy_is_rechecked_at_install_time(self) -> None:
        for invariant in (
            '["max_prs_per_bundle"] == 1',
            '["merge_method"] == "squash"',
            '["publish"] is False',
            '["delete_branch"] is False',
        ):
            self.assertIn(invariant, self.install)

    def test_runtime_package_is_exact_and_entrypoint_is_preflighted(self) -> None:
        for module in (
            "__init__.py",
            "john_lomein_release_broker_protocol.py",
            "john_lomein_release_broker_actions.py",
            "john_lomein_release_broker_github_app.py",
            "john_lomein_release_broker_github_live.py",
            "john_lomein_release_broker_store.py",
            "john_lomein_release_broker_receipts.py",
            "john_lomein_release_broker_service.py",
            "john_lomein_release_broker_daemon.py",
            "run_release_broker.py",
        ):
            self.assertIn(module, self.install)
        self.assertIn(
            '"$PYTHON" -I -B "$ENTRYPOINT" --help',
            self.install,
        )
        self.assertIn(
            'ENTRYPOINT="$CODE_ROOT/release_broker/run_release_broker.py"',
            self.install,
        )
        for permission in (
            '"checks": "read"',
            '"contents": "write"',
            '"issues": "read"',
            '"metadata": "read"',
            '"pull_requests": "read"',
            '"statuses": "read"',
        ):
            self.assertIn(permission, self.install)
        self.assertIn('API_VERSION != "2026-03-10"', self.install)
        self.assertNotIn('"pull_requests": "write"', self.install)

    def test_upgrade_rolls_back_every_authority_and_durable_asset(self) -> None:
        required = (
            "TRANSACTION_STARTED=0",
            "TRANSACTION_COMMITTED=0",
            "PREVIOUS_LOADED=0",
            "restore_managed_file",
            "$ROLLBACK_DIR/github-app.pem",
            "$ROLLBACK_DIR/owner-public.pem",
            "$ROLLBACK_DIR/receipt-private.pem",
            "$ROLLBACK_DIR/receipt-public.pem",
            "$ROLLBACK_DIR/release-broker-config.json",
            "$ROLLBACK_DIR/client-config.json",
            "$ROLLBACK_DIR/launchdaemon.plist",
            "$ROLLBACK_DIR/release-broker.sqlite",
            "$ROLLBACK_DIR/release-broker.sqlite-wal",
            "$ROLLBACK_DIR/release-broker.sqlite-shm",
            "$ROLLBACK_DIR/release-broker.sqlite-journal",
            "CODE_BACKUP",
            'if [ "$PREVIOUS_LOADED" -eq 1 ]',
            'launchctl bootstrap system "$PLIST_PATH"',
            "rollback was incomplete; service remains fail-closed",
            "RUN_DIR_QUARANTINED=1",
            "STATE_DIR_QUARANTINED=1",
            '/usr/sbin/chown root:wheel "$STATE_DIR"',
        )
        for value in required:
            self.assertIn(value, self.install)

    def test_rollback_snapshots_never_follow_broker_controlled_names(
        self,
    ) -> None:
        match = re.search(
            r"backup_optional_file\(\) \{\n(?P<body>.*?)\n\}",
            self.install,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        assert match is not None
        body = match.group("body")
        self.assertIn("os.O_NOFOLLOW", body)
        self.assertIn("source_fd = os.open(source, source_flags)", body)
        self.assertIn("before = os.fstat(source_fd)", body)
        self.assertIn("after = os.fstat(source_fd)", body)
        self.assertIn("rollback source changed during snapshot", body)
        self.assertIn("os.fchown(backup_fd", body)
        self.assertIn("os.fchmod(backup_fd", body)
        self.assertNotIn('/bin/cp -p "$source" "$backup"', body)

    def test_shared_code_guard_covers_every_release_instance(self) -> None:
        self.assertIn(
            "installed code root is shared by all protected-release-broker instances",
            self.install,
        )
        self.assertIn(
            "/Library/LaunchDaemons/com.john-lomein.protected-release-broker.*.plist",
            self.install,
        )
        self.assertIn(
            "shared release broker code cannot be upgraded while another instance is loaded",
            self.install,
        )

    def test_launchdaemon_is_isolated_and_disabled_never_bootstraps(
        self,
    ) -> None:
        required = (
            '"ProgramArguments": [',
            '"-I",',
            '"-B",',
            '"--config",',
            '"UserName": broker_user',
            '"GroupName": broker_group',
            '"Umask": 0o077',
            '"RunAtLoad": True',
            '"KeepAlive": {"SuccessfulExit": False}',
            'launchctl disable "system/$LABEL"',
            'launchctl enable "system/$LABEL"',
            'launchctl bootstrap system "$PLIST_PATH"',
            'launchctl kickstart -k "system/$LABEL"',
            'launchctl print "system/$LABEL"',
        )
        for value in required:
            self.assertIn(value, self.install)
        gate = self.install.index('if [ "$ENABLED" -eq 0 ]')
        disabled_exit = self.install.index("exit 0", gate)
        bootstrap = self.install.index(
            '/bin/launchctl bootstrap system "$PLIST_PATH"',
            gate,
        )
        self.assertLess(disabled_exit, bootstrap)
        self.assertIn(
            '/bin/launchctl bootstrap system "$PLIST_PATH"',
            self.install[:gate],
            msg="rollback must restore a previously loaded daemon",
        )
        for secret in ("GH_TOKEN", "GITHUB_TOKEN"):
            self.assertIn(f'"{secret}": ""', self.install)

    def test_uninstall_preserves_authority_and_state_by_default(self) -> None:
        self.assertIn(
            "usage: uninstall-protected-release-broker.sh --slug SLUG",
            self.uninstall,
        )
        self.assertIn('id -u)" -eq 0', self.uninstall)
        self.assertIn('uname -s)" = "Darwin"', self.uninstall)
        self.assertIn('launchctl bootout "system/$LABEL"', self.uninstall)
        self.assertIn('launchctl disable "system/$LABEL"', self.uninstall)
        self.assertIn('launchctl print "system/$LABEL"', self.uninstall)
        self.assertNotIn("rm -rf", self.uninstall)
        self.assertIn('/bin/rm -f "$PLIST_PATH"', self.uninstall)
        self.assertIn(
            'remove_transient "$SOCKET_PATH" socket',
            self.uninstall,
        )
        self.assertIn(
            'remove_transient "$SOCKET_LOCK_PATH" file',
            self.uninstall,
        )
        for preserved in (
            "preserved durable release state",
            "preserved root-owned release keys",
            "preserved installed release broker config",
            "preserved public release client config",
            "preserved public release receipt key",
            "preserved root-owned release broker code",
        ):
            self.assertIn(preserved, self.uninstall)


if __name__ == "__main__":
    unittest.main()
