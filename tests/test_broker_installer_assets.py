#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "install-protected-broker.sh"
UNINSTALLER = ROOT / "scripts" / "uninstall-protected-broker.sh"
CLIENT_TEMPLATE = (
    ROOT / "templates" / "protected-broker-client-config.json.example"
)


class ProtectedBrokerInstallerAssetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.install = INSTALLER.read_text(encoding="utf-8")
        cls.uninstall = UNINSTALLER.read_text(encoding="utf-8")

    def test_shell_assets_use_fixed_bash_and_are_syntax_valid(self) -> None:
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

    def test_installer_has_explicit_operator_cli_and_platform_gate(self) -> None:
        for option in (
            "--slug",
            "--config",
            "--github-app-private-key",
            "--receipt-private-key",
            "--receipt-public-key",
            "--python",
            "--broker-user",
            "--requester-user",
            "--submit-group",
        ):
            self.assertIn(option, self.install)
        self.assertIn('id -u)" -eq 0', self.install)
        self.assertIn('uname -s)" = "Darwin"', self.install)
        self.assertIn("macOS LaunchDaemons only", self.install)

    def test_install_source_must_be_root_controlled(self) -> None:
        self.assertIn(
            'validate_existing_path "$SCRIPT_PATH" 0 file "installer script"',
            self.install,
        )
        self.assertIn(
            'validate_root_owned_tree "$SOURCE_BROKER_DIR" "broker source"',
            self.install,
        )
        self.assertIn(
            "root-controlled source snapshot",
            self.install,
        )
        self.assertIn(
            "group/other-writable path component",
            self.install,
        )
        self.assertIn("has an access-control list", self.install)

    def test_canonical_paths_avoid_macos_symlinked_runtime_roots(self) -> None:
        required = (
            "/private/etc/john-lomein-broker.d",
            "/private/etc/john-lomein-broker-public",
            "/private/var/db/john-lomein-broker",
            "/usr/local/libexec/john-lomein-protected-broker",
            "/Library/LaunchDaemons",
            'RUN_DIR="$RUN_ROOT/$SLUG"',
            'STATE_DIR="$STATE_ROOT/$SLUG"',
            "broker.sock",
            "broker.sqlite",
        )
        for value in required:
            self.assertIn(value, self.install)
        self.assertNotIn("'/var/run", self.install)
        self.assertNotIn('"/var/run', self.install)
        self.assertNotIn("'/etc/john", self.install)
        self.assertNotIn('"/etc/john', self.install)
        self.assertNotIn("/Users/", self.install)
        self.assertNotIn("HERMES_HOME", self.install)
        self.assertNotIn("uv run", self.install)

    def test_python_and_dependency_runtime_are_fully_trust_checked(self) -> None:
        required = (
            'validate_existing_path "$PYTHON" 0 executable',
            '"$PYTHON" -I -S -c',
            '"$PYTHON" -I -c',
            "sys.executable",
            "sys.base_prefix",
            "sys.prefix",
            "sys.exec_prefix",
            "sysconfig.get_paths()",
            "validate_runtime_path",
            "/usr/bin/find -x",
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
        self.assertIn('"-I"', self.install)
        self.assertIn('"PYTHONHOME": ""', self.install)
        self.assertIn('"PYTHONPATH": ""', self.install)
        self.assertIn('"LD_LIBRARY_PATH": ""', self.install)
        for variable in (
            "DYLD_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH",
            "DYLD_FALLBACK_LIBRARY_PATH",
            "DYLD_FALLBACK_FRAMEWORK_PATH",
            "DYLD_INSERT_LIBRARIES",
        ):
            self.assertIn(f'"{variable}": ""', self.install)

    def test_identity_and_socket_group_membership_are_bound(self) -> None:
        self.assertIn('id -u "$BROKER_USER"', self.install)
        self.assertIn('id -u "$REQUESTER_USER"', self.install)
        self.assertIn('id -G "$user"', self.install)
        self.assertIn(
            'user_has_gid "$BROKER_USER" "$SUBMIT_GID"',
            self.install,
        )
        self.assertIn(
            'user_has_gid "$REQUESTER_USER" "$SUBMIT_GID"',
            self.install,
        )
        self.assertIn(
            "broker and requester must be different OS identities",
            self.install,
        )
        self.assertIn(
            'config.get("broker_uid") == int(broker_uid)',
            self.install,
        )
        self.assertIn(
            'config.get("transport", {}).get("requester_uid")',
            self.install,
        )
        self.assertIn(
            'config.get("transport", {}).get("submit_gid")',
            self.install,
        )
        self.assertIn("broker socket mode is not 0660", self.install)

    def test_config_and_keys_are_snapshotted_and_exactly_bound(self) -> None:
        required = (
            "O_NOFOLLOW",
            "input changed while being snapshotted",
            "input must be a singly linked regular file",
            "object_pairs_hook=reject_duplicates",
            "parse_constant=reject_nonfinite",
            "duplicate JSON field",
            "receipt private and public keys do not match",
            "receipt public-key fingerprint does not match config",
            "GitHub App RSA key must be at least 2048 bits",
            '"socket path"',
            '"database path"',
            '"GitHub private-key path"',
            '"receipt private-key path"',
            '"receipt public-key path"',
            "does not match installer binding",
        )
        for value in required:
            self.assertIn(value, self.install)

    def test_install_modes_and_owners_match_the_boundary(self) -> None:
        expected_fragments = (
            '"$RUN_DIR" "$BROKER_USER" "$SUBMIT_GROUP" 0750',
            '"$STATE_DIR" "$BROKER_USER" "$BROKER_PRIMARY_GROUP" 0700',
            '"$SECRETS_DIR" "$BROKER_USER" "$BROKER_PRIMARY_GROUP" 0700',
            '"$GITHUB_KEY_SNAPSHOT" "$GITHUB_KEY_PATH" "$BROKER_USER"',
            '"$RECEIPT_PRIVATE_SNAPSHOT" "$RECEIPT_PRIVATE_PATH" "$BROKER_USER"',
            '"$RECEIPT_PUBLIC_SNAPSHOT" "$RECEIPT_PUBLIC_PATH" root wheel 0444',
            '"$CONFIG_SNAPSHOT" "$CONFIG_PATH" root "$BROKER_PRIMARY_GROUP" 0640',
            '"$PLIST_SNAPSHOT" "$PLIST_PATH" root wheel 0644',
            "-o root -g wheel -m 0444",
        )
        for value in expected_fragments:
            self.assertIn(value, self.install)

    def test_client_config_schema_matches_public_template(self) -> None:
        template_keys = set(
            json.loads(CLIENT_TEMPLATE.read_text(encoding="utf-8"))
        )
        match = re.search(
            r"client = \{\n(?P<body>.*?)\n\}",
            self.install,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        assert match is not None
        generated_keys = set(
            re.findall(r'^\s{4}"([^"]+)":', match.group("body"), re.MULTILINE)
        )
        self.assertEqual(generated_keys, template_keys)
        self.assertIn('"connect_timeout_seconds": 5', match.group("body"))
        self.assertIn('"max_response_bytes": 524288', match.group("body"))
        self.assertIn("config_digest(config)", self.install)

    def test_upgrade_has_rollback_for_code_config_keys_and_state(self) -> None:
        required = (
            "TRANSACTION_STARTED=0",
            "TRANSACTION_COMMITTED=0",
            "PREVIOUS_LOADED=0",
            "restore_managed_file",
            "$ROLLBACK_DIR/github-app.pem",
            "$ROLLBACK_DIR/receipt-private.pem",
            "$ROLLBACK_DIR/receipt-public.pem",
            "$ROLLBACK_DIR/broker-config.json",
            "$ROLLBACK_DIR/client-config.json",
            "$ROLLBACK_DIR/launchdaemon.plist",
            "$ROLLBACK_DIR/broker.sqlite",
            "$ROLLBACK_DIR/broker.sqlite-wal",
            "$ROLLBACK_DIR/broker.sqlite-shm",
            "$ROLLBACK_DIR/broker.sqlite-journal",
            "CODE_BACKUP",
            'if [ "$PREVIOUS_LOADED" -eq 1 ]',
            'launchctl bootstrap system "$PLIST_PATH"',
            "rollback was incomplete; service remains fail-closed",
        )
        for value in required:
            self.assertIn(value, self.install)
        self.assertIn("RUN_DIR_QUARANTINED=1", self.install)
        self.assertIn('/bin/chmod 0700 "$RUN_DIR"', self.install)
        self.assertIn('/bin/chmod 0750 "$RUN_DIR"', self.install)
        self.assertIn("STATE_DIR_QUARANTINED=1", self.install)
        self.assertIn(
            '/usr/sbin/chown root:wheel "$STATE_DIR"',
            self.install,
        )

    def test_rollback_snapshots_do_not_follow_broker_controlled_names(
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

    def test_shared_code_upgrade_requires_other_instances_to_be_stopped(
        self,
    ) -> None:
        self.assertIn(
            "installed code root is shared by all protected-broker instances",
            self.install,
        )
        self.assertIn(
            "/Library/LaunchDaemons/com.john-lomein.protected-broker.*.plist",
            self.install,
        )
        self.assertIn(
            "shared broker code cannot be upgraded while another instance is loaded",
            self.install,
        )

    def test_broker_owned_directories_allow_root_ancestors_but_bind_final_owner(
        self,
    ) -> None:
        self.assertIn('allowed_uids="0,$owner_uid"', self.install)
        self.assertIn(
            'stat -f \'%u\' "$path")" -eq "$owner_uid"',
            self.install,
        )
        self.assertIn(
            "final directory has the wrong owner",
            self.install,
        )

    def test_launchdaemon_is_isolated_and_enablement_is_fail_closed(self) -> None:
        required = (
            '"ProgramArguments": [',
            '"-I",',
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
        bootstrap = self.install.index(
            '/bin/launchctl bootstrap system "$PLIST_PATH"',
            gate,
        )
        disable = self.install.index(
            '/bin/launchctl disable "system/$LABEL"',
            gate,
        )
        disabled_exit = self.install.index("exit 0", gate)
        self.assertLess(gate, bootstrap)
        self.assertLess(disable, disabled_exit)
        self.assertLess(disabled_exit, bootstrap)
        self.assertIn(
            '/bin/launchctl bootstrap system "$PLIST_PATH"',
            self.install[:gate],
            msg="rollback must be able to restore a previously loaded daemon",
        )
        for secret in ("GH_TOKEN", "GITHUB_TOKEN"):
            self.assertIn(f'"{secret}": ""', self.install)

    def test_uninstall_only_removes_service_and_transient_socket_assets(self) -> None:
        self.assertIn("usage: uninstall-protected-broker.sh --slug SLUG", self.uninstall)
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
            "preserved durable state and private keys",
            "preserved installed broker config",
            "preserved public client config",
            "preserved public receipt key",
            "preserved root-owned broker code",
        ):
            self.assertIn(preserved, self.uninstall)


if __name__ == "__main__":
    unittest.main()
