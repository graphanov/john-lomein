#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from owner_gateway import john_lomein_discord_release_source as source
from owner_gateway import john_lomein_release_owner_signer as signer
from release_broker import john_lomein_release_broker_protocol as protocol


INSTALLER = (
    ROOT / "scripts" / "install-protected-release-owner-gateway.sh"
)
UNINSTALLER = (
    ROOT / "scripts" / "uninstall-protected-release-owner-gateway.sh"
)
SIGNER_TEMPLATE = (
    ROOT / "templates" / "protected-release-owner-signer-config.json.example"
)
SOURCE_TEMPLATE = (
    ROOT
    / "templates"
    / "protected-release-owner-discord-source-config.json.example"
)


class ProtectedReleaseOwnerGatewayInstallerAssetTests(unittest.TestCase):
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

    def test_installer_cli_and_platform_gate_are_explicit(self) -> None:
        for option in (
            "--slug",
            "--signer-config",
            "--discord-source-config",
            "--signing-private-key",
            "--signing-public-key",
            "--discord-bot-token",
            "--python",
            "--signer-user",
            "--requester-user",
            "--submit-group",
        ):
            self.assertIn(option, self.install)
        self.assertIn('id -u)" -eq 0', self.install)
        self.assertIn('uname -s)" = "Darwin"', self.install)
        self.assertNotIn("launchctl", self.install)
        self.assertNotIn("LaunchDaemon", self.install)

    def test_source_runtime_and_inputs_are_root_controlled(self) -> None:
        required = (
            'validate_existing_path "$SCRIPT_PATH" 0 file "installer script"',
            '"$SOURCE_OWNER_DIR/john_lomein_release_owner_signer.py"',
            '"$SOURCE_OWNER_DIR/john_lomein_discord_release_source.py"',
            '"$SOURCE_RELEASE_DIR/john_lomein_release_broker_protocol.py"',
            '"$SOURCE_RELEASE_DIR/john_lomein_release_broker_github_app.py"',
            '"$SOURCE_RELEASE_DIR/john_lomein_release_broker_github_live.py"',
            'validate_existing_path "$SOURCE_ENTRYPOINT" 0 file',
            'validate_existing_path "$PYTHON" 0 executable',
            "root-controlled source snapshot",
            "group/other-writable path component",
            "has an access-control list",
            "O_NOFOLLOW",
            "input changed while being snapshotted",
            "input must be a singly linked regular file",
            "private input grants group or other permissions",
        )
        for fragment in required:
            self.assertIn(fragment, self.install)

    def test_python_and_locked_crypto_are_trust_checked(self) -> None:
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
            "serialization",
            "ed25519",
        )
        for fragment in required:
            self.assertIn(fragment, self.install)

    def test_os_identity_boundary_has_only_one_shared_submit_group(
        self,
    ) -> None:
        required = (
            'id -u "$SIGNER_USER"',
            'id -u "$REQUESTER_USER"',
            'id -G "$user"',
            'user_has_gid "$SIGNER_USER" "$SUBMIT_GID"',
            'user_has_gid "$REQUESTER_USER" "$SUBMIT_GID"',
            "signer and requester must be different OS identities",
            "signer private group and submit group must differ",
            "requester user must not belong to the signer private group",
            "signer private group must be dedicated to the signer OS identity",
            "submit group must be dedicated to signer and requester identities",
            'signer_config["signer_uid"] == int(signer_uid)',
            'signer_config["signer_gid"] == int(signer_gid)',
            'signer_config["runtime_uid"] == int(requester_uid)',
        )
        for fragment in required:
            self.assertIn(fragment, self.install)

    def test_canonical_paths_and_modes_match_the_gateway_boundary(self) -> None:
        required_paths = (
            "/private/etc/john-lomein-release-owner-gateway.d",
            "/private/etc/john-lomein-release-owner-gateway-public",
            "/private/var/db/john-lomein-release-owner-gateway",
            "/usr/local/libexec/john-lomein-release-owner-gateway-instances",
            'CODE_ROOT="$WRAPPER_DIR/code"',
            'ENTRYPOINT="$CODE_ROOT/scripts/john-lomein-release-owner-sign.py"',
            "/private/etc/sudoers.d",
            'SUDOERS_SAFE_SLUG="$(encode_sudoers_slug "$SLUG")"',
            "SUDOERS_PATH=\"$SUDOERS_DIR/john-lomein-release-owner-$SUDOERS_SAFE_SLUG\"",
            'WRAPPER_PATH="$WRAPPER_DIR/mint"',
        )
        for path in required_paths:
            self.assertIn(path, self.install)
        expected_modes = (
            '"$SECRETS_DIR" root "$SIGNER_GROUP" 0750',
            '"$STATE_DIR" "$SIGNER_USER" "$SIGNER_GROUP" 0700',
            '"$TMP_DIR" "$SIGNER_USER" "$SIGNER_GROUP" 0700',
            '"$REQUEST_DIR" root "$SUBMIT_GROUP" 2770',
            '"$SIGNER_CONFIG_SNAPSHOT" "$SIGNER_CONFIG_PATH" root "$SIGNER_GROUP" 0440',
            '"$SOURCE_CONFIG_SNAPSHOT" "$SOURCE_CONFIG_PATH" root "$SIGNER_GROUP" 0440',
            '"$PRIVATE_KEY_SNAPSHOT" "$PRIVATE_KEY_PATH" root "$SIGNER_GROUP" 0640',
            '"$PUBLIC_KEY_SNAPSHOT" "$PUBLIC_KEY_PATH" root "$SIGNER_GROUP" 0440',
            '"$BOT_TOKEN_SNAPSHOT" "$BOT_TOKEN_PATH" root "$SIGNER_GROUP" 0640',
            '"$WRAPPER_SNAPSHOT" "$WRAPPER_PATH" root wheel 0555',
            '"$PUBLIC_CONFIG_SNAPSHOT" "$PUBLIC_CONFIG_PATH" root wheel 0444',
            '"$SUDOERS_SNAPSHOT" "$SUDOERS_PATH" root wheel 0440',
        )
        for fragment in expected_modes:
            self.assertIn(fragment, self.install)
        self.assertNotIn("/Users/", self.install)
        self.assertNotIn("HERMES_HOME", self.install)
        self.assertNotIn("uv run", self.install)

    def test_strict_configs_keys_and_token_are_preflighted(self) -> None:
        required = (
            "signer.normalize_signer_config",
            "source.normalize_source_config",
            "protocol.parse_json_bytes",
            'signer_config["private_key_path"] == expected_private_key_path',
            'signer_config["public_key_path"] == expected_public_key_path',
            'signer_config["state_directory"] == expected_state_path',
            'source_config["bot_token_path"] == expected_token_path',
            "protocol.sha256_json(signer_config)",
            'signer_config["enabled"] is source_config["enabled"]',
            "signer._load_key_pair",
            "signer public-key fingerprint does not match config",
            "source.BOT_TOKEN_RE.fullmatch",
            "Discord observer bot token is invalid",
        )
        for fragment in required:
            self.assertIn(fragment, self.install)

    def test_templates_are_strict_bound_and_disabled_by_default(self) -> None:
        signer_raw = json.loads(SIGNER_TEMPLATE.read_text(encoding="utf-8"))
        signer_config = signer.normalize_signer_config(signer_raw)
        source_raw = json.loads(SOURCE_TEMPLATE.read_text(encoding="utf-8"))
        source_config = source.normalize_source_config(
            source_raw,
            signer_config,
        )
        self.assertFalse(signer_config["enabled"])
        self.assertFalse(source_config["enabled"])
        self.assertEqual(
            source_config["signer_config_sha256"],
            protocol.sha256_json(signer_config),
        )
        self.assertEqual(
            source_config["api_base_url"],
            "https://discord.com/api/v10",
        )
        self.assertEqual(signer_config["signer_uid"], 505)
        self.assertEqual(signer_config["signer_gid"], 506)
        self.assertEqual(signer_config["runtime_uid"], 502)
        self.assertNotEqual(
            signer_config["signer_gid"],
            signer_config["runtime_uid"],
        )

    def test_public_invocation_config_has_the_coordinated_exact_schema(
        self,
    ) -> None:
        match = re.search(
            r"public = \{\n(?P<body>.*?)\n\}",
            self.install,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        assert match is not None
        generated_keys = set(
            re.findall(
                r'^\s{4}"([^"]+)":',
                match.group("body"),
                flags=re.MULTILINE,
            )
        )
        self.assertEqual(
            generated_keys,
            {
                "schema_version",
                "instance_slug",
                "repository_full_name",
                "approval_channel_ids",
                "requester_uid",
                "signer_user",
                "signer_primary_group",
                "request_spool_dir",
                "wrapper_path",
            },
        )
        self.assertIn(
            '"schema_version": "john-lomein.release-owner-gateway-invocation.v2"',
            match.group("body"),
        )
        self.assertIn(
            '"approval_channel_ids": config["discord"]["approval_channel_ids"]',
            match.group("body"),
        )

    def test_wrapper_is_fixed_argument_constrained_and_sanitized(self) -> None:
        required = (
            'expected --bundle, --channel-id, and --message-id',
            '[ "$1" = "--bundle" ]',
            '[ "$3" = "--channel-id" ]',
            '[ "$5" = "--message-id" ]',
            "bundle must be an absolute JSON path in the instance request spool",
            "bundle must be a direct child of the instance request spool",
            "bundle path is not normalized",
            "channel ID is not a Discord snowflake",
            "message ID is not a Discord snowflake",
            "exec /usr/bin/env -i",
            'body = f"""#!/bin/bash',
            "PYTHONDONTWRITEBYTECODE=1",
            "-I -B",
            "--config",
            "--discord-source-config",
            '"$ENTRYPOINT" --help',
            '/bin/bash -n "$WRAPPER_SNAPSHOT"',
        )
        for fragment in required:
            self.assertIn(fragment, self.install)
        self.assertNotIn("--event", self.install)
        self.assertNotIn("--approval-text", self.install)

    def test_generated_wrapper_renders_and_rejects_spool_escape(self) -> None:
        match = re.search(
            r'WRAPPER_SNAPSHOT=.*?<<\'PY\'\n(?P<code>.*?)\nPY\n'
            r'/bin/chmod 0555 "\$WRAPPER_SNAPSHOT"',
            self.install,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match)
        assert match is not None
        generator = match.group("code")
        with tempfile.TemporaryDirectory() as temporary:
            wrapper = Path(temporary) / "mint"
            request_dir = "/private/var/db/john-lomein-release-owner-gateway/requests/example"
            original_argv = sys.argv
            try:
                sys.argv = [
                    "wrapper-generator",
                    str(wrapper),
                    str(os.geteuid()),
                    str(os.getegid()),
                    request_dir,
                    "/usr/bin/false",
                    "/root-owned/code/owner-sign.py",
                    "/root-owned/config/signer.json",
                    "/root-owned/config/source.json",
                    "/signer-owned/state/tmp",
                ]
                exec(
                    compile(generator, "<owner-wrapper-generator>", "exec"),
                    {"__name__": "__main__"},
                )
            finally:
                sys.argv = original_argv
            wrapper.chmod(0o555)
            rendered = wrapper.read_text(encoding="utf-8")
            self.assertTrue(rendered.startswith("#!/bin/bash\n"))
            subprocess.run(
                ["/bin/bash", "-n", str(wrapper)],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            escaped = subprocess.run(
                [
                    str(wrapper),
                    "--bundle",
                    f"{request_dir}/nested/bundle.json",
                    "--channel-id",
                    "1234567890123456" + "7",
                    "--message-id",
                    "2234567890123456" + "7",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(escaped.returncode, 2)
            self.assertIn(
                "direct child of the instance request spool",
                escaped.stderr,
            )
            malformed = subprocess.run(
                [
                    str(wrapper),
                    "--bundle",
                    f"{request_dir}/bundle.json",
                    "--channel-id",
                    "not-a-snowflake",
                    "--message-id",
                    "2234567890123456" + "7",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(malformed.returncode, 2)
            self.assertIn("channel ID is not a Discord snowflake", malformed.stderr)

    def test_sudoers_rule_is_validated_and_withheld_while_disabled(
        self,
    ) -> None:
        required = (
            "Cmnd_Alias",
            "env_reset, !setenv, umask=0077",
            "NOPASSWD",
            "/usr/sbin/visudo -cf",
            "/usr/sbin/visudo -c",
            "/usr/bin/sudo -n -l",
            '-U "$REQUESTER_USER"',
            '-u "$SIGNER_USER"',
            '-g "$SIGNER_GROUP"',
            '"$WRAPPER_PATH" --status',
            "installed sudoers policy is not effective for the requester",
            "installed release owner gateway self-check failed",
            'if [ "$ENABLED" -eq 0 ]',
            '/bin/rm -f "$SUDOERS_PATH"',
            "runtime sudo authorization was not installed",
        )
        for fragment in required:
            self.assertIn(fragment, self.install)
        gate = self.install.index('if [ "$ENABLED" -eq 0 ]')
        remove = self.install.index('/bin/rm -f "$SUDOERS_PATH"', gate)
        install = self.install.index(
            '"$SUDOERS_SNAPSHOT" "$SUDOERS_PATH" root wheel 0440',
            gate,
        )
        self.assertLess(remove, install)

    def test_upgrade_rolls_back_every_authority_bearing_file(self) -> None:
        required = (
            "TRANSACTION_STARTED=0",
            "TRANSACTION_COMMITTED=0",
            "restore_managed_file",
            "$ROLLBACK_DIR/signer-config.json",
            "$ROLLBACK_DIR/source-config.json",
            "$ROLLBACK_DIR/private-key.pem",
            "$ROLLBACK_DIR/public-key.pem",
            "$ROLLBACK_DIR/bot-token",
            "$ROLLBACK_DIR/mint-wrapper",
            "$ROLLBACK_DIR/public-config.json",
            "$ROLLBACK_DIR/sudoers",
            "CODE_BACKUP",
            "rollback source changed during snapshot",
            "os.O_NOFOLLOW",
            "os.fchown(backup_fd",
            "os.fchmod(backup_fd",
            "rollback was incomplete; invocation remains fail-closed",
        )
        for fragment in required:
            self.assertIn(fragment, self.install)

    def test_uninstall_removes_invocation_but_preserves_evidence(self) -> None:
        self.assertIn(
            "usage: uninstall-protected-release-owner-gateway.sh --slug SLUG",
            self.uninstall,
        )
        self.assertIn('id -u)" -eq 0', self.uninstall)
        self.assertIn('uname -s)" = "Darwin"', self.uninstall)
        self.assertIn(
            'SUDOERS_SAFE_SLUG="$(encode_sudoers_slug "$SLUG")"',
            self.uninstall,
        )
        self.assertNotIn(
            'john-lomein-release-owner-$SLUG"',
            self.uninstall,
        )
        self.assertIn(
            'remove_root_file "$SUDOERS_PATH"',
            self.uninstall,
        )
        self.assertIn(
            'remove_root_file "$WRAPPER_PATH"',
            self.uninstall,
        )
        self.assertIn(
            'remove_root_file "$PUBLIC_CONFIG_PATH"',
            self.uninstall,
        )
        self.assertNotIn("rm -rf", self.uninstall)
        for preserved in (
            "preserved root-owned signer configs and credentials",
            "preserved signer audit state",
            "preserved request evidence",
            "preserved per-instance root-owned gateway code",
        ):
            self.assertIn(preserved, self.uninstall)


if __name__ == "__main__":
    unittest.main()
