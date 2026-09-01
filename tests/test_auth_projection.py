#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in os.sys.path:
    os.sys.path.insert(0, str(SCRIPTS))

import john_lomein_auth_projection as projection


def _segment(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _jwt(account: str, *, exp: float | None = None, iat: float | None = None) -> str:
    now = time.time()
    claims = {
        "iss": "https://auth.openai.com",
        "sub": f"user-{account}",
        "iat": now - 5 if iat is None else iat,
        "exp": now + 7200 if exp is None else exp,
        "https://api.openai.com/auth": {
            "chatgpt_account_id": account,
            "chatgpt_user_id": f"user-{account}",
        },
    }
    return ".".join(
        (
            _segment({"alg": "RS256", "typ": "JWT"}),
            _segment(claims),
            "signature",
        )
    )


def _authority_store(
    *,
    account: str = "account-a",
    refreshed_at: str = "2026-07-19T12:00:00+00:00",
    access_token: str | None = None,
    refresh_token: str = "refresh-authority",
) -> dict:
    access = access_token or _jwt(account)
    state = {
        "auth_mode": "chatgpt",
        "last_refresh": refreshed_at,
        "tokens": {
            "access_token": access,
            "refresh_token": refresh_token,
            "id_token": _jwt(account),
            "account_id": account,
        },
    }
    row = {
        "id": "device-row",
        "label": "device_code",
        "auth_type": "oauth",
        "priority": 0,
        "source": "device_code",
        "access_token": access,
        "refresh_token": refresh_token,
        "last_refresh": refreshed_at,
        "base_url": projection.BASE_URL,
        "last_status": None,
    }
    return {
        "version": 1,
        "providers": {projection.PROVIDER: state, "other": {"api_key": "keep"}},
        "credential_pool": {
            projection.PROVIDER: [row],
            "other": [{"access_token": "keep-pool"}],
        },
        "active_provider": projection.PROVIDER,
        "updated_at": refreshed_at,
    }


class AuthProjectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.root = Path(self._temporary.name)
        os.chmod(self.root, 0o700)
        self.authority = self.root / "authority"
        self.runtime = self.root / "runtime"
        self.authority.mkdir(mode=0o700)
        self.runtime.mkdir(mode=0o700)
        (self.runtime / "profiles").mkdir(mode=0o755)
        self.profiles = []
        for name in projection.CANONICAL_PROFILE_NAMES:
            profile = self.runtime / "profiles" / name
            profile.mkdir(mode=0o700)
            self.profiles.append(profile)
        self._write(
            self.authority / "auth.json",
            _authority_store(),
        )

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _write(self, path: Path, payload: dict, mode: int = 0o600) -> None:
        path.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(path, mode)

    def _existing_projection(self, *, marker: str = "old") -> dict:
        return {
            "version": 7,
            "active_provider": "zai",
            "providers": {
                "zai": {"api_key": f"{marker}-zai"},
                projection.PROVIDER: {
                    "tokens": {
                        "access_token": "old-access",
                        "refresh_token": "must-disappear",
                    }
                },
            },
            "credential_pool": {
                "zai": [{"access_token": f"{marker}-pool"}],
                projection.PROVIDER: [
                    {
                        "access_token": "old-access",
                        "refresh_token": "must-disappear",
                    }
                ],
            },
            "suppressed_sources": {
                "zai": ["env:ZAI_API_KEY"],
                projection.PROVIDER: ["device_code"],
            },
        }

    def test_sync_projects_access_only_and_preserves_non_openai_material(self):
        for home in [self.runtime, *self.profiles]:
            self._write(home / "auth.json", self._existing_projection())
        fresh = _jwt("account-a")

        result = projection.sync_projection(
            self.runtime,
            authority_home=self.authority,
            _refresh=lambda _authority: fresh,
        )

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["targets"], 1 + len(self.profiles))
        for home in [self.runtime, *self.profiles]:
            path = home / "auth.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(payload["providers"], {"zai": {"api_key": "old-zai"}})
            self.assertEqual(
                payload["credential_pool"]["zai"],
                [{"access_token": "old-pool"}],
            )
            self.assertNotIn(projection.PROVIDER, payload["providers"])
            rows = payload["credential_pool"][projection.PROVIDER]
            self.assertEqual(len(rows), 1)
            self.assertEqual(set(rows[0]), projection.PROJECTION_KEYS)
            self.assertEqual(rows[0]["access_token"], fresh)
            self.assertEqual(rows[0]["source"], "manual:api_key")
            self.assertEqual(rows[0]["auth_type"], "api_key")
            self.assertNotIn("refresh_token", json.dumps(rows))
            self.assertNotIn("id_token", json.dumps(rows))
            self.assertNotIn("account_id", json.dumps(rows))
            self.assertEqual(payload["active_provider"], "zai")
            self.assertEqual(
                payload["suppressed_sources"],
                {"zai": ["env:ZAI_API_KEY"]},
            )

        verified = projection.verify_projection(
            self.runtime,
            authority_home=self.authority,
        )
        self.assertEqual(verified["targets"], 1 + len(self.profiles))

    def test_non_openai_provider_is_a_true_noop(self):
        result = projection.sync_projection(
            Path("/does/not/exist"),
            authority_home=Path("/also/missing"),
            provider="zai",
        )
        self.assertEqual(
            result,
            {"status": "not_applicable", "provider": "zai", "targets": 0},
        )
        verified = projection.verify_projection(
            Path("/does/not/exist"),
            authority_home=Path("/also/missing"),
            provider="zai",
        )
        self.assertEqual(verified["status"], "not_applicable")

    def test_current_projection_skips_authority_refresh_and_all_writes(self):
        fresh = _jwt("account-a")
        projection.sync_projection(
            self.runtime,
            authority_home=self.authority,
            _refresh=lambda _authority: fresh,
        )
        before = {
            home: (home / "auth.json").read_bytes()
            for home in [self.runtime, *self.profiles]
        }

        result = projection.sync_projection(
            self.runtime,
            authority_home=self.authority,
            _refresh=mock.Mock(
                side_effect=AssertionError("authority must not be consulted")
            ),
        )

        self.assertEqual(result["status"], "current")
        for home, raw in before.items():
            self.assertEqual((home / "auth.json").read_bytes(), raw)

    def test_cli_quiet_suppresses_status_output(self):
        completed = subprocess.run(
            [
                os.sys.executable,
                str(SCRIPTS / "john_lomein_auth_projection.py"),
                "sync",
                "--runtime-home",
                "/does/not/exist",
                "--provider",
                "zai",
                "--quiet",
            ],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "")

    def test_malformed_or_unsafe_authority_preserves_existing_projection(self):
        old = self._existing_projection(marker="sentinel")
        for home in [self.runtime, *self.profiles]:
            self._write(home / "auth.json", old)
        before = (self.runtime / "auth.json").read_bytes()
        (self.authority / "auth.json").write_text("{", encoding="utf-8")
        os.chmod(self.authority / "auth.json", 0o600)

        with self.assertRaisesRegex(
            projection.AuthProjectionError,
            "authority_malformed",
        ):
            projection.sync_projection(
                self.runtime,
                authority_home=self.authority,
            )
        self.assertEqual((self.runtime / "auth.json").read_bytes(), before)

        self._write(self.authority / "auth.json", _authority_store(), mode=0o644)
        with self.assertRaisesRegex(
            projection.AuthProjectionError,
            "authority_unsafe",
        ):
            projection.sync_projection(
                self.runtime,
                authority_home=self.authority,
            )
        self.assertEqual((self.runtime / "auth.json").read_bytes(), before)

    def test_symlink_and_hardlink_credentials_are_rejected(self):
        real = self.root / "real-authority"
        real.mkdir(mode=0o700)
        self._write(real / "auth.json", _authority_store())
        redirected = self.root / "redirected"
        redirected.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(
            projection.AuthProjectionError,
            "symlink_component",
        ):
            projection.sync_projection(
                self.runtime,
                authority_home=redirected,
            )

        self._write(self.runtime / "auth.json", self._existing_projection())
        hardlink = self.root / "hardlink-auth.json"
        os.link(self.runtime / "auth.json", hardlink)
        with self.assertRaisesRegex(
            projection.AuthProjectionError,
            "target_0_unsafe",
        ):
            projection.sync_projection(
                self.runtime,
                authority_home=self.authority,
                _refresh=lambda _authority: _jwt("account-a"),
            )

    def test_atomic_replace_failure_preserves_last_valid_projection(self):
        for home in [self.runtime, *self.profiles]:
            self._write(home / "auth.json", self._existing_projection())
        before = (self.runtime / "auth.json").read_bytes()

        with mock.patch.object(
            projection.os,
            "replace",
            side_effect=OSError("injected"),
        ):
            with self.assertRaisesRegex(
                projection.AuthProjectionError,
                "target_0_replace_failed",
            ):
                projection.sync_projection(
                    self.runtime,
                    authority_home=self.authority,
                    _refresh=lambda _authority: _jwt("account-a"),
                )

        self.assertEqual((self.runtime / "auth.json").read_bytes(), before)
        self.assertEqual(
            list(self.runtime.glob(".auth.json.tmp.*")),
            [],
        )

    def test_verify_rejects_singleton_secret_rows_and_divergent_tokens(self):
        token = _jwt("account-a")
        for home in [self.runtime, *self.profiles]:
            payload = projection._projection_payload({}, access_token=token)
            self._write(home / "auth.json", payload)

        invalid = json.loads((self.runtime / "auth.json").read_text())
        invalid["providers"][projection.PROVIDER] = {
            "tokens": {"refresh_token": "forbidden"}
        }
        self._write(self.runtime / "auth.json", invalid)
        with self.assertRaisesRegex(
            projection.AuthProjectionError,
            "provider_singleton_present",
        ):
            projection.verify_projection(
                self.runtime,
                authority_home=self.authority,
            )

        invalid = projection._projection_payload({}, access_token=token)
        invalid["credential_pool"][projection.PROVIDER][0][
            "refresh_token"
        ] = "forbidden"
        self._write(self.runtime / "auth.json", invalid)
        with self.assertRaisesRegex(
            projection.AuthProjectionError,
            "row_shape_invalid",
        ):
            projection.verify_projection(
                self.runtime,
                authority_home=self.authority,
            )

        self._write(
            self.runtime / "auth.json",
            projection._projection_payload({}, access_token=token),
        )
        self._write(
            self.profiles[0] / "auth.json",
            projection._projection_payload(
                {}, access_token=_jwt("account-a")
            ),
        )
        with self.assertRaisesRegex(
            projection.AuthProjectionError,
            "tokens_diverged",
        ):
            projection.verify_projection(
                self.runtime,
                authority_home=self.authority,
            )

    def test_sync_normalizes_hermes_lock_mode(self):
        lock = self.runtime / "auth.lock"
        lock.write_text("", encoding="utf-8")
        os.chmod(lock, 0o644)
        for home in self.profiles:
            self._write(home / "auth.json", self._existing_projection())
        self._write(self.runtime / "auth.json", self._existing_projection())

        projection.sync_projection(
            self.runtime,
            authority_home=self.authority,
            _refresh=lambda _authority: _jwt("account-a"),
        )

        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)

    def test_expired_authority_access_can_be_refreshed(self):
        expired = _jwt("account-a", exp=time.time() - 60)
        self._write(
            self.authority / "auth.json",
            _authority_store(access_token=expired),
        )
        fresh = _jwt("account-a")

        with mock.patch.object(
            projection,
            "_run_hermes_refresh",
        ) as refresh:
            def replace_authority(_home, *, refresh_horizon_seconds):
                self._write(
                    self.authority / "auth.json",
                    _authority_store(access_token=fresh),
                )

            refresh.side_effect = replace_authority
            result = projection.sync_projection(
                self.runtime,
                authority_home=self.authority,
            )

        self.assertEqual(result["status"], "ok")
        runtime = json.loads(
            (self.runtime / "auth.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            runtime["credential_pool"][projection.PROVIDER][0]["access_token"],
            fresh,
        )

    def test_recovery_promotes_only_newer_same_account_singleton_chain(self):
        source_access = _jwt("account-a")
        source = _authority_store(
            refreshed_at="2026-07-19T13:00:00+00:00",
            access_token=source_access,
            refresh_token="new-refresh",
        )
        source["credential_pool"][projection.PROVIDER].insert(
            0,
            {
                "id": "stale-unrelated",
                "source": "manual:device_code",
                "auth_type": "oauth",
                "priority": 0,
                "access_token": _jwt("account-a"),
                "refresh_token": "stale-unrelated-refresh",
                "last_refresh": "2026-06-01T00:00:00+00:00",
            },
        )
        source["providers"][projection.PROVIDER]["last_auth_error"] = {
            "code": "old-sandbox-error"
        }
        matching = source["credential_pool"][projection.PROVIDER][1]
        matching["last_status"] = "exhausted"
        matching["last_error_code"] = 401
        self._write(self.profiles[0] / "auth.json", source)

        result = projection.recover_authority(
            self.runtime,
            from_profile=self.profiles[0],
            authority_home=self.authority,
        )

        self.assertTrue(result["recovered"])
        recovered = json.loads(
            (self.authority / "auth.json").read_text(encoding="utf-8")
        )
        state = recovered["providers"][projection.PROVIDER]
        self.assertEqual(state["tokens"]["access_token"], source_access)
        self.assertEqual(state["tokens"]["refresh_token"], "new-refresh")
        self.assertNotIn("last_auth_error", state)
        rows = recovered["credential_pool"][projection.PROVIDER]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["access_token"], source_access)
        self.assertEqual(rows[0]["source"], "device_code")
        self.assertEqual(rows[0]["priority"], 0)
        self.assertIsNone(rows[0]["last_status"])
        self.assertIsNone(rows[0]["last_error_code"])
        self.assertEqual(
            recovered["providers"]["other"],
            {"api_key": "keep"},
        )

    def test_recovery_gates_preserve_authority(self):
        authority_path = self.authority / "auth.json"
        cases = []

        cases.append(
            (
                "not_newer",
                _authority_store(
                    refreshed_at="2026-07-19T11:00:00+00:00",
                    refresh_token="candidate",
                ),
                "recovery_not_newer",
            )
        )
        cases.append(
            (
                "different_account",
                _authority_store(
                    account="account-b",
                    refreshed_at="2026-07-19T13:00:00+00:00",
                    refresh_token="candidate",
                ),
                "recovery_account_mismatch",
            )
        )
        expired = _jwt("account-a", exp=time.time() - 1)
        cases.append(
            (
                "expired",
                _authority_store(
                    refreshed_at="2026-07-19T13:00:00+00:00",
                    access_token=expired,
                    refresh_token="candidate",
                ),
                "expired_or_expiring",
            )
        )
        malformed = _authority_store(
            refreshed_at="2026-07-19T13:00:00+00:00",
            refresh_token="candidate",
        )
        malformed["providers"][projection.PROVIDER]["tokens"][
            "access_token"
        ] = "not-a-jwt"
        malformed["credential_pool"][projection.PROVIDER][0][
            "access_token"
        ] = "not-a-jwt"
        cases.append(("malformed", malformed, "access_token_invalid"))

        for name, candidate, error in cases:
            with self.subTest(name=name):
                self._write(authority_path, _authority_store())
                before = authority_path.read_bytes()
                self._write(self.profiles[0] / "auth.json", candidate)
                with self.assertRaisesRegex(
                    projection.AuthProjectionError,
                    error,
                ):
                    projection.recover_authority(
                        self.runtime,
                        from_profile=self.profiles[0],
                        authority_home=self.authority,
                    )
                self.assertEqual(authority_path.read_bytes(), before)

    def test_recovery_rejects_noncanonical_profile_and_ambiguous_pool(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        self._write(
            outside / "auth.json",
            _authority_store(
                refreshed_at="2026-07-19T13:00:00+00:00"
            ),
        )
        with self.assertRaisesRegex(
            projection.AuthProjectionError,
            "profile_not_canonical",
        ):
            projection.recover_authority(
                self.runtime,
                from_profile=outside,
                authority_home=self.authority,
            )

        source = _authority_store(
            refreshed_at="2026-07-19T13:00:00+00:00",
            refresh_token="candidate",
        )
        source["credential_pool"][projection.PROVIDER].append(
            dict(source["credential_pool"][projection.PROVIDER][0])
        )
        self._write(self.profiles[0] / "auth.json", source)
        with self.assertRaisesRegex(
            projection.AuthProjectionError,
            "pool_chain_ambiguous",
        ):
            projection.recover_authority(
                self.runtime,
                from_profile=self.profiles[0],
                authority_home=self.authority,
            )


if __name__ == "__main__":
    unittest.main()
