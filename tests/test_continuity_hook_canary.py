#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import shutil
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CANARY_PATH = ROOT / "scripts" / "john-lomein-continuity-hook-canary.py"
SPEC = importlib.util.spec_from_file_location(
    "john_lomein_continuity_hook_canary_test",
    CANARY_PATH,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load continuity hook canary")
canary = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = canary
SPEC.loader.exec_module(canary)


class ContinuityHookCanaryTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("hermes"), "Hermes CLI is unavailable")
    def test_installed_runtime_reaches_actual_model_request(self):
        result = canary.run_canary(shutil.which("hermes"), timeout=45)
        self.assertEqual(result["schema_version"], canary.RESULT_SCHEMA)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["context_target"], "current_user_message")
        self.assertRegex(result["model_request_sha256"], r"^[0-9a-f]{64}$")

    @unittest.skipUnless(shutil.which("hermes"), "Hermes CLI is unavailable")
    def test_actual_product_plugin_helper_store_and_profile_reach_model_request(self):
        result = canary.run_product_canary(
            shutil.which("hermes"),
            asset_root=ROOT,
            timeout=45,
        )
        self.assertEqual(result["schema_version"], canary.PRODUCT_RESULT_SCHEMA)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["profile"], "john-lomein-maintainer")
        self.assertEqual(result["context_target"], "current_user_message")
        self.assertRegex(result["entry_id"], r"^jlce-[0-9a-f]{24}$")
        self.assertRegex(result["model_request_sha256"], r"^[0-9a-f]{64}$")

    def test_deploy_and_doctor_require_capability_and_product_canaries(self):
        deploy = (ROOT / "scripts" / "deploy-instance.sh").read_text(
            encoding="utf-8"
        )
        doctor = (ROOT / "scripts" / "doctor-instance.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("john-lomein-continuity-hook-canary.py", deploy)
        self.assertIn("--asset-root \"$BOT_HERMES_HOME\"", deploy)
        self.assertIn("john-lomein.continuity-hook-canary.v1", doctor)
        self.assertIn("john-lomein.continuity-product-hook-canary.v1", doctor)
        self.assertIn("current_user_message", doctor)


if __name__ == "__main__":
    unittest.main()
