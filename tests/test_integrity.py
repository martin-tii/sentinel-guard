import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import src.core as core
from src.policy import PolicyEnforcer


class RuntimeTamperDetectionTests(unittest.TestCase):
    def setUp(self):
        core.deactivate_sentinel()
        self._original_env = dict(os.environ)
        os.environ.pop("SENTINEL_DISABLE", None)
        os.environ.pop("SENTINEL_ALLOW_DISABLE", None)
        os.environ["SENTINEL_TAMPER_CHECK_INTERVAL_MS"] = "0"

    def tearDown(self):
        core.deactivate_sentinel()
        os.environ.clear()
        os.environ.update(self._original_env)

    def test_runtime_hook_drift_is_blocked(self):
        core.activate_sentinel()
        self.assertTrue(core._sentinel_active)

        # Simulate attacker restoring an original function.
        import subprocess
        subprocess.run = core._original_run

        with self.assertRaises(PermissionError):
            core.sentinel_run(["echo", "ok"])


class PolicyIntegrityTests(unittest.TestCase):
    def setUp(self):
        self._original_env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._original_env)

    def test_immutable_policy_detects_drift(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "policy.yaml"
            policy_path.write_text("allowed_paths: ['./workspace']\n", encoding="utf-8")

            os.environ["SENTINEL_POLICY_IMMUTABLE"] = "true"
            enforcer = PolicyEnforcer(policy_path=str(policy_path))

            policy_path.write_text("allowed_paths: ['./changed']\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                enforcer.verify_policy_immutability()

    def test_policy_sha256_verification(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "policy.yaml"
            raw = "allowed_paths: ['./workspace']\n"
            policy_path.write_text(raw, encoding="utf-8")

            import hashlib
            os.environ["SENTINEL_POLICY_SHA256"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            enforcer = PolicyEnforcer(policy_path=str(policy_path))
            self.assertIsInstance(enforcer.policy, dict)

            os.environ["SENTINEL_POLICY_SHA256"] = "0" * 64
            with self.assertRaises(RuntimeError):
                PolicyEnforcer(policy_path=str(policy_path))


class IntegritySchedulingAndAttestationTests(unittest.TestCase):
    def setUp(self):
        self._original_env = dict(os.environ)
        self._original_last_check = core._last_integrity_check_at

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._original_env)
        core._last_integrity_check_at = self._original_last_check

    def test_integrity_interval_seconds_clamps_non_positive(self):
        os.environ["SENTINEL_TAMPER_CHECK_INTERVAL_MS"] = "-5"
        self.assertEqual(core._integrity_interval_seconds(), 0.0)
        os.environ["SENTINEL_TAMPER_CHECK_INTERVAL_MS"] = "0"
        self.assertEqual(core._integrity_interval_seconds(), 0.0)

    def test_integrity_sample_rate_is_clamped(self):
        os.environ["SENTINEL_TAMPER_CHECK_SAMPLE_RATE"] = "-0.5"
        self.assertEqual(core._integrity_sample_rate(), 0.0)
        os.environ["SENTINEL_TAMPER_CHECK_SAMPLE_RATE"] = "2"
        self.assertEqual(core._integrity_sample_rate(), 1.0)

    def test_should_run_integrity_check_honors_interval_and_force(self):
        os.environ["SENTINEL_TAMPER_CHECK_INTERVAL_MS"] = "60000"
        os.environ["SENTINEL_TAMPER_CHECK_SAMPLE_RATE"] = "0"
        core._last_integrity_check_at = time.monotonic()

        self.assertFalse(core._should_run_integrity_check(force=False))
        self.assertTrue(core._should_run_integrity_check(force=True))

    def test_emit_startup_attestation_includes_expected_fields(self):
        fake_attestation = {
            "production_mode": True,
            "policy_source": "file",
            "signature_mode": "sha256",
            "immutable_policy": True,
            "policy_sha256": "abc123",
        }
        with mock.patch.object(core.policy, "attestation", return_value=fake_attestation):
            with mock.patch.object(core, "audit") as audit_mock:
                core._emit_startup_attestation()

        audit_mock.assert_called_once()
        args = audit_mock.call_args.args
        self.assertEqual(args[0], "ATTESTATION")
        self.assertIn("production=True", args[1])
        self.assertIn("policy_source=file", args[1])
        self.assertIn("signature_mode=sha256", args[1])
        self.assertIn("immutable=True", args[1])
        self.assertIn("policy_sha256=abc123", args[1])
        self.assertEqual(args[2], "INFO")


if __name__ == "__main__":
    unittest.main()
