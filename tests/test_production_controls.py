import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.isolation import IsolationConfig, IsolationError, build_docker_run_command
from src.policy import PolicyEnforcer


class ProductionPolicyIntegrityTests(unittest.TestCase):
    def setUp(self):
        self._original_env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._original_env)

    def test_production_requires_signed_and_immutable_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "policy.yaml"
            policy_path.write_text("allowed_paths: ['./workspace']\n", encoding="utf-8")

            os.environ["SENTINEL_PRODUCTION"] = "true"
            os.environ.pop("SENTINEL_POLICY_IMMUTABLE", None)
            os.environ.pop("SENTINEL_POLICY_SHA256", None)
            os.environ.pop("SENTINEL_POLICY_HMAC_SHA256", None)
            with self.assertRaises(RuntimeError):
                PolicyEnforcer(policy_path=str(policy_path))

    def test_production_policy_integrity_passes_with_sha_and_immutable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_path = Path(tmpdir) / "policy.yaml"
            raw = "allowed_paths: ['./workspace']\n"
            policy_path.write_text(raw, encoding="utf-8")

            os.environ["SENTINEL_PRODUCTION"] = "true"
            os.environ["SENTINEL_POLICY_IMMUTABLE"] = "true"
            os.environ["SENTINEL_POLICY_SHA256"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()

            enforcer = PolicyEnforcer(policy_path=str(policy_path))
            attestation = enforcer.attestation()
            self.assertTrue(attestation["production_mode"])
            self.assertTrue(attestation["immutable_policy"])
            self.assertEqual(attestation["signature_mode"], "sha256")


class ProductionIsolationNetworkTests(unittest.TestCase):
    def setUp(self):
        self._original_env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._original_env)

    def test_production_blocks_networked_isolation_without_exception_flag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            workspace = tmp / "workspace"
            workspace.mkdir()
            policy = tmp / "sentinel.yaml"
            policy.write_text("allowed_paths: ['./workspace']\n", encoding="utf-8")
            seccomp = tmp / "seccomp.json"
            seccomp.write_text("{}", encoding="utf-8")

            os.environ["SENTINEL_PRODUCTION"] = "true"
            os.environ.pop("SENTINEL_ALLOW_NETWORK_IN_PRODUCTION", None)

            cfg = IsolationConfig(
                workspace=str(workspace),
                policy=str(policy),
                seccomp=str(seccomp),
                network_mode="bridge",
            )
            with self.assertRaises(IsolationError):
                build_docker_run_command(["python", "app.py"], cfg)

    def test_production_allows_networked_isolation_with_exception_flag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            workspace = tmp / "workspace"
            workspace.mkdir()
            policy = tmp / "sentinel.yaml"
            policy.write_text("allowed_paths: ['./workspace']\n", encoding="utf-8")
            seccomp = tmp / "seccomp.json"
            seccomp.write_text("{}", encoding="utf-8")

            os.environ["SENTINEL_PRODUCTION"] = "true"
            os.environ["SENTINEL_ALLOW_NETWORK_IN_PRODUCTION"] = "true"

            cfg = IsolationConfig(
                workspace=str(workspace),
                policy=str(policy),
                seccomp=str(seccomp),
                network_mode="bridge",
            )
            cmd = build_docker_run_command(["python", "app.py"], cfg)
            self.assertIn("--network", cmd)
            self.assertIn("bridge", cmd)


if __name__ == "__main__":
    unittest.main()
