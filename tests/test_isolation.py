import os
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.isolation import IsolationConfig, IsolationError, build_docker_run_command


class IsolationCommandBuildTests(unittest.TestCase):
    def test_build_docker_command_includes_hardening_flags(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            workspace = tmp / "workspace"
            workspace.mkdir()
            policy = tmp / "sentinel.yaml"
            policy.write_text("allowed_paths: ['./workspace']\n", encoding="utf-8")
            seccomp = tmp / "seccomp.json"
            seccomp.write_text("{}", encoding="utf-8")

            cfg = IsolationConfig(
                image="sentinel-guard:test",
                workspace=str(workspace),
                policy=str(policy),
                seccomp=str(seccomp),
                network_mode="none",
            )
            cmd = build_docker_run_command(["python", "app.py"], cfg)

            joined = " ".join(cmd)
            self.assertIn("docker run", joined)
            self.assertIn("--read-only", cmd)
            self.assertIn("--cap-drop", cmd)
            self.assertIn("ALL", cmd)
            self.assertIn("--security-opt", cmd)
            self.assertIn("no-new-privileges:true", cmd)
            self.assertIn("--network", cmd)
            self.assertIn("none", cmd)
            self.assertIn("--workdir", cmd)
            self.assertIn("/workspace", cmd)
            self.assertEqual(cmd[-3:], ["sentinel-guard:test", "python", "app.py"])

    def test_invalid_network_mode_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            workspace = tmp / "workspace"
            workspace.mkdir()
            policy = tmp / "sentinel.yaml"
            policy.write_text("allowed_paths: ['./workspace']\n", encoding="utf-8")
            seccomp = tmp / "seccomp.json"
            seccomp.write_text("{}", encoding="utf-8")

            cfg = IsolationConfig(
                workspace=str(workspace),
                policy=str(policy),
                seccomp=str(seccomp),
                network_mode="invalid",
            )
            with self.assertRaises(IsolationError):
                build_docker_run_command(["python", "app.py"], cfg)

    def test_missing_command_rejected(self):
        with self.assertRaises(IsolationError):
            build_docker_run_command([])

    def test_seccomp_off_uses_unconfined_without_profile_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            workspace = tmp / "workspace"
            workspace.mkdir()
            policy = tmp / "sentinel.yaml"
            policy.write_text("allowed_paths: ['./workspace']\n", encoding="utf-8")

            cfg = IsolationConfig(
                workspace=str(workspace),
                policy=str(policy),
                seccomp=str(tmp / "missing-seccomp.json"),
                seccomp_mode="off",
            )
            cmd = build_docker_run_command(["python", "app.py"], cfg)
            self.assertIn("seccomp=unconfined", cmd)

    def test_invalid_seccomp_mode_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            workspace = tmp / "workspace"
            workspace.mkdir()
            policy = tmp / "sentinel.yaml"
            policy.write_text("allowed_paths: ['./workspace']\n", encoding="utf-8")
            seccomp = tmp / "seccomp.json"
            seccomp.write_text("{}", encoding="utf-8")

            cfg = IsolationConfig(
                workspace=str(workspace),
                policy=str(policy),
                seccomp=str(seccomp),
                seccomp_mode="invalid",
            )
            with self.assertRaises(IsolationError):
                build_docker_run_command(["python", "app.py"], cfg)


if __name__ == "__main__":
    unittest.main()
