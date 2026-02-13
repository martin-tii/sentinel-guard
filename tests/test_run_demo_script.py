import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


class RunDemoScriptTests(unittest.TestCase):
    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[1]

    def _write_fake_docker(self, bin_dir: Path, log_path: Path):
        docker_path = bin_dir / "docker"
        docker_path.write_text(
            "#!/bin/sh\n"
            "echo \"$@\" >> \"$FAKE_DOCKER_LOG\"\n"
            "exit 0\n",
            encoding="utf-8",
        )
        mode = docker_path.stat().st_mode
        docker_path.chmod(mode | stat.S_IXUSR)

    def test_run_demo_defaults_to_strict_profile(self):
        script = self._repo_root() / "run_demo.sh"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            fake_bin = tmp / "bin"
            fake_bin.mkdir()
            docker_log = tmp / "docker.log"
            self._write_fake_docker(fake_bin, docker_log)

            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
            env["FAKE_DOCKER_LOG"] = str(docker_log)

            result = subprocess.run(
                ["bash", str(script)],
                cwd=str(tmp),
                env=env,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0)
            self.assertIn("Mode: Strict (network disabled)", result.stdout)
            self.assertTrue((tmp / "sandbox-workspace").exists())
            log_text = docker_log.read_text(encoding="utf-8")
            self.assertIn("compose version", log_text)
            self.assertIn("compose build", log_text)
            self.assertIn("--profile strict run --rm sentinel-strict", log_text)

    def test_run_demo_standard_flag_switches_profile(self):
        script = self._repo_root() / "run_demo.sh"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            fake_bin = tmp / "bin"
            fake_bin.mkdir()
            docker_log = tmp / "docker.log"
            self._write_fake_docker(fake_bin, docker_log)

            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
            env["FAKE_DOCKER_LOG"] = str(docker_log)

            result = subprocess.run(
                ["bash", str(script), "--standard"],
                cwd=str(tmp),
                env=env,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0)
            self.assertIn("Mode: Standard (network enabled)", result.stdout)
            log_text = docker_log.read_text(encoding="utf-8")
            self.assertIn("--profile standard run --rm sentinel-standard", log_text)


if __name__ == "__main__":
    unittest.main()
