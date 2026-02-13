import subprocess
import tempfile
import unittest
from pathlib import Path


class EntrypointScriptTests(unittest.TestCase):
    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[1]

    def _render_testable_script(self, source: Path, tmp: Path, workspace: Path, baseline_policy: Path) -> Path:
        raw = source.read_text(encoding="utf-8")
        raw = raw.replace("/workspace/workspace", str(workspace / "workspace"))
        raw = raw.replace("/workspace/sentinel.yaml", str(workspace / "sentinel.yaml"))
        raw = raw.replace("cd /workspace", f"cd {workspace}")
        raw = raw.replace("/opt/sentinel/sentinel.yaml", str(baseline_policy))
        rendered = tmp / "entrypoint-test.sh"
        rendered.write_text(raw, encoding="utf-8")
        return rendered

    def test_entrypoint_bootstraps_workspace_and_policy(self):
        source = self._repo_root() / "scripts" / "entrypoint.sh"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            workspace = tmp / "workspace"
            baseline_policy = tmp / "baseline.yaml"
            baseline_policy.write_text("allowed_paths:\n  - './workspace'\n", encoding="utf-8")
            script = self._render_testable_script(source, tmp, workspace, baseline_policy)

            result = subprocess.run(
                ["sh", str(script), "sh", "-c", "pwd"],
                cwd=str(tmp),
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0)
            self.assertTrue((workspace / "workspace").exists())
            self.assertTrue((workspace / "sentinel.yaml").exists())
            self.assertEqual(result.stdout.strip(), str(workspace))

    def test_entrypoint_does_not_overwrite_existing_policy(self):
        source = self._repo_root() / "scripts" / "entrypoint.sh"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            workspace = tmp / "workspace"
            workspace.mkdir(parents=True, exist_ok=True)
            existing_policy = workspace / "sentinel.yaml"
            existing_policy.write_text("existing: true\n", encoding="utf-8")
            baseline_policy = tmp / "baseline.yaml"
            baseline_policy.write_text("new: false\n", encoding="utf-8")
            script = self._render_testable_script(source, tmp, workspace, baseline_policy)

            result = subprocess.run(
                ["sh", str(script), "sh", "-c", "echo ok"],
                cwd=str(tmp),
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0)
            self.assertEqual(existing_policy.read_text(encoding="utf-8"), "existing: true\n")


if __name__ == "__main__":
    unittest.main()
