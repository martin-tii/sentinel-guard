import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class EntrypointWithOPAScriptTests(unittest.TestCase):
    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[1]

    def _render_testable_script(self, source: Path, tmp: Path, workspace: Path, baseline_policy: Path) -> Path:
        raw = source.read_text(encoding="utf-8")
        raw = raw.replace("/workspace/workspace", str(workspace / "workspace"))
        raw = raw.replace("/workspace/sentinel.yaml", str(workspace / "sentinel.yaml"))
        raw = raw.replace("cd /workspace", f"cd {workspace}")
        raw = raw.replace("/opt/sentinel/sentinel.yaml", str(baseline_policy))
        rendered = tmp / "entrypoint-opa-test.sh"
        rendered.write_text(raw, encoding="utf-8")
        return rendered

    def test_entrypoint_with_opa_bootstraps_when_opa_disabled(self):
        source = self._repo_root() / "scripts" / "entrypoint_with_opa.sh"
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
                env={**os.environ, "SENTINEL_EMBED_OPA_ENABLED": "false"},
            )

            self.assertEqual(result.returncode, 0)
            self.assertTrue((workspace / "workspace").exists())
            self.assertTrue((workspace / "sentinel.yaml").exists())
            self.assertEqual(result.stdout.strip(), str(workspace))


if __name__ == "__main__":
    unittest.main()
