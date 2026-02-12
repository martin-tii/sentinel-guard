import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.isolation import IsolationError
from src.openclaw_isolation import main


class OpenClawIsolationTests(unittest.TestCase):
    def test_requires_openclaw_command(self):
        with self.assertRaises(IsolationError):
            main([])

    @patch("src.openclaw_isolation.run_isolated")
    def test_main_wraps_openclaw_with_home_redirect(self, run_isolated_mock):
        run_isolated_mock.return_value.returncode = 0
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            workspace = tmp / "workspace"
            policy = tmp / "sentinel.yaml"
            policy.write_text("allowed_paths: ['./workspace']\n", encoding="utf-8")

            code = main(
                [
                    "--workspace",
                    str(workspace),
                    "--policy",
                    str(policy),
                    "--image",
                    "openclaw:test",
                    "--",
                    "gateway",
                    "--port",
                    "18789",
                ]
            )

            self.assertTrue(workspace.exists())

        self.assertEqual(code, 0)
        run_isolated_mock.assert_called_once()
        call_args = run_isolated_mock.call_args.args
        cmd = call_args[0]
        cfg = call_args[1]
        self.assertEqual(cmd[:3], ["env", "HOME=/workspace", "openclaw"])
        self.assertEqual(cmd[3:], ["gateway", "--port", "18789"])
        self.assertEqual(cfg.image, "openclaw:test")
        self.assertEqual(cfg.network_mode, "bridge")
        self.assertFalse(cfg.build_if_missing)

    @patch("src.openclaw_isolation.run_isolated")
    def test_main_allows_disabling_home_redirect(self, run_isolated_mock):
        run_isolated_mock.return_value.returncode = 0
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            workspace = tmp / "workspace"
            policy = tmp / "sentinel.yaml"
            policy.write_text("allowed_paths: ['./workspace']\n", encoding="utf-8")

            code = main(
                [
                    "--workspace",
                    str(workspace),
                    "--policy",
                    str(policy),
                    "--no-home-redirect",
                    "--",
                    "doctor",
                ]
            )

        self.assertEqual(code, 0)
        call_args = run_isolated_mock.call_args.args
        cmd = call_args[0]
        self.assertEqual(cmd, ["openclaw", "doctor"])


if __name__ == "__main__":
    unittest.main()
