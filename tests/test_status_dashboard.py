import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import src.status_dashboard as status_dashboard


class StatusDashboardTests(unittest.TestCase):
    def test_render_dashboard_human_readable(self):
        items = [
            status_dashboard.StatusItem("Docker", "Running", "ok"),
            status_dashboard.StatusItem("Policy", "Loaded", "warn"),
        ]
        text = status_dashboard._render_dashboard(items)
        self.assertIn("Sentinel Status Dashboard", text)
        self.assertIn("[OK]", text)
        self.assertIn("[WARN]", text)

    def test_main_json_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repo = root / "repo"
            home = root / "home"
            repo.mkdir()
            home.mkdir()
            (repo / "sentinel.yaml").write_text("allowed_paths:\n  - ./sandbox-workspace\n", encoding="utf-8")
            (repo / "sandbox-workspace").mkdir()

            fake_ok = type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            with (
                mock.patch.object(status_dashboard, "_repo_root", return_value=repo),
                mock.patch.object(status_dashboard, "_home_dir", return_value=home),
                mock.patch.object(status_dashboard.shutil, "which", side_effect=lambda x: "/usr/bin/docker" if x == "docker" else None),
                mock.patch.object(status_dashboard.subprocess, "run", return_value=fake_ok),
                mock.patch("builtins.print") as print_mock,
            ):
                rc = status_dashboard.main(["--json"])

            self.assertEqual(rc, 0)
            self.assertTrue(print_mock.called)
            payload = json.loads(print_mock.call_args.args[0])
            self.assertTrue(isinstance(payload, list))
            labels = {item.get("label") for item in payload}
            self.assertIn("Docker binary", labels)
            self.assertIn("Policy file", labels)


if __name__ == "__main__":
    unittest.main()
