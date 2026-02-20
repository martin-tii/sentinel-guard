import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import src.setup_wizard as setup_wizard


class SetupWizardTests(unittest.TestCase):
    def test_friendly_error_for_missing_docker_binary(self):
        msg = setup_wizard._friendly_prereq_error("Prerequisite check", "docker: command not found")
        self.assertIn("Docker is not installed", msg)

    def test_write_policy_create_keep_update(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            workspace = tmp / "workspace"
            workspace.mkdir()
            policy = tmp / "sentinel.yaml"

            status = setup_wizard._write_policy(policy, workspace, overwrite=False)
            self.assertEqual(status, "created")
            body1 = policy.read_text(encoding="utf-8")
            self.assertIn("policies/rego/sentinel/authz.rego", body1)

            status = setup_wizard._write_policy(policy, workspace, overwrite=False)
            self.assertEqual(status, "kept")
            body2 = policy.read_text(encoding="utf-8")
            self.assertEqual(body1, body2)

            status = setup_wizard._write_policy(policy, workspace, overwrite=True)
            self.assertEqual(status, "updated")

    def test_main_non_interactive_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            workspace = tmp / "workspace"
            policy = tmp / "sentinel.yaml"

            with (
                mock.patch.object(setup_wizard, "_check_docker_binary"),
                mock.patch.object(setup_wizard, "_check_docker_daemon"),
                mock.patch.object(setup_wizard, "_check_docker_compose"),
                mock.patch.object(setup_wizard, "_run_smoke_test"),
            ):
                rc = setup_wizard.main(
                    [
                        "--non-interactive",
                        "--workspace",
                        str(workspace),
                        "--policy",
                        str(policy),
                    ]
                )

            self.assertEqual(rc, 0)
            self.assertTrue(workspace.exists())
            self.assertTrue(policy.exists())

    def test_main_returns_error_code_on_setup_error(self):
        with mock.patch.object(
            setup_wizard,
            "_check_docker_binary",
            side_effect=setup_wizard.SetupError("Docker not found"),
        ):
            rc = setup_wizard.main(["--non-interactive", "--skip-smoke-test"])

        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
