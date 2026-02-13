import os
import sys
import unittest
from unittest.mock import patch


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.install_openclaw_with_sentinel import SENTINEL_HELPER, _run_sentinel_helper, main


class InstallOpenClawWithSentinelTests(unittest.TestCase):
    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._prompt_yes_no")
    @patch("scripts.install_openclaw_with_sentinel._install_openclaw")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_missing_openclaw_installs_then_enables_sentinel(
        self,
        installed_mock,
        install_mock,
        prompt_mock,
        helper_mock,
        _next_steps_mock,
    ):
        installed_mock.return_value = False
        prompt_mock.return_value = True
        helper_mock.return_value = 0

        rc = main([])

        self.assertEqual(rc, 0)
        install_mock.assert_called_once()
        helper_mock.assert_called_once_with("")

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._prompt_yes_no")
    @patch("scripts.install_openclaw_with_sentinel._install_openclaw")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_present_openclaw_skips_install_and_enables(
        self,
        installed_mock,
        install_mock,
        prompt_mock,
        helper_mock,
        _next_steps_mock,
    ):
        installed_mock.return_value = True
        prompt_mock.return_value = True
        helper_mock.return_value = 0

        rc = main([])

        self.assertEqual(rc, 0)
        install_mock.assert_not_called()
        helper_mock.assert_called_once_with("")

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._prompt_yes_no")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_user_decline_skips_helper(self, installed_mock, prompt_mock, helper_mock, _next_steps_mock):
        installed_mock.return_value = True
        prompt_mock.return_value = False

        rc = main([])

        self.assertEqual(rc, 0)
        helper_mock.assert_not_called()

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._prompt_yes_no")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_non_interactive_yes_calls_helper(self, installed_mock, prompt_mock, helper_mock, _next_steps_mock):
        installed_mock.return_value = True
        helper_mock.return_value = 0

        rc = main(["--non-interactive", "--enable-sentinel", "yes"])

        self.assertEqual(rc, 0)
        prompt_mock.assert_not_called()
        helper_mock.assert_called_once_with("")

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._prompt_yes_no")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_non_interactive_no_skips_helper(self, installed_mock, prompt_mock, helper_mock, _next_steps_mock):
        installed_mock.return_value = True

        rc = main(["--non-interactive", "--enable-sentinel", "no"])

        self.assertEqual(rc, 0)
        prompt_mock.assert_not_called()
        helper_mock.assert_not_called()

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._prompt_yes_no")
    @patch("scripts.install_openclaw_with_sentinel._install_openclaw")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_installer_failure_returns_nonzero(
        self,
        installed_mock,
        install_mock,
        prompt_mock,
        helper_mock,
        _next_steps_mock,
    ):
        installed_mock.return_value = False
        install_mock.side_effect = RuntimeError("installer failed")
        prompt_mock.return_value = True
        helper_mock.return_value = 0

        rc = main([])

        self.assertEqual(rc, 1)
        helper_mock.assert_not_called()

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._prompt_yes_no")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_helper_failure_propagates_exit_code(self, installed_mock, prompt_mock, helper_mock, _next_steps_mock):
        installed_mock.return_value = True
        prompt_mock.return_value = True
        helper_mock.return_value = 7

        rc = main([])

        self.assertEqual(rc, 7)

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_sentinel_network_is_passed(self, installed_mock, helper_mock, _next_steps_mock):
        installed_mock.return_value = True
        helper_mock.return_value = 0

        rc = main(["--non-interactive", "--enable-sentinel", "yes", "--sentinel-network", "custom-net"])

        self.assertEqual(rc, 0)
        helper_mock.assert_called_once_with("custom-net")

    @patch("scripts.install_openclaw_with_sentinel._run")
    def test_run_sentinel_helper_sets_network_env(self, run_mock):
        run_mock.return_value = 0

        rc = _run_sentinel_helper("custom-net")

        self.assertEqual(rc, 0)
        args, kwargs = run_mock.call_args
        self.assertEqual(args[0][1], str(SENTINEL_HELPER))
        self.assertEqual(kwargs["env"]["SENTINEL_OPENCLAW_DOCKER_NETWORK"], "custom-net")


if __name__ == "__main__":
    unittest.main()
