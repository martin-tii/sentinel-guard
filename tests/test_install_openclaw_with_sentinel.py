import os
import sys
import unittest
from unittest.mock import patch


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.install_openclaw_with_sentinel import (
    SENTINEL_HELPER,
    _install_openclaw,
    build_default_exec_approvals,
    _run_sentinel_helper,
    main,
)


class InstallOpenClawWithSentinelTests(unittest.TestCase):
    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._install_preexec_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_injection_guard_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_popup_guard_background")
    @patch("scripts.install_openclaw_with_sentinel._apply_secure_exec_approvals")
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
        approvals_mock,
        preexec_plugin_mock,
        injection_plugin_mock,
        popup_guard_mock,
        _next_steps_mock,
    ):
        installed_mock.return_value = False
        prompt_mock.return_value = True
        helper_mock.return_value = 0
        approvals_mock.return_value = 0

        rc = main([])

        self.assertEqual(rc, 0)
        install_mock.assert_called_once_with("https://openclaw.ai/install.sh", run_onboard=True)
        helper_mock.assert_called_once_with("")
        approvals_mock.assert_called_once()
        preexec_plugin_mock.assert_called_once()
        injection_plugin_mock.assert_called_once()
        popup_guard_mock.assert_called_once()

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._install_preexec_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_injection_guard_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_popup_guard_background")
    @patch("scripts.install_openclaw_with_sentinel._apply_secure_exec_approvals")
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
        approvals_mock,
        preexec_plugin_mock,
        injection_plugin_mock,
        popup_guard_mock,
        _next_steps_mock,
    ):
        installed_mock.return_value = True
        prompt_mock.return_value = True
        helper_mock.return_value = 0
        approvals_mock.return_value = 0

        rc = main([])

        self.assertEqual(rc, 0)
        install_mock.assert_not_called()
        helper_mock.assert_called_once_with("")
        approvals_mock.assert_called_once()
        preexec_plugin_mock.assert_called_once()
        injection_plugin_mock.assert_called_once()
        popup_guard_mock.assert_called_once()

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._install_preexec_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_injection_guard_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_popup_guard_background")
    @patch("scripts.install_openclaw_with_sentinel._apply_secure_exec_approvals")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._prompt_yes_no")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_user_decline_skips_helper(
        self,
        installed_mock,
        prompt_mock,
        helper_mock,
        approvals_mock,
        popup_guard_mock,
        preexec_plugin_mock,
        injection_plugin_mock,
        _next_steps_mock,
    ):
        installed_mock.return_value = True
        prompt_mock.return_value = False

        rc = main([])

        self.assertEqual(rc, 0)
        helper_mock.assert_not_called()
        approvals_mock.assert_not_called()
        popup_guard_mock.assert_not_called()
        preexec_plugin_mock.assert_not_called()
        injection_plugin_mock.assert_not_called()

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._install_preexec_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_injection_guard_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_popup_guard_background")
    @patch("scripts.install_openclaw_with_sentinel._apply_secure_exec_approvals")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._prompt_yes_no")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_non_interactive_yes_calls_helper(
        self,
        installed_mock,
        prompt_mock,
        helper_mock,
        approvals_mock,
        popup_guard_mock,
        preexec_plugin_mock,
        injection_plugin_mock,
        _next_steps_mock,
    ):
        installed_mock.return_value = True
        helper_mock.return_value = 0
        approvals_mock.return_value = 0

        rc = main(["--non-interactive", "--enable-sentinel", "yes"])

        self.assertEqual(rc, 0)
        prompt_mock.assert_not_called()
        helper_mock.assert_called_once_with("")
        approvals_mock.assert_called_once()
        popup_guard_mock.assert_called_once()
        preexec_plugin_mock.assert_called_once()
        injection_plugin_mock.assert_called_once()

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._install_preexec_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_injection_guard_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_popup_guard_background")
    @patch("scripts.install_openclaw_with_sentinel._apply_secure_exec_approvals")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._prompt_yes_no")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_non_interactive_no_skips_helper(
        self,
        installed_mock,
        prompt_mock,
        helper_mock,
        approvals_mock,
        popup_guard_mock,
        preexec_plugin_mock,
        injection_plugin_mock,
        _next_steps_mock,
    ):
        installed_mock.return_value = True

        rc = main(["--non-interactive", "--enable-sentinel", "no"])

        self.assertEqual(rc, 0)
        prompt_mock.assert_not_called()
        helper_mock.assert_not_called()
        approvals_mock.assert_not_called()
        popup_guard_mock.assert_not_called()
        preexec_plugin_mock.assert_not_called()
        injection_plugin_mock.assert_not_called()

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._install_preexec_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_injection_guard_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_popup_guard_background")
    @patch("scripts.install_openclaw_with_sentinel._apply_secure_exec_approvals")
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
        approvals_mock,
        preexec_plugin_mock,
        injection_plugin_mock,
        popup_guard_mock,
        _next_steps_mock,
    ):
        installed_mock.return_value = False
        install_mock.side_effect = RuntimeError("installer failed")
        prompt_mock.return_value = True
        helper_mock.return_value = 0

        rc = main([])

        self.assertEqual(rc, 1)
        helper_mock.assert_not_called()
        approvals_mock.assert_not_called()
        popup_guard_mock.assert_not_called()
        preexec_plugin_mock.assert_not_called()
        injection_plugin_mock.assert_not_called()

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._install_preexec_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_injection_guard_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_popup_guard_background")
    @patch("scripts.install_openclaw_with_sentinel._apply_secure_exec_approvals")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._prompt_yes_no")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_helper_failure_propagates_exit_code(
        self,
        installed_mock,
        prompt_mock,
        helper_mock,
        approvals_mock,
        popup_guard_mock,
        preexec_plugin_mock,
        injection_plugin_mock,
        _next_steps_mock,
    ):
        installed_mock.return_value = True
        prompt_mock.return_value = True
        helper_mock.return_value = 7
        approvals_mock.return_value = 0

        rc = main([])

        self.assertEqual(rc, 7)
        approvals_mock.assert_not_called()
        popup_guard_mock.assert_not_called()
        preexec_plugin_mock.assert_not_called()
        injection_plugin_mock.assert_not_called()

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._install_preexec_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_injection_guard_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_popup_guard_background")
    @patch("scripts.install_openclaw_with_sentinel._apply_secure_exec_approvals")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_sentinel_network_is_passed(
        self,
        installed_mock,
        helper_mock,
        approvals_mock,
        popup_guard_mock,
        preexec_plugin_mock,
        injection_plugin_mock,
        _next_steps_mock,
    ):
        installed_mock.return_value = True
        helper_mock.return_value = 0
        approvals_mock.return_value = 0

        rc = main(["--non-interactive", "--enable-sentinel", "yes", "--sentinel-network", "custom-net"])

        self.assertEqual(rc, 0)
        helper_mock.assert_called_once_with("custom-net")
        approvals_mock.assert_called_once()
        popup_guard_mock.assert_called_once()
        preexec_plugin_mock.assert_called_once()
        injection_plugin_mock.assert_called_once()

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._install_preexec_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_injection_guard_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_popup_guard_background")
    @patch("scripts.install_openclaw_with_sentinel._apply_secure_exec_approvals")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._prompt_yes_no")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_approvals_failure_propagates_exit_code(
        self,
        installed_mock,
        prompt_mock,
        helper_mock,
        approvals_mock,
        popup_guard_mock,
        preexec_plugin_mock,
        injection_plugin_mock,
        _next_steps_mock,
    ):
        installed_mock.return_value = True
        prompt_mock.return_value = True
        helper_mock.return_value = 0
        approvals_mock.return_value = 9

        rc = main([])

        self.assertEqual(rc, 9)
        popup_guard_mock.assert_not_called()
        preexec_plugin_mock.assert_not_called()
        injection_plugin_mock.assert_not_called()

    @patch("scripts.install_openclaw_with_sentinel._run")
    def test_run_sentinel_helper_sets_network_env(self, run_mock):
        run_mock.return_value = 0

        rc = _run_sentinel_helper("custom-net")

        self.assertEqual(rc, 0)
        args, kwargs = run_mock.call_args
        self.assertEqual(args[0][1], str(SENTINEL_HELPER))
        self.assertEqual(kwargs["env"]["SENTINEL_OPENCLAW_DOCKER_NETWORK"], "custom-net")

    @patch("scripts.install_openclaw_with_sentinel._install_openclaw_via_npm")
    @patch("scripts.install_openclaw_with_sentinel._run_remote_installer")
    def test_install_openclaw_uses_npm_after_script_failures(self, installer_mock, npm_mock):
        installer_mock.side_effect = [RuntimeError("primary down"), RuntimeError("fallback down")]

        _install_openclaw("https://openclaw.ai/install.sh", run_onboard=True)

        self.assertEqual(installer_mock.call_count, 2)
        npm_mock.assert_called_once_with(run_onboard=True)

    def test_default_exec_approvals_baseline(self):
        baseline = build_default_exec_approvals()
        self.assertEqual(baseline["version"], 1)
        self.assertEqual(baseline["defaults"]["ask"], "always")
        self.assertEqual(baseline["defaults"]["askFallback"], "deny")
        self.assertFalse(baseline["defaults"]["autoAllowSkills"])
        self.assertEqual(baseline["agents"]["main"]["ask"], "always")
        self.assertEqual(baseline["agents"]["main"]["allowlist"], [])

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._install_preexec_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_injection_guard_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_popup_guard_background")
    @patch("scripts.install_openclaw_with_sentinel._apply_secure_exec_approvals")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_popup_guard_install_failure_does_not_fail_install(
        self,
        installed_mock,
        helper_mock,
        approvals_mock,
        popup_guard_mock,
        preexec_plugin_mock,
        injection_plugin_mock,
        _next_steps_mock,
    ):
        installed_mock.return_value = True
        helper_mock.return_value = 0
        approvals_mock.return_value = 0
        preexec_plugin_mock.return_value = None
        injection_plugin_mock.return_value = None
        popup_guard_mock.side_effect = RuntimeError("launchctl failure")

        rc = main(["--non-interactive", "--enable-sentinel", "yes"])

        self.assertEqual(rc, 0)

    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_skip_openclaw_install_fails_when_openclaw_missing(self, installed_mock):
        installed_mock.return_value = False
        rc = main(["--skip-openclaw-install"])
        self.assertEqual(rc, 1)

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._install_preexec_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_injection_guard_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_popup_guard_background")
    @patch("scripts.install_openclaw_with_sentinel._apply_secure_exec_approvals")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._prompt_yes_no")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_non_interactive_ask_resolves_to_yes(
        self,
        installed_mock,
        prompt_mock,
        helper_mock,
        approvals_mock,
        popup_guard_mock,
        injection_plugin_mock,
        preexec_plugin_mock,
        _next_steps_mock,
    ):
        installed_mock.return_value = True
        helper_mock.return_value = 0
        approvals_mock.return_value = 0

        rc = main(["--non-interactive", "--enable-sentinel", "ask"])

        self.assertEqual(rc, 0)
        prompt_mock.assert_not_called()
        helper_mock.assert_called_once()
        approvals_mock.assert_called_once()
        popup_guard_mock.assert_called_once()
        injection_plugin_mock.assert_called_once()
        preexec_plugin_mock.assert_called_once()

    @patch("scripts.install_openclaw_with_sentinel._print_next_steps")
    @patch("scripts.install_openclaw_with_sentinel._install_preexec_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_injection_guard_plugin")
    @patch("scripts.install_openclaw_with_sentinel._install_popup_guard_background")
    @patch("scripts.install_openclaw_with_sentinel._apply_secure_exec_approvals")
    @patch("scripts.install_openclaw_with_sentinel._run_sentinel_helper")
    @patch("scripts.install_openclaw_with_sentinel._is_openclaw_installed")
    def test_preexec_plugin_install_failure_returns_nonzero(
        self,
        installed_mock,
        helper_mock,
        approvals_mock,
        popup_guard_mock,
        injection_plugin_mock,
        preexec_plugin_mock,
        _next_steps_mock,
    ):
        installed_mock.return_value = True
        helper_mock.return_value = 0
        approvals_mock.return_value = 0
        injection_plugin_mock.return_value = None
        preexec_plugin_mock.side_effect = RuntimeError("plugin install failed")
        popup_guard_mock.return_value = "launch-agent"

        rc = main(["--non-interactive", "--enable-sentinel", "yes"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
