import os
import sys
import unittest
from unittest import mock


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.approval import (  # noqa: E402
    SecurityAlert,
    clear_approval_handler,
    request_user_approval,
)
import src.approval as approval


class ApprovalDefaultModeTests(unittest.TestCase):
    def setUp(self):
        self._original_env = dict(os.environ)
        clear_approval_handler()
        approval._always_allow_rules.clear()
        approval._rules_loaded = True

    def tearDown(self):
        clear_approval_handler()
        approval._always_allow_rules.clear()
        approval._rules_loaded = True
        os.environ.clear()
        os.environ.update(self._original_env)

    def _alert(self):
        return SecurityAlert(
            action="command_execution",
            target="rm -rf /tmp/test",
            reason="Blocked by policy",
            recommendation="Reject unless expected.",
        )

    def test_console_handler_allows_once_with_option_1(self):
        with mock.patch.object(approval.builtins, "input", return_value="1"):
            self.assertTrue(approval.console_approval_handler(self._alert()))

    def test_console_handler_blocks_with_option_3(self):
        with mock.patch.object(approval.builtins, "input", return_value="3"):
            self.assertFalse(approval.console_approval_handler(self._alert()))

    def test_console_handler_always_allow_persists_and_auto_approves(self):
        with mock.patch.object(approval, "_save_always_allow_rules"):
            with mock.patch.object(approval.builtins, "input", return_value="2"):
                self.assertTrue(approval.console_approval_handler(self._alert()))
        # Subsequent request should auto-approve with no prompt.
        os.environ["SENTINEL_APPROVAL_MODE"] = "reject"
        with mock.patch.object(approval, "_resolve_default_handler", side_effect=AssertionError("unexpected prompt")):
            self.assertTrue(request_user_approval(self._alert()))

    def test_reject_mode_rejects_when_no_handler(self):
        os.environ["SENTINEL_APPROVAL_MODE"] = "reject"
        self.assertFalse(request_user_approval(self._alert()))

    def test_auto_mode_headless_rejects_without_interactive_handler(self):
        os.environ["SENTINEL_APPROVAL_MODE"] = "auto"
        with mock.patch.object(approval, "_can_try_tkinter_popup", return_value=False):
            with mock.patch.object(sys.stdin, "isatty", return_value=False):
                self.assertFalse(request_user_approval(self._alert()))

    def test_tkinter_mode_uses_default_popup_handler(self):
        os.environ["SENTINEL_APPROVAL_MODE"] = "tkinter"
        with mock.patch.object(approval, "tkinter_approval_handler", return_value=True):
            self.assertTrue(request_user_approval(self._alert()))

    def test_popup_mode_uses_native_popup_handler(self):
        os.environ["SENTINEL_APPROVAL_MODE"] = "popup"
        with mock.patch.object(approval, "_platform_popup_available", return_value=True):
            with mock.patch.object(approval, "native_popup_approval_handler", return_value=True):
                self.assertTrue(request_user_approval(self._alert()))

    def test_console_mode_uses_default_console_handler_when_tty(self):
        os.environ["SENTINEL_APPROVAL_MODE"] = "console"
        with mock.patch.object(approval, "console_approval_handler", return_value=True):
            with mock.patch.object(sys.stdin, "isatty", return_value=True):
                self.assertTrue(request_user_approval(self._alert()))

    def test_native_popup_allow_once_on_macos(self):
        with mock.patch.object(sys, "platform", "darwin"):
            with mock.patch.object(approval.subprocess, "run") as run_mock:
                run_mock.return_value = type("R", (), {"stdout": "button returned:Allow once", "stderr": ""})()
                self.assertTrue(approval.native_popup_approval_handler(self._alert()))

    def test_native_popup_always_allow_on_macos_persists_rule(self):
        with mock.patch.object(sys, "platform", "darwin"):
            with mock.patch.object(approval, "_set_always_allow") as persist_mock:
                with mock.patch.object(approval.subprocess, "run") as run_mock:
                    run_mock.return_value = type(
                        "R", (), {"stdout": "button returned:Always allow this app", "stderr": ""}
                    )()
                    self.assertTrue(approval.native_popup_approval_handler(self._alert()))
                    persist_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
