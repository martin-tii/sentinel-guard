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

    def tearDown(self):
        clear_approval_handler()
        os.environ.clear()
        os.environ.update(self._original_env)

    def _alert(self):
        return SecurityAlert(
            action="command_execution",
            target="rm -rf /tmp/test",
            reason="Blocked by policy",
            recommendation="Reject unless expected.",
        )

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

    def test_console_mode_uses_default_console_handler_when_tty(self):
        os.environ["SENTINEL_APPROVAL_MODE"] = "console"
        with mock.patch.object(approval, "console_approval_handler", return_value=True):
            with mock.patch.object(sys.stdin, "isatty", return_value=True):
                self.assertTrue(request_user_approval(self._alert()))


if __name__ == "__main__":
    unittest.main()
