import os
import sys
import unittest
from unittest import mock


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import src.core as core


class RuntimePathBypassTests(unittest.TestCase):
    def test_runtime_read_path_is_bypassed(self):
        runtime_file = getattr(os, "__file__", "")
        self.assertTrue(core._should_bypass_file_policy(runtime_file, mode="r"))

    def test_runtime_write_path_is_not_bypassed(self):
        runtime_file = getattr(os, "__file__", "")
        self.assertFalse(core._should_bypass_file_policy(runtime_file, mode="w"))

    def test_non_runtime_read_path_not_bypassed(self):
        self.assertFalse(core._should_bypass_file_policy("/tmp/sentinel-user-file.txt", mode="r"))

    def test_runtime_fallback_skips_recursive_prompt_on_read(self):
        with (
            mock.patch.object(core, "_assert_runtime_integrity"),
            mock.patch.object(core, "_should_bypass_file_policy", return_value=False),
            mock.patch.object(core.policy, "check_file_access", side_effect=PermissionError("blocked")),
            mock.patch.object(core, "_is_runtime_internal_path", return_value=True),
            mock.patch.object(core, "_original_open", return_value="ok") as open_mock,
            mock.patch.object(core, "_enforce_or_escalate", side_effect=AssertionError("unexpected escalate")),
        ):
            result = core.sentinel_open("/opt/homebrew/anaconda3/lib/python312.zip", mode="r")

        self.assertEqual(result, "ok")
        open_mock.assert_called_once()

    def test_sentinel_run_bypasses_policy_during_approval_prompt(self):
        with (
            mock.patch.object(core, "in_approval_prompt", return_value=True),
            mock.patch.object(core, "_assert_runtime_integrity"),
            mock.patch.object(core, "_original_run", return_value="ok") as run_mock,
            mock.patch.object(core.policy, "check_command", side_effect=AssertionError("unexpected policy check")),
        ):
            result = core.sentinel_run(["osascript", "-e", "display dialog \"x\""])

        self.assertEqual(result, "ok")
        run_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
