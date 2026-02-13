import os
import sys
import unittest
from unittest.mock import patch


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.openclaw_popup_guard import (
    DEFAULT_RISKY_TOOLS,
    TOOL_FAIL_RE,
    TOOL_START_RE,
    _block_tool_globally,
    _risky_tools,
)


class OpenClawPopupGuardTests(unittest.TestCase):
    def test_default_risky_tools(self):
        with patch.dict(os.environ, {}, clear=False):
            tools = _risky_tools()
        self.assertEqual(tools, set(DEFAULT_RISKY_TOOLS))

    def test_env_override_risky_tools(self):
        with patch.dict(os.environ, {"SENTINEL_OPENCLAW_POPUP_TOOLS": "exec, process, custom_tool"}, clear=False):
            tools = _risky_tools()
        self.assertEqual(tools, {"exec", "process", "custom_tool"})

    def test_tool_start_regex_extracts_tool_and_call_id(self):
        line = "embedded run tool start: runId=abc tool=process toolCallId=proc_123"
        match = TOOL_START_RE.search(line)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group(1), "process")
        self.assertEqual(match.group(2), "proc_123")

    def test_tool_fail_regex_extracts_tool(self):
        line = "[tools] apply_patch failed: permission denied"
        match = TOOL_FAIL_RE.search(line)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group(1), "apply_patch")

    @patch("scripts.openclaw_popup_guard._run")
    @patch("scripts.openclaw_popup_guard._get_allow_tools")
    def test_block_tool_globally_removes_specific_tool(self, get_tools_mock, run_mock):
        get_tools_mock.return_value = ["read", "write", "process", "image"]
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = ""
        run_mock.return_value.stderr = ""

        _block_tool_globally("process")

        calls = run_mock.call_args_list
        self.assertTrue(calls)
        first_cmd = calls[0].args[0]
        self.assertEqual(first_cmd[:4], ["openclaw", "config", "set", "--json"])
        self.assertEqual(first_cmd[4], "tools.sandbox.tools.allow")
        self.assertIn('"read"', first_cmd[5])
        self.assertIn('"write"', first_cmd[5])
        self.assertIn('"image"', first_cmd[5])
        self.assertNotIn('"process"', first_cmd[5])


if __name__ == "__main__":
    unittest.main()
