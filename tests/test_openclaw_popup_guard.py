import os
import queue
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.openclaw_popup_guard import (
    DEFAULT_RISKY_TOOLS,
    TOOL_FAIL_RE,
    TOOL_START_RE,
    _alert_and_decide,
    _block_tool_globally,
    _get_allow_tools,
    _risky_tools,
    main,
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
    def test_get_allow_tools_uses_resolved_openclaw_binary(self, run_mock):
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = '["read","write"]'
        run_mock.return_value.stderr = ""
        tools = _get_allow_tools("/custom/openclaw")
        self.assertEqual(tools, ["read", "write"])
        run_mock.assert_called_once()
        self.assertEqual(run_mock.call_args.args[0][0], "/custom/openclaw")

    @patch("scripts.openclaw_popup_guard._run")
    @patch("scripts.openclaw_popup_guard._get_allow_tools")
    def test_block_tool_globally_removes_specific_tool(self, get_tools_mock, run_mock):
        get_tools_mock.return_value = ["read", "write", "process", "image"]
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = ""
        run_mock.return_value.stderr = ""

        blocked = _block_tool_globally("process", "/custom/openclaw")
        self.assertTrue(blocked)

        calls = run_mock.call_args_list
        self.assertTrue(calls)
        first_cmd = calls[0].args[0]
        self.assertEqual(first_cmd[:4], ["/custom/openclaw", "config", "set", "--json"])
        self.assertEqual(first_cmd[4], "tools.sandbox.tools.allow")
        self.assertIn('"read"', first_cmd[5])
        self.assertIn('"write"', first_cmd[5])
        self.assertIn('"image"', first_cmd[5])
        self.assertNotIn('"process"', first_cmd[5])

    @patch("scripts.openclaw_popup_guard._run")
    @patch("scripts.openclaw_popup_guard._get_allow_tools")
    def test_block_tool_globally_does_not_mutate_on_empty_allowlist(self, get_tools_mock, run_mock):
        get_tools_mock.return_value = []
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = ""
        run_mock.return_value.stderr = ""

        blocked = _block_tool_globally("exec", "openclaw")
        self.assertTrue(blocked)
        run_mock.assert_not_called()

    @patch("scripts.openclaw_popup_guard._run")
    @patch("scripts.openclaw_popup_guard._get_allow_tools")
    def test_block_tool_globally_fails_closed_when_allowlist_unavailable(self, get_tools_mock, run_mock):
        get_tools_mock.return_value = None

        blocked = _block_tool_globally("exec", "openclaw")
        self.assertFalse(blocked)
        run_mock.assert_not_called()

    @patch("scripts.openclaw_popup_guard._popup_decision", return_value=None)
    @patch("scripts.openclaw_popup_guard._terminal_decision", return_value=None)
    @patch("scripts.openclaw_popup_guard.queue.Queue.get", side_effect=queue.Empty)
    def test_alert_and_decide_timeout_defaults_to_block(self, _queue_get, _terminal_mock, _popup_mock):
        decision = _alert_and_decide("exec")
        self.assertEqual(decision, "block")

    @patch("scripts.openclaw_popup_guard._popup_decision", return_value="block")
    @patch("scripts.openclaw_popup_guard._terminal_decision", side_effect=lambda _: (time.sleep(0.01), "ignore")[1])
    def test_alert_and_decide_first_responder_wins(self, _terminal_mock, _popup_mock):
        decision = _alert_and_decide("process")
        self.assertEqual(decision, "block")

    @patch.dict(os.environ, {"SENTINEL_OPENCLAW_POPUP_TOOLS": "process"}, clear=False)
    @patch("scripts.openclaw_popup_guard._handle_tool_alert")
    @patch("scripts.openclaw_popup_guard._find_openclaw_bin", return_value="openclaw")
    @patch("scripts.openclaw_popup_guard.time.time")
    @patch("scripts.openclaw_popup_guard.subprocess.Popen")
    def test_main_dedupes_tool_call_ids_and_debounces_alerts(
        self,
        popen_mock,
        time_mock,
        _find_openclaw_bin_mock,
        handle_alert_mock,
    ):
        # Same toolCallId repeated should alert once; near-immediate second event is debounced.
        lines = iter(
            [
                "embedded run tool start: runId=a tool=process toolCallId=proc_1\n",
                "embedded run tool start: runId=a tool=process toolCallId=proc_1\n",
                "embedded run tool start: runId=a tool=process toolCallId=proc_2\n",
                "embedded run tool start: runId=a tool=process toolCallId=proc_3\n",
            ]
        )
        popen_mock.return_value = SimpleNamespace(stdout=lines)
        time_mock.side_effect = [100.0, 101.0, 111.0]

        rc = main()
        self.assertEqual(rc, 0)
        self.assertEqual(handle_alert_mock.call_count, 2)
        self.assertEqual(handle_alert_mock.call_args_list[0].args[0], "process")
        self.assertEqual(handle_alert_mock.call_args_list[1].args[0], "process")
        self.assertEqual(handle_alert_mock.call_args_list[0].args[1], "openclaw")

    def test_tool_start_regex_handles_hyphenated_tool_names(self):
        line = "embedded run tool start: runId=abc tool=custom-tool toolCallId=proc_123"
        match = TOOL_START_RE.search(line)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group(1), "custom-tool")
        self.assertEqual(match.group(2), "proc_123")


if __name__ == "__main__":
    unittest.main()
