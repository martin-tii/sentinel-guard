import os
import queue
import tempfile
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
    _extract_tool_context,
    _extract_exec_hint,
    _format_tool_call_id_hint,
    _get_allow_tools,
    _primary_approvals_available,
    _acquire_singleton_lock,
    _release_singleton_lock,
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
    @patch(
        "scripts.openclaw_popup_guard._terminal_decision",
        side_effect=lambda *_args, **_kwargs: (time.sleep(0.01), "ignore")[1],
    )
    def test_alert_and_decide_first_responder_wins(self, _terminal_mock, _popup_mock):
        decision = _alert_and_decide("process")
        self.assertEqual(decision, "block")

    @patch.dict(os.environ, {"SENTINEL_OPENCLAW_POPUP_TOOLS": "process"}, clear=False)
    @patch("scripts.openclaw_popup_guard._handle_tool_alert")
    @patch("scripts.openclaw_popup_guard._find_openclaw_bin", return_value="openclaw")
    @patch("scripts.openclaw_popup_guard._primary_approvals_available", return_value=False)
    @patch("scripts.openclaw_popup_guard.time.time")
    @patch("scripts.openclaw_popup_guard.subprocess.Popen")
    def test_main_dedupes_tool_call_ids_and_debounces_alerts(
        self,
        popen_mock,
        time_mock,
        _primary_mock,
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
        times = iter([100.0, 100.0, 101.0, 111.0])
        time_mock.side_effect = lambda: next(times, 111.0)

        lock_path = os.path.join(tempfile.gettempdir(), f"popup-guard-test-{os.getpid()}-dedupe.lock")
        with patch("scripts.openclaw_popup_guard._resolve_lock_path", return_value=lock_path):
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

    def test_extract_tool_context_from_command_field(self):
        line = 'embedded run tool start: runId=a tool=exec toolCallId=x command="rm -rf /tmp/demo"'
        context = _extract_tool_context(line, "exec")
        self.assertEqual(context, "Executable hint: rm (full command: rm -rf /tmp/demo)")

    def test_extract_tool_context_from_tool_call_id_when_command_absent(self):
        line = "embedded run tool start: runId=a tool=exec toolCallId=exec_1771217924992_4"
        context = _extract_tool_context(line, "exec")
        self.assertEqual(
            context,
            "No executable details yet. Invocation ID: exec_1771217924992_4 (started UTC: 2026-02-16T04:58:44.992000Z)",
        )

    def test_format_tool_call_id_hint_nonstandard(self):
        hint = _format_tool_call_id_hint("exec_custom_id", tool_name="exec")
        self.assertEqual(hint, "No executable details yet. Invocation ID: exec_custom_id")

    def test_extract_exec_hint_from_json_command(self):
        hint = _extract_exec_hint('{"tool":"exec","command":"open -a Safari"}')
        self.assertEqual(hint, "Executable hint: open (full command: open -a Safari)")

    @patch("scripts.openclaw_popup_guard._run")
    def test_primary_approvals_available_true_when_preexec_enabled(self, run_mock):
        run_mock.return_value = SimpleNamespace(returncode=0, stdout="true\n", stderr="")
        self.assertTrue(_primary_approvals_available("openclaw"))

    @patch("scripts.openclaw_popup_guard._run")
    def test_primary_approvals_available_false_when_preexec_disabled(self, run_mock):
        run_mock.return_value = SimpleNamespace(returncode=0, stdout="false\n", stderr="")
        self.assertFalse(_primary_approvals_available("openclaw"))

    def test_singleton_lock_prevents_second_instance(self):
        with tempfile.TemporaryDirectory() as td:
            lock_path = os.path.join(td, "guard.lock")
            self.assertTrue(_acquire_singleton_lock(lock_path))
            try:
                self.assertFalse(_acquire_singleton_lock(lock_path))
            finally:
                _release_singleton_lock(lock_path)

    @patch.dict(os.environ, {"SENTINEL_OPENCLAW_POPUP_TOOLS": "exec"}, clear=False)
    @patch("scripts.openclaw_popup_guard._handle_tool_alert")
    @patch("scripts.openclaw_popup_guard._find_openclaw_bin", return_value="openclaw")
    @patch("scripts.openclaw_popup_guard._primary_approvals_available", return_value=False)
    @patch("scripts.openclaw_popup_guard.time.time")
    @patch("scripts.openclaw_popup_guard.subprocess.Popen")
    def test_main_passes_context_into_alert_handler(
        self,
        popen_mock,
        time_mock,
        _primary_mock,
        _find_openclaw_bin_mock,
        handle_alert_mock,
    ):
        lines = iter(
            [
                'embedded run tool start: runId=a tool=exec toolCallId=exec_1 command="uname -a"\n',
            ]
        )
        popen_mock.return_value = SimpleNamespace(stdout=lines)
        time_mock.return_value = 100.0

        lock_path = os.path.join(tempfile.gettempdir(), f"popup-guard-test-{os.getpid()}-context.lock")
        with patch("scripts.openclaw_popup_guard._resolve_lock_path", return_value=lock_path):
            rc = main()
        self.assertEqual(rc, 0)
        self.assertEqual(handle_alert_mock.call_count, 1)
        self.assertEqual(handle_alert_mock.call_args.args[0], "exec")
        self.assertEqual(handle_alert_mock.call_args.args[1], "openclaw")
        self.assertEqual(
            handle_alert_mock.call_args.kwargs.get("context"),
            "Executable hint: uname (full command: uname -a)",
        )

    @patch.dict(os.environ, {"SENTINEL_OPENCLAW_POPUP_TOOLS": "exec"}, clear=False)
    @patch("scripts.openclaw_popup_guard._handle_tool_alert")
    @patch("scripts.openclaw_popup_guard._find_openclaw_bin", return_value="openclaw")
    @patch("scripts.openclaw_popup_guard._primary_approvals_available", return_value=True)
    @patch("scripts.openclaw_popup_guard.time.time")
    @patch("scripts.openclaw_popup_guard.subprocess.Popen")
    def test_main_suppresses_fallback_alert_when_primary_available(
        self,
        popen_mock,
        time_mock,
        _primary_mock,
        _find_openclaw_bin_mock,
        handle_alert_mock,
    ):
        lines = iter(
            [
                'embedded run tool start: runId=a tool=exec toolCallId=exec_1 command="uname -a"\n',
            ]
        )
        popen_mock.return_value = SimpleNamespace(stdout=lines)
        time_mock.side_effect = [100.0, 100.0]

        lock_path = os.path.join(tempfile.gettempdir(), f"popup-guard-test-{os.getpid()}-suppress.lock")
        with patch("scripts.openclaw_popup_guard._resolve_lock_path", return_value=lock_path):
            rc = main()
        self.assertEqual(rc, 0)
        handle_alert_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
