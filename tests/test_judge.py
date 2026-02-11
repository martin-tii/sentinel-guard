import os
import sys
import unittest


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.judge import AIJudge


class StubJudge(AIJudge):
    def __init__(self, config=None):
        super().__init__(config=config)
        self.responses = []
        self.calls = 0

    def call_ollama(self, prompt):
        self.calls += 1
        if self.responses:
            return self.responses.pop(0)
        return {"ok": True, "response": "SAFE: default allow"}


class AIJudgeRuntimeTests(unittest.TestCase):
    def test_low_risk_skips_model_adjudication(self):
        judge = StubJudge({"runtime_judge_threshold": 0.4, "risk_threshold": 0.7, "fail_open": False})
        verdict = judge.evaluate_action("subprocess.run", "echo hello")
        self.assertTrue(verdict["safe"])
        self.assertFalse(verdict["needs_human"])
        self.assertEqual(judge.calls, 0)

    def test_medium_risk_uses_model_and_blocks_on_unsafe(self):
        judge = StubJudge({"runtime_judge_threshold": 0.4, "risk_threshold": 0.7, "fail_open": False})
        judge.responses = [{"ok": True, "response": "UNSAFE: shell redirection is risky"}]

        verdict = judge.evaluate_action("subprocess.run", "echo x | cat")
        self.assertFalse(verdict["safe"])
        self.assertTrue(verdict["needs_human"])
        self.assertEqual(judge.calls, 1)

    def test_high_risk_fails_closed_when_judge_unavailable(self):
        judge = StubJudge({"runtime_judge_threshold": 0.4, "risk_threshold": 0.7, "fail_open": False})
        judge.responses = [{"ok": False, "reason": "AI Judge unavailable"}]

        verdict = judge.evaluate_action("subprocess.run", "rm -rf /tmp/test")
        self.assertFalse(verdict["safe"])
        self.assertTrue(verdict["needs_human"])
        self.assertIn("unavailable", verdict["reason"].lower())

    def test_high_risk_unavailable_respects_fail_open(self):
        judge = StubJudge({"runtime_judge_threshold": 0.4, "risk_threshold": 0.7, "fail_open": True})
        judge.responses = [{"ok": False, "reason": "AI Judge unavailable"}]

        verdict = judge.evaluate_action("subprocess.run", "rm -rf /tmp/test")
        self.assertTrue(verdict["safe"])
        self.assertFalse(verdict["needs_human"])

    def test_exec_spawn_family_gets_command_heuristics(self):
        judge = StubJudge({"runtime_judge_threshold": 0.4, "risk_threshold": 0.7, "fail_open": False})
        judge.responses = [{"ok": True, "response": "SAFE: understood"}]

        verdict = judge.evaluate_action("os.spawnvp", "wget http://example.com/file.sh")
        self.assertTrue(verdict["safe"])
        self.assertEqual(judge.calls, 1)


if __name__ == "__main__":
    unittest.main()
