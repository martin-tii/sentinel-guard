import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.policy import PolicyEnforcer
from src.opa_client import OPAClientError


class FakeOPAClient:
    def __init__(self, result=None, error=None):
        self.result = result or {"allow": True, "reason": "ok", "tags": ["allow"]}
        self.error = error

    def decide(self, _input_payload):
        if self.error is not None:
            raise self.error
        return self.result


class OPAEnforcementTests(unittest.TestCase):
    def _policy_path(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "sentinel.yaml"
        path.write_text(
            "allowed_paths:\n  - './workspace'\n"
            "opa:\n"
            "  enabled: true\n"
            "  fail_mode: deny\n",
            encoding="utf-8",
        )
        return path

    def test_check_file_access_allows_when_opa_allows(self):
        path = self._policy_path()
        enforcer = PolicyEnforcer(policy_path=str(path))
        enforcer._opa_enabled = True
        enforcer._opa_client = FakeOPAClient(result={"allow": True, "reason": "workspace", "tags": ["allow"]})
        self.assertTrue(enforcer.check_file_access("./workspace/readme.md"))

    def test_check_command_denies_when_opa_denies(self):
        path = self._policy_path()
        enforcer = PolicyEnforcer(policy_path=str(path))
        enforcer._opa_enabled = True
        enforcer._opa_client = FakeOPAClient(result={"allow": False, "reason": "blocked", "tags": ["deny"]})
        with self.assertRaises(PermissionError):
            enforcer.check_command(["ls", "-la"], shell=False)

    def test_check_network_fail_closed_on_opa_error(self):
        path = self._policy_path()
        enforcer = PolicyEnforcer(policy_path=str(path))
        enforcer._opa_enabled = True
        enforcer._opa_fail_mode = "deny"
        enforcer._opa_client = FakeOPAClient(error=OPAClientError("timeout", code="opa_timeout"))
        with self.assertRaises(PermissionError):
            enforcer.check_network("https://api.openai.com/v1/models")

    def test_check_network_fail_open_when_configured(self):
        path = self._policy_path()
        enforcer = PolicyEnforcer(policy_path=str(path))
        enforcer._opa_enabled = True
        enforcer._opa_fail_mode = "allow"
        enforcer._opa_client = FakeOPAClient(error=OPAClientError("timeout", code="opa_timeout"))
        self.assertTrue(enforcer.check_network("https://api.openai.com/v1/models"))


if __name__ == "__main__":
    unittest.main()
