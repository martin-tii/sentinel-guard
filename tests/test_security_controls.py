import os
import sys
import unittest
from pathlib import Path


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import src.core as core


class SecurityControlTests(unittest.TestCase):
    def setUp(self):
        core.deactivate_sentinel()
        self._original_env = dict(os.environ)
        os.environ["SENTINEL_APPROVAL_MODE"] = "reject"

    def tearDown(self):
        core.deactivate_sentinel()
        os.environ.clear()
        os.environ.update(self._original_env)

    def test_policy_file_is_not_bypassed(self):
        policy_path = Path(core.policy.policy_path)
        self.assertFalse(core._should_bypass_file_policy(policy_path))

        with self.assertRaises(PermissionError):
            core.sentinel_open(str(policy_path), "r")

    def test_disable_requires_dual_control(self):
        os.environ["SENTINEL_DISABLE"] = "true"
        os.environ.pop("SENTINEL_ALLOW_DISABLE", None)

        with self.assertRaises(RuntimeError):
            core.activate_sentinel()

    def test_disable_allowed_with_explicit_dual_control(self):
        os.environ["SENTINEL_DISABLE"] = "true"
        os.environ["SENTINEL_ALLOW_DISABLE"] = "true"

        core.activate_sentinel()
        self.assertFalse(core._sentinel_active)


if __name__ == "__main__":
    unittest.main()
