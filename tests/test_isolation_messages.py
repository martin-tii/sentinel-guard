import os
import sys
import unittest
from unittest import mock


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import src.isolation as isolation


class IsolationUserMessageTests(unittest.TestCase):
    def test_friendly_isolation_error_for_seccomp(self):
        msg = isolation._friendly_isolation_error("Seccomp profile does not exist")
        self.assertIn("What happened:", msg)
        self.assertIn("low-level system call", msg)

    def test_main_returns_2_and_prints_friendly_message_on_error(self):
        args = isolation._parse_args(["--", "python", "app.py"])
        with (
            mock.patch.object(isolation, "_parse_args", return_value=args),
            mock.patch.object(isolation, "run_isolated", side_effect=isolation.IsolationError("seccomp denied")),
            mock.patch("builtins.print") as print_mock,
        ):
            rc = isolation.main(["--", "python", "app.py"])

        self.assertEqual(rc, 2)
        rendered = " ".join(" ".join(str(p) for p in call.args) for call in print_mock.call_args_list)
        self.assertIn("What happened:", rendered)


if __name__ == "__main__":
    unittest.main()
