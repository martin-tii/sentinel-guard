import os
import sys
import unittest


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.policy import PolicyEnforcer


class NetworkPolicyTests(unittest.TestCase):
    def _policy(self):
        enforcer = PolicyEnforcer()
        enforcer.policy = {
            "host_match_mode": "exact",
            "allowed_hosts": [],
            "network_failsafe": {
                "socket_connect": True,
                "allow_private_network": True,
                "blocked_hosts": [],
                "blocked_ips": [],
                "allowed_ips": [],
            },
        }
        return enforcer

    def test_exact_mode_blocks_subdomain(self):
        enforcer = self._policy()
        enforcer.policy["allowed_hosts"] = ["openai.com"]

        with self.assertRaises(PermissionError):
            enforcer.check_network("https://api.openai.com/v1/models")

    def test_subdomain_mode_allows_subdomain(self):
        enforcer = self._policy()
        enforcer.policy["host_match_mode"] = "subdomain"
        enforcer.policy["allowed_hosts"] = ["openai.com"]

        self.assertTrue(enforcer.check_network("https://api.openai.com/v1/models"))

    def test_scheme_and_port_constraints_enforced(self):
        enforcer = self._policy()
        enforcer.policy["allowed_hosts"] = [
            {"host": "api.openai.com", "match": "exact", "schemes": ["https"], "ports": [443]}
        ]

        self.assertTrue(enforcer.check_network("https://api.openai.com/v1/models"))
        with self.assertRaises(PermissionError):
            enforcer.check_network("http://api.openai.com/v1/models")
        with self.assertRaises(PermissionError):
            enforcer.check_network("https://api.openai.com:444/v1/models")

    def test_socket_port_constraints_enforced(self):
        enforcer = self._policy()
        enforcer.policy["allowed_hosts"] = [
            {"host": "api.openai.com", "match": "exact", "ports": [443]}
        ]

        self.assertTrue(enforcer.check_socket_connect("api.openai.com", 443))
        with self.assertRaises(PermissionError):
            enforcer.check_socket_connect("api.openai.com", 80)


if __name__ == "__main__":
    unittest.main()
