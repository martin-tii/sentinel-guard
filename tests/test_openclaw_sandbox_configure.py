import os
import sys
import unittest


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.openclaw_configure_sentinel_sandbox import (
    build_openclaw_docker_config,
    build_openclaw_sandbox_config,
)


class OpenClawSandboxConfigureTests(unittest.TestCase):
    def test_build_openclaw_sandbox_config_contains_expected_defaults(self):
        cfg = build_openclaw_sandbox_config(
            network_name="sentinel-sandbox_sentinel-internal",
            seccomp_profile_path="/Users/me/.openclaw/seccomp/sentinel-seccomp-datasci.json",
        )

        self.assertEqual(cfg["mode"], "non-main")
        self.assertEqual(cfg["scope"], "agent")
        self.assertEqual(cfg["workspaceAccess"], "rw")
        self.assertIn("docker", cfg)

    def test_build_openclaw_docker_config_contains_expected_hardening(self):
        docker_cfg = build_openclaw_docker_config(
            network_name="sentinel-sandbox_sentinel-internal",
            seccomp_profile_path="/Users/me/.openclaw/seccomp/sentinel-seccomp-datasci.json",
        )

        self.assertTrue(docker_cfg["readOnlyRoot"])
        self.assertEqual(docker_cfg["capDrop"], ["ALL"])
        self.assertEqual(docker_cfg["tmpfs"], ["/tmp", "/var/tmp", "/run"])
        self.assertEqual(docker_cfg["pidsLimit"], 256)
        self.assertEqual(docker_cfg["memory"], "512m")
        self.assertIsInstance(docker_cfg["cpus"], (int, float))
        self.assertEqual(docker_cfg["network"], "sentinel-sandbox_sentinel-internal")
        self.assertEqual(
            docker_cfg["env"]["HTTP_PROXY"],
            "http://sentinel-proxy:3128",
        )
        self.assertEqual(
            docker_cfg["env"]["HTTPS_PROXY"],
            "http://sentinel-proxy:3128",
        )
        self.assertEqual(
            docker_cfg["env"]["NO_PROXY"],
            "localhost,127.0.0.1,sentinel-proxy",
        )
        self.assertEqual(
            docker_cfg["seccompProfile"],
            "/Users/me/.openclaw/seccomp/sentinel-seccomp-datasci.json",
        )


if __name__ == "__main__":
    unittest.main()

