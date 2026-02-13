import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.openclaw_configure_sentinel_sandbox import (
    _openclaw_config_is_valid,
    build_openclaw_docker_config,
    build_openclaw_sandbox_config,
    main,
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

    @patch("scripts.openclaw_configure_sentinel_sandbox._run")
    def test_openclaw_config_is_valid_detects_unknown_keys(self, run_mock):
        run_mock.return_value.returncode = 1
        run_mock.return_value.stdout = "Config invalid"
        run_mock.return_value.stderr = "Unknown config keys"
        self.assertFalse(_openclaw_config_is_valid())

    @patch("scripts.openclaw_configure_sentinel_sandbox._run")
    def test_openclaw_config_is_valid_true_on_clean_doctor(self, run_mock):
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = "All checks passed"
        run_mock.return_value.stderr = ""
        self.assertTrue(_openclaw_config_is_valid())

    @patch("scripts.openclaw_configure_sentinel_sandbox._recreate_sandboxes")
    @patch("scripts.openclaw_configure_sentinel_sandbox._apply_openclaw_config")
    @patch("scripts.openclaw_configure_sentinel_sandbox._install_seccomp_profile")
    @patch("scripts.openclaw_configure_sentinel_sandbox._ensure_sentinel_proxy_running")
    @patch("scripts.openclaw_configure_sentinel_sandbox._openclaw_config_is_valid")
    @patch("scripts.openclaw_configure_sentinel_sandbox._openclaw_version")
    def test_main_invokes_full_hardening_flow_with_network_override(
        self,
        version_mock,
        config_valid_mock,
        ensure_proxy_mock,
        install_seccomp_mock,
        apply_config_mock,
        recreate_mock,
    ):
        version_mock.return_value = "openclaw 2026.2.12"
        config_valid_mock.return_value = True
        install_seccomp_mock.return_value = Path("/tmp/seccomp.json")

        with patch.dict(os.environ, {"SENTINEL_OPENCLAW_DOCKER_NETWORK": "custom-net"}, clear=False):
            rc = main()

        self.assertEqual(rc, 0)
        ensure_proxy_mock.assert_called_once()
        install_seccomp_mock.assert_called_once()
        apply_config_mock.assert_called_once()
        recreate_mock.assert_called_once()
        cfg = apply_config_mock.call_args.kwargs["sandbox_cfg"]
        self.assertEqual(cfg["docker"]["network"], "custom-net")

    @patch("scripts.openclaw_configure_sentinel_sandbox._openclaw_config_is_valid", return_value=False)
    @patch("scripts.openclaw_configure_sentinel_sandbox._openclaw_version", return_value="openclaw 2026.2.12")
    def test_main_returns_two_when_openclaw_config_invalid(self, _version_mock, _valid_mock):
        rc = main()
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
