import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import src.config_manager as config_manager


class ConfigManagerTests(unittest.TestCase):
    def test_backup_and_restore_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repo = root / "repo"
            home = root / "home"
            repo.mkdir()
            home.mkdir()

            (repo / "seccomp").mkdir(parents=True)
            (repo / "proxy").mkdir(parents=True)
            (home / ".sentinel-guard").mkdir(parents=True)

            original = "allowed_commands:\n  - echo\n"
            (repo / "sentinel.yaml").write_text(original, encoding="utf-8")
            (repo / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            (repo / "proxy" / "allowed-domains.txt").write_text("example.com\n", encoding="utf-8")
            (repo / "seccomp" / "sentinel-seccomp.json").write_text("{}\n", encoding="utf-8")
            (repo / "seccomp" / "sentinel-seccomp-datasci.json").write_text("{}\n", encoding="utf-8")
            (home / ".sentinel-guard" / "approval-rules.json").write_text('{"always_allow": []}\n', encoding="utf-8")

            with (
                mock.patch.object(config_manager, "_repo_root", return_value=repo),
                mock.patch.object(config_manager, "_home_dir", return_value=home),
            ):
                archive = config_manager.backup_config()
                self.assertTrue(archive.exists())

                (repo / "sentinel.yaml").write_text("allowed_commands:\n  - ls\n", encoding="utf-8")
                restored = config_manager.restore_config(str(archive), force=True)
                self.assertTrue(restored)

                data = (repo / "sentinel.yaml").read_text(encoding="utf-8")
                self.assertEqual(data, original)

                backups = config_manager.list_backups()
                self.assertEqual(len(backups), 1)

    def test_restore_requires_force_when_file_exists(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            repo = root / "repo"
            home = root / "home"
            repo.mkdir()
            home.mkdir()
            (repo / "seccomp").mkdir(parents=True)
            (repo / "proxy").mkdir(parents=True)

            (repo / "sentinel.yaml").write_text("allowed_commands:\n  - echo\n", encoding="utf-8")

            with (
                mock.patch.object(config_manager, "_repo_root", return_value=repo),
                mock.patch.object(config_manager, "_home_dir", return_value=home),
            ):
                archive = config_manager.backup_config()
                with self.assertRaises(FileExistsError):
                    config_manager.restore_config(str(archive), force=False)


if __name__ == "__main__":
    unittest.main()
