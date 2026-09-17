"""Tests for bounded maintenance, alert and backup-inspection tools."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from src import operations
from src.recover import get_backup_status, verify_backup


class TestOperations(unittest.TestCase):
    def setUp(self):
        self.records = {}
        self.load = patch("src.operations._load", side_effect=lambda name: self.records.get(name, {}))
        self.save = patch("src.operations._save", side_effect=lambda name, value: self.records.__setitem__(name, value))
        self.load.start()
        self.save.start()

    def tearDown(self):
        self.load.stop()
        self.save.stop()

    def test_maintenance_window_expires_without_granting_permissions(self):
        created = operations.create_maintenance_window(
            "Deploy API configuration", "api.example.test", allowed_actions=["deploy_config_change"]
        )
        self.assertEqual(created["status"], "ok")
        self.assertIn("still follow the active safety mode", created["note"])
        listed = operations.list_maintenance_windows()
        self.assertEqual(listed["window_count"], 1)
        closed = operations.close_maintenance_window(created["window"]["window_id"], "password=never-store-this")
        self.assertEqual(closed["status"], "ok")
        self.assertNotIn("never-store-this", closed["window"]["outcome"])

    @patch("src.operations.psutil.disk_usage")
    @patch("src.operations.psutil.swap_memory")
    @patch("src.operations.psutil.virtual_memory")
    @patch("src.operations.psutil.cpu_percent")
    def test_resource_alerts_are_on_demand_and_thresholded(self, cpu, memory, swap, disk):
        cpu.return_value = 92.0
        memory.return_value.percent = 40.0
        swap.return_value.percent = 0.0
        disk.return_value.percent = 50.0
        created = operations.watch_resource_threshold("cpu", 90, 30)
        self.assertEqual(created["status"], "ok")
        result = operations.get_resource_alerts()
        self.assertEqual(result["alert_count"], 1)
        self.assertEqual(result["alerts"][0]["metric"], "cpu")
        self.assertEqual(result["alerts"][0]["current_percent"], 92.0)
        self.assertIn("no background polling", result["note"])
        cpu.assert_called_once_with(interval=0.1)


class TestBackupInspection(unittest.TestCase):
    def test_backup_status_and_verification_are_isolated(self):
        entry = MagicMock()
        entry.name = "backup_site_20260917.tar.gz"
        entry.path = "/var/backups/vps-guardian/backup_site_20260917.tar.gz"
        entry.is_symlink.return_value = False
        entry.is_file.return_value = True
        entry.stat.return_value.st_size = 128
        entry.stat.return_value.st_mtime = 1_700_000_000
        directory = MagicMock()
        directory.__enter__.return_value = [entry]
        archive = MagicMock()
        archive.__enter__.return_value.next.side_effect = [MagicMock(), None]
        with patch("src.recover._backup_destination", return_value="/var/backups/vps-guardian"), \
             patch("src.recover.os.scandir", return_value=directory), \
             patch("src.recover._safe_backup_path", side_effect=lambda path: entry.path if path else None), \
             patch("src.recover.os.path.getsize", return_value=128), \
             patch("src.recover.tarfile.open", return_value=archive):
            status = get_backup_status()
            verification = verify_backup(entry.path)
            forbidden = verify_backup("")
        self.assertEqual(status["archive_count"], 1)
        self.assertEqual(verification["status"], "ok")
        self.assertTrue(verification["verified"])
        self.assertEqual(forbidden["status"], "forbidden")


if __name__ == "__main__":
    unittest.main()
