"""Unit tests for src.proc_deep module."""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from src.proc_deep import (
    check_system_limits,
    detect_zombie_processes,
    get_process_details,
)


class TestProcDeep(unittest.TestCase):
    """Test suite for process inspection, zombie detection, and system limits."""

    def test_get_process_details_current_process(self):
        """Verify detailed diagnostics for the running test runner process."""
        current_pid = os.getpid()
        result = get_process_details(current_pid)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["pid"], current_pid)
        self.assertIn("name", result)
        self.assertIn("cpu", result)
        self.assertIn("memory", result)
        self.assertIn("timing", result)
        self.assertIn("hierarchy", result)
        self.assertIsInstance(result["cpu"]["cpu_percent"], (int, float))
        self.assertIsInstance(result["memory"]["details"]["rss_bytes"], int)

    def test_get_process_details_invalid_pid(self):
        """Verify rejection of non-integer and non-positive PIDs."""
        res_str = get_process_details("not_a_pid")  # type: ignore
        self.assertEqual(res_str["status"], "error")
        self.assertIn("Invalid PID", res_str["error"])

        res_neg = get_process_details(-10)
        self.assertEqual(res_neg["status"], "error")

        res_zero = get_process_details(0)
        self.assertEqual(res_zero["status"], "error")

    def test_get_process_details_nonexistent_pid(self):
        """Verify graceful handling when a PID does not exist."""
        result = get_process_details(99999999)
        self.assertEqual(result["status"], "not_found")
        self.assertIn("does not exist", result["error"])

    def test_detect_zombie_processes(self):
        """Verify zombie detector returns clean status structure."""
        result = detect_zombie_processes()
        self.assertEqual(result["status"], "ok")
        self.assertIn("zombie_count", result)
        self.assertIsInstance(result["zombies"], list)

    def test_check_system_limits_structure(self):
        """Verify check_system_limits returns structured dictionary with all sections."""
        limits = check_system_limits()
        self.assertEqual(limits["status"], "ok")
        self.assertIn("file_descriptors", limits)
        self.assertIn("processes_and_threads", limits)
        self.assertIn("virtual_memory", limits)
        self.assertIn("network_backlog", limits)
        self.assertIn("warnings", limits)
        self.assertIsInstance(limits["warnings"], list)

    def test_check_system_limits_high_usage_warning(self):
        """Verify warning triggers when mocked file descriptor usage exceeds 80%."""
        mock_data = {
            "/proc/sys/fs/file-nr": "9000 500 10000",
            "/proc/sys/fs/file-max": "10000",
            "/proc/sys/kernel/pid_max": "32768",
            "/proc/sys/vm/swappiness": "60",
        }

        def fake_read(path):
            return mock_data.get(path)

        with patch("src.proc_deep._read_proc_sys", side_effect=fake_read):
            report = check_system_limits()
            self.assertEqual(report["status"], "ok")
            self.assertEqual(report["file_descriptors"]["usage_percent"], 85.0)
            self.assertTrue(any("file descriptor usage is high" in w for w in report["warnings"]))
            self.assertFalse(report["healthy"])


if __name__ == "__main__":
    unittest.main()
