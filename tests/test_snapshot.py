"""Tests for privacy-preserving state snapshots and drift comparison."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from src import snapshot


def _snapshot_state(**overrides):
    state = {
        "failed_units": [],
        "open_ports": [],
        "cron_jobs": [],
        "systemd_timers": [],
        "docker_containers": [],
        "config_files": {"status": "ok", "files": [], "truncated": False, "skipped": []},
    }
    state.update(overrides)
    return {
        "schema_version": 1,
        "captured_at": "2026-09-12T10:00:00+00:00",
        "host": {"hostname": "vps-1", "os": "Linux", "architecture": "x86_64"},
        "state": state,
        "collection_errors": {},
    }


class TestSystemSnapshots(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(dir=os.getcwd())
        self.env = patch.dict(os.environ, {"VPS_GUARDIAN_SNAPSHOT_DIR": self.tempdir.name})
        self.env.start()
        snapshot._last_snapshot_dir = None

    def tearDown(self):
        snapshot._last_snapshot_dir = None
        self.env.stop()
        self.tempdir.cleanup()

    @patch("src.snapshot._collect_snapshot")
    def test_snapshot_is_stored_and_listed(self, collect):
        collect.return_value = _snapshot_state()
        result = snapshot.create_system_snapshot("before-change")
        listing = snapshot.list_system_snapshots()

        self.assertEqual(result["status"], "ok")
        self.assertTrue(os.path.isfile(result["snapshot_path"]))
        self.assertEqual(listing["snapshot_count"], 1)
        self.assertEqual(listing["snapshots"][0]["label"], "before-change")

    @patch("src.snapshot._config_manifest", return_value={"status": "ok", "files": []})
    @patch("src.snapshot.list_docker_containers", return_value={"status": "ok", "containers": []})
    @patch("src.snapshot.list_systemd_timers", return_value={"status": "ok", "timers": []})
    @patch("src.snapshot.list_cron_jobs")
    @patch("src.snapshot.get_open_ports", return_value={"status": "ok", "ports": []})
    @patch("src.snapshot.get_failed_systemd_units", return_value={"status": "ok", "failed_units": []})
    @patch("src.snapshot.get_system_health", return_value={"status": "ok", "system": {"hostname": "vps-1"}})
    def test_snapshot_never_persists_cron_command_content(self, _health, _failed, _ports, cron, *_rest):
        cron.return_value = {
            "status": "ok",
            "cron_jobs": [{"source": "/etc/crontab", "line_number": 1, "user": "root", "schedule": "* * * * *", "command": "curl https://x/?token=private-value"}],
        }
        result = snapshot.create_system_snapshot("privacy")
        with open(result["snapshot_path"], encoding="utf-8") as snapshot_file:
            saved = snapshot_file.read()

        self.assertNotIn("private-value", saved)
        self.assertIn("command_sha256", saved)

    @patch("src.snapshot._collect_snapshot")
    def test_compare_prioritizes_failed_unit_and_drift(self, collect):
        baseline = _snapshot_state()
        current = _snapshot_state(
            failed_units=[{"unit": "nginx.service", "active": "failed", "sub": "failed"}],
            open_ports=[{"protocol": "tcp", "ip": "0.0.0.0", "port": 8080, "process_name": "app"}],
            config_files={"status": "ok", "files": [{"path": "/etc/nginx/site.conf", "size_bytes": 10, "sha256": "new"}]},
        )
        collect.side_effect = [baseline, current]
        first = snapshot.create_system_snapshot("baseline")
        second = snapshot.create_system_snapshot("after")
        result = snapshot.compare_system_snapshots(first["snapshot_id"], second["snapshot_id"])

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["overall_severity"], "critical")
        self.assertEqual(result["changes"][0]["category"], "failed_units")
        self.assertIn("open_ports", {item["category"] for item in result["changes"]})

    def test_rejects_traversal_as_snapshot_id(self):
        result = snapshot.compare_system_snapshots("../secrets", "../other")
        self.assertEqual(result["status"], "error")
        self.assertIn("Invalid snapshot_id", result["error"])


if __name__ == "__main__":
    unittest.main()
