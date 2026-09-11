"""Tests for the unified incident report."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from src.incident import generate_incident_report


class TestIncidentReport(unittest.TestCase):
    @patch("src.incident.get_database_health")
    @patch("src.incident.check_kernel_errors")
    @patch("src.incident.check_oom_events")
    @patch("src.incident.list_docker_containers")
    @patch("src.incident.get_failed_systemd_units")
    @patch("src.incident.get_system_health")
    def test_critical_findings_are_prioritized(
        self,
        health,
        failed_units,
        docker,
        oom,
        kernel,
        databases,
    ):
        health.return_value = {
            "status": "ok",
            "cpu": {"usage_percent_total": 30},
            "memory": {"ram": {"used_percent": 50}},
            "disk": {"used_percent": 97},
        }
        failed_units.return_value = {
            "status": "ok",
            "failed_units": [{"unit": "api.service"}],
        }
        docker.return_value = {
            "status": "ok",
            "containers": [{"name": "api", "health": "healthy", "oom_killed": False}],
        }
        oom.return_value = {"status": "ok", "total_oom_events": 0}
        kernel.return_value = {"status": "ok", "critical_hardware_errors_count": 0}
        databases.return_value = {"status": "ok", "databases": []}

        report = generate_incident_report(
            include_updates=False,
            include_security=False,
            include_network=False,
        )

        self.assertEqual(report["overall_severity"], "critical")
        self.assertEqual(report["summary"]["critical_findings"], 2)
        self.assertEqual(report["findings"][0]["severity"], "critical")
        self.assertIn("root_filesystem_saturation", {
            finding["code"] for finding in report["findings"]
        })

    @patch("src.incident.get_database_health", side_effect=RuntimeError("probe failed"))
    @patch("src.incident.check_kernel_errors", return_value={"status": "ok"})
    @patch("src.incident.check_oom_events", return_value={"status": "ok"})
    @patch("src.incident.list_docker_containers", return_value={"status": "unavailable"})
    @patch("src.incident.get_failed_systemd_units", return_value={"status": "ok"})
    @patch("src.incident.get_system_health", return_value={"status": "ok"})
    def test_collector_failures_do_not_abort_report(self, *_mocks):
        report = generate_incident_report(
            include_updates=False,
            include_security=False,
            include_network=False,
        )
        self.assertEqual(report["status"], "ok")
        self.assertGreaterEqual(report["summary"]["sections_unavailable"], 2)
        self.assertIn("incomplete_telemetry", {
            finding["code"] for finding in report["findings"]
        })


if __name__ == "__main__":
    unittest.main()
