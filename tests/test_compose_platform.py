"""Tests for Compose guards and cross-distribution capability adapters."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from src import compose, platform as platform_adapter


class TestComposeTools(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(dir=os.getcwd())
        self.compose_file = os.path.join(self.tempdir.name, "compose.yaml")
        with open(self.compose_file, "w", encoding="utf-8") as compose_yaml:
            compose_yaml.write("services: {}\n")
        self.path_policy = patch("src.compose.is_path_permitted", return_value=(True, self.compose_file))
        self.path_policy.start()

    def tearDown(self):
        self.path_policy.stop()
        self.tempdir.cleanup()

    @patch("src.compose.get_compose_command", return_value=["docker", "compose"])
    @patch("src.compose.subprocess.run")
    def test_inspection_returns_safe_service_topology(self, run, _command):
        run.return_value = subprocess.CompletedProcess(
            ["docker", "compose"], 0,
            '{"services":{"web":{"image":"nginx:1.27","ports":["80:80"],"environment":{"TOKEN":"not-returned"},"healthcheck":{"test":["CMD","true"]}}}}',
            "warning: obsolete field\n",
        )
        result = compose.inspect_compose_project(self.compose_file)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["services"][0]["name"], "web")
        self.assertNotIn("environment", result["services"][0])
        self.assertNotIn("not-returned", str(result))

    @patch("src.compose.record_audit_event", return_value="/tmp/audit.jsonl")
    @patch("src.compose.get_compose_command", return_value=["docker", "compose"])
    @patch("src.compose.subprocess.run")
    def test_compose_action_requires_matching_confirmation(self, run, _command, audit):
        with patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "controlled"}):
            plan = compose.compose_project_action(self.compose_file, "restart", ["web"])
            self.assertEqual(plan["status"], "confirmation_required")
            self.assertFalse(run.called)
            run.return_value = subprocess.CompletedProcess(["docker", "compose"], 0, "restarted", "")
            result = compose.compose_project_action(self.compose_file, "restart", ["web"], plan["confirmation_token"])

        self.assertEqual(result["status"], "ok")
        audit.assert_called_once()

    def test_rejects_unsafe_service_name(self):
        result = compose.compose_project_action(self.compose_file, "restart", ["web; rm -rf /"])
        self.assertEqual(result["status"], "error")


class TestPlatformAdapters(unittest.TestCase):
    @patch("src.platform.get_service_manager", return_value="openrc")
    @patch("src.platform.shutil.which", return_value="rc-service")
    def test_openrc_service_command_is_shell_free(self, _which, _manager):
        manager, command, target = platform_adapter.build_service_command("restart", "nginx.service")
        self.assertEqual(manager, "openrc")
        self.assertEqual(command, ["rc-service", "nginx", "restart"])
        self.assertEqual(target, "nginx")

    @patch("src.platform.get_package_manager", return_value="dnf")
    @patch("src.platform.shutil.which", return_value="dnf")
    @patch("src.platform.subprocess.run")
    def test_dnf_check_update_accepts_exit_100(self, run, _which, _manager):
        run.return_value = subprocess.CompletedProcess(["dnf"], 100, "nginx.x86_64 1.27\n", "")
        result = platform_adapter.get_package_updates()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["update_count"], 1)

    @patch("src.platform.get_firewall_backend", return_value="nftables")
    @patch("src.platform.shutil.which", return_value="nft")
    @patch("src.platform.subprocess.run")
    def test_nftables_status_is_normalized(self, run, _which, _backend):
        run.return_value = subprocess.CompletedProcess(["nft"], 0, "table inet filter {}\n", "")
        result = platform_adapter.get_firewall_status()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["backend"], "nftables")

    @patch("src.platform.get_compose_command", return_value=None)
    @patch("src.platform.get_service_manager", return_value="openrc")
    @patch("src.platform.get_firewall_backend", return_value="firewalld")
    @patch("src.platform.get_package_manager", return_value="pacman")
    def test_capabilities_reports_detected_backends(self, manager, firewall, service, compose_command):
        result = platform_adapter.get_platform_capabilities()
        self.assertEqual(result["package_manager"], "pacman")
        self.assertEqual(result["firewall_backend"], "firewalld")
        self.assertEqual(result["service_manager"], "openrc")
        self.assertFalse(result["docker_compose_available"])


if __name__ == "__main__":
    unittest.main()
