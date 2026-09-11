"""Tests for transactional configuration deployment and rollback."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from src import deploy


def _completed(command, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


class TestConfigDeployment(unittest.TestCase):
    def setUp(self):
        deploy._plans.clear()
        # Keep artifacts inside the repository: the CI/sandbox user may not
        # have permission to write to the operating system temporary directory.
        self.tempdir = tempfile.TemporaryDirectory(dir=os.getcwd())
        self.path = os.path.join(self.tempdir.name, "site.conf")
        with open(self.path, "w", encoding="utf-8") as config:
            config.write("server { listen 80; }\n")

    def tearDown(self):
        deploy._plans.clear()
        self.tempdir.cleanup()

    def _path_policy(self):
        return patch("src.deploy.is_path_permitted", return_value=(True, self.path))

    def _service_policy(self):
        return patch("src.deploy._service_for_path", return_value=("nginx", None))

    def test_caddy_validation_uses_caddyfile_adapter(self):
        command = deploy._validator_command("caddy", "/etc/caddy/Caddyfile")
        self.assertEqual(command[-2:], ["--adapter", "caddyfile"])

    @patch("src.deploy.subprocess.run")
    def test_controlled_plan_validates_without_changing_live_file(self, run):
        run.return_value = _completed(["nginx", "-t"], 0, "syntax is ok")
        with self._path_policy(), self._service_policy(), patch.dict(
            os.environ, {"VPS_GUARDIAN_MODE": "controlled"}
        ):
            result = deploy.plan_config_deployment(self.path, "server { listen 443; }\n")

        self.assertEqual(result["status"], "confirmation_required")
        self.assertIn("confirmation_token", result)
        self.assertIn("-server { listen 80; }", result["diff"])
        with open(self.path, encoding="utf-8") as config:
            self.assertEqual(config.read(), "server { listen 80; }\n")
        self.assertEqual(run.call_count, 1)

    @patch("src.deploy.record_audit_event", return_value="/tmp/audit.jsonl")
    @patch("src.deploy.subprocess.run")
    def test_successful_deployment_writes_reloads_and_checks_health(self, run, audit):
        run.side_effect = [
            _completed(["nginx", "-t"], 0),
            _completed(["systemctl", "reload", "nginx"], 0),
            _completed(["systemctl", "is-active", "nginx"], 0, "active"),
        ]
        with self._path_policy(), self._service_policy(), patch.dict(
            os.environ, {"VPS_GUARDIAN_MODE": "controlled"}
        ):
            plan = deploy.plan_config_deployment(self.path, "server { listen 443; }\n")
            result = deploy.deploy_config_change(
                plan["deployment_id"], plan["confirmation_token"]
            )

        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["rolled_back"])
        with open(self.path, encoding="utf-8") as config:
            self.assertEqual(config.read(), "server { listen 443; }\n")
        self.assertEqual(run.call_count, 3)
        audit.assert_called_once()

    @patch("src.deploy.record_audit_event", return_value="/tmp/audit.jsonl")
    @patch("src.deploy.subprocess.run")
    def test_failed_reload_restores_original_config(self, run, _audit):
        run.side_effect = [
            _completed(["nginx", "-t"], 0),
            _completed(["systemctl", "reload", "nginx"], 1, stderr="reload failed"),
            _completed(["systemctl", "reload", "nginx"], 0),
        ]
        with self._path_policy(), self._service_policy(), patch.dict(
            os.environ, {"VPS_GUARDIAN_MODE": "unrestricted"}
        ):
            plan = deploy.plan_config_deployment(self.path, "server { listen 443; }\n")
            result = deploy.deploy_config_change(plan["deployment_id"])

        self.assertEqual(result["status"], "rolled_back")
        self.assertTrue(result["rolled_back"])
        with open(self.path, encoding="utf-8") as config:
            self.assertEqual(config.read(), "server { listen 80; }\n")

    @patch("src.deploy.subprocess.run")
    def test_live_change_after_plan_is_rejected(self, run):
        run.return_value = _completed(["nginx", "-t"], 0)
        with self._path_policy(), self._service_policy(), patch.dict(
            os.environ, {"VPS_GUARDIAN_MODE": "unrestricted"}
        ):
            plan = deploy.plan_config_deployment(self.path, "server { listen 443; }\n")
            with open(self.path, "w", encoding="utf-8") as config:
                config.write("server { listen 8080; }\n")
            result = deploy.deploy_config_change(plan["deployment_id"])

        self.assertEqual(result["status"], "conflict")
        with open(self.path, encoding="utf-8") as config:
            self.assertEqual(config.read(), "server { listen 8080; }\n")

    @patch("src.deploy.subprocess.run")
    def test_invalid_candidate_never_creates_a_plan(self, run):
        run.return_value = _completed(["nginx", "-t"], 1, stderr="syntax error")
        with self._path_policy(), self._service_policy():
            result = deploy.plan_config_deployment(self.path, "not valid\n")

        self.assertEqual(result["status"], "error")
        self.assertFalse(deploy._plans)


if __name__ == "__main__":
    unittest.main()
