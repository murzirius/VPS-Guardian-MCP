"""Tests for state-change confirmation gates and redacted audit logging."""

from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from src.safety import (
    get_safety_status,
    record_audit_event,
    request_authorization,
)
from src.files import write_file_content
from src.recover import run_recovery_action


class TestSafetyGate(unittest.TestCase):
    def test_read_only_mode_blocks_state_changes(self):
        with patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "read-only"}):
            result = request_authorization(
                "write_file_content",
                {"file_path": "/etc/nginx/nginx.conf", "content": "secret"},
                "Replace a file.",
            )
        self.assertEqual(result["status"], "forbidden")
        self.assertFalse(result["success"])
        self.assertEqual(result["safety_mode"], "read-only")

    def test_controlled_mode_requires_matching_single_use_token(self):
        params = {"container_name": "web", "action": "restart", "timeout": 10}
        with patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "controlled"}):
            plan = request_authorization("docker_container_action", params, "Restart container.")
            self.assertEqual(plan["status"], "confirmation_required")

            allowed = request_authorization(
                "docker_container_action",
                params,
                "Restart container.",
                plan["confirmation_token"],
            )
            self.assertIsNone(allowed)

            replay = request_authorization(
                "docker_container_action",
                params,
                "Restart container.",
                plan["confirmation_token"],
            )
            self.assertEqual(replay["status"], "forbidden")

    def test_token_is_bound_to_exact_parameters(self):
        with patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "controlled"}):
            plan = request_authorization(
                "clean_docker_garbage", {"prune_type": "images"}, "Delete images."
            )
            result = request_authorization(
                "clean_docker_garbage",
                {"prune_type": "volumes"},
                "Delete volumes.",
                plan["confirmation_token"],
            )
        self.assertEqual(result["status"], "forbidden")
        self.assertIn("does not match", result["error"])

    def test_expired_token_is_rejected(self):
        params = {"action_name": "restart_service", "target": "nginx"}
        with patch.dict(
            os.environ,
            {
                "VPS_GUARDIAN_MODE": "controlled",
                "VPS_GUARDIAN_CONFIRM_TTL": "30",
            },
        ):
            with patch("src.safety.time.time", return_value=1000):
                plan = request_authorization(
                    "execute_recovery", params, "Restart a service."
                )
            with patch("src.safety.time.time", return_value=1031):
                result = request_authorization(
                    "execute_recovery",
                    params,
                    "Restart a service.",
                    plan["confirmation_token"],
                )
        self.assertEqual(result["status"], "forbidden")
        self.assertIn("expired", result["error"])

    def test_audit_log_redacts_content_and_tokens(self):
        captured = {}

        def capture_event(_path, event):
            captured.update(event)
            return True

        with patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "controlled"}):
            with patch("src.safety._append_json_line", side_effect=capture_event):
                record_audit_event(
                    "write_file_content",
                    {
                        "file_path": "/etc/nginx/test.conf",
                        "content": "PASSWORD=top-secret",
                        "confirmation_token": "must-not-leak",
                    },
                    {"status": "ok", "success": True},
                )

        serialized = json.dumps(captured)
        self.assertNotIn("top-secret", serialized)
        self.assertNotIn("must-not-leak", serialized)
        self.assertIn("redacted", serialized.lower())

    def test_safety_status_reports_mode(self):
        with patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "controlled"}):
            status = get_safety_status()
        self.assertEqual(status["safety_mode"], "controlled")
        self.assertTrue(status["confirmation_required"])

    def test_file_write_returns_plan_without_touching_file(self):
        target = os.path.join(os.getcwd(), "safety-plan-test.conf")
        self.assertFalse(os.path.exists(target))
        with patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "controlled"}):
            result = write_file_content(target, "server { listen 80; }")
        self.assertEqual(result["status"], "confirmation_required")
        self.assertFalse(os.path.exists(target))

    def test_recovery_handler_runs_only_after_confirmation(self):
        with patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "controlled"}):
            plan = run_recovery_action("restart_service", "nginx")
            with patch(
                "src.recover._action_restart_service",
                return_value={"status": "ok", "success": True},
            ) as handler:
                with patch(
                    "src.recover.record_audit_event",
                    return_value="/tmp/audit.jsonl",
                ):
                    result = run_recovery_action(
                        "restart_service",
                        "nginx",
                        confirmation_token=plan["confirmation_token"],
                    )
        self.assertEqual(result["status"], "ok")
        handler.assert_called_once_with("nginx")


if __name__ == "__main__":
    unittest.main()
