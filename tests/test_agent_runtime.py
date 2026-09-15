"""Tests for expiring, secret-safe agent runtime state."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from src import agent_runtime


class TestAgentRuntime(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.environment = mock.patch.dict(os.environ, {"VPS_GUARDIAN_STATE_DIR": self.temporary.name})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()

    def test_session_records_redacted_finding_and_handoff(self):
        started = agent_runtime.start_agent_session("Repair site", "example.com")
        session_id = started["session"]["session_id"]
        recorded = agent_runtime.record_session_finding(session_id, "token=private-value caused a failure")
        self.assertIn("***REDACTED***", recorded["finding"]["summary"])
        handed_off = agent_runtime.handoff_agent_session(session_id, "next-agent", "Nginx is healthy")
        self.assertEqual(handed_off["session"]["handoff"]["next_agent"], "next-agent")

    def test_workload_lock_rejects_second_active_session(self):
        first = agent_runtime.start_agent_session("First worker")["session"]["session_id"]
        second = agent_runtime.start_agent_session("Second worker")["session"]["session_id"]
        self.assertEqual(agent_runtime.lock_workload(first, "api.example.com")["status"], "ok")
        self.assertEqual(agent_runtime.lock_workload(second, "api.example.com")["status"], "locked")

    def test_event_watch_is_expiring_cursor(self):
        watch = agent_runtime.open_event_watch("nginx")
        result = agent_runtime.get_event_watch(watch["watch"]["watch_id"])
        self.assertEqual(result["status"], "ok")
        self.assertIn("events", result)


if __name__ == "__main__":
    unittest.main()
