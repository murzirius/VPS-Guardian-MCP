"""Tests for expiring, secret-safe agent runtime state."""

from __future__ import annotations

import os
import tempfile
import unittest
import datetime as dt
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

    def test_task_dependencies_leases_and_redacted_result(self):
        first_session = agent_runtime.start_agent_session("Queue worker one")["session"]["session_id"]
        second_session = agent_runtime.start_agent_session("Queue worker two")["session"]["session_id"]
        first = agent_runtime.create_agent_task("Inspect Docker health", priority=90, created_by_session=first_session)["task"]
        second = agent_runtime.create_agent_task("Summarize incident", depends_on=[first["task_id"]])["task"]

        blocked = agent_runtime.claim_agent_task(second["task_id"], second_session)
        self.assertEqual(blocked["status"], "blocked")
        claimed = agent_runtime.claim_agent_task(first["task_id"], first_session)
        self.assertEqual(claimed["status"], "ok")
        self.assertEqual(agent_runtime.claim_agent_task(first["task_id"], second_session)["status"], "claimed")
        finished = agent_runtime.finish_agent_task(first["task_id"], first_session, "completed", "token=private-value healthy")
        self.assertIn("***REDACTED***", finished["task"]["result"])
        self.assertEqual(agent_runtime.claim_agent_task(second["task_id"], second_session)["status"], "ok")

    def test_expired_task_lease_is_released_on_queue_read(self):
        session_id = agent_runtime.start_agent_session("Short lease worker")["session"]["session_id"]
        task = agent_runtime.create_agent_task("Check backup archive")["task"]
        agent_runtime.claim_agent_task(task["task_id"], session_id, 5)
        future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=6)
        with mock.patch("src.agent_runtime._now", return_value=future):
            listed = agent_runtime.list_agent_tasks()
        refreshed = next(item for item in listed["tasks"] if item["task_id"] == task["task_id"])
        self.assertEqual(refreshed["status"], "pending")
        self.assertEqual(refreshed["lease_expirations"], 1)


if __name__ == "__main__":
    unittest.main()
