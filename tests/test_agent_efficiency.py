"""Focused checks for compact, on-demand agent answers."""

from __future__ import annotations

import asyncio
import json
import unittest
from unittest import mock

from src import agent_efficiency


class TestAgentEfficiency(unittest.TestCase):
    def test_log_groups_and_unchanged_fingerprint(self):
        logs = {"status": "ok", "logs": "2026-09-23T10:00:00 error 1234\n2026-09-23T10:00:01 error 5678\nready"}
        with mock.patch.object(agent_efficiency, "read_service_logs", return_value=logs):
            summary = agent_efficiency.summarize_service_logs("worker")
            self.assertEqual(summary["groups"][0]["count"], 2)
            self.assertEqual(agent_efficiency.summarize_service_logs("worker", if_fingerprint=summary["fingerprint"])["status"], "unchanged")

    def test_event_cursor_returns_only_new_events(self):
        events = [{"timestamp": "2026-09-23T10:00:00", "event": "first"}, {"timestamp": "2026-09-23T10:01:00", "event": "second"}]
        with mock.patch.object(agent_efficiency, "get_recent_server_events", return_value={"status": "ok", "events": events, "event_count": 2}):
            first = agent_efficiency.get_server_event_delta(max_events=1)
            second = agent_efficiency.get_server_event_delta(after_cursor=first["cursor"])
        self.assertEqual(second["event_count"], 1)
        self.assertEqual(second["events"][0]["event"], "second")

    def test_workload_brief_is_bounded_and_cacheable(self):
        health = {"status": "ok", "overall_status": "ok", "found": 1, "matched_components": [{"kind": "container", "identity": "worker", "component": {"image": "private"}}], "host_pressure": {"cpu_percent": 1}, "collection_errors": {}}
        with mock.patch.object(agent_efficiency, "get_workload_health", return_value=health):
            result = agent_efficiency.get_workload_brief("worker")
            cached = agent_efficiency.get_workload_brief("worker", if_fingerprint=result["fingerprint"])
        self.assertEqual(result["health"]["components"][0]["identity"], "worker")
        self.assertNotIn("private", str(result))
        self.assertEqual(cached["status"], "unchanged")

    def test_mcp_tool_returns_compact_text_and_structured_object(self):
        from src import server

        result = asyncio.run(server.mcp.call_tool("get_guardian_launch", {}))
        self.assertEqual(json.loads(result.content[0].text), result.structuredContent)
        self.assertNotIn("\n", result.content[0].text)


if __name__ == "__main__":
    unittest.main()
