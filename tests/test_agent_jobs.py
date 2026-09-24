"""Durable Agent Jobs never start a worker or silently run recovery."""

from __future__ import annotations

import datetime as dt
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

from src import agent_jobs


class TestAgentJobs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.environment = mock.patch.dict(os.environ, {"VPS_GUARDIAN_STATE_DIR": self.temporary.name, "VPS_GUARDIAN_MODE": "controlled"})
        self.environment.start()
        self.budget = mock.patch("src.agent_jobs.get_runtime_budget", return_value={"profile": "standard"})
        self.budget.start()

    def tearDown(self):
        self.budget.stop()
        self.environment.stop()
        self.temporary.cleanup()

    def _job(self, checks=None, target=None):
        created = agent_jobs.create_agent_job("Investigate a VPS workload", checks or ["runtime_budget"], target)
        self.assertEqual(created["status"], "ok", created)
        return created["job"]["job_id"]

    def test_persisted_checks_delta_and_agent_conclusion(self):
        job_id = self._job(["runtime_budget", "system_health"])
        with mock.patch("src.agent_jobs._run_check", side_effect=[{"status": "ok", "value": "token=private-value"}, {"status": "ok", "cpu_percent": 12}]):
            first = agent_jobs.advance_agent_job(job_id)
            self.assertEqual(first["job"]["status"], "pending")
            self.assertIn("***REDACTED***", str(first["check"]["result"]))
            revision = first["job"]["revision"]
            self.assertEqual(agent_jobs.get_agent_job(job_id, revision)["status"], "unchanged")
            second = agent_jobs.advance_agent_job(job_id)
        self.assertEqual(second["job"]["status"], "awaiting_agent")
        delta = agent_jobs.get_agent_job(job_id, revision)
        self.assertEqual(len(delta["checks"]), 1)
        self.assertEqual(delta["checks"][0]["name"], "system_health")
        self.assertEqual(agent_jobs.finish_agent_job(job_id, "Healthy after inspection")["job"]["status"], "completed")
        self.assertEqual(agent_jobs.get_agent_job(job_id)["job"]["status"], "completed")
        self.assertEqual(agent_jobs.list_agent_jobs()["job_count"], 0)

    def test_strict_check_and_target_validation(self):
        self.assertEqual(agent_jobs.create_agent_job("An incident", ["shell"], "nginx")["status"], "error")
        self.assertEqual(agent_jobs.create_agent_job("An incident", ["service_status"])["status"], "error")
        self.assertEqual(agent_jobs.create_agent_job("An incident", ["service_status"], "nginx; shutdown")["status"], "error")
        self.assertEqual(agent_jobs.create_agent_job("An incident", ["runtime_budget"], ttl_hours=True)["status"], "error")

    def test_expired_read_only_lease_can_retry_after_reconnect(self):
        job_id = self._job()
        with agent_jobs._transaction() as connection:
            job = agent_jobs._load(connection, job_id)
            job["status"] = "running"
            job["lease_id"] = "lost-process"
            job["lease_expires_at"] = (agent_jobs._now() - dt.timedelta(seconds=1)).isoformat()
            agent_jobs._save(connection, job)
        with mock.patch("src.agent_jobs._run_check", return_value={"status": "ok"}):
            self.assertEqual(agent_jobs.advance_agent_job(job_id)["job"]["status"], "awaiting_agent")
        self.assertEqual(agent_jobs.get_agent_job(job_id)["checks"][0]["attempts"], 1)

    def test_cancelled_job_cannot_be_revived_by_inflight_check(self):
        job_id = self._job()

        def concurrent_cancel(_check, _target):
            self.assertEqual(agent_jobs.cancel_agent_job(job_id)["status"], "ok")
            return {"status": "ok"}

        with mock.patch("src.agent_jobs._run_check", side_effect=concurrent_cancel):
            self.assertEqual(agent_jobs.advance_agent_job(job_id)["status"], "interrupted")
        self.assertEqual(agent_jobs.get_agent_job(job_id)["job"]["status"], "cancelled")

    def test_large_results_and_critical_memory_are_bounded(self):
        job_id = self._job(["service_logs"], "nginx")
        with mock.patch("src.agent_jobs.get_runtime_budget", return_value={"profile": "critical"}):
            self.assertEqual(agent_jobs.advance_agent_job(job_id)["status"], "resource_limited")
        with mock.patch("src.agent_jobs._run_check", return_value={"status": "ok", **{f"item_{index}": "x" * 500 for index in range(20)}}):
            checked = agent_jobs.advance_agent_job(job_id)
        self.assertEqual(checked["job"]["status"], "awaiting_agent")
        self.assertTrue(checked["check"]["result"]["truncated"])
        self.assertLess(len(str(agent_jobs.get_agent_job(job_id))), 4000)

    @unittest.skipUnless(os.name == "posix", "Detached workers are Linux-only")
    def test_detached_step_persists_after_call_returns(self):
        job_id = self._job(["runtime_budget"])
        started = agent_jobs.advance_agent_job(job_id, background=True)
        self.assertEqual(started["status"], "running", started)
        for _ in range(100):
            state = agent_jobs.get_agent_job(job_id)
            if state["job"]["status"] != "running":
                break
            time.sleep(0.05)
        self.assertEqual(state["job"]["status"], "awaiting_agent", state)
        self.assertEqual(state["checks"][0]["result"]["status"], "ok")

    def test_recovery_requires_proposal_and_verification(self):
        job_id = self._job(["service_status"], "nginx")
        self.assertNotEqual(agent_jobs.execute_agent_job_recovery(job_id)["status"], "ok")
        with mock.patch("src.agent_jobs._run_check", return_value={"status": "ok", "is_running": False}):
            agent_jobs.advance_agent_job(job_id)
        proposed = agent_jobs.propose_agent_job_recovery(job_id, "nginx", "Service is inactive")
        self.assertEqual(proposed["job"]["status"], "awaiting_confirmation")
        with mock.patch("src.agent_jobs.run_recovery_action", side_effect=[
            {"status": "confirmation_required", "confirmation_token": "single-use"},
            {"status": "ok", "success": True, "audit_log_path": "/var/log/vps-guardian/audit.jsonl"},
        ]) as recovery:
            planned = agent_jobs.execute_agent_job_recovery(job_id)
            self.assertEqual(planned["status"], "confirmation_required")
            self.assertEqual(agent_jobs.get_agent_job(job_id)["job"]["status"], "awaiting_confirmation")
            applied = agent_jobs.execute_agent_job_recovery(job_id, "single-use")
        self.assertEqual(recovery.call_count, 2)
        self.assertEqual(applied["job"]["status"], "verification_pending")
        with mock.patch("src.agent_jobs.check_service_status", return_value={"status": "ok", "is_running": True}):
            verified = agent_jobs.verify_agent_job_recovery(job_id)
        self.assertEqual(verified["job"]["status"], "awaiting_agent")
        self.assertEqual(agent_jobs.finish_agent_job(job_id, "Restart verified")["job"]["status"], "completed")

    def test_uncertain_recovery_is_never_replayed(self):
        job_id = self._job(["service_status"], "nginx")
        with mock.patch("src.agent_jobs._run_check", return_value={"status": "ok", "is_running": False}):
            agent_jobs.advance_agent_job(job_id)
        agent_jobs.propose_agent_job_recovery(job_id, "nginx", "Needs restart")
        with mock.patch("src.agent_jobs.run_recovery_action", side_effect=RuntimeError("connection lost")) as recovery:
            result = agent_jobs.execute_agent_job_recovery(job_id, "expired-token")
        self.assertEqual(result["job"]["status"], "action_uncertain")
        self.assertEqual(agent_jobs.execute_agent_job_recovery(job_id, "expired-token")["status"], "action_uncertain")
        self.assertEqual(recovery.call_count, 1)

    def test_recovery_needs_matching_service_evidence_and_bad_token_is_retryable(self):
        job_id = self._job(["runtime_budget"])
        with mock.patch("src.agent_jobs._run_check", return_value={"status": "ok"}):
            agent_jobs.advance_agent_job(job_id)
        self.assertEqual(agent_jobs.propose_agent_job_recovery(job_id, "nginx", "Needs restart")["status"], "error")
        service_job = self._job(["service_status"], "nginx")
        with mock.patch("src.agent_jobs._run_check", return_value={"status": "ok", "is_running": False}):
            agent_jobs.advance_agent_job(service_job)
        agent_jobs.propose_agent_job_recovery(service_job, "nginx", "Needs restart")
        with mock.patch("src.agent_jobs.run_recovery_action", return_value={"status": "forbidden", "error": "Token expired"}):
            blocked = agent_jobs.execute_agent_job_recovery(service_job, "old-token")
        self.assertEqual(blocked["job"]["status"], "awaiting_confirmation")

    def test_real_controlled_gate_requires_single_use_token(self):
        job_id = self._job(["service_status"], "nginx")
        with mock.patch("src.agent_jobs._run_check", return_value={"status": "ok", "is_running": False}):
            agent_jobs.advance_agent_job(job_id)
        agent_jobs.propose_agent_job_recovery(job_id, "nginx", "Service inactive")
        audit_path = os.path.join(self.temporary.name, "audit.jsonl")
        with mock.patch.dict(os.environ, {"VPS_GUARDIAN_AUDIT_LOG": audit_path}):
            with mock.patch("src.recover._action_restart_service", return_value={"status": "ok", "success": True}) as restart:
                preview = agent_jobs.execute_agent_job_recovery(job_id)
                self.assertEqual(preview["status"], "confirmation_required")
                restart.assert_not_called()
                applied = agent_jobs.execute_agent_job_recovery(job_id, preview["recovery"]["confirmation_token"])
        self.assertEqual(applied["job"]["status"], "verification_pending")
        restart.assert_called_once_with("nginx")

    def test_only_two_standard_read_only_jobs_run_concurrently(self):
        ids = [self._job() for _ in range(3)]
        entered = threading.Event()
        release = threading.Event()

        def slow_check(_check, _target):
            entered.set()
            release.wait(5)
            return {"status": "ok"}

        with mock.patch("src.agent_jobs._run_check", side_effect=slow_check):
            thread = threading.Thread(target=agent_jobs.advance_agent_job, args=(ids[0],))
            thread.start()
            self.assertTrue(entered.wait(3))
            with agent_jobs._transaction() as connection:
                second = agent_jobs._load(connection, ids[1])
                second["status"] = "running"
                second["lease_expires_at"] = (agent_jobs._now() + dt.timedelta(seconds=60)).isoformat()
                agent_jobs._save(connection, second)
            self.assertEqual(agent_jobs.advance_agent_job(ids[2])["status"], "busy")
            release.set()
            thread.join(5)
            self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
