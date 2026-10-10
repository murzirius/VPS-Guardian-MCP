"""Mission assignment, untrusted report reconciliation and independent evidence."""
from contextlib import contextmanager
import datetime as dt
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src import mission_tasks as tasks, mission_control as workspaces, gateway
from src.safe_io import private_directory, read_bounded
import tests.test_mission_control as fixtures


def operator(function, *args):
    return tasks._safe_errors(function.__wrapped__.__wrapped__)(*args)


class TestMissionTasks(unittest.TestCase):
    target = fixtures.TestMissionWorkflow.target
    draft = fixtures.TestMissionWorkflow.draft
    approve = fixtures.TestMissionWorkflow.approve

    def setUp(self):
        fixtures.TestMissionWorkflow.setUp(self)
        self.policy["expires_at"] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).isoformat()
        self.other = {**self.policy, "agent_id": "second", "account": "vg_second", "key_fingerprint": "SHA256:" + "b" * 43}
        self.policies = {"bot": self.policy, "second": self.other}
        self.stack.enter_context(patch("src.mission_control._live_policy", side_effect=lambda agent: self.policies[agent] if self.policies[agent]["enabled"] else (_ for _ in ()).throw(PermissionError())))
        self.stack.enter_context(patch("src.gateway._read_policy", side_effect=lambda agent: self.policies[agent]))
        self.stack.enter_context(patch("src.gateway.pwd", SimpleNamespace(getpwnam=lambda account: SimpleNamespace(pw_gid=1000))))
        self.stack.enter_context(patch("src.mission_tasks._directory", side_effect=lambda: Path(private_directory(str(gateway.POLICY_BASE / "tasks")))))
        self.stack.enter_context(patch("src.mission_tasks._read", side_effect=lambda path, *args, **kw: json.loads(read_bounded(str(path), tasks.MAX_RECORD, private=True))))
        self.stack.enter_context(patch("src.mission_tasks._feed_directory", side_effect=lambda policy, gid, **kw: Path(private_directory(str(self.base / "feed" / policy["agent_id"])))))
        self.stack.enter_context(patch("src.mission_tasks._export", side_effect=self.export))
        self.stack.enter_context(patch("src.mission_tasks._read_feed_path", side_effect=self.read_feed))
        self.stack.enter_context(patch("src.mission_tasks._parse", return_value={"passed": True}))

        @contextmanager
        def lock(policy):
            yield Path(private_directory(str(tasks._progress_directory(policy))))
        self.stack.enter_context(patch("src.mission_tasks._progress_lock", side_effect=lock))

    def export(self, item):
        policy = self.policies[item["agent_id"]]
        directory = tasks._feed_directory(policy, item["gid"])
        feed = {**tasks._public(item, detail=True), "uid": item["uid"], "key_fingerprint": item["key_fingerprint"],
                "epoch": item["epoch"], "last_report_hash": item.get("last_report_hash")}
        tasks._write(directory / (item["mission_id"] + ".json"), feed)

    def read_feed(self, path, policy, gid):
        value = tasks._read(path, policy["uid"])
        if value["agent_id"] != policy["agent_id"] or value["key_fingerprint"] != policy["key_fingerprint"]:
            raise PermissionError()
        return value

    def create(self, checks=None):
        result = operator(tasks.create_mission_task, "bot", str(self.project), "Update message", "Improve the displayed message",
                          ["The message is readable"], ["python_syntax"] if checks is None else checks)
        self.assertEqual(result["status"], "ok", result)
        self.assertTrue(result["assignment_exported"])
        return result["mission"]

    def latest(self, item):
        result = operator(tasks.inspect_mission_task, item["mission_id"])
        self.assertEqual(result["status"], "ok", result)
        return result["mission"]

    def submit(self, item):
        workspace = self.draft()
        workspaces.submit_mission_workspace(workspace)
        report = tasks.report_mission_progress(item["mission_id"], item["revision"], "needs_review", "Ready for operator review", workspace)
        self.assertEqual(report["status"], "ok", report)
        self.assertFalse(report["acknowledged"])
        return self.latest(item)

    def imported(self):
        item = self.submit(self.create())
        result = operator(tasks.import_mission_task_review, item["mission_id"], item["revision"])
        self.assertEqual(result["status"], "ok", result)
        return result["mission"], result["review"]["review"]

    def checked(self):
        item, review = self.imported()
        result = operator(tasks.run_mission_task_check, item["mission_id"], item["revision"])
        self.assertTrue(result["mission"]["checks"]["passed"], result)
        return result["mission"], review

    def applied(self):
        item, review = self.checked()
        self.approve(review)
        result = operator(workspaces.apply_mission_review, review["review_id"], review["digest"])
        self.assertEqual(result["review"]["state"], "completed", result)
        return self.latest(item), review

    def test_private_assignment_compact_cursor_and_unverified_report(self):
        item = self.create()
        self.assertEqual(tasks.list_assigned_missions()["missions"][0]["mission_id"], item["mission_id"])
        brief = tasks.get_mission_brief(item["mission_id"])
        self.assertEqual(brief["mission"]["goal"], item["goal"])
        unchanged = tasks.get_mission_brief(item["mission_id"], item["revision"])
        self.assertTrue(unchanged["unchanged"])
        self.assertNotIn("goal", unchanged)
        self.assertLess(len(json.dumps(unchanged)), 260)
        report = tasks.report_mission_progress(item["mission_id"], item["revision"], "working", "token=private-value checked", job_id="job_" + "a" * 16)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(tasks._task(item["mission_id"])["state"], "queued")
        acknowledged = self.latest(item)
        self.assertEqual(acknowledged["state"], "working")
        self.assertNotIn("private-value", acknowledged["agent_report"])
        self.assertEqual(acknowledged["reported_job_id"], "job_" + "a" * 16)
        self.assertIsNone(acknowledged["verification"])
        self.assertEqual(self.latest(acknowledged)["revision"], acknowledged["revision"])

    def test_complete_flow_requires_checks_operator_apply_verification_and_finish(self):
        item, review = self.imported()
        self.assertEqual(operator(workspaces.decide_mission_review, review["review_id"], review["digest"], "approve")["status"], "error")
        self.assertEqual(self.file.read_bytes(), b"print('original')\n")
        result = operator(tasks.run_mission_task_check, item["mission_id"], item["revision"])
        self.assertTrue(result["mission"]["checks"]["passed"])
        self.approve(review)
        ready = self.latest(result["mission"])
        self.assertEqual(ready["state"], "ready_to_apply")
        operator(workspaces.apply_mission_review, review["review_id"], review["digest"])
        applied = self.latest(ready)
        self.assertEqual(applied["state"], "verifying")
        self.assertEqual(operator(tasks.finish_mission_task, applied["mission_id"], applied["revision"])["status"], "error")
        verified = operator(tasks.verify_mission_task, applied["mission_id"], applied["revision"])["mission"]
        self.assertTrue(verified["verification"]["passed"])
        completed = operator(tasks.finish_mission_task, verified["mission_id"], verified["revision"])
        self.assertEqual(completed["mission"]["state"], "done", completed)
        self.assertEqual(tasks.list_assigned_missions()["missions"], [])

    def test_cancel_blocks_previously_approved_linked_apply(self):
        item, review = self.checked()
        self.approve(review)
        item = self.latest(item)
        cancelled = operator(tasks.cancel_mission_task, item["mission_id"], item["revision"])
        self.assertEqual(cancelled["mission"]["state"], "cancelled")
        self.assertEqual(operator(workspaces.apply_mission_review, review["review_id"], review["digest"])["status"], "error")
        self.assertEqual(self.file.read_bytes(), b"print('original')\n")

    def test_return_withdraws_old_approval_and_does_not_transfer_it(self):
        item, review = self.checked()
        self.approve(review)
        item = self.latest(item)
        returned = operator(tasks.return_mission_task, item["mission_id"], item["revision"])
        self.assertEqual(returned["mission"]["state"], "working", returned)
        self.assertIsNone(returned["mission"]["review_id"])
        self.assertEqual(operator(workspaces.apply_mission_review, review["review_id"], review["digest"])["status"], "error")
        self.assertEqual(operator(workspaces.get_mission_review, review["review_id"])["review"]["state"], "superseded")

    def test_handoff_rejects_old_worker_and_old_report_epoch(self):
        item = self.create()
        tasks.report_mission_progress(item["mission_id"], item["revision"], "working", "Preparing changes")
        item = self.latest(item)
        handed = operator(tasks.reassign_mission_task, item["mission_id"], item["revision"], "second")
        self.assertEqual(handed["mission"]["agent_id"], "second", handed)
        self.assertEqual(tasks.get_mission_brief(item["mission_id"])["status"], "error")
        with patch("src.mission_control._worker_policy", return_value=self.other):
            brief = tasks.get_mission_brief(item["mission_id"])
            self.assertEqual(brief["mission"]["state"], "queued")
            self.assertIsNone(brief["mission"]["workspace_id"])
        self.assertEqual(self.latest(handed["mission"])["state"], "queued")

    def test_agent_cannot_report_done_or_forge_another_mission(self):
        item = self.create()
        for phase in ("done", "ready_to_apply", "verifying", "approved"):
            self.assertEqual(tasks.report_mission_progress(item["mission_id"], item["revision"], phase, "Trust me")["status"], "error")
        with patch("src.mission_control._worker_policy", return_value=self.other):
            self.assertEqual(tasks.get_mission_brief(item["mission_id"])["status"], "error")
        self.assertEqual(self.latest(item)["state"], "queued")

    def test_forged_mailbox_or_stale_revision_cannot_authorize_success(self):
        item = self.create()
        tasks.report_mission_progress(item["mission_id"], item["revision"], "working", "Started")
        path = tasks._progress_directory(self.policy) / (item["mission_id"] + ".json")
        report = tasks._read(path, self.policy["uid"])
        report["phase"] = "done"
        tasks._write(path, report)
        inspected = self.latest(item)
        self.assertEqual(inspected["state"], "queued")
        self.assertTrue(inspected["report_error"])
        self.assertEqual(operator(tasks.cancel_mission_task, item["mission_id"], item["revision"])["status"], "conflict")

    def test_failed_static_check_refuses_approval_then_can_be_retried(self):
        item, review = self.imported()
        with patch("src.mission_tasks._parse", return_value={"passed": False, "error": "SyntaxError"}):
            result = operator(tasks.run_mission_task_check, item["mission_id"], item["revision"])
        self.assertFalse(result["mission"]["checks"]["passed"])
        self.assertEqual(operator(workspaces.decide_mission_review, review["review_id"], review["digest"], "approve")["status"], "error")
        item = result["mission"]
        retry = operator(tasks.run_mission_task_check, item["mission_id"], item["revision"])
        self.assertTrue(retry["mission"]["checks"]["passed"])

    def test_production_changed_after_verify_cannot_be_marked_done(self):
        item, _ = self.applied()
        verified = operator(tasks.verify_mission_task, item["mission_id"], item["revision"])["mission"]
        self.file.write_bytes(b"print('external')\n")
        result = operator(tasks.finish_mission_task, item["mission_id"], verified["revision"])
        self.assertEqual(result["status"], "error")
        self.assertEqual(self.latest(item)["state"], "verifying")

    def test_applied_or_uncertain_work_cannot_be_cancelled_or_reset(self):
        item, review = self.applied()
        for function in (tasks.cancel_mission_task, tasks.return_mission_task):
            self.assertEqual(operator(function, item["mission_id"], item["revision"])["status"], "error")
        path = workspaces._review_directory() / (review["review_id"] + ".json")
        record = workspaces._read_json(path, uid=0)
        record["state"] = "applying"
        workspaces._write(path, record)
        item = self.latest(item)
        self.assertEqual(item["state"], "needs_attention")
        self.assertEqual(operator(tasks.verify_mission_task, item["mission_id"], item["revision"])["status"], "error")
        self.assertEqual(operator(tasks.return_mission_task, item["mission_id"], item["revision"])["status"], "error")

    def test_live_task_keeps_expired_review_for_verification_but_not_reapply(self):
        self.policy["expires_at"] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)).isoformat()
        item, review = self.applied()
        with patch("src.mission_control.time.time", return_value=review["expires_at"] + 60):
            listed = operator(workspaces.list_mission_reviews)
            self.assertEqual(listed["reviews"][0]["review_id"], review["review_id"])
            self.assertEqual(operator(workspaces.apply_mission_review, review["review_id"], review["digest"])["status"], "error")
            verified = operator(tasks.verify_mission_task, item["mission_id"], item["revision"])
            self.assertTrue(verified["mission"]["verification"]["passed"], verified)

    def test_expiry_or_revocation_blocks_approval_but_operator_can_cancel(self):
        item, review = self.checked()
        self.policy["enabled"] = False
        self.assertEqual(operator(workspaces.decide_mission_review, review["review_id"], review["digest"], "approve")["status"], "error")
        item = self.latest(item)
        self.assertEqual(operator(tasks.cancel_mission_task, item["mission_id"], item["revision"])["mission"]["state"], "cancelled")

    def test_invalid_inputs_capacity_and_no_checks_are_explicit(self):
        for checks in (["shell"], ["python_syntax"] * 4):
            result = operator(tasks.create_mission_task, "bot", str(self.project), "title", "goal", ["criterion"], checks)
            self.assertEqual(result["status"], "error")
        for _ in range(tasks.MAX_ACTIVE_PER_AGENT):
            self.create(checks=[])
        self.assertEqual(operator(tasks.create_mission_task, "bot", str(self.project), "title", "goal", ["criterion"], [])["status"], "error")

    def test_import_requires_matching_submitted_project_and_binds_digest(self):
        item = self.create()
        draft = self.draft()
        self.assertEqual(tasks.report_mission_progress(item["mission_id"], item["revision"], "needs_review", "not submitted", draft)["status"], "error")
        item = self.submit(item)
        self.assertEqual(operator(workspaces.import_mission_review, "bot", item["workspace_id"])["status"], "error")
        result = operator(tasks.import_mission_task_review, item["mission_id"], item["revision"])
        self.assertEqual(result["review"]["review"]["mission_id"], item["mission_id"])
        self.assertEqual(result["mission"]["review_digest"], result["review"]["review"]["digest"])
        self.assertEqual(operator(tasks.reassign_mission_task, item["mission_id"], result["mission"]["revision"], "second")["status"], "error")


class TestMissionTaskBoundaries(unittest.TestCase):
    def test_panel_refuses_unknown_fields_commands_and_stale_types(self):
        from src.local_panel import PanelController, PanelInputError
        panel = PanelController()
        panel.state.update(connection="connected", mission_tasks_supported=True)
        mission = "mission_" + "a" * 24
        for name, value in (("exec", {}), ("finish_mission_task", {"mission_id": mission, "expected_revision": True}),
                            ("inspect_mission_task", {"mission_id": "../../etc"}), ("inspect_mission_task", {"mission_id": mission, "command": "sh"})):
            with self.assertRaises(PanelInputError):
                panel.tasks_request(name, value)
        panel.tasks_request("inspect_mission_task", {"mission_id": mission})
        self.assertEqual(panel.policy_job, ("inspect_mission_task", {"mission_id": mission}))
        with self.assertRaises(RuntimeError):
            panel.tasks_request("list_mission_tasks", {})
        panel.disconnect()
        self.assertIsNone(panel.state["mission_task"])
        self.assertFalse(panel.state["mission_tasks_supported"])

    def test_operator_methods_are_not_agent_tools(self):
        from src.access_policy import tool_catalog
        names = {tool["name"] for tool in tool_catalog()}
        self.assertFalse(tasks.OPERATOR_TOOLS & names)
        self.assertTrue({"list_assigned_missions", "get_mission_brief", "report_mission_progress"} <= set(gateway.MISSION_TOOLS))
        self.assertNotIn("execute_agent_job_recovery", gateway.MISSION_TOOLS)

    def test_low_memory_static_parser_fails_closed(self):
        with patch("src.mission_tasks.get_runtime_budget", return_value={"available_memory_bytes": 100 * 1024**2}), patch("src.mission_tasks.subprocess.Popen") as process:
            self.assertFalse(tasks._parse("python_syntax", "print('ok')")["passed"])
            process.assert_not_called()

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux bounded parser")
    def test_real_static_parser_does_not_execute_candidate_and_handles_invalid_json(self):
        with patch("src.mission_tasks.get_runtime_budget", return_value={"available_memory_bytes": 512 * 1024**2}):
            source = "raise RuntimeError('must never execute')\n"
            self.assertTrue(tasks._parse("python_syntax", source)["passed"])
            self.assertFalse(tasks._parse("python_syntax", "def broken(:")["passed"])
            self.assertTrue(tasks._parse("json_syntax", '{"value":42}')["passed"])
            self.assertFalse(tasks._parse("json_syntax", '{"value":NaN}')["passed"])

    def test_bidi_and_command_fields_are_not_mission_text(self):
        for value in ("hidden\u202etitle", "bad\0value", ""):
            with self.assertRaises(ValueError):
                tasks._text(value, 120)


if __name__ == "__main__":
    unittest.main()
