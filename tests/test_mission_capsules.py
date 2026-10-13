"""Mission capsule bindings, refusal paths and operator-only test gates."""
from contextlib import nullcontext
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from src import mission_capsules as capsules, mission_control as workspaces, mission_tasks as tasks, test_capsules
from tests import test_mission_tasks as fixtures

operator = fixtures.operator


class TestMissionCapsules(fixtures.TestMissionTasks):
    def setUp(self):
        super().setUp()
        tests = self.project / "tests"
        tests.mkdir()
        (tests / "test_main.py").write_text("import unittest\nclass Example(unittest.TestCase):\n def test_ok(self): self.assertTrue(True)\n", encoding="utf-8")
        self.stack.enter_context(patch("src.mission_capsules._image", return_value=("docker", "sha256:" + "a" * 64)))
        self.stack.enter_context(patch("src.mission_capsules._lock", return_value=nullcontext()))
        copy = test_capsules._copy_snapshot
        self.copy = self.stack.enter_context(patch("src.test_capsules._copy_snapshot", side_effect=lambda project, dest, **kw: copy(project, dest)))
        self.container = self.stack.enter_context(patch("src.test_capsules._run_container", return_value={"status": "ok", "success": True, "exit_code": 0}))

    def imported_with_tests(self, checks=None):
        item = self.submit(self.create(checks=["python_syntax", "python_unittest"] if checks is None else checks))
        result = operator(tasks.import_mission_task_review, item["mission_id"], item["revision"])
        self.assertEqual(result["status"], "ok", result)
        return result["mission"], result["review"]["review"]

    def run_tests(self, item):
        result = operator(tasks.run_mission_task_tests, item["mission_id"], item["revision"])
        self.assertEqual(result["status"], "ok", result)
        return result["mission"]

    def test_isolated_tests_are_required_and_production_stays_unchanged(self):
        item, review = self.imported_with_tests()
        item = operator(tasks.run_mission_task_check, item["mission_id"], item["revision"])["mission"]
        self.assertFalse(item["checks"]["passed"])
        self.assertEqual(operator(workspaces.decide_mission_review, review["review_id"], review["digest"], "approve")["status"], "error")
        item = self.run_tests(item)
        self.assertTrue(item["checks"]["passed"], item)
        self.assertEqual(self.copy.call_args.kwargs, {"protected": True})
        command = self.container.call_args.args
        self.assertEqual(command[1], "sha256:" + "a" * 64)
        self.assertNotEqual(command[2], str(self.project))
        self.assertFalse(Path(command[2]).exists())
        self.assertEqual(self.file.read_text(), "print('original')\n")
        self.approve(review)

    def test_context_change_blocks_apply_and_invalidates_other_passes(self):
        item, review = self.imported_with_tests(["python_unittest"])
        item = self.run_tests(item)
        item = operator(tasks.run_mission_task_check, item["mission_id"], item["revision"])["mission"]
        self.approve(review)
        (self.project / "tests" / "test_main.py").write_text("# context changed\n", encoding="utf-8")
        result = operator(workspaces.apply_mission_review, review["review_id"], review["digest"])
        self.assertEqual(result["status"], "error")
        item = self.latest(item)
        self.assertFalse(item["checks"]["passed"])
        self.assertEqual(item["checks"]["capsules"][0]["status"], "stale")
        self.assertEqual(self.file.read_text(), "print('original')\n")

    def test_pinned_image_change_invalidates_evidence(self):
        item, review = self.imported_with_tests(["python_unittest"])
        item = self.run_tests(item)
        item = operator(tasks.run_mission_task_check, item["mission_id"], item["revision"])["mission"]
        with patch("src.mission_capsules._image", return_value=("docker", "sha256:" + "b" * 64)):
            self.assertEqual(operator(workspaces.decide_mission_review, review["review_id"], review["digest"], "approve")["status"], "error")

    def test_missing_runtime_failed_timeout_cleanup_and_interrupt_are_not_passes(self):
        item, review = self.imported_with_tests(["python_unittest"])
        with patch("src.mission_capsules._image", side_effect=ValueError("384 MiB required")):
            item = self.run_tests(item)
        self.assertEqual(item["checks"]["capsules"][0]["status"], "not_run")
        self.container.assert_not_called()
        for result in ({"status": "failed", "success": False, "exit_code": 1},
                       {"status": "timeout", "success": False, "exit_code": None},
                       {"status": "ok", "success": True, "exit_code": 0, "cleanup_uncertain": True}):
            self.container.return_value = result
            item = self.run_tests(item)
            self.assertFalse(item["checks"]["passed"])
        with patch("src.mission_capsules.run", side_effect=RuntimeError("helper interrupted")):
            with self.assertRaises(RuntimeError):
                operator(tasks.run_mission_task_tests, item["mission_id"], item["revision"])
        item = self.latest(item)
        self.assertFalse(item["checks"]["passed"])
        self.assertEqual(item["checks"]["capsules"][0]["status"], "running")

    def test_changes_during_test_and_inline_secrets_refused(self):
        item, review = self.imported_with_tests(["python_unittest"])
        def mutate(*args):
            (self.project / "tests" / "test_main.py").write_text("# changed during test", encoding="utf-8")
            return {"status": "ok", "success": True, "exit_code": 0}
        self.container.side_effect = mutate
        item = self.run_tests(item)
        self.assertFalse(item["checks"]["passed"])
        (self.project / "config.py").write_text('API_TOKEN="secret-do-not-copy"\n', encoding="utf-8")
        self.container.reset_mock()
        item = self.run_tests(item)
        self.container.assert_not_called()
        self.assertNotIn("secret-do-not-copy", json.dumps(item))

    def test_empty_test_tree_and_binary_inputs_not_run(self):
        item, review = self.imported_with_tests(["python_unittest"])
        (self.project / "tests" / "test_main.py").unlink()
        item = self.run_tests(item)
        self.container.assert_not_called()
        self.assertEqual(item["checks"]["capsules"][0]["status"], "not_run")
        (self.project / "data.bin").write_bytes(b"\xff")
        item = self.run_tests(item)
        self.assertFalse(item["checks"]["passed"])

    def test_zero_discovered_cases_do_not_pass(self):
        (self.project / "tests" / "test_main.py").write_text("def test_pytest_only(): pass\n", encoding="utf-8")
        result = subprocess.run([sys.executable, "-B", "-c", capsules._UNITTEST], cwd=self.project, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"No unittest cases", result.stderr)

    def test_all_skipped_cases_do_not_pass(self):
        (self.project / "tests" / "test_main.py").write_text("import unittest\n@unittest.skip('no environment')\nclass Example(unittest.TestCase):\n def test_skip(self): pass\n", encoding="utf-8")
        result = subprocess.run([sys.executable, "-B", "-c", capsules._UNITTEST], cwd=self.project, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)

    def test_deletion_only_candidate_removes_copied_file_not_production(self):
        item = self.create(checks=["python_unittest"])
        created = workspaces.create_mission_workspace(str(self.project), ["main.py"], "Delete obsolete source")["workspace"]
        deleted = workspaces.stage_mission_file_deletion(created["workspace_id"], "main.py", created["files"][0]["candidate_sha256"])
        self.assertEqual(deleted["status"], "ok", deleted)
        workspaces.submit_mission_workspace(created["workspace_id"])
        tasks.report_mission_progress(item["mission_id"], item["revision"], "needs_review", "Ready", created["workspace_id"])
        item = self.latest(item)
        item = operator(tasks.import_mission_task_review, item["mission_id"], item["revision"])["mission"]
        def inspect(_docker, _image, snapshot, _command):
            self.assertFalse(Path(snapshot, "main.py").exists())
            if os.name == "posix":
                self.assertEqual(Path(snapshot).parent.stat().st_mode & 0o777, 0o700)
            return {"status": "ok", "success": True, "exit_code": 0}
        self.container.side_effect = inspect
        item = self.run_tests(item)
        self.assertTrue(item["checks"]["passed"], item)
        self.assertTrue(self.file.exists())

    def test_operator_tests_not_added_to_worker_catalog_and_panel_rejects_commands(self):
        from src import gateway
        self.assertNotIn("run_mission_task_tests", gateway.MISSION_TOOLS)
        from src.local_panel import PanelController, PanelInputError
        panel = PanelController()
        panel.state.update(connection="connected", mission_tasks_supported=True, mission_capsules_supported=True)
        item = self.create()
        body = {"mission_id": item["mission_id"], "expected_revision": item["revision"]}
        with self.assertRaises(PanelInputError):
            panel.tasks_request("run_mission_task_tests", {**body, "command": "sh"})
        panel.tasks_request("run_mission_task_tests", body)
        self.assertEqual(panel.policy_job, ("run_mission_task_tests", body))

    def test_create_delete_candidates_and_npm_missing_script(self):
        item = self.create(checks=["npm_test"])
        workspace = self.draft()
        staged = workspaces.stage_mission_new_file(workspace, "package.json", json.dumps({"scripts": {"test": "node -e 'process.exit(0)'"}}))
        self.assertEqual(staged["status"], "ok", staged)
        # Check the actual staging API response rather than accidentally testing
        # an unbound fabricated candidate.
        source = workspaces._workspace(workspaces._workspace_directory(self.policy), workspace, self.policy)
        if not any(f["relative_path"] == "package.json" for f in source["files"]):
            self.fail("new file did not stage")
        workspaces.submit_mission_workspace(workspace)
        tasks.report_mission_progress(item["mission_id"], item["revision"], "needs_review", "Ready", workspace)
        item = self.latest(item)
        imported = operator(tasks.import_mission_task_review, item["mission_id"], item["revision"])
        item = self.run_tests(imported["mission"])
        self.assertTrue(item["checks"]["capsules"][0]["passed"], item)
        self.assertFalse((self.project / "package.json").exists())


if __name__ == "__main__":
    unittest.main()
