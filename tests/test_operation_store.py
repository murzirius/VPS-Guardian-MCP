"""Shared drafts survive process boundaries; unsafe or uncertain writes fail closed."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from mcp import StdioServerParameters
from src import operation_store as store, project_workspace as workspace, changeset, access_policy, agent_jobs
from src.local_panel import PanelController, PanelInputError


class TestSharedOperations(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.policy = str(self.directory / "policy")
        self.project = self.directory / "worker"
        self.project.mkdir()
        (self.project / "main.py").write_text("API_TOKEN=private-baseline\nprint('old')\n", encoding="utf-8")
        for item in (patch.object(access_policy, "policy_directory", return_value=self.policy),
                     patch.dict(os.environ, {"VPS_GUARDIAN_PROJECT_ROOTS": str(self.project), "VPS_GUARDIAN_MODE": "controlled"}),
                     patch("src.project_workspace.record_audit_event", return_value=None)):
            item.start()
            self.addCleanup(item.stop)

    def draft(self):
        result = workspace.begin_project_patch(str(self.project), "Update worker")
        self.assertEqual(result["status"], "ok", result)
        return result["patch"]["patch_id"]

    def child(self, expression):
        script = "from unittest.mock import patch; from src import access_policy, project_workspace as w, operation_store as s; import json; " + f"access_policy.policy_directory=lambda:{self.policy!r}; " + expression
        result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_draft_staging_and_fresh_confirmation_survive_other_process(self):
        identity = self.draft()
        workspace.stage_project_file_change(identity, "main.py", "API_TOKEN=private-candidate\nprint('new')\n")
        old = workspace.preview_project_patch(identity)
        result = self.child(f"print(json.dumps(w.preview_project_patch({identity!r})))")
        self.assertEqual(result["status"], "confirmation_required")
        self.assertNotEqual(old["confirmation_token"], result["confirmation_token"])
        self.assertNotIn("private-baseline", json.dumps(result))
        self.assertNotIn("private-candidate", json.dumps(result))
        with patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "unrestricted"}):
            applied = self.child(f"print(json.dumps(w.apply_project_patch({identity!r})))")
        self.assertTrue(applied["success"], applied)
        self.assertIn("print('new')", (self.project / "main.py").read_text(encoding="utf-8"))
        history = store.get_operation(identity)["operation"]
        self.assertEqual(history["state"], "completed")
        self.assertTrue(history["result"]["success"])
        self.assertEqual(workspace.preview_project_patch(identity)["status"], "error")
        with store.transaction() as connection:
            self.assertIsNone(connection.execute("SELECT payload FROM operations WHERE id=?", (identity,)).fetchone()[0])

    def test_history_never_exposes_source_original_tokens_or_raw_output(self):
        identity = self.draft()
        workspace.stage_project_file_change(identity, "main.py", "API_TOKEN=private-candidate\n")
        workspace.preview_project_patch(identity)
        metadata = json.dumps(store.list_operations()) + json.dumps(store.get_operation(identity))
        for forbidden in ("private-baseline", "private-candidate", "confirmation_token", "original", "content"):
            self.assertNotIn(forbidden, metadata)
        self.assertIn("candidate_sha256", metadata)

    def test_concurrent_process_style_mappings_merge_under_sqlite_lock(self):
        identity = self.draft()
        def update(field):
            other = store.PersistentDrafts("patch", 24)
            with other:
                item = other[identity]
                item[field] = field
                time.sleep(.03)
        with ThreadPoolExecutor(2) as pool:
            list(pool.map(update, ["first", "second"]))
        with workspace._patch_lock:
            self.assertEqual(workspace._patches[identity]["first"], "first")
            self.assertEqual(workspace._patches[identity]["second"], "second")

    def test_interrupted_apply_never_replays_and_becomes_uncertain(self):
        identity = self.draft()
        workspace.stage_project_file_change(identity, "main.py", "print('new')\n")
        with patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "unrestricted"}), patch.object(workspace, "atomic_write_file", side_effect=OSError("Lost connection")) as write:
            self.assertEqual(workspace.apply_project_patch(identity)["status"], "storage_error")
            self.assertEqual(workspace.apply_project_patch(identity)["status"], "not_found")
            write.assert_called_once()
        with workspace._patch_lock:
            workspace._patches[identity]["expires_at"] = time.time() - 1
        metadata = store.get_operation(identity)["operation"]
        self.assertEqual(metadata["state"], "uncertain")
        self.assertEqual(workspace.preview_project_patch(identity)["status"], "error")

    def test_expiry_archives_and_capacity_does_not_evict_active_drafts(self):
        identity = self.draft()
        tiny = store.PersistentDrafts("patch", 1)
        with self.assertRaises(ValueError):
            with tiny:
                tiny["patch_newdraft123"] = {"patch_id": "patch_newdraft123", "title": "Overflow", "state": "staging", "files": [], "expires_at": time.time() + 10}
        self.assertEqual(store.get_operation(identity)["operation"]["state"], "staging")
        with workspace._patch_lock:
            workspace._patches[identity]["expires_at"] = time.time() - 1
        self.assertEqual(store.get_operation(identity)["operation"]["state"], "expired")

    def test_storage_capacity_failure_does_not_commit_mutated_candidate(self):
        identity = self.draft()
        workspace.stage_project_file_change(identity, "main.py", "print('first')\n")
        with patch.object(store, "MAX_ACTIVE_BYTES", 100):
            self.assertEqual(workspace.stage_project_file_change(identity, "main.py", "print('oversized')\n")["status"], "storage_error")
        preview = workspace.preview_project_patch(identity)
        self.assertIn("print('first')", preview["diffs"][0]["diff"])
        self.assertNotIn("oversized", str(preview))

    def test_concurrent_apply_claims_once_and_does_not_double_write(self):
        identity = self.draft()
        workspace.stage_project_file_change(identity, "main.py", "print('new')\n")
        entered, release = threading.Event(), threading.Event()
        original_write = workspace.atomic_write_file
        def slow_write(*args, **kwargs):
            entered.set()
            self.assertTrue(release.wait(5))
            return original_write(*args, **kwargs)
        with patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "unrestricted"}), patch.object(workspace, "atomic_write_file", side_effect=slow_write) as write, ThreadPoolExecutor(1) as pool:
            first = pool.submit(workspace.apply_project_patch, identity)
            try:
                self.assertTrue(entered.wait(3))
                self.assertEqual(workspace.apply_project_patch(identity)["status"], "not_found")
            finally:
                release.set()
            self.assertTrue(first.result(5)["success"])
            write.assert_called_once()

    def test_stable_cursor_includes_timestamp_ties_and_read_prunes_old_history(self):
        ids = [self.draft() for _ in range(3)]
        stamp = time.time()
        with store.transaction() as connection:
            connection.execute("UPDATE operations SET updated=?", (stamp,))
        seen, cursor = [], None
        for _ in range(3):
            response = store.list_operations(1, cursor)
            seen += [item["operation_id"] for item in response["operations"]]
            cursor = response["next_before"]
        self.assertEqual(sorted(seen), sorted(ids))
        with store.transaction() as connection:
            connection.execute("UPDATE operations SET payload=NULL,updated=? WHERE id=?", (time.time() - store.HISTORY_SECONDS - 1, ids[0]))
        self.assertEqual(store.get_operation(ids[0])["status"], "not_found")

    def test_jobs_shared_independent_of_session_state_directory(self):
        with patch.dict(os.environ, {"VPS_GUARDIAN_STATE_DIR": str(self.directory / "agent-one")}):
            result = agent_jobs.create_agent_job("Check worker health", ["runtime_budget"])
        identity = result["job"]["job_id"]
        with patch.dict(os.environ, {"VPS_GUARDIAN_STATE_DIR": str(self.directory / "agent-two")}):
            self.assertEqual(agent_jobs.get_agent_job(identity)["status"], "ok")
            self.assertEqual(store.get_operation(identity)["job"]["job_id"], identity)
            self.assertEqual(store.list_operations()["jobs"][0]["job_id"], identity)

    def test_read_only_mode_and_changed_roots_still_block_resumed_apply(self):
        identity = self.draft()
        workspace.stage_project_file_change(identity, "main.py", "print('new')\n")
        with patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "read-only"}):
            self.assertEqual(workspace.apply_project_patch(identity)["status"], "forbidden")
        before = access_policy.load_policy()
        access_policy.save_access_policy({**before["policy"], "project_roots": []}, before["revision"])
        self.assertEqual(workspace.apply_project_patch(identity)["status"], "forbidden")

    def test_changesets_also_visible_and_persist_across_mapping_instances(self):
        created = changeset.begin_change_set("Update web configuration")
        identity = created["change_set"]["change_set_id"]
        other = store.PersistentDrafts("changeset", 32)
        with other:
            self.assertEqual(other[identity]["title"], "Update web configuration")
        self.assertEqual(store.get_operation(identity)["operation"]["kind"], "changeset")

    def test_changeset_apply_persists_outcome_and_removes_source(self):
        config = self.directory / "nginx.conf"
        config.write_text("server {}\n", encoding="utf-8")
        identity = changeset.begin_change_set("Update test configuration")["change_set"]["change_set_id"]
        with patch.object(changeset, "is_path_permitted", return_value=(True, str(config))), patch.object(changeset, "_service_for_path", return_value="nginx"), patch.object(changeset, "_run_systemctl", return_value={"success": True}), patch.object(changeset, "test_nginx_config", return_value={"test_successful": True}), patch.object(changeset, "record_audit_event", return_value=None):
            self.assertEqual(changeset.stage_file_change(identity, str(config), "server { listen 80; }\n")["status"], "ok")
            preview = changeset.preview_change_set(identity)
            result = changeset.apply_change_set(identity, preview["confirmation_token"])
        self.assertTrue(result["success"], result)
        self.assertEqual(store.get_operation(identity)["operation"]["state"], "completed")
        self.assertEqual(changeset.preview_change_set(identity)["status"], "not_found")

    def test_unsafe_database_or_journal_fails_closed(self):
        self.draft()
        if os.name != "posix":
            self.skipTest("POSIX ownership checks")
        path = Path(store.job_directory()) / "operations.sqlite3"
        path.chmod(0o644)
        self.assertEqual(store.list_operations()["status"], "storage_error")
        path.chmod(0o600)
        (path.parent / (path.name + "-journal")).symlink_to(self.project / "main.py")
        self.assertEqual(store.list_operations()["status"], "storage_error")

    def test_regular_read_write_open_preserves_binary_eof_byte(self):
        from src.safe_io import open_regular_fd
        path = self.directory / "binary-state"
        path.write_bytes(b"state\x1a")
        descriptor = open_regular_fd(str(path), os.O_RDWR | os.O_CREAT)
        os.close(descriptor)
        self.assertEqual(path.read_bytes(), b"state\x1a")

    def test_strict_ids_pagination_and_bounded_timeline(self):
        self.assertEqual(store.get_operation("../policy.json")["status"], "error")
        self.assertEqual(store.list_operations(True)["status"], "error")
        self.assertEqual(store.list_operations(before=float("nan"))["status"], "error")
        identity = self.draft()
        for number in range(25):
            workspace.stage_project_file_change(identity, "main.py", f"print({number})\n")
        self.draft()
        first = store.list_operations(1)
        self.assertIsNotNone(first["next_before"])
        self.assertEqual(store.list_operations(1, first["next_before"])["operations"][0]["operation_id"], identity)
        result = store.get_operation(identity)
        self.assertEqual(result["status"], "ok", (identity, result))
        self.assertEqual(len(result["operation"]["events"]), 20)


class TestOperationsPanel(unittest.TestCase):
    def test_fixed_queue_validates_operations_and_old_server(self):
        controller = PanelController()
        controller.state.update(connection="connected", workspace_supported=True)
        with self.assertRaises(RuntimeError): controller.workspace_request("list_operations", {})
        controller.state["operations_supported"] = True
        with self.assertRaises(PanelInputError): controller.workspace_request("get_operation", {"operation_id": "../../bad"})
        controller.workspace_request("list_operations", {})
        self.assertEqual(controller.policy_job, ("list_operations", {}))
        with self.assertRaises(RuntimeError): controller.workspace_request("get_operation", {"operation_id": "job_0123456789abcdef"})
        controller.disconnect()
        self.assertIsNone(controller.status()["operations"])

    def test_actual_stdio_helper_reads_shared_agent_draft_while_agents_paused(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = str(Path(directory) / "policy")
            project = Path(directory) / "worker"
            project.mkdir()
            with patch.object(access_policy, "policy_directory", return_value=policy), patch.dict(os.environ, {"VPS_GUARDIAN_PROJECT_ROOTS": str(project)}):
                identity = workspace.begin_project_patch(str(project), "Shared panel draft")["patch"]["patch_id"]
                access_policy.save_access_policy({**access_policy.DEFAULT_POLICY, "enabled": False}, "none")
            params = StdioServerParameters(command=sys.executable, args=["-u", str(Path(__file__).with_name("panel_fixture.py"))], env={"PANEL_TEST_POLICY_DIR": policy})
            controller = PanelController()
            controller.state.update(connection="connected", workspace_supported=True, operations_supported=True)
            asyncio.run(controller._operator(params, "list_operations", {}))
            self.assertIsNone(controller.status()["operations_error"])
            self.assertEqual(controller.status()["operations"]["operations"][0]["operation_id"], identity)
            asyncio.run(controller._operator(params, "get_operation", {"operation_id": identity}))
            self.assertEqual(controller.status()["operation"]["operation"]["state"], "staging")
