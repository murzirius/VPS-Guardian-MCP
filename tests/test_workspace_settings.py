"""Actual shared operator settings, live enforcement and bounded project metadata."""
import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mcp import StdioServerParameters
from src import access_policy as access, resource_policy as limits, project_workspace as workspace
from src import operator_projects, test_capsules, changeset
from src.local_panel import PanelController, PanelInputError, read_tool


class TestWorkspaceSettings(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.project = self.directory / "worker"
        self.project.mkdir()
        (self.project / "pyproject.toml").write_text("[project]\nname='worker'\n", encoding="utf-8")
        (self.project / "main.py").write_text("print('old')\n", encoding="utf-8")
        self.patches = [patch.object(access, "policy_directory", return_value=str(self.directory / "policy")),
                        patch("src.safety.record_audit_event", return_value=None),
                        patch.dict(os.environ, {"VPS_GUARDIAN_PROJECT_ROOTS": str(self.project)}),
                        patch.object(limits.psutil, "virtual_memory", return_value=SimpleNamespace(available=1024**3, total=2 * 1024**3)),
                        patch.object(limits.psutil, "cpu_count", return_value=2)]
        for item in self.patches: item.start()
        workspace._patches.clear()

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.temp.cleanup()

    def custom(self, **changes):
        return {"profile": "custom", "limits": {**limits.PRESETS["standard"], **changes}}

    def test_presets_persist_without_changing_access(self):
        before = access.load_policy()
        result = limits.save_workspace_settings({"profile": "small", "limits": {}}, "none")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["runtime"]["limits"]["project_read_bytes"], 32000)
        self.assertEqual(access.load_policy(), before)
        self.assertEqual(limits.load_settings()["revision"], result["revision"])
        self.assertEqual(limits.save_workspace_settings({"profile": "standard", "limits": {}}, "none")["status"], "conflict")
        self.assertEqual(limits.load_settings()["settings"]["profile"], "small")

    def test_custom_limits_reject_unknown_bool_out_of_range_and_missing(self):
        bad = [self.custom(project_read_bytes=True), self.custom(project_read_bytes=300001), self.custom(capsule_concurrency=2),
               {"profile": "custom", "limits": {}}, {"profile": "small", "limits": {"directory_items": 500}},
               {"profile": "oops", "limits": {}}, {"profile": "auto", "limits": {}, "command": "bad"}]
        for settings in bad:
            with self.subTest(settings=settings):
                self.assertEqual(limits.save_workspace_settings(settings, "none")["status"], "error")
                self.assertFalse(Path(limits.settings_path()).exists())

    def test_host_guards_cannot_be_raised_by_custom_settings(self):
        limits.save_workspace_settings(self.custom(project_read_bytes=300000), "none")
        with patch.object(limits.psutil, "virtual_memory", return_value=SimpleNamespace(available=200 * 1024**2, total=1024**3)):
            result = limits.get_runtime_budget()
        self.assertEqual(result["configured_profile"], "custom")
        self.assertEqual(result["profile"], "critical")
        self.assertEqual(result["limits"]["project_read_bytes"], 64000)
        self.assertEqual(result["limits"]["capsule_concurrency"], 0)
        self.assertEqual(result["limits"]["project_patch_files"], 1)
        self.assertIn("project_read_bytes", result["reduced_limits"])

    def test_invalid_private_file_falls_back_to_small(self):
        limits.save_workspace_settings({"profile": "standard", "limits": {}}, "none")
        Path(limits.settings_path()).write_text('{"profile":"unlimited"}', encoding="utf-8")
        state = limits.load_settings()
        self.assertEqual(state["settings"]["profile"], "small")
        self.assertTrue(state["error"])
        self.assertEqual(limits.save_workspace_settings({"profile": "auto", "limits": {}}, state["revision"])["status"], "ok")

    @unittest.skipUnless(os.name == "posix", "POSIX ownership/permissions")
    def test_unsafe_or_symlink_limits_are_never_followed(self):
        limits.save_workspace_settings({"profile": "standard", "limits": {}}, "none")
        stored = Path(limits.settings_path())
        stored.chmod(0o666)
        self.assertTrue(limits.load_settings()["error"])
        self.assertEqual(limits.save_workspace_settings({"profile": "auto", "limits": {}}, "unreadable")["status"], "error")
        stored.unlink()
        outside = self.directory / "outside.json"
        outside.write_text("secret", encoding="utf-8")
        stored.symlink_to(outside)
        self.assertTrue(limits.load_settings()["error"])
        self.assertEqual(outside.read_text(), "secret")

    def test_project_reads_follow_saved_limits_without_restart(self):
        (self.project / "main.py").write_text("# " + "x" * 200000, encoding="utf-8")
        initial = workspace.read_project_file(str(self.project), "main.py", 300000)
        self.assertEqual(initial["bytes_read"], 100000)
        result = limits.save_workspace_settings(self.custom(project_read_bytes=300000), "none")
        self.assertEqual(workspace.read_project_file(str(self.project), "main.py", 300000)["bytes_read"], 200002)
        limits.save_workspace_settings({"profile": "small", "limits": {}}, result["revision"])
        self.assertEqual(workspace.read_project_file(str(self.project), "main.py", 300000)["bytes_read"], 32000)
        self.assertEqual(workspace.read_project_file_range(str(self.project), "main.py", byte_offset=0, max_bytes=300000)["bytes_read"], 32000)

    def test_search_respects_byte_and_file_budgets(self):
        for index in range(20): (self.project / f"f{index}.py").write_text("# needle\n" * 500, encoding="utf-8")
        limits.save_workspace_settings(self.custom(project_search_files=10, project_search_bytes=64000), "none")
        result = workspace.search_project_code(str(self.project), "missing")
        self.assertLessEqual(result["scanned_files"], 10)
        self.assertLessEqual(result["scanned_bytes"], 64000)
        self.assertTrue(result["truncated"])

    def staged(self):
        patch_id = workspace.begin_project_patch(str(self.project), "Patch candidate")["patch"]["patch_id"]
        self.assertEqual(workspace.stage_project_file_change(patch_id, "main.py", "print('new')\n")["status"], "ok")
        return patch_id

    def test_revoked_root_blocks_cached_preview_stage_apply_and_capsule(self):
        patch_id = self.staged()
        policy = {**access.DEFAULT_POLICY, "project_roots": []}
        self.assertEqual(access.save_access_policy(policy, "none")["status"], "ok")
        with patch.object(workspace, "request_authorization") as authorize, patch.object(workspace, "atomic_write_file") as write:
            self.assertEqual(workspace.preview_project_patch(patch_id)["status"], "forbidden")
            self.assertEqual(workspace.stage_project_file_change(patch_id, "other.py", "pass\n")["status"], "forbidden")
            self.assertEqual(workspace.apply_project_patch(patch_id)["status"], "forbidden")
            self.assertEqual(test_capsules.test_project_patch(patch_id)["status"], "forbidden")
            authorize.assert_not_called(); write.assert_not_called()
        self.assertIn("old", (self.project / "main.py").read_text())

    def test_reduced_patch_budget_blocks_existing_candidate(self):
        patch_id = self.staged()
        workspace.stage_project_file_change(patch_id, "second.py", "pass\n")
        limits.save_workspace_settings({"profile": "small", "limits": {}}, "none")
        with patch.object(workspace, "atomic_write_file") as write:
            self.assertEqual(workspace.preview_project_patch(patch_id)["status"], "resource_limited")
            self.assertEqual(workspace.apply_project_patch(patch_id)["status"], "resource_limited")
            write.assert_not_called()

    def test_reduced_changeset_budget_blocks_cached_apply(self):
        limits.save_workspace_settings({"profile": "small", "limits": {}}, "none")
        item = {"files": [{"content": "x"}, {"content": "y"}]}
        with patch.object(changeset, "_active", return_value=item), patch.object(changeset, "request_authorization") as authorize:
            self.assertEqual(changeset.apply_change_set("fixture")["status"], "resource_limited")
            authorize.assert_not_called()

    def test_oversized_response_is_valid_json_keeps_status_token_id(self):
        limits.save_workspace_settings(self.custom(tool_response_bytes=16000), "none")
        data = {"status": "confirmation_required", "confirmation_token": "fixture-token", "patch_id": "fixture",
                "response_truncated": False, "content": "я" * 100000}
        result = limits.bounded_response(data, "fixture")
        raw = json.dumps(result, separators=(",", ":"), ensure_ascii=False).encode()
        self.assertLessEqual(len(raw), 16000)
        self.assertTrue(result["response_truncated"])
        self.assertEqual(result["confirmation_token"], "fixture-token")
        self.assertEqual(result["patch_id"], "fixture")
        self.assertEqual(result["status"], "confirmation_required")
        self.assertIn("content", result["omitted_fields"])

    def test_operator_project_scan_reads_metadata_only_and_hides_secrets(self):
        (self.project / ".env").write_text("TOKEN=secret", encoding="utf-8")
        (self.project / "credentials.json").write_text("secret", encoding="utf-8")
        with patch("subprocess.run", side_effect=AssertionError("No commands allowed")), patch("src.project_workspace.read_bounded", side_effect=AssertionError("No source reads")):
            result = operator_projects.list_operator_projects()
            self.assertIn(os.path.realpath(self.project), [row["path"] for row in result["projects"]])
            inspected = operator_projects.inspect_operator_project(str(self.project))
        names = [row["name"] for row in inspected["files"]]
        self.assertIn("main.py", names)
        self.assertNotIn(".env", names)
        self.assertNotIn("credentials.json", names)
        self.assertFalse(limits.load_settings()["configured"])
        self.assertEqual(operator_projects.inspect_operator_project(str(self.directory))["status"], "forbidden")
        self.assertEqual(operator_projects.inspect_operator_project("../worker")["status"], "forbidden")

    def test_project_scan_is_bounded_for_large_directories(self):
        for index in range(1100): (self.project / f"empty-{index}").touch()
        result = operator_projects.list_operator_projects()
        self.assertTrue(result["truncated"])
        self.assertLessEqual(result["scanned_entries"], 1000)
        self.assertLessEqual(len(operator_projects.inspect_operator_project(str(self.project))["files"]), 80)

    def test_helper_tools_are_not_ordinary_agent_tools(self):
        names = {item["name"] for item in access.tool_catalog()}
        for name in ("get_workspace_settings", "save_workspace_settings", "list_operator_projects", "inspect_operator_project"):
            self.assertNotIn(name, names)
            with self.assertRaises(ValueError): asyncio.run(read_tool(None, name))

    def test_server_wrapper_caps_output_without_repeating_mutation(self):
        from src import server
        limits.save_workspace_settings(self.custom(tool_response_bytes=16000), "none")
        with patch.object(server, "_apply_project_patch", return_value={"status": "ok", "success": True, "patch_id": "fixture", "writes": "x" * 100000}) as apply:
            result = server.apply_project_patch("fixture")
        apply.assert_called_once_with("fixture", None)
        self.assertTrue(result.structuredContent["success"])
        self.assertTrue(result.structuredContent["response_truncated"])
        self.assertEqual(json.loads(result.content[0].text), result.structuredContent)
        self.assertLessEqual(len(result.content[0].text.encode()), 16000)

    def test_redaction_handles_long_generated_lines_in_linear_time(self):
        import subprocess
        code = "from src.files import _redact_config_text; s='x'*300000+' https://user:secret@host'; out,n=_redact_config_text(s); assert 'secret' not in out and n==1"
        subprocess.run([sys.executable, "-c", code], check=True, timeout=5)


class TestWorkspacePanel(unittest.TestCase):
    def test_fixed_queue_validates_and_rejects_concurrent_requests(self):
        controller = PanelController()
        with self.assertRaises(RuntimeError): controller.workspace_request("get_workspace_settings", {})
        controller.state.update(connection="connected", workspace_supported=True)
        for name, data in (("exec", {}), ("get_workspace_settings", {"command": "bad"}),
                           ("save_workspace_settings", {"settings": {}, "expected_revision": "none"}),
                           ("inspect_operator_project", {"project_path": "x\ncommand"})):
            with self.assertRaises(PanelInputError): controller.workspace_request(name, data)
        controller.workspace_request("get_workspace_settings", {})
        with self.assertRaises(RuntimeError): controller.workspace_request("list_operator_projects", {})
        controller.disconnect()
        self.assertIsNone(controller.policy_job)

    def wait(self, controller):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            state = controller.status()
            if state["connection"] == "error": self.fail(str(state))
            if state["connection"] == "connected" and not state["policy_busy"]: return state
            time.sleep(.05)
        self.fail(str(controller.status()))

    def test_real_stdio_projects_limits_save_reload_and_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "worker"; project.mkdir()
            (project / "pyproject.toml").write_text("[project]\nname='worker'", encoding="utf-8")
            params = StdioServerParameters(command=sys.executable, args=["-u", str(Path(__file__).with_name("panel_fixture.py"))],
                env={"PANEL_TEST_POLICY_DIR": str(Path(directory) / "policy"), "VPS_GUARDIAN_PROJECT_ROOTS": str(project)})
            controller = PanelController()
            with patch("src.local_panel.ssh_parameters", return_value=params):
                try:
                    controller.connect({"host": "fixture.example"})
                    state = self.wait(controller)
                    self.assertTrue(state["workspace_supported"])
                    self.assertEqual(state["workspace"]["revision"], "none")
                    controller.workspace_request("save_workspace_settings", {"settings": {"profile": "small", "limits": {}}, "expected_revision": "none"})
                    state = self.wait(controller)
                    self.assertEqual(state["workspace"]["runtime"]["limits"]["project_read_bytes"], 32000)
                    controller.workspace_request("get_workspace_settings", {})
                    self.assertEqual(self.wait(controller)["workspace"]["settings"]["profile"], "small")
                    controller.workspace_request("save_workspace_settings", {"settings": {"profile": "standard", "limits": {}}, "expected_revision": "none"})
                    self.assertIn("changed elsewhere", self.wait(controller)["workspace_error"])
                    controller.workspace_request("list_operator_projects", {})
                    self.assertEqual(self.wait(controller)["projects"]["projects"][0]["path"], os.path.realpath(project))
                    controller.workspace_request("inspect_operator_project", {"project_path": str(project)})
                    self.assertEqual(self.wait(controller)["project"]["name"], "worker")
                    controller.workspace_request("inspect_operator_project", {"project_path": str(Path(directory))})
                    state = self.wait(controller)
                    self.assertIsNone(state["project"])
                    self.assertTrue(state["projects_error"])
                    self.assertEqual(state["access"]["revision"], "none")
                finally: controller.close()
