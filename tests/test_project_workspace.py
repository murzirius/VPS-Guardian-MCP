"""Tests for bounded project workspace operations."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from src import project_workspace


class TestProjectWorkspace(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.environment = mock.patch.dict(os.environ, {"VPS_GUARDIAN_PROJECT_ROOTS": self.temp.name})
        self.environment.start()
        self.project = os.path.join(self.temp.name, "worker")
        os.mkdir(self.project)
        with open(os.path.join(self.project, "pyproject.toml"), "w", encoding="utf-8") as file:
            file.write("[project]\nname='worker'\n")
        with open(os.path.join(self.project, "main.py"), "w", encoding="utf-8") as file:
            file.write("API_TOKEN=secret-value\nprint('hello')\n")
        project_workspace._patches.clear()

    def tearDown(self):
        self.environment.stop(); self.temp.cleanup()

    def test_discover_and_inspect_project(self):
        found = project_workspace.discover_projects(self.temp.name)
        self.assertEqual(found["status"], "ok")
        self.assertEqual(found["projects"][0]["stacks"], ["python"])
        inspected = project_workspace.inspect_project(self.project)
        self.assertEqual(inspected["status"], "ok")

    def test_read_and_search_redact_secret(self):
        read = project_workspace.read_project_file(self.project, "main.py")
        self.assertNotIn("secret-value", read["content"])
        searched = project_workspace.search_project_code(self.project, "print")
        self.assertEqual(searched["matches"][0]["relative_path"], "main.py")

    def test_large_file_range_symbols_and_search(self):
        source = "".join(f"# filler {number:05d} {'x' * 40}\n" for number in range(3000))
        source += "def payment_handler():\n    return 'paid'\n"
        with open(os.path.join(self.project, "main.py"), "w", encoding="utf-8") as file:
            file.write(source)
        prefix = project_workspace.read_project_file(self.project, "main.py")
        self.assertTrue(prefix["is_truncated"])
        result = project_workspace.read_project_file_range(self.project, "main.py", start_line=3001)
        self.assertIn("payment_handler", result["content"])
        tail = project_workspace.read_project_file_range(self.project, "main.py", byte_offset=os.path.getsize(os.path.join(self.project, "main.py")) - 64, max_bytes=100)
        self.assertIn("payment_handler", tail["content"])
        self.assertEqual(project_workspace.read_project_file_range(self.project, "main.py", if_sha256=result["sha256"])["status"], "unchanged")
        self.assertEqual(project_workspace.get_project_symbols(self.project, "main.py")["symbols"][0]["start_line"], 3001)
        self.assertEqual(project_workspace.search_project_code(self.project, "payment_handler")["matches"][0]["line"], 3001)

    def test_stage_line_edit_on_large_file(self):
        source = "".join(f"# filler {number:05d} {'x' * 40}\n" for number in range(3000))
        source += "def payment_handler():\n    return 'old'\n"
        with open(os.path.join(self.project, "main.py"), "w", encoding="utf-8") as file:
            file.write(source)
        fingerprint = project_workspace.read_project_file_range(self.project, "main.py", start_line=3002)["sha256"]
        patch_id = project_workspace.begin_project_patch(self.project, "Fix payment handler")["patch"]["patch_id"]
        staged = project_workspace.stage_project_line_edit(patch_id, "main.py", 3002, 3002, "    return 'new'\n", fingerprint)
        self.assertEqual(staged["status"], "ok")
        preview = project_workspace.preview_project_patch(patch_id)
        self.assertIn("return 'new'", preview["diffs"][0]["diff"])
        with mock.patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "unrestricted"}):
            result = project_workspace.apply_project_patch(patch_id)
        self.assertTrue(result["success"])
        with open(os.path.join(self.project, "main.py"), encoding="utf-8") as file:
            self.assertIn("return 'new'", file.read())

    def test_line_edit_rejects_stale_fingerprint_and_escape(self):
        patch_id = project_workspace.begin_project_patch(self.project, "Fix payment handler")["patch"]["patch_id"]
        self.assertEqual(project_workspace.stage_project_line_edit(patch_id, "main.py", 1, 1, "pass\n", "0" * 64)["status"], "conflict")
        self.assertEqual(project_workspace.stage_project_line_edit(patch_id, "../outside.py", 1, 1, "pass\n")["status"], "error")

    def test_read_rejects_symlink_inside_project(self):
        alias = os.path.join(self.project, "alias.py")
        try:
            os.symlink(os.path.join(self.project, "main.py"), alias)
        except OSError:
            self.skipTest("Creating symlinks requires elevated privileges on this host")
        self.assertEqual(project_workspace.read_project_file_range(self.project, "alias.py")["status"], "forbidden")

    def test_patch_refuses_path_escape(self):
        patch = project_workspace.begin_project_patch(self.project, "Fix worker")
        staged = project_workspace.stage_project_file_change(patch["patch"]["patch_id"], "../outside.py", "pass")
        self.assertEqual(staged["status"], "error")

    def test_confirmed_patch_writes_backed_up_file(self):
        patch = project_workspace.begin_project_patch(self.project, "Fix worker")
        project_workspace.stage_project_file_change(patch["patch"]["patch_id"], "main.py", "print('fixed')\n")
        with mock.patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "unrestricted"}):
            result = project_workspace.apply_project_patch(patch["patch"]["patch_id"])
        self.assertTrue(result["success"])
        with open(os.path.join(self.project, "main.py"), encoding="utf-8") as file:
            self.assertEqual(file.read(), "print('fixed')\n")


if __name__ == "__main__":
    unittest.main()
