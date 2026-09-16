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
