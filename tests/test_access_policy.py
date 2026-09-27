"""Live MCP entry-point restrictions and private, atomic operator policies."""
from __future__ import annotations

import asyncio
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src import access_policy as access, project_workspace, safety


class TestAccessPolicy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = str(Path(self.temp.name) / "vps-guardian-access")
        self.path_patch = patch("src.access_policy.policy_directory", return_value=self.directory)
        self.path_patch.start()
        self.audit_patch = patch("src.safety.record_audit_event")
        self.audit_patch.start()

    def tearDown(self):
        self.audit_patch.stop()
        self.path_patch.stop()
        self.temp.cleanup()

    def save(self, **changes):
        policy = {**access.load_policy()["policy"], **changes}
        return access.save_access_policy(policy, access.load_policy()["revision"])

    def test_defaults_preserve_launch_behavior_without_creating_files(self):
        self.assertEqual(access.load_policy()["policy"], access.DEFAULT_POLICY)
        self.assertFalse(os.path.exists(self.directory))
        self.assertIsNone(access.access_denial("get_system_health"))
        self.assertGreater(len(access.tool_catalog()), 100)

    def test_pause_and_resume_without_restart(self):
        self.assertEqual(self.save(enabled=False)["status"], "ok")
        self.assertEqual(access.access_denial("get_system_health")["status"], "forbidden")
        self.assertIsNone(access.access_denial("get_safety_status"))
        self.assertEqual(access.mode_cap(), "read-only")
        self.assertEqual(self.save(enabled=True)["status"], "ok")
        self.assertIsNone(access.access_denial("get_system_health"))

    def test_explicit_allowlist_denies_unlisted_and_future_tools(self):
        self.save(allowed_tools=["get_system_health"])
        self.assertIsNone(access.access_denial("get_system_health"))
        self.assertIsNone(access.access_denial("get_safety_status"))
        self.assertEqual(access.access_denial("restart_service")["status"], "forbidden")
        self.assertEqual(access.access_denial("a_future_tool")["status"], "forbidden")

    def test_cap_cannot_escalate_the_launch_mode(self):
        for launch in access.MODES:
            for cap in access.MODES:
                with self.subTest(launch=launch, cap=cap), patch.dict(os.environ, {"VPS_GUARDIAN_MODE": launch}):
                    self.save(mode_cap=cap)
                    expected = min((launch, cap), key=access.MODES.get)
                    self.assertEqual(safety.get_safety_mode(), expected)

    def test_compare_and_swap_prevents_overwriting_newer_policy(self):
        before = access.get_access_policy()
        saved = self.save(mode_cap="read-only")
        self.assertNotEqual(saved["revision"], before["revision"])
        stale = access.save_access_policy(before["policy"], before["revision"])
        self.assertEqual(stale["status"], "conflict")
        self.assertEqual(access.load_policy()["revision"], saved["revision"])

    def test_invalid_values_do_not_save(self):
        invalid = [{"extra": True}, {"enabled": 1}, {"mode_cap": []}, {"mode_cap": "admin"},
                   {"allowed_tools": ["save_access_policy"]}, {"allowed_tools": [1]},
                   {"project_roots": ["relative"]}, {"project_roots": [os.path.abspath(os.sep)]},
                   {"project_roots": [self.temp.name + "\nsecret"]}]
        for fields in invalid:
            result = access.save_access_policy({**access.DEFAULT_POLICY, **fields}, "none")
            self.assertEqual(result["status"], "error", fields)
        self.assertEqual(access.load_policy()["revision"], "none")

    def test_corrupt_or_oversized_policy_fails_closed_and_can_be_repaired(self):
        self.save()
        for raw in (b"{", b"x" * (access.MAX_POLICY_BYTES + 1)):
            Path(access.policy_path()).write_bytes(raw)
            state = access.load_policy()
            self.assertIsNotNone(state["error"])
            self.assertFalse(state["policy"]["enabled"])
            self.assertEqual(access.access_denial("get_system_health")["status"], "forbidden")
        # Oversized previous files must be repaired manually, never read unbounded.
        Path(access.policy_path()).write_bytes(b"{")
        result = access.save_access_policy(copy.deepcopy(access.DEFAULT_POLICY), access.load_policy()["revision"])
        self.assertEqual(result["status"], "ok")

    @unittest.skipIf(os.name == "nt", "POSIX ownership/permission guards")
    def test_unsafe_parent_fails_closed_even_when_policy_is_missing(self):
        Path(self.directory).mkdir(mode=0o777)
        os.chmod(self.directory, 0o777)
        self.assertFalse(access.load_policy()["policy"]["enabled"])
        self.assertEqual(self.save()["status"], "error")

    @unittest.skipIf(os.name == "nt", "POSIX symlink/permission guards")
    def test_symlink_policy_and_link_roots_rejected(self):
        self.save()
        Path(access.policy_path()).unlink()
        target = Path(self.temp.name) / "target"
        target.write_text("{}")
        Path(access.policy_path()).symlink_to(target)
        self.assertFalse(access.load_policy()["policy"]["enabled"])
        link = Path(self.temp.name) / "linked-root"
        link.symlink_to(Path(self.temp.name), target_is_directory=True)
        self.assertEqual(self.save(project_roots=[str(link)])["status"], "error")

    @unittest.skipIf(os.name == "nt", "POSIX private file modes")
    def test_saved_policy_and_directory_are_private(self):
        self.save()
        self.assertEqual(os.stat(self.directory).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(access.policy_path()).st_mode & 0o777, 0o600)

    def test_custom_project_roots_replace_env_and_empty_blocks_projects(self):
        root = Path(self.temp.name) / "project"
        root.mkdir()
        with patch.dict(os.environ, {"VPS_GUARDIAN_PROJECT_ROOTS": self.temp.name}):
            self.save(project_roots=[str(root)])
            self.assertEqual(project_workspace._roots(), [str(root.resolve())])
            self.assertIsNotNone(project_workspace._project_path(self.temp.name)[1])
            self.save(project_roots=[])
            self.assertEqual(project_workspace._roots(), [])
            self.save(project_roots=None)
            self.assertEqual(project_workspace._roots(), [str(Path(self.temp.name).resolve())])

    def test_project_and_file_tools_cannot_edit_operator_policy(self):
        from src.files import is_path_permitted
        self.save(project_roots=[self.temp.name])
        self.assertIsNotNone(project_workspace._project_path(self.directory)[1])
        path, error = project_workspace._project_file(self.temp.name, "vps-guardian-access/policy.json")
        self.assertIsNone(path)
        self.assertEqual(error["status"], "forbidden")
        with patch("src.files.get_allowed_directories", return_value=[self.temp.name]):
            self.assertFalse(is_path_permitted(access.policy_path())[0])

    def test_actual_registered_tool_is_revoked_in_same_process(self):
        from src import server
        with patch("src.server._get_system_health", return_value={"status": "ok"}) as health:
            self.assertEqual(server.get_system_health().structuredContent["status"], "ok")
            self.save(enabled=False)
            self.assertEqual(server.get_system_health().structuredContent["status"], "forbidden")
            self.assertEqual(health.call_count, 1)
            self.save(enabled=True)
            self.assertEqual(server.get_system_health().structuredContent["status"], "ok")

    def test_operator_helper_not_registered_as_agent_tools(self):
        from src import server
        tools = asyncio.run(server.mcp.list_tools())
        names = {tool.name for tool in tools}
        self.assertNotIn("save_access_policy", names)
        self.assertNotIn("get_access_policy", names)

    def test_resources_do_not_bypass_tool_restrictions(self):
        from src import server
        self.save(enabled=False)
        resources = asyncio.run(server.mcp.list_resources())
        self.assertEqual(len(resources), 3)
        for resource in resources:
            result = asyncio.run(server.mcp.read_resource(str(resource.uri)))
            contents = list(result)
            self.assertEqual(json.loads(contents[0].content)["status"], "forbidden")

    def test_selective_resource_denial_does_not_block_other_tools(self):
        from src import server
        self.save(allowed_tools=["get_system_health"])
        with patch("src.server._get_system_health", return_value={"status": "ok"}) as health:
            self.assertEqual(server.get_system_health().structuredContent["status"], "ok")
            self.assertEqual(json.loads(server.get_system_overview_resource())["status"], "forbidden")
            self.assertEqual(health.call_count, 1)


if __name__ == "__main__":
    unittest.main()
