"""Snapshot binding, approval separation, durable recovery and bounded reads."""
from contextlib import ExitStack, contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src import gateway, mission_control as missions
from src.local_panel import PanelController, PanelInputError
from src.safe_io import atomic_replace, private_directory, read_bounded


def operator(function, *args):
    # Unit tests exercise the workflow without pretending to be Linux root.
    # The public root/SSH boundary is exercised by the isolated integration test.
    return missions._safe_errors(function.__wrapped__.__wrapped__)(*args)


class TestMissionWorkflow(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        temp = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.base = Path(temp).resolve()
        self.project = self.base / "project"
        self.project.mkdir()
        self.file = self.project / "main.py"
        self.file.write_bytes(b"print('original')\n")
        self.policy = {"agent_id": "bot", "uid": getattr(os, "geteuid", lambda: 0)(), "account": "vg_bot",
                       "profile": "mission-worker", "enabled": True, "project_roots": [str(self.project)],
                       "key_fingerprint": "SHA256:" + "a" * 43}
        self.stack.enter_context(patch("src.gateway.HOME_BASE", self.base / "agents"))
        self.stack.enter_context(patch("src.gateway.POLICY_BASE", self.base / "policies"))
        self.stack.enter_context(patch("src.gateway._trusted_directory"))
        self.stack.enter_context(patch("src.mission_control._worker_policy", return_value=self.policy))
        self.stack.enter_context(patch("src.mission_control._live_policy", return_value=self.policy))
        self.stack.enter_context(patch("src.mission_control._budget", return_value=(3, 100000, 300000)))
        self.stack.enter_context(patch("src.mission_control._review_directory", side_effect=lambda: Path(private_directory(str(self.base / "reviews")))))
        self.stack.enter_context(patch("src.mission_control._read_json", side_effect=lambda path, **kw: json.loads(read_bounded(str(path), missions.MAX_RECORD_BYTES, private=True))))
        self.real_target = missions._target
        self.stack.enter_context(patch("src.mission_control._target", side_effect=self.target))

        @contextmanager
        def lock(policy):
            yield Path(private_directory(str(missions._workspace_directory(policy))))
        self.stack.enter_context(patch("src.mission_control._workspace_lock", side_effect=lock))

    def target(self, policy, project, relative):
        root = missions._project(policy, str(project))
        if not isinstance(relative, str) or not missions._allowed(relative) or ".." in relative.split("/"):
            raise ValueError("Invalid test target")
        path = root / relative
        return path, missions._text(read_bounded(str(path), 100000).decode())

    def draft(self, content="print('candidate')\n"):
        created = missions.create_mission_workspace(str(self.project), ["main.py"], "Review update")
        self.assertEqual(created["status"], "ok", created)
        workspace = created["workspace"]
        staged = missions.stage_mission_file(workspace["workspace_id"], "main.py", content, workspace["files"][0]["candidate_sha256"])
        self.assertEqual(staged["status"], "ok", staged)
        return workspace["workspace_id"]

    def review(self, content="print('candidate')\n"):
        workspace_id = self.draft(content)
        self.assertEqual(missions.submit_mission_workspace(workspace_id)["status"], "ok")
        result = operator(missions.import_mission_review, "bot", workspace_id)
        self.assertEqual(result["status"], "ok", result)
        return workspace_id, result["review"]

    def approve(self, review):
        result = operator(missions.decide_mission_review, review["review_id"], review["digest"], "approve")
        self.assertEqual(result["status"], "ok", result)

    def test_production_unchanged_until_operator_approval_and_apply(self):
        workspace, review = self.review()
        self.assertEqual(self.file.read_bytes(), b"print('original')\n")
        refused = operator(missions.apply_mission_review, review["review_id"], review["digest"])
        self.assertEqual(refused["status"], "error")
        self.approve(review)
        self.assertEqual(self.file.read_bytes(), b"print('original')\n")
        result = operator(missions.apply_mission_review, review["review_id"], review["digest"])
        self.assertEqual(result["review"]["state"], "completed", result)
        self.assertEqual(self.file.read_bytes(), b"print('candidate')\n")
        self.assertFalse(result["review"]["result"]["automatic_replay"])
        backup = result["review"]["result"]["written"][0]["backup"]
        self.assertEqual(Path(backup).read_bytes(), b"print('original')\n")
        self.assertEqual(operator(missions.apply_mission_review, review["review_id"], review["digest"])["status"], "error")

    def test_agent_snapshot_substitution_cannot_change_imported_bytes(self):
        workspace, review = self.review()
        proposal = missions._workspace_directory(self.policy) / (workspace + ".json")
        value = json.loads(proposal.read_bytes())
        value["files"][0]["candidate"] = "print('substituted')\n"
        missions._write(proposal, value)
        reimported = operator(missions.import_mission_review, "bot", workspace)
        self.assertEqual(reimported["review"]["digest"], review["digest"])
        self.assertNotIn("substituted", reimported["diff"])
        self.approve(review)
        operator(missions.apply_mission_review, review["review_id"], review["digest"])
        self.assertEqual(self.file.read_bytes(), b"print('candidate')\n")

    def test_changed_baseline_refuses_approval_and_apply(self):
        _, review = self.review()
        self.file.write_bytes(b"print('external')\n")
        self.assertEqual(operator(missions.decide_mission_review, review["review_id"], review["digest"], "approve")["status"], "error")
        self.file.write_bytes(b"print('original')\n")
        self.approve(review)
        self.file.write_bytes(b"print('external')\n")
        self.assertEqual(operator(missions.apply_mission_review, review["review_id"], review["digest"])["status"], "error")
        self.assertEqual(self.file.read_bytes(), b"print('external')\n")

    def test_wrong_digest_rejection_and_scope_change(self):
        _, review = self.review()
        self.assertEqual(operator(missions.decide_mission_review, review["review_id"], "0" * 64, "approve")["status"], "error")
        self.policy["project_roots"] = []
        self.assertEqual(operator(missions.decide_mission_review, review["review_id"], review["digest"], "approve")["status"], "error")
        rejected = operator(missions.decide_mission_review, review["review_id"], review["digest"], "reject")
        self.assertEqual(rejected["review"]["state"], "rejected")
        self.assertEqual(operator(missions.apply_mission_review, review["review_id"], review["digest"])["status"], "error")

    def test_revocation_and_expiry_invalidate_approved_review(self):
        _, review = self.review()
        self.approve(review)
        with patch("src.mission_control._live_policy", side_effect=PermissionError("revoked")):
            self.assertEqual(operator(missions.apply_mission_review, review["review_id"], review["digest"])["status"], "error")
        with patch("src.mission_control.time.time", return_value=review["expires_at"] + 1):
            self.assertEqual(operator(missions.apply_mission_review, review["review_id"], review["digest"])["status"], "error")

    def test_durable_claim_precedes_write_and_uncertain_never_replays(self):
        _, review = self.review()
        self.approve(review)
        replace = missions.atomic_replace
        def fail_write(path, data, **kwargs):
            if Path(path) == self.file:
                saved = json.loads((self.base / "reviews" / (review["review_id"] + ".json")).read_bytes())
                self.assertEqual(saved["state"], "applying")
                raise OSError("simulated write failure")
            return replace(path, data, **kwargs)
        with patch("src.mission_control.atomic_replace", side_effect=fail_write):
            result = operator(missions.apply_mission_review, review["review_id"], review["digest"])
        self.assertEqual(result["review"]["state"], "uncertain")
        self.assertEqual(operator(missions.apply_mission_review, review["review_id"], review["digest"])["status"], "error")

    def test_abandoned_applying_record_becomes_uncertain_on_reconnect(self):
        _, review = self.review()
        path = self.base / "reviews" / (review["review_id"] + ".json")
        saved = json.loads(path.read_bytes())
        saved["state"] = "applying"
        missions._write(path, saved)
        reloaded = operator(missions.get_mission_review, review["review_id"])
        self.assertEqual(reloaded["review"]["state"], "uncertain")

    def test_truncated_diff_cannot_be_approved(self):
        _, review = self.review("x" * 50000 + "\n")
        detail = operator(missions.get_mission_review, review["review_id"])
        self.assertTrue(detail["diff_truncated"])
        self.assertEqual(operator(missions.decide_mission_review, review["review_id"], review["digest"], "approve")["status"], "error")

    def test_line_edit_hash_conflict_freeze_and_restart_listing(self):
        workspace = self.draft()
        info = missions.read_mission_workspace(workspace, "main.py")
        sha = info["workspace"]["files"][0]["candidate_sha256"]
        self.assertEqual(missions.stage_mission_line_edit(workspace, "main.py", 1, 1, "print('small edit')\n", "bad")["status"], "conflict")
        result = missions.stage_mission_line_edit(workspace, "main.py", 1, 1, "print('small edit')\n", sha)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(missions.read_mission_workspace(workspace, "main.py")["content"], "print('small edit')\n")
        self.assertEqual(missions.list_mission_workspaces()["workspaces"][0]["workspace_id"], workspace)
        missions.submit_mission_workspace(workspace)
        self.assertEqual(missions.stage_mission_file(workspace, "main.py", "x", result["workspace"]["files"][0]["candidate_sha256"])["status"], "error")
        self.assertEqual(operator(missions.list_mission_submissions, "bot")["submissions"][0]["workspace_id"], workspace)

    def test_invalid_sources_paths_payloads_and_capacity(self):
        for paths in (["../main.py"], [".env"], ["main.py", "main.py"], [], ["main.py"] * 4):
            self.assertEqual(missions.create_mission_workspace(str(self.project), paths, "bad")["status"], "error")
        workspace = self.draft()
        sha = missions.read_mission_workspace(workspace, "main.py")["workspace"]["files"][0]["candidate_sha256"]
        for content in ("a" * 100001, "password = 'secret-value'\n", "bad\0data", "\n" * 2001):
            self.assertEqual(missions.stage_mission_file(workspace, "main.py", content, sha)["status"], "error")
        for _ in range(missions.MAX_WORKSPACES - 1):
            self.draft()
        self.assertEqual(missions.create_mission_workspace(str(self.project), ["main.py"], "over capacity")["status"], "error")

    def test_source_does_not_run_and_read_ranges_are_bounded(self):
        marker = self.project / "must-not-exist"
        self.file.write_bytes(("open(" + repr(str(marker)) + ", 'w').write('bad')\n" + "#" * 400).encode())
        workspace = self.draft()
        info = missions.read_mission_workspace(workspace, "main.py", 0, 100)
        self.assertLessEqual(len(info["content"].encode()), 100)
        self.assertFalse(marker.exists())
        self.assertEqual(missions.read_mission_workspace(workspace, "unknown.py")["status"], "error")
        self.assertEqual(missions.read_mission_workspace(workspace, "main.py", -1)["status"], "error")

    def test_tampered_root_snapshot_digest_refuses_apply(self):
        _, review = self.review()
        self.approve(review)
        path = self.base / "reviews" / (review["review_id"] + ".json")
        saved = json.loads(path.read_bytes())
        saved["files"][0]["candidate"] = "tampered"
        missions._write(path, saved)
        self.assertEqual(operator(missions.apply_mission_review, review["review_id"], review["digest"])["status"], "error")


class TestMissionBoundaries(unittest.TestCase):
    def test_legacy_and_editor_identity_cannot_create_workspace(self):
        for policy in (None, {}, {"profile": "project-editor"}, {"profile": "observer"}):
            with patch("src.gateway._active_policy", return_value=policy):
                self.assertEqual(missions.create_mission_workspace("/srv/test", ["main.py"], "test")["status"], "error")

    def test_budget_refuses_low_memory_and_honors_host_caps(self):
        from src.resource_policy import get_runtime_budget
        budget = get_runtime_budget()
        budget["available_memory_bytes"] = 95 * 1024 * 1024
        with patch("src.mission_control.get_runtime_budget", return_value=budget), self.assertRaises(ValueError):
            missions._budget()
        budget["available_memory_bytes"] = 512 * 1024 * 1024
        budget["limits"].update(project_patch_files=1, project_read_bytes=50000, project_patch_bytes=50000)
        with patch("src.mission_control.get_runtime_budget", return_value=budget):
            self.assertEqual(missions._budget(), (1, 50000, 50000))

    def test_guardian_source_and_parent_roots_are_excluded(self):
        source = Path(missions.__file__).resolve().parent
        policy = {"project_roots": [str(source.parent)]}
        with patch("src.gateway._trusted_directory"):
            for path in (source, source.parent):
                with self.assertRaises(PermissionError):
                    missions._project(policy, str(path))

    def test_atomic_replace_checks_baseline_inside_pinned_write(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "main.py"
            path.write_bytes(b"original")
            with self.assertRaises(OSError):
                atomic_replace(str(path), b"changed", backup=True, expected_sha256="0" * 64)
            self.assertEqual(path.read_bytes(), b"original")
            self.assertFalse(list(Path(temp).glob("*.bak*")))
            atomic_replace(str(path), b"changed", expected_sha256=hashlib.sha256(b"original").hexdigest())
            self.assertEqual(path.read_bytes(), b"changed")

    def test_panel_accepts_only_fixed_scoped_review_requests(self):
        panel = PanelController()
        panel.state.update(connection="connected", mission_supported=True)
        for data in ({"review_id": "../../etc"}, {"review_id": "review_" + "a" * 24, "command": "sh"}):
            with self.assertRaises(PanelInputError):
                panel.mission_request("get_mission_review", data)
        with self.assertRaises(PanelInputError):
            panel.mission_request("apply_mission_review", {"review_id": "review_" + "a" * 24, "digest": "wrong"})
        panel.mission_request("list_mission_reviews", {})
        self.assertEqual(panel.policy_job, ("list_mission_reviews", {}))
        with self.assertRaises(RuntimeError):
            panel.mission_request("list_mission_reviews", {})

    def test_operator_tools_never_appear_in_agent_catalog(self):
        from src.access_policy import tool_catalog
        names = {tool["name"] for tool in tool_catalog()}
        self.assertTrue(set(gateway.MISSION_TOOLS).issubset(names))
        self.assertFalse(missions.OPERATOR_TOOLS & names)
        self.assertNotIn("apply_project_patch", gateway.MISSION_TOOLS)
        self.assertNotIn("begin_project_patch", gateway.MISSION_TOOLS)

    @unittest.skipIf(os.name == "nt", "POSIX file ownership and permissions")
    def test_proposal_special_files_links_and_permissive_permissions_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state.json"
            path.write_text("{}")
            path.chmod(0o644)
            with self.assertRaises(PermissionError):
                missions._read_json(path, uid=os.geteuid())
            path.chmod(0o600)
            self.assertEqual(missions._read_json(path, uid=os.geteuid()), {})
            with self.assertRaises(PermissionError):
                missions._read_json(path, uid=os.geteuid() + 1)
            linked = Path(temp) / "linked.json"
            os.link(path, linked)
            with self.assertRaises(PermissionError):
                missions._read_json(path, uid=os.geteuid())
            fifo = Path(temp) / "fifo.json"
            os.mkfifo(fifo)
            with self.assertRaises(OSError):
                missions._read_json(fifo, uid=os.geteuid())


if __name__ == "__main__":
    unittest.main()
