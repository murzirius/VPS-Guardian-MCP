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
from src.safe_io import atomic_create, atomic_replace, backed_up_delete, private_directory, read_bounded


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
        self.stack.enter_context(patch("src.mission_control._budget", return_value=(16, 512000, 1000000)))
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
        return path, missions._text(read_bounded(str(path), missions._budget()[1]).decode())

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

    def test_copied_source_and_ids_survive_production_change_without_authorizing_it(self):
        workspace = self.draft()
        missions.submit_mission_workspace(workspace)
        self.file.write_bytes(b"print('external')\n")
        read = missions.read_mission_workspace(workspace, "main.py")
        self.assertEqual(read["status"], "ok", read)
        self.assertEqual(read["content"], "print('candidate')\n")
        self.assertFalse(read["live_baseline_checked"])
        listed = missions.list_mission_workspaces()
        self.assertEqual(listed["workspaces"][0]["workspace_id"], workspace)
        self.assertFalse(listed["live_baseline_checked"])
        submitted = operator(missions.list_mission_submissions, "bot")
        self.assertEqual(submitted["submissions"][0]["workspace_id"], workspace)
        self.assertEqual(operator(missions.import_mission_review, "bot", workspace)["status"], "error")
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
        for paths in (["../main.py"], [".env"], ["main.py", "main.py"], ["main.py"] * 17):
            self.assertEqual(missions.create_mission_workspace(str(self.project), paths, "bad")["status"], "error")
        workspace = self.draft()
        sha = missions.read_mission_workspace(workspace, "main.py")["workspace"]["files"][0]["candidate_sha256"]
        for content in ("a" * 512001, "password = 'secret-value'\n", "bad\0data", "\n" * 10001):
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

    def test_large_file_line_window_and_small_edit(self):
        self.file.write_bytes(("# readable project source " + "x" * 60 + "\n").encode() * 4000)
        created = missions.create_mission_workspace(str(self.project), ["main.py"], "Large source")
        self.assertEqual(created["status"], "ok", created)
        workspace = created["workspace"]["workspace_id"]
        window = missions.read_mission_workspace_lines(workspace, "main.py", 3999, 2)
        self.assertEqual(window["status"], "ok", window)
        self.assertNotIn("workspace", window)  # Do not repeat all file metadata.
        changed = missions.stage_mission_line_edit(workspace, "main.py", 4000, 4000, "print('last')\n", window["candidate_sha256"])
        self.assertEqual(changed["status"], "ok", changed)
        self.assertEqual(missions.read_mission_workspace_lines(workspace, "main.py", 4000)["content"], "print('last')\n")
        self.assertEqual(missions.submit_mission_workspace(workspace)["status"], "ok")
        reviewed = operator(missions.import_mission_review, "bot", workspace)
        self.assertFalse(reviewed["diff_truncated"])
        self.approve(reviewed["review"])
        self.assertEqual(operator(missions.apply_mission_review, reviewed["review"]["review_id"], reviewed["review"]["digest"])["review"]["state"], "completed")

    def test_extend_workspace_more_than_three_files_and_live_limits(self):
        workspace = self.draft()
        for index in range(5):
            (self.project / f"part{index}.py").write_bytes(b"# source\n")
        added = missions.add_mission_workspace_files(workspace, [f"part{i}.py" for i in range(5)])
        self.assertEqual(added["status"], "ok", added)
        self.assertEqual(len(added["workspace"]["files"]), 6)
        self.assertEqual(missions.add_mission_workspace_files(workspace, ["part0.py"])["status"], "error")
        with patch("src.mission_control._budget", return_value=(2, 64000, 128000)):
            self.assertEqual(missions.submit_mission_workspace(workspace)["status"], "error")
        missions.submit_mission_workspace(workspace)
        self.assertEqual(missions.add_mission_workspace_files(workspace, ["part0.py"])["status"], "error")

    def test_create_and_delete_need_independent_approval_and_backup(self):
        workspace = self.draft()
        added = missions.stage_mission_new_file(workspace, "new.py", "print('new')\n")
        self.assertEqual(added["status"], "ok", added)
        old_sha = added["workspace"]["files"][0]["candidate_sha256"]
        self.assertEqual(missions.stage_mission_file_deletion(workspace, "main.py", "bad")["status"], "conflict")
        deleted = missions.stage_mission_file_deletion(workspace, "main.py", old_sha)
        self.assertEqual(deleted["status"], "ok", deleted)
        self.assertEqual(deleted["workspace"]["files"][0]["action"], "delete")
        self.assertEqual(missions.read_mission_workspace(workspace, "main.py")["status"], "error")
        self.assertTrue(self.file.exists())
        self.assertFalse((self.project / "new.py").exists())
        missions.submit_mission_workspace(workspace)
        reviewed = operator(missions.import_mission_review, "bot", workspace)
        self.assertIn("DELETE main.py", reviewed["diff"])
        self.assertIn("CREATE new.py", reviewed["diff"])
        review = reviewed["review"]
        self.assertEqual(operator(missions.apply_mission_review, review["review_id"], review["digest"])["status"], "error")
        self.approve(review)
        applied = operator(missions.apply_mission_review, review["review_id"], review["digest"])
        self.assertEqual(applied["review"]["state"], "completed", applied)
        self.assertFalse(self.file.exists())
        self.assertEqual((self.project / "new.py").read_bytes(), b"print('new')\n")
        backup = applied["review"]["result"]["written"][0]["backup"]
        self.assertEqual(Path(backup).read_bytes(), b"print('original')\n")
        self.assertIsNone(applied["review"]["result"]["written"][1]["backup"])

    def test_empty_creation_deletion_is_explicit_even_without_diff_lines(self):
        created = missions.create_mission_workspace(str(self.project), [], "Empty files")
        workspace = created["workspace"]["workspace_id"]
        self.assertEqual(missions.submit_mission_workspace(workspace)["status"], "error")
        added = missions.stage_mission_new_file(workspace, "empty.txt", "")
        self.assertEqual(added["workspace"]["files"][0]["action"], "create")
        missions.submit_mission_workspace(workspace)
        reviewed = operator(missions.import_mission_review, "bot", workspace)
        self.assertIn("CREATE empty.txt", reviewed["diff"])
        self.approve(reviewed["review"])
        operator(missions.apply_mission_review, reviewed["review"]["review_id"], reviewed["review"]["digest"])
        self.assertEqual((self.project / "empty.txt").read_bytes(), b"")

    def test_new_file_collision_invalidates_approval_and_apply(self):
        workspace = self.draft()
        missions.stage_mission_new_file(workspace, "new.py", "# proposed\n")
        missions.submit_mission_workspace(workspace)
        review = operator(missions.import_mission_review, "bot", workspace)["review"]
        self.approve(review)
        collision = self.project / "new.py"
        collision.write_bytes(b"# external\n")
        self.assertEqual(operator(missions.apply_mission_review, review["review_id"], review["digest"])["status"], "error")
        self.assertEqual(collision.read_bytes(), b"# external\n")
        self.assertEqual(self.file.read_bytes(), b"print('original')\n")

    def test_new_file_submission_freeze_cancel_and_empty_line_insertion(self):
        workspace = missions.create_mission_workspace(str(self.project), [], "New source")["workspace"]["workspace_id"]
        created = missions.stage_mission_new_file(workspace, "new.py", "")
        sha = created["workspace"]["files"][0]["candidate_sha256"]
        result = missions.stage_mission_line_edit(workspace, "new.py", 1, 0, "# inserted\n", sha)
        self.assertEqual(result["status"], "ok", result)
        sha = result["workspace"]["files"][0]["candidate_sha256"]
        result = missions.stage_mission_line_edit(workspace, "new.py", 2, 1, "# append\n", sha)
        self.assertEqual(result["status"], "ok", result)
        sha = result["workspace"]["files"][0]["candidate_sha256"]
        cancelled = missions.stage_mission_file_deletion(workspace, "new.py", sha)
        self.assertEqual(cancelled["workspace"]["files"], [])
        self.assertFalse((self.project / "new.py").exists())
        missions.stage_mission_new_file(workspace, "new.py", "# ready\n")
        missions.submit_mission_workspace(workspace)
        self.assertEqual(missions.stage_mission_new_file(workspace, "other.py", "")["status"], "error")
        self.assertEqual(missions.stage_mission_file_deletion(workspace, "new.py", sha)["status"], "error")

    def test_new_paths_and_source_candidate_aggregate_budgets(self):
        workspace = self.draft()
        for relative in ("../outside.py", ".env", "main.py", "missing/child.py", "bad\nname.py"):
            # Unit fixture mocks ancestor protection; still use the real missing-parent check.
            with patch("src.gateway._trusted_directory", side_effect=lambda path, **kw: None if Path(path).is_dir() else (_ for _ in ()).throw(FileNotFoundError())):
                self.assertEqual(missions.stage_mission_new_file(workspace, relative, "# source\n")["status"], "error")
        with patch("src.mission_control._budget", return_value=(16, 512000, 40)):
            self.assertEqual(missions.stage_mission_new_file(workspace, "large.py", "x" * 40)["status"], "error")
        (self.project / "big.py").write_bytes(b"x" * 100)
        with patch("src.mission_control._budget", return_value=(16, 512000, 110)):
            self.assertEqual(missions.add_mission_workspace_files(workspace, ["big.py"])["status"], "error")

    def test_line_window_ranges_and_utf8_byte_boundaries(self):
        workspace = self.draft("# unicode: \u044f\n" * 3000)
        read = missions.read_mission_workspace_lines(workspace, "main.py", 1, 200)
        self.assertEqual(read["next_line"], 201)
        for start, count in ((0, 80), (1, 201), (3001, 1), (True, 1)):
            self.assertEqual(missions.read_mission_workspace_lines(workspace, "main.py", start, count)["status"], "error")
        self.assertEqual(missions.read_mission_workspace(workspace, "main.py", 100000)["status"], "error")
        # The first Cyrillic character begins at byte 11.
        self.assertEqual(missions.read_mission_workspace(workspace, "main.py", 12)["status"], "error")

    def test_partial_create_delete_failure_is_uncertain_not_replayed(self):
        workspace = self.draft()
        missions.stage_mission_new_file(workspace, "new.py", "# new\n")
        missions.submit_mission_workspace(workspace)
        review = operator(missions.import_mission_review, "bot", workspace)["review"]
        self.approve(review)
        with patch("src.mission_control.atomic_create", side_effect=OSError("storage error")):
            result = operator(missions.apply_mission_review, review["review_id"], review["digest"])
        self.assertEqual(result["review"]["state"], "uncertain")
        self.assertEqual(len(result["review"]["result"]["written"]), 1)
        self.assertFalse((self.project / "new.py").exists())
        self.assertEqual(operator(missions.apply_mission_review, review["review_id"], review["digest"])["status"], "error")

    def test_large_changed_region_is_work_limited_and_cannot_be_approved(self):
        self.file.write_bytes(b"# old\n" * 1500)
        _, review = self.review("# new\n" * 1500)
        inspected = operator(missions.get_mission_review, review["review_id"])
        self.assertTrue(inspected["diff_truncated"])
        self.assertIn("work budget", inspected["diff"])
        self.assertEqual(operator(missions.decide_mission_review, review["review_id"], review["digest"], "approve")["status"], "error")

    def test_exact_diff_budget_boundary_never_hides_later_changes(self):
        workspace = self.draft()
        missions.stage_mission_new_file(workspace, "new.py", "# new\n")
        missions.submit_mission_workspace(workspace)
        with patch("src.mission_control._file_diff", return_value=("x", False)), patch("src.mission_control.MAX_DIFF", 17):
            detail = operator(missions.import_mission_review, "bot", workspace)
            self.assertTrue(detail["diff_truncated"])
            review = detail["review"]
            self.assertEqual(operator(missions.decide_mission_review, review["review_id"], review["digest"], "approve")["status"], "error")

    def test_unchanged_selected_files_are_not_replaced_or_backed_up(self):
        workspace = self.draft()
        extra = self.project / "unchanged.py"
        extra.write_bytes(b"# retained\n")
        missions.add_mission_workspace_files(workspace, ["unchanged.py"])
        before = extra.stat().st_ino
        missions.submit_mission_workspace(workspace)
        detail = operator(missions.import_mission_review, "bot", workspace)
        self.assertNotIn("unchanged.py", detail["diff"])
        self.approve(detail["review"])
        applied = operator(missions.apply_mission_review, detail["review"]["review_id"], detail["review"]["digest"])
        self.assertEqual(len(applied["review"]["result"]["written"]), 1)
        self.assertEqual(extra.stat().st_ino, before)

    def test_large_file_diff_reports_original_line_numbers(self):
        original = "# same\n" * 4000
        file = {"relative_path": "main.py", "original": original,
                "candidate": "# same\n" * 3999 + "# new\n"}
        diff, limited = missions._file_diff(file)
        self.assertFalse(limited)
        self.assertIn("@@ -3997,4 +3997,4 @@", diff)

    def test_missing_final_newline_is_explicit_in_review(self):
        diff, limited = missions._file_diff({"relative_path": "main.py", "original": "old", "candidate": "new\n"})
        self.assertFalse(limited)
        self.assertIn("-old\n\\ No newline at end of file\n+new\n", diff)

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
        budget["limits"].update(mission_files=1, mission_file_bytes=50000, mission_total_bytes=50000)
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

    def test_exclusive_creation_and_backed_up_delete(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "new.py"
            atomic_create(str(path), b"# new\n")
            with self.assertRaises(OSError):
                atomic_create(str(path), b"overwrite")
            self.assertEqual(path.read_bytes(), b"# new\n")
            with self.assertRaises(OSError):
                backed_up_delete(str(path), "0" * 64)
            self.assertFalse(list(Path(temp).glob("*.bak*")))
            backup = backed_up_delete(str(path), hashlib.sha256(b"# new\n").hexdigest())
            self.assertFalse(path.exists())
            self.assertEqual(Path(backup).read_bytes(), b"# new\n")
            if os.name == "posix":
                self.assertEqual(Path(backup).stat().st_mode & 0o777, 0o600)

    @unittest.skipIf(os.name == "nt", "POSIX special-file and mode checks")
    def test_new_publication_never_replaces_links_and_is_non_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            source = directory / "source.py"
            source.write_bytes(b"# original\n")
            link = directory / "link.py"
            link.symlink_to(source)
            with self.assertRaises(OSError):
                atomic_create(str(link), b"# refused\n")
            with self.assertRaises(OSError):
                backed_up_delete(str(link), hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(source.read_bytes(), b"# original\n")
            new = directory / "new.py"
            atomic_create(str(new), b"# safe\n")
            self.assertEqual(new.stat().st_mode & 0o777, 0o644)
            self.assertEqual(new.stat().st_nlink, 1)

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
