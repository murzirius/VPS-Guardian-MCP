"""Capsules must fail closed and must not run staged code on the live host."""

from __future__ import annotations

import io
import os
import tempfile
import types
import unittest
from unittest import mock

from src import project_workspace, test_capsules


class TestCapsules(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.environment = mock.patch.dict(os.environ, {
            "VPS_GUARDIAN_PROJECT_ROOTS": self.temp.name,
            "VPS_GUARDIAN_STATE_DIR": os.path.join(self.temp.name, "state"),
            "VPS_GUARDIAN_MODE": "unrestricted",
        })
        self.environment.start()
        self.project = os.path.join(self.temp.name, "bot")
        os.mkdir(self.project)
        with open(os.path.join(self.project, "main.py"), "w", encoding="utf-8") as file:
            file.write("print('old')\n")
        with open(os.path.join(self.project, ".env"), "w", encoding="utf-8") as file:
            file.write("API_TOKEN=do-not-copy\n")
        with open(os.path.join(self.project, "private.pem"), "w", encoding="utf-8") as file:
            file.write("private key\n")
        project_workspace._patches.clear()
        self.patch_id = project_workspace.begin_project_patch(self.project, "Fix bot output")["patch"]["patch_id"]
        project_workspace.stage_project_line_edit(self.patch_id, "main.py", 1, 1, "print('new')\n")

    def tearDown(self):
        project_workspace._patches.clear()
        self.environment.stop()
        self.temp.cleanup()

    def _prerequisites(self):
        flock = types.SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=lambda *_: None)
        return mock.patch.multiple(test_capsules, fcntl=flock, _preflight=mock.Mock(return_value=("python:local", None)))

    def test_candidate_uses_filtered_temporary_copy(self):
        seen = {}

        def run(_docker, _image, snapshot, command):
            seen["snapshot"] = snapshot
            seen["command"] = command
            with open(os.path.join(snapshot, "main.py"), encoding="utf-8") as file:
                seen["candidate"] = file.read()
            seen["excluded"] = [name for name in (".env", "private.pem") if os.path.exists(os.path.join(snapshot, name))]
            return {"status": "ok", "success": True, "exit_code": 0}

        with self._prerequisites(), mock.patch.object(test_capsules, "_run_container", side_effect=run):
            result = test_capsules.test_project_patch(self.patch_id)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(seen["candidate"], "print('new')\n")
        self.assertEqual(seen["excluded"], [])
        self.assertFalse(os.path.exists(seen["snapshot"]))
        self.assertEqual(seen["command"][0], "python")
        with open(os.path.join(self.project, "main.py"), encoding="utf-8") as file:
            self.assertEqual(file.read(), "print('old')\n")

    def test_controlled_mode_requires_test_and_promotion_confirmation(self):
        with mock.patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "controlled"}), self._prerequisites(), mock.patch.object(test_capsules, "_run_container", return_value={"status": "ok", "success": True, "exit_code": 0}) as run:
            proposal = test_capsules.test_project_patch(self.patch_id)
            self.assertEqual(proposal["status"], "confirmation_required")
            run.assert_not_called()
            tested = test_capsules.test_project_patch(self.patch_id, confirmation_token=proposal["confirmation_token"])
            self.assertTrue(tested["success"])
            preview = project_workspace.preview_project_patch(self.patch_id)
            self.assertEqual(preview["status"], "confirmation_required")
            applied = test_capsules.promote_tested_project_patch(self.patch_id, preview["confirmation_token"])
        self.assertTrue(applied["success"])
        with open(os.path.join(self.project, "main.py"), encoding="utf-8") as file:
            self.assertEqual(file.read(), "print('new')\n")

    def test_promotion_refuses_untested_or_changed_candidate(self):
        self.assertEqual(test_capsules.promote_tested_project_patch(self.patch_id)["status"], "forbidden")
        with self._prerequisites(), mock.patch.object(test_capsules, "_run_container", return_value={"status": "ok", "success": True, "exit_code": 0}):
            self.assertTrue(test_capsules.test_project_patch(self.patch_id)["success"])
        project_workspace.stage_project_line_edit(self.patch_id, "main.py", 1, 1, "print('different')\n")
        self.assertEqual(test_capsules.promote_tested_project_patch(self.patch_id)["status"], "forbidden")

    def test_missing_isolation_does_not_run_or_apply(self):
        with mock.patch.object(test_capsules, "_preflight", return_value=(None, "Docker is missing")), mock.patch.object(test_capsules, "_run_container") as run:
            result = test_capsules.test_project_patch(self.patch_id)
            self.assertEqual(result["status"], "unavailable")
            run.assert_not_called()
        with open(os.path.join(self.project, "main.py"), encoding="utf-8") as file:
            self.assertEqual(file.read(), "print('old')\n")

    def test_read_only_mode_never_runs_code(self):
        with mock.patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "read-only"}), self._prerequisites(), mock.patch.object(test_capsules, "_run_container") as run:
            result = test_capsules.test_project_patch(self.patch_id)
            self.assertEqual(result["status"], "forbidden")
            run.assert_not_called()

    def test_stale_live_file_or_failed_check_cannot_be_promoted(self):
        with open(os.path.join(self.project, "main.py"), "w", encoding="utf-8") as file:
            file.write("print('someone else changed it')\n")
        with self._prerequisites(), mock.patch.object(test_capsules, "_run_container") as run:
            result = test_capsules.test_project_patch(self.patch_id)
            self.assertEqual(result["status"], "error")
            run.assert_not_called()
        with open(os.path.join(self.project, "main.py"), "w", encoding="utf-8") as file:
            file.write("print('old')\n")
        with self._prerequisites(), mock.patch.object(test_capsules, "_run_container", return_value={"status": "failed", "success": False, "exit_code": 1}):
            result = test_capsules.test_project_patch(self.patch_id)
        self.assertFalse(result["success"])
        self.assertEqual(test_capsules.promote_tested_project_patch(self.patch_id)["status"], "forbidden")

    def test_snapshot_budget_and_sensitive_staged_file(self):
        with open(os.path.join(self.project, "huge.bin"), "wb") as file:
            file.write(b"x" * (test_capsules.MAX_SNAPSHOT_BYTES + 1))
        with self._prerequisites(), mock.patch.object(test_capsules, "_run_container") as run:
            result = test_capsules.test_project_patch(self.patch_id)
            self.assertEqual(result["status"], "error")
            run.assert_not_called()
        os.remove(os.path.join(self.project, "huge.bin"))
        project_workspace.stage_project_file_change(self.patch_id, ".env", "API_TOKEN=new\n")
        with self._prerequisites(), mock.patch.object(test_capsules, "_run_container") as run:
            result = test_capsules.test_project_patch(self.patch_id)
            self.assertEqual(result["status"], "error")
            run.assert_not_called()

    def test_docker_command_has_no_network_or_live_mount_and_redacts_output(self):
        process = mock.Mock()
        process.stdout = io.BytesIO(b"API_TOKEN=leaked-secret\n")
        process.wait.return_value = 1
        with mock.patch.object(test_capsules.subprocess, "Popen", return_value=process) as popen:
            result = test_capsules._run_container("docker", "python:local", "/tmp/snapshot", ["python", "-B", "-c", "pass"])
        args = popen.call_args.args[0]
        self.assertIn("--network=none", args)
        self.assertIn("--read-only", args)
        self.assertIn("--cap-drop=ALL", args)
        self.assertIn("--user=65534:65534", args)
        self.assertIn("type=bind,src=/tmp/snapshot,dst=/workspace,readonly", args)
        self.assertNotIn(self.project, " ".join(args))
        self.assertNotIn("leaked-secret", result["output"])

    def test_remote_docker_host_is_refused(self):
        with mock.patch.object(test_capsules.sys, "platform", "linux"), mock.patch.object(test_capsules, "fcntl", object()), mock.patch.dict(os.environ, {"DOCKER_HOST": "ssh://other-vps"}), mock.patch.object(test_capsules.shutil, "which", return_value="docker"):
            image, error = test_capsules._preflight("python_syntax")
        self.assertIsNone(image)
        self.assertIn("local Unix Docker daemon", error)

    def test_low_memory_refuses_before_contacting_docker(self):
        with mock.patch.object(test_capsules.sys, "platform", "linux"), mock.patch.object(test_capsules, "fcntl", object()), mock.patch.object(test_capsules, "get_runtime_budget", return_value={"available_memory_bytes": 100 * 1024 * 1024}), mock.patch.object(test_capsules.subprocess, "run") as run:
            image, error = test_capsules._preflight("python_syntax")
        self.assertIsNone(image)
        self.assertIn("384 MiB", error)
        run.assert_not_called()

    def test_snapshot_omits_symlink_to_outside_file(self):
        outside = os.path.join(self.temp.name, "outside.py")
        with open(outside, "w", encoding="utf-8") as file:
            file.write("print('outside')\n")
        try:
            os.symlink(outside, os.path.join(self.project, "alias.py"))
        except OSError:
            self.skipTest("Creating symlinks requires elevated privileges on this host")
        present = []
        def run(_docker, _image, snapshot, _command):
            present.append(os.path.lexists(os.path.join(snapshot, "alias.py")))
            return {"status": "ok", "success": True, "exit_code": 0}
        with self._prerequisites(), mock.patch.object(test_capsules, "_run_container", side_effect=run):
            result = test_capsules.test_project_patch(self.patch_id)
            self.assertTrue(result["success"])
            self.assertEqual(present, [False])


if __name__ == "__main__":
    unittest.main()
