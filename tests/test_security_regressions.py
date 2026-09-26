"""Reproductions for launcher, redaction, regular-file I/O and audit hardening."""

import json
import os
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from src import files, safety, safe_io, project_workspace, agent_runtime, operations


class TestSecurityRegressions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = self.temp.name
        self.environment = mock.patch.dict(os.environ, {"VPS_GUARDIAN_PROJECT_ROOTS": self.root, "VPS_GUARDIAN_STATE_DIR": self.root, "VPS_GUARDIAN_AUDIT_LOG": os.path.join(self.root, "audit.jsonl")})
        self.environment.start()
        safety._last_audit_path = None

    def tearDown(self):
        safety._last_audit_path = None
        self.environment.stop()
        self.temp.cleanup()

    def fixture(self, name, data=b"unchanged"):
        path = os.path.join(self.root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        os.chmod(path, 0o600)
        return path

    def symlink(self, target, link):
        try:
            os.symlink(target, link)
        except OSError:
            self.skipTest("Symlinks require privileges")

    def test_bare_json_directive_and_diff_secrets_are_redacted(self):
        inputs = ["password=bare-secret", "token = 'a secret with spaces#more'", "key: key-secret", '{"password":"json-secret", "token":"escaped-\\\"secret"}', "requirepass redis-secret", "+TOKEN=diff-secret", "-password removed-secret", "https://private-user:private-password@example.invalid", "https://private-token@example.invalid"]
        for value in inputs:
            clean, count = files._redact_config_text(value)
            self.assertGreater(count, 0, value)
            for secret in ("bare-secret", "a secret", "json-secret", "escaped-", "key-secret", "redis-secret", "diff-secret", "removed-secret", "private-user", "private-password", "private-token"):
                self.assertNotIn(secret, clean)

    def test_audit_scrubs_secrets_inside_non_sensitive_parameter_names(self):
        result = safety._redact({"target": "https://secret-token@example.invalid", "reason": 'request {"password":"private phrase"}', "details": "token=another-private-value"})
        serialized = json.dumps(result)
        for value in ("secret-token", "private phrase", "another-private-value"):
            self.assertNotIn(value, serialized)

    def test_backup_copies_are_unique_and_private(self):
        path = self.fixture("config.conf", b"first")
        first = files.atomic_write_file(path, "second")
        second = files.atomic_write_file(path, "third")
        self.assertTrue(first["success"] and second["success"])
        self.assertNotEqual(first["backup_created"], second["backup_created"])
        self.assertEqual(safe_io.read_bounded(first["backup_created"], 100), b"first")
        self.assertEqual(safe_io.read_bounded(second["backup_created"], 100), b"second")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(first["backup_created"]).st_mode), 0o600)

    def test_backup_symlink_cannot_overwrite_other_file(self):
        path = self.fixture("config.conf", b"original")
        other = self.fixture("outside.txt", b"keep")
        self.symlink(other, path + ".bak")
        result = files.atomic_write_file(path, "replacement")
        self.assertFalse(result["success"])
        self.assertEqual(safe_io.read_bounded(other, 100), b"keep")
        self.assertEqual(safe_io.read_bounded(path, 100), b"original")

    def test_target_symlink_is_refused_by_write_primitive(self):
        other = self.fixture("outside.txt", b"keep")
        link = os.path.join(self.root, "link")
        self.symlink(other, link)
        self.assertFalse(files.atomic_write_file(link, "replacement")["success"])
        self.assertEqual(safe_io.read_bounded(other, 100), b"keep")

    def test_read_refuses_parent_symlink(self):
        directory = os.path.join(self.root, "real")
        path = self.fixture("real/source.py")
        alias = os.path.join(self.root, "alias")
        self.symlink(directory, alias)
        with self.assertRaises(OSError):
            safe_io.read_bounded(os.path.join(alias, "source.py"), 100)
        self.assertEqual(safe_io.read_bounded(path, 100), b"unchanged")

    def test_audit_symlink_refused_for_read_and_write(self):
        other = self.fixture("outside.txt", b"keep")
        audit = os.path.join(self.root, "audit.jsonl")
        self.symlink(other, audit)
        self.assertFalse(safety._append_json_line(audit, {"message": "bad"}))
        self.assertEqual(safety.get_audit_events()["status"], "error")
        self.assertEqual(safe_io.read_bounded(other, 100), b"keep")

    def test_audit_tail_and_file_size_are_bounded(self):
        line = json.dumps({"operation": "read", "parameters": {"target": "https://private-token@example.invalid"}}).encode() + b"\n"
        path = self.fixture("audit.jsonl", line * 10000)
        result = safety.get_audit_events(3)
        self.assertEqual(result["event_count"], 3)
        self.assertTrue(result["tail_truncated"])
        self.assertNotIn("private-token", json.dumps(result))
        with mock.patch.object(safety, "MAX_AUDIT_BYTES", 100):
            self.assertFalse(safety._append_json_line(path, {"operation": "write"}))

    def test_audit_lock_contention_refuses_without_waiting_or_writing(self):
        path = self.fixture("audit.jsonl", b"original")
        lock = SimpleNamespace(LOCK_EX=1, LOCK_NB=2, flock=mock.Mock(side_effect=BlockingIOError("busy")))
        with mock.patch.object(safety, "fcntl", lock):
            self.assertFalse(safety._append_json_line(path, {"operation": "write"}))
        self.assertEqual(safe_io.read_bounded(path, 100), b"original")

    def test_hardlinked_audit_and_backup_refused(self):
        other = self.fixture("other", b"keep")
        audit = os.path.join(self.root, "audit.jsonl")
        try:
            os.link(other, audit)
        except OSError:
            self.skipTest("Hardlinks unavailable")
        self.assertFalse(safety._append_json_line(audit, {"operation": "write"}))
        self.assertEqual(safe_io.read_bounded(other, 100), b"keep")

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_private_file_and_directory_permissions_are_enforced(self):
        path = self.fixture("audit.jsonl")
        os.chmod(path, 0o644)
        self.assertFalse(safety._append_json_line(path, {"operation": "write"}))
        with self.assertRaises(OSError):
            safe_io.atomic_replace(path, b"new", private=True)
        os.chmod(self.root, 0o755)
        try:
            with self.assertRaises(OSError):
                safe_io.private_directory(self.root)
        finally:
            os.chmod(self.root, 0o700)

    @unittest.skipUnless(os.name == "posix", "POSIX ownership")
    def test_normal_mode_and_owner_preserved_but_special_bits_removed(self):
        path = self.fixture("config", b"old")
        os.chmod(path, 0o4750)
        before = os.stat(path)
        self.assertTrue(files.atomic_write_file(path, "new", backup=False)["success"])
        after = os.stat(path)
        self.assertEqual((after.st_uid, after.st_gid), (before.st_uid, before.st_gid))
        self.assertEqual(stat.S_IMODE(after.st_mode), 0o750)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO")
    def test_special_files_never_block_reads_or_audit(self):
        path = os.path.join(self.root, "source.py")
        os.mkfifo(path)
        with self.assertRaises(OSError):
            safe_io.read_bounded(path, 100)
        self.assertEqual(project_workspace.read_project_file(self.root, "source.py")["status"], "error")
        self.assertFalse(safety._append_json_line(path, {"operation": "write"}))
        with mock.patch.object(files, "get_allowed_directories", return_value=[self.root]):
            self.assertEqual(files.view_file_content(path)["status"], "error")

    def test_bounded_original_prevents_oversized_stage_and_write(self):
        path = self.fixture("huge.py", b"x" * (files.MAX_FILE_WRITE_BYTES + 1))
        with self.assertRaises(OSError):
            project_workspace._read_bytes(path)
        self.assertFalse(files.atomic_write_file(path, "new")["success"])

    def test_wrong_state_type_falls_back_and_state_writes_are_private(self):
        self.fixture("agent-sessions.json", b"[]")
        self.assertEqual(agent_runtime._load("agent-sessions.json", {}), {})
        agent_runtime._save("new.json", {"value": 1})
        operations._save("operations.json", {})
        self.assertEqual(agent_runtime._load("new.json", {}), {"value": 1})
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.root, "new.json")).st_mode), 0o600)

    def test_existing_state_symlink_not_read_or_overwritten(self):
        other = self.fixture("other.json", b'{"value":"private"}')
        self.symlink(other, os.path.join(self.root, "state.json"))
        self.assertEqual(agent_runtime._load("state.json", {}), {})
        with self.assertRaises(OSError):
            agent_runtime._save("state.json", {})
        self.assertEqual(safe_io.read_bounded(other, 100), b'{"value":"private"}')

    def test_safety_status_does_not_claim_human_approval(self):
        with mock.patch.dict(os.environ, {"VPS_GUARDIAN_MODE": "controlled"}):
            self.assertFalse(safety.get_safety_status()["human_approval_enforced"])

    def test_session_and_operation_notes_use_full_secret_scrubbing(self):
        value = 'target=https://private-token@example.invalid note {"password":"private phrase"}'
        for clean in (agent_runtime._scrub(value), operations._scrub(value)):
            self.assertNotIn("private-token", clean)
            self.assertNotIn("private phrase", clean)

    def test_syntax_check_isolated_and_errors_do_not_echo_source(self):
        sentinel = os.path.join(self.root, "executed")
        self.fixture("sitecustomize.py", (f"open({sentinel!r}, 'w').write('bad')\n").encode())
        self.fixture("main.py", b"password = 'private-source'; invalid(\n")
        with mock.patch.dict(os.environ, {"PYTHONPATH": self.root}):
            result = project_workspace.run_project_checks(self.root, "python_compile")
        self.assertEqual(result["status"], "error")
        self.assertFalse(os.path.exists(sentinel))
        self.assertNotIn("private-source", json.dumps(result))
        self.assertIn("main.py", result["output"])

    def test_syntax_check_does_not_claim_success_for_skipped_large_file(self):
        self.fixture("huge.py", b"#" + b"x" * 128000)
        result = project_workspace.run_project_checks(self.root, "python_compile")
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(result["success"])

    def test_write_refuses_concurrent_source_change_and_cleans_temporary(self):
        path = self.fixture("config", b"original")
        real_fsync = safe_io.os.fsync
        changed = False
        def change(fd):
            nonlocal changed
            if not changed and stat.S_ISREG(os.fstat(fd).st_mode):
                changed = True
                with open(path, "wb") as handle:
                    handle.write(b"external change")
            return real_fsync(fd)
        with mock.patch.object(safe_io.os, "fsync", side_effect=change):
            self.assertFalse(files.atomic_write_file(path, "replacement", backup=False)["success"])
        self.assertEqual(safe_io.read_bounded(path, 100), b"external change")
        self.assertFalse(any(name.startswith(".guardian_tmp_") for name in os.listdir(self.root)))


if __name__ == "__main__":
    unittest.main()
