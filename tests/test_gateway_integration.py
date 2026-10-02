"""Opt-in real SSH test for an isolated, disposable GitHub-hosted CI runner.

Never enable this on a production server. Ordinary test runs skip it.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from src import gateway, mission_control as missions


@unittest.skipUnless(os.environ.get("VPS_GUARDIAN_GATEWAY_INTEGRATION") == "1"
                     and os.environ.get("GITHUB_ACTIONS") == "true" and os.name == "posix",
                     "Only enabled on a disposable GitHub-hosted Linux CI runner")
class TestGatewaySSH(unittest.TestCase):
    def test_real_ssh_identity_scope_forced_command_and_live_revocation(self):
        for profile in ("observer", "project-editor", "mission-worker"):
            with self.subTest(profile=profile):
                self._exercise_profile(profile)

    def _exercise_profile(self, profile):
        self.assertEqual(os.geteuid(), 0)
        base = Path("/var/lib/guardian-gateway-ci")
        self.assertTrue(base.is_dir())
        agent_id = "ci-" + os.urandom(6).hex()
        account = gateway._account(agent_id)
        enrolled = False
        daemon = None
        with tempfile.TemporaryDirectory(dir=base) as temp:
            temporary = Path(temp)
            temporary.chmod(0o755)
            project = temporary / "project"
            project.mkdir(mode=0o755)
            (project / "main.py").write_text("print('gateway-ci')\n")
            key = temporary / "agent-key"
            host_key = temporary / "host-key"
            for path in (key, host_key):
                subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True, timeout=10)
            diagnostics = []
            def trace(frame, event, arg):
                if event == "exception" and frame.f_code.co_filename == gateway.__file__:
                    diagnostics.append((frame.f_lineno, arg[0].__name__, str(arg[1])))
                    if frame.f_code.co_name == "_trusted_directory":
                        current = frame.f_locals.get("current")
                        diagnostics.append(("directory", str(current), oct(current.lstat().st_mode), current.lstat().st_uid))
                return trace
            with patch("src.gateway.sys.argv", [str(base / "venv" / "bin" / "vps-guardian-access")]):
                sys.settrace(trace)
                try:
                    result = gateway.create_agent(agent_id, key.with_suffix(".pub").read_text(), [str(project)], profile=profile)
                finally:
                    sys.settrace(None)
            self.assertEqual(result["status"], "ok", {"result": result, "diagnostics": diagnostics[-5:]})
            enrolled = True
            try:
                user = gateway.pwd.getpwnam(account)
                if profile != "mission-worker":
                    os.chown(project, user.pw_uid, user.pw_gid)
                    os.chown(project / "main.py", user.pw_uid, user.pw_gid)
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", 0))
                    port = sock.getsockname()[1]
                config = temporary / "sshd_config"
                config.write_text(f"""Port {port}
ListenAddress 127.0.0.1
HostKey {host_key}
PidFile {temporary}/sshd.pid
AuthorizedKeysFile .ssh/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
StrictModes yes
PermitRootLogin no
AllowUsers {account}
LogLevel VERBOSE
""")
                known_hosts = temporary / "known_hosts"
                host_public = host_key.with_suffix(".pub").read_text().split()
                known_hosts.write_text(f"[127.0.0.1]:{port} {host_public[0]} {host_public[1]}\n")
                Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)
                with (temporary / "sshd.log").open("w+") as log:
                    daemon = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], stdout=log, stderr=log)
                    for _ in range(100):
                        if daemon.poll() is not None:
                            log.seek(0)
                            self.fail(log.read(4000))
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                                break
                        except OSError:
                            time.sleep(0.05)
                    args = ["-F", "/dev/null", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
                            "-p", str(port), "-i", str(key), f"{account}@127.0.0.1"]
                    marker = temporary / "must-not-exist"

                    async def check():
                        from mcp import ClientSession, StdioServerParameters
                        from mcp.client.stdio import stdio_client
                        params = StdioServerParameters(command="/usr/bin/ssh", args=args + [f"touch {marker}"])
                        async with stdio_client(params) as (reader, writer), ClientSession(reader, writer) as session:
                            await session.initialize()
                            tools = await session.list_tools()
                            expected = {"observer": gateway.DEFAULT_TOOLS, "project-editor": gateway.EDITOR_TOOLS,
                                        "mission-worker": gateway.MISSION_TOOLS}[profile]
                            self.assertEqual({tool.name for tool in tools.tools}, set(expected))
                            self.assertFalse(marker.exists())  # Client command is ignored by forced SSH command.

                            def data(response):
                                return response.structuredContent or json.loads(response.content[0].text)

                            read = data(await session.call_tool("read_project_file", {"project_path": str(project), "relative_path": "main.py"}))
                            self.assertEqual(read["status"], "ok", read)
                            outside = data(await session.call_tool("read_project_file", {"project_path": "/etc", "relative_path": "passwd"}))
                            self.assertEqual(outside["status"], "forbidden", outside)
                            write = await session.call_tool("restart_service", {"service_name": "sshd"})
                            self.assertTrue(write.isError)
                            if profile == "observer":
                                blocked = await session.call_tool("begin_project_patch", {"project_path": str(project), "title": "Must not write"})
                                self.assertTrue(blocked.isError)
                            elif profile == "mission-worker":
                                for forbidden in ("apply_project_patch", "apply_mission_review", "decide_mission_review", "create_agent"):
                                    self.assertTrue((await session.call_tool(forbidden, {})).isError)
                                created = data(await session.call_tool("create_mission_workspace", {"project_path": str(project), "relative_paths": ["main.py"], "title": "Independent SSH review"}))
                                self.assertEqual(created["status"], "ok", created)
                                workspace = created["workspace"]
                                staged = data(await session.call_tool("stage_mission_line_edit", {"workspace_id": workspace["workspace_id"], "relative_path": "main.py", "start_line": 1, "end_line": 1,
                                                                                                  "replacement": "print('reviewed')\n", "expected_sha256": workspace["files"][0]["candidate_sha256"]}))
                                self.assertEqual(staged["status"], "ok", staged)
                                self.assertEqual(data(await session.call_tool("submit_mission_workspace", {"workspace_id": workspace["workspace_id"]}))["status"], "ok")
                                self.assertEqual((project / "main.py").read_text(), "print('gateway-ci')\n")
                                reviewed = missions.import_mission_review(agent_id, workspace["workspace_id"])
                                self.assertEqual(reviewed["status"], "ok", reviewed)
                                review = reviewed["review"]
                                self.assertEqual(missions.apply_mission_review(review["review_id"], review["digest"])["status"], "error")
                                # The agent's OS account cannot modify production
                                # even if it somehow obtains another shell.
                                direct = subprocess.run(["/usr/sbin/runuser", "-u", account, "--", "/bin/sh", "-c", 'printf bypass >> "$1"', "sh", str(project / "main.py")], capture_output=True, timeout=5)
                                self.assertNotEqual(direct.returncode, 0)
                                approved = missions.decide_mission_review(review["review_id"], review["digest"], "approve")
                                self.assertEqual(approved["status"], "ok", approved)
                                applied = missions.apply_mission_review(review["review_id"], review["digest"])
                                self.assertEqual(applied["review"]["state"], "completed", applied)
                                self.assertEqual((project / "main.py").read_text(), "print('reviewed')\n")
                                copied = data(await session.call_tool("read_mission_workspace", {"workspace_id": workspace["workspace_id"], "relative_path": "main.py"}))
                                self.assertEqual(copied["status"], "ok", copied)
                                self.assertFalse(copied["live_baseline_checked"])
                                recovered = data(await session.call_tool("list_mission_workspaces", {}))
                                self.assertEqual(recovered["workspaces"][0]["workspace_id"], workspace["workspace_id"])
                                # Root snapshots remain unreadable to the worker.
                                snapshot = gateway.POLICY_BASE / "reviews" / (review["review_id"] + ".json")
                                leak = subprocess.run(["/usr/sbin/runuser", "-u", account, "--", "/bin/cat", str(snapshot)], capture_output=True, timeout=5)
                                self.assertNotEqual(leak.returncode, 0)
                                snapshot.unlink()
                            else:
                                begun = data(await session.call_tool("begin_project_patch", {"project_path": str(project), "title": "Gateway CI syntax update"}))
                                self.assertEqual(begun["status"], "ok", begun)
                                patch_id = begun["patch"]["patch_id"]
                                staged = data(await session.call_tool("stage_project_file_change", {"patch_id": patch_id, "relative_path": "main.py", "content": "print('updated')\n"}))
                                self.assertEqual(staged["status"], "ok", staged)
                                preview = data(await session.call_tool("preview_project_patch", {"patch_id": patch_id}))
                                self.assertEqual(preview["status"], "confirmation_required", preview)
                                self.assertEqual((project / "main.py").read_text(), "print('gateway-ci')\n")
                                applied = data(await session.call_tool("apply_project_patch", {"patch_id": patch_id, "confirmation_token": preview["confirmation_token"]}))
                                self.assertEqual(applied["status"], "ok", applied)
                                self.assertTrue(applied["success"], applied)
                                self.assertEqual((project / "main.py").read_text(), "print('updated')\n")
                                checked = data(await session.call_tool("run_project_checks", {"project_path": str(project), "check": "python_compile"}))
                                self.assertEqual(checked["status"], "ok", checked)
                            self.assertEqual(gateway.revoke_agent(agent_id)["status"], "ok")
                            revoked = data(await session.call_tool("get_system_health", {}))
                            self.assertEqual(revoked["status"], "forbidden", revoked)
                        denied = subprocess.run(["/usr/bin/ssh", *args, "true"], capture_output=True, timeout=10)
                        self.assertNotEqual(denied.returncode, 0)
                        for _ in range(100):
                            processes = subprocess.run(["/usr/bin/ps", "-u", str(user.pw_uid), "-o", "args="], capture_output=True, text=True, timeout=3)
                            if "vps-guardian-gateway" not in processes.stdout:
                                break
                            await asyncio.sleep(0.05)
                        self.assertNotIn("vps-guardian-gateway", processes.stdout, "Gateway process survived SSH disconnect")
                    asyncio.run(asyncio.wait_for(check(), timeout=45))
            finally:
                if daemon is not None:
                    daemon.terminate()
                    daemon.wait(timeout=10)
                if enrolled:
                    gateway.revoke_agent(agent_id)
                    # PAM may leave a systemd user manager after SSH logout.
                    # Terminate ONLY this disposable test UID, never root or a
                    # production account, before removing its CI account.
                    subprocess.run(["/usr/bin/pkill", "-KILL", "-u", str(user.pw_uid)], timeout=5, capture_output=True)
                    for _ in range(50):
                        removed = subprocess.run(["/usr/sbin/userdel", account], timeout=10, capture_output=True)
                        if removed.returncode != 8:
                            break
                        time.sleep(0.05)
                    removed.check_returncode()
                    gateway._policy_path(agent_id).unlink(missing_ok=True)
                    # Exact random test identity only, never the account base.
                    test_home = gateway.HOME_BASE / agent_id
                    self.assertEqual(test_home.parent, Path("/var/lib/vps-guardian-agents"))
                    shutil.rmtree(test_home)


if __name__ == "__main__":
    unittest.main(verbosity=2)
