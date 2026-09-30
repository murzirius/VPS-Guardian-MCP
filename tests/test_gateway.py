"""Gateway keys, live policy intersection and panel routing stay fail-closed."""
from __future__ import annotations

import base64
from contextlib import nullcontext
import datetime as dt
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from src import access_policy, gateway
from src.files import is_path_permitted
from src.local_panel import PanelController, PanelInputError


def public_key():
    raw = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))
    return "ssh-ed25519 " + base64.b64encode(raw).decode("ascii") + " test"


class TestGatewayValidation(unittest.TestCase):
    def test_key_is_structurally_validated(self):
        key, fingerprint = gateway._public_key(public_key())
        self.assertTrue(key.startswith("ssh-ed25519 "))
        self.assertTrue(fingerprint.startswith("SHA256:"))
        for bad in ("ssh-rsa AAAA", "command=whoami " + public_key(),
                    public_key().replace("test", "x\ncommand=whoami"),
                    "ssh-ed25519 " + base64.b64encode(b"wrong").decode()):
            with self.subTest(bad=bad[:30]), self.assertRaises(ValueError):
                gateway._public_key(bad)

    def test_agent_names_prevent_path_and_username_injection(self):
        self.assertEqual(gateway._account("deploy-bot"), "vg_deploy_bot")
        for bad in ("", "../bot", "A", "a_b", "bot;id", "-bot", "a" * 25):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                gateway._account(bad)

    def test_gateway_denies_invalid_policy_and_disallowed_tools(self):
        with patch("src.gateway._active_policy", return_value={}):
            self.assertEqual(gateway.access_denial("get_system_health")["status"], "forbidden")
            self.assertEqual(gateway.mode_cap(), "read-only")
            self.assertEqual(gateway.project_roots(), [])
        with patch("src.gateway._active_policy", return_value={"allowed_tools": ["get_system_health"],
                                                          "mode_cap": "read-only", "project_roots": ["/srv/bot"]}):
            self.assertIsNone(gateway.access_denial("get_system_health"))
            self.assertEqual(gateway.access_denial("restart_service")["status"], "forbidden")
            self.assertIsNone(gateway.access_denial("get_safety_status"))
        with patch("src.gateway._active_policy", return_value=None):
            self.assertIsNone(gateway.access_denial("restart_service"))

    def test_shared_policy_cannot_elevate_gateway_roots_or_mode(self):
        base = os.path.abspath(tempfile.gettempdir())
        shared_a = os.path.join(base, "srv", "bot")
        shared_b = os.path.join(base, "opt", "sites")
        agent_a = os.path.join(base, "srv")
        agent_b = os.path.join(base, "opt", "sites", "blog")
        with patch("src.access_policy.load_policy", return_value={"policy": {
            **access_policy.DEFAULT_POLICY, "project_roots": [shared_a, shared_b],
            "mode_cap": "controlled"}}), patch("src.gateway.project_roots", return_value=[agent_a, agent_b]), patch("src.gateway.mode_cap", return_value="read-only"):
            self.assertEqual(access_policy.mode_cap(), "read-only")
            self.assertEqual(access_policy.managed_project_roots(), sorted([shared_a, agent_b]))

    @unittest.skipIf(os.name == "nt", "POSIX configuration directory allowlist")
    def test_configuration_file_access_does_not_escape_gateway_roots(self):
        with patch.dict(os.environ, {"VPS_GUARDIAN_GATEWAY_AGENT": "bot"}), \
             patch("src.access_policy.managed_project_roots", return_value=["/var/www/one"]):
            self.assertTrue(is_path_permitted("/var/www/one/index.html")[0])
            self.assertFalse(is_path_permitted("/var/www/two/index.html")[0])
            self.assertFalse(is_path_permitted("/etc/nginx/nginx.conf")[0])

    def test_panel_request_validation(self):
        panel = PanelController()
        with self.assertRaises(PanelInputError):
            panel.gateway_request("create_agent", {"agent_id": "../bad"})
        with self.assertRaises(PanelInputError):
            panel.gateway_request("revoke_agent", {"agent_id": "../bad"})
        with panel.lock:
            panel.state.update(connection="connected", gateway_supported=True)
        panel.gateway_request("list_agents", {})
        self.assertEqual(panel.policy_job, ("list_agents", {}))

    def test_invalid_root_and_expiry_do_not_provision(self):
        with tempfile.TemporaryDirectory() as temp, patch("src.gateway._trusted_directory"), \
             patch("src.gateway._administration_lock", return_value=nullcontext()), \
             patch("src.gateway.POLICY_BASE", Path(temp) / "policy"), \
             patch("src.gateway.HOME_BASE", Path(temp) / "home"), \
             patch("src.gateway.subprocess.run") as run:
            self.assertEqual(gateway.create_agent("bot", "invalid", [temp])["status"], "error")
            self.assertEqual(gateway.create_agent("bot", public_key(), ["/"])["status"], "error")
            self.assertEqual(gateway.create_agent("bot", public_key(), [temp], expires_hours=0)["status"], "error")
            run.assert_not_called()

    @unittest.skipIf(os.name == "nt", "Linux-only gateway enrollment")
    def test_enrollment_forces_command_and_locks_policy_to_os_uid(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            (base / "policy").mkdir()
            (base / "home").mkdir()
            executable = base / "vps-guardian-gateway"
            executable.write_text("placeholder")
            fake_account = SimpleNamespace(pw_uid=51515, pw_gid=51515, pw_dir=str(base / "home" / "deploy-bot"), pw_shell="/bin/sh")
            with patch("src.gateway._trusted_directory"), patch("src.gateway.POLICY_BASE", base / "policy"), \
                 patch("src.gateway._administration_lock", return_value=nullcontext()), \
                 patch("src.gateway.HOME_BASE", base / "home"), \
                 patch("src.gateway.sys.argv", [str(executable)]), \
                 patch("src.gateway.os.access", return_value=True), \
                 patch("src.gateway._check_installation"), \
                 patch("src.gateway.os.chown"), \
                 patch("src.gateway.pwd", SimpleNamespace(getpwnam=unittest.mock.Mock(side_effect=[KeyError, fake_account]))), \
                 patch("src.gateway.subprocess.run") as run, \
                 patch("src.gateway._write_policy") as write:
                result = gateway.create_agent("deploy-bot", public_key(), [temp], profile="project-editor")
            self.assertEqual(result["status"], "ok")
            args = run.call_args.args[0]
            self.assertEqual(args[0], "/usr/sbin/useradd")
            self.assertIn("vg_deploy_bot", args)
            line = (base / "home" / "deploy-bot" / ".ssh" / "authorized_keys").read_text()
            self.assertIn('restrict,command="', line)
            self.assertIn('/usr/bin/env -i HOME=', line)
            self.assertIn("vps-guardian-gateway serve deploy-bot", line)
            self.assertNotIn(" test\n", line)  # Public-key comments are discarded.
            self.assertEqual((base / "home" / "deploy-bot" / ".ssh").stat().st_mode & 0o777, 0o755)
            self.assertEqual((base / "home" / "deploy-bot" / ".ssh" / "authorized_keys").stat().st_mode & 0o777, 0o644)
            policy = write.call_args.args[1]
            self.assertEqual(policy["uid"], 51515)
            self.assertEqual(policy["mode_cap"], "controlled")
            self.assertIn("apply_project_patch", policy["allowed_tools"])
            self.assertEqual(policy["project_roots"], [str(base.resolve())])

    def test_live_uid_binding_expiry_and_revocation_fail_closed(self):
        expiry = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)
        policy = {"uid": 51515, "account": "vg_bot", "enabled": True,
                  "expires_at": expiry.isoformat(), "allowed_tools": ["get_system_health"]}
        with patch.dict(os.environ, {"VPS_GUARDIAN_GATEWAY_AGENT": "bot"}), \
             patch("src.gateway._read_policy", side_effect=lambda _: dict(policy)), \
             patch("src.gateway.os.geteuid", return_value=51515, create=True), \
             patch("src.gateway.pwd", SimpleNamespace(getpwuid=lambda _: SimpleNamespace(pw_name="vg_bot"))):
            self.assertIsNone(gateway.access_denial("get_system_health"))
            self.assertEqual(gateway.catalog_tools(), {"get_safety_status", "get_system_health"})
            policy["enabled"] = False
            self.assertEqual(gateway.access_denial("get_system_health")["status"], "forbidden")
            policy["enabled"] = True
            policy["uid"] = 0
            self.assertEqual(gateway.access_denial("get_system_health")["status"], "forbidden")
            policy["uid"] = 51515
            policy["expires_at"] = (expiry - dt.timedelta(hours=2)).isoformat()
            self.assertEqual(gateway.access_denial("get_system_health")["status"], "forbidden")

    @unittest.skipIf(os.name == "nt", "Root-owned POSIX policy files")
    def test_unsafe_policy_modes_links_and_fifo_are_refused(self):
        with tempfile.TemporaryDirectory() as temp, patch("src.gateway.POLICY_BASE", Path(temp)), \
             patch("src.gateway._trusted_directory"):
            path = Path(temp) / "bot.json"
            path.write_text("{}")
            path.chmod(0o666)
            with self.assertRaises(PermissionError):
                gateway._read_policy("bot")
            path.unlink()
            os.mkfifo(path)
            with self.assertRaises(PermissionError):
                gateway._read_policy("bot")



if __name__ == "__main__":
    unittest.main()
