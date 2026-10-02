"""Loopback API security and actual SDK stdio integration for the local panel."""
from __future__ import annotations

import asyncio
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from mcp import StdioServerParameters
from src.local_panel import (
    ALLOWED_TOOLS, DEFAULT_REMOTE, PanelController, PanelServer, compact_snapshot,
    connection_error, read_tool, ssh_parameters, validate_connection,
)


class FakeController:
    def __init__(self):
        self.calls = []

    def status(self):
        return {"connection": "disconnected", "snapshot": None}

    def connect(self, data):
        self.calls.append(("connect", validate_connection(data)))

    def disconnect(self):
        self.calls.append(("disconnect",))

    def refresh(self):
        self.calls.append(("refresh",))

    def policy_request(self, data=None):
        self.calls.append(("policy", data))

    def workspace_request(self, name, data):
        self.calls.append((name, data))

    def gateway_request(self, name, data):
        self.calls.append((name, data))

    def mission_request(self, name, data):
        self.calls.append((name, data))


class TestPanelHTTP(unittest.TestCase):
    def setUp(self):
        self.controller = FakeController()
        self.server = PanelServer(controller=self.controller)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method="GET", path="/api/status", data=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        body = json.dumps(data) if data is not None else None
        conn.request(method, path, body, headers or {})
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    def auth(self):
        return {"Authorization": "Bearer " + self.server.token, "Origin": self.server.origin,
                "Content-Type": "application/json"}

    def test_binds_only_loopback(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_status_needs_capability(self):
        self.assertEqual(self.request()[0], 401)
        self.assertEqual(self.request(headers={"Authorization": "Bearer invalid"})[0], 401)
        self.assertEqual(self.request(headers=self.auth())[0], 200)

    def test_rebinding_host_rejected_for_assets_and_api(self):
        for path in ("/", "/api/status"):
            headers = {**self.auth(), "Host": "attacker.example"}
            self.assertEqual(self.request(path=path, headers=headers)[0], 403)

    def test_cross_origin_and_null_origin_rejected(self):
        for origin in ("https://attacker.example", "null", "http://localhost:1234"):
            headers = {**self.auth(), "Origin": origin}
            self.assertEqual(self.request("POST", "/api/connect", {"host": "example.com"}, headers)[0], 403)
        self.assertFalse(self.controller.calls)

    def test_mutation_requires_origin_even_with_token(self):
        headers = self.auth()
        del headers["Origin"]
        self.assertEqual(self.request("POST", "/api/disconnect", {}, headers)[0], 403)

    def test_cross_site_fetch_metadata_rejected(self):
        self.assertEqual(self.request(headers={**self.auth(), "Sec-Fetch-Site": "cross-site"})[0], 403)

    def test_authenticated_connect_and_disconnect(self):
        self.assertEqual(self.request("POST", "/api/connect", {"host": "example.com"}, self.auth())[0], 202)
        self.assertEqual(self.controller.calls[0][1]["host"], "example.com")
        self.assertEqual(self.request("POST", "/api/disconnect", {}, self.auth())[0], 202)

    def test_arbitrary_tool_command_and_mode_not_exposed(self):
        for path in ("/api/tool", "/api/command", "/api/exec"):
            self.assertEqual(self.request("POST", path, {}, self.auth())[0], 404)
        self.assertEqual(self.request("POST", "/api/connect", {"host": "example.com", "mode": "unrestricted"}, self.auth())[0], 400)
        self.assertFalse(self.controller.calls)

    def test_operator_endpoints_require_token_and_same_origin(self):
        for path in ("/api/policy", "/api/policy/reload", "/api/limits", "/api/limits/reload", "/api/projects/reload", "/api/projects/inspect", "/api/operations/reload", "/api/operations/inspect", "/api/gateway/list", "/api/gateway/create", "/api/gateway/revoke", "/api/missions/list", "/api/missions/submissions", "/api/missions/import", "/api/missions/inspect", "/api/missions/decide", "/api/missions/apply"):
            self.assertEqual(self.request("POST", path, {}, {**self.auth(), "Authorization": "Bearer invalid"})[0], 401)
            self.assertEqual(self.request("POST", path, {}, {**self.auth(), "Origin": "https://evil.example"})[0], 403)
        self.assertFalse(self.controller.calls)
        self.assertEqual(self.request("POST", "/api/policy/reload", {}, self.auth())[0], 202)
        self.assertEqual(self.controller.calls, [("policy", None)])

    def test_gateway_routes_are_fixed_operator_calls(self):
        self.assertEqual(self.request("POST", "/api/gateway/list", {}, self.auth())[0], 202)
        self.assertEqual(self.controller.calls, [("list_agents", {})])
        self.assertEqual(self.request("POST", "/api/gateway/execute", {}, self.auth())[0], 404)

    def test_mission_routes_are_fixed_operator_calls(self):
        self.assertEqual(self.request("POST", "/api/missions/list", {}, self.auth())[0], 202)
        self.assertEqual(self.controller.calls, [("list_mission_reviews", {})])
        self.assertEqual(self.request("POST", "/api/missions/execute", {}, self.auth())[0], 404)

    def test_panel_is_english_and_permissions_are_primary(self):
        html = self.request(path="/")[2].decode()
        self.assertIn('lang="en"', html)
        self.assertLess(html.index("MCP Access</h2>"), html.index("Server overview"))
        self.assertIn("Apply permissions", html)
        self.assertIn('data-section="projects"', html)
        self.assertIn('data-section="limits"', html)
        self.assertIn('data-section="operations"', html)
        self.assertIn('data-section="gateway"', html)
        self.assertIn('data-section="missions"', html)
        self.assertIn("Effective on VPS", html)
        for path in ("/", "/app.js"):
            self.assertNotRegex(self.request(path=path)[2].decode(), r"[А-Яа-яёЁ]")

    def test_body_size_and_content_type(self):
        self.assertEqual(self.request("POST", "/api/connect", {"host": "a" * 9000}, self.auth())[0], 400)
        self.assertEqual(self.request("POST", "/api/connect", {}, {**self.auth(), "Content-Type": "text/plain"})[0], 400)

    def test_static_assets_have_csp_and_no_token(self):
        for path in ("/", "/app.js", "/style.css"):
            code, headers, body = self.request(path=path)
            self.assertEqual(code, 200)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
            self.assertNotIn(self.server.token.encode(), body)
        self.assertEqual(self.request(path="/../pyproject.toml")[0], 404)


class TestPanelConnection(unittest.TestCase):
    def test_rejects_unsafe_or_invalid_connection_fields(self):
        for data in ([1], {"host": "-oProxyCommand=bad"}, {"host": "x;touch y"},
                     {"host": "root@host"}, {"host": "host", "user": "a\nb"},
                     {"host": "host", "port": True}, {"host": "host", "port": 65536},
                     {"host": "host", "port": "22junk"}, {"host": "host", "port": 22.0},
                     {"host": "host", "remote_path": "relative"}, {"host": "host", "key": "x\x00y"},
                     {"host": "host", "command": "bad"}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                validate_connection(data)

    def test_local_paths_and_ip_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / "key"
            key.touch()
            result = validate_connection({"host": "2001:db8::1", "key": str(key), "port": "2222"})
            self.assertEqual(result["port"], 2222)
            self.assertEqual(result["key"], str(key.absolute()))
            with self.assertRaises(ValueError):
                validate_connection({"host": "host", "key": str(key) + "-missing"})

    @patch("src.local_panel.shutil.which", return_value="ssh")
    def test_transport_is_strict_readonly_and_shell_quoted(self, _):
        config = validate_connection({"host": "example.com", "remote_path": "/opt/a'b;$(bad)/guardian"})
        params = ssh_parameters(config)
        self.assertEqual(params.command, "ssh")
        self.assertIn("StrictHostKeyChecking=yes", params.args)
        self.assertIn("BatchMode=yes", params.args)
        self.assertIn("ForwardAgent=no", params.args)
        self.assertIn("LogLevel=INFO", params.args)
        self.assertEqual(params.args[:2], ["-F", "none"])
        self.assertEqual(params.args[-1], "env VPS_GUARDIAN_MODE=read-only VPS_GUARDIAN_TOOL_PROFILE=full '/opt/a'\"'\"'b;$(bad)/guardian'")

    @patch("src.local_panel.shutil.which", return_value=None)
    def test_missing_ssh_reports_failure(self, _):
        with self.assertRaisesRegex(ValueError, "OpenSSH"):
            ssh_parameters(validate_connection({"host": "example.com"}))

    @patch("src.local_panel.shutil.which", return_value="ssh")
    def test_known_hosts_spaces_are_quoted(self, _):
        config = validate_connection({"host": "example.com"})
        config["known_hosts"] = "/home/user with spaces/known_hosts"
        self.assertIn('UserKnownHostsFile="/home/user with spaces/known_hosts"', ssh_parameters(config).args)

    @unittest.skipUnless(os.name == "nt" and shutil.which("ssh"), "Windows OpenSSH regression")
    def test_windows_ssh_receives_programdata_and_reports_network_error(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        params = ssh_parameters(validate_connection({"host": "127.0.0.1", "port": port}))
        self.assertEqual(params.env["ProgramData"], os.environ["ProgramData"])
        controller = PanelController()
        try:
            controller.connect({"host": "127.0.0.1", "port": port})
            self.wait_state(controller, "error")
            self.assertEqual(controller.status()["error"]["code"], "network")
        finally:
            controller.close()

    def test_only_fixed_tool_allowlist(self):
        self.assertEqual(ALLOWED_TOOLS, {"get_safety_status", "get_system_health", "get_failed_systemd_units"})
        with self.assertRaises(ValueError):
            asyncio.run(read_tool(None, "restart_service"))
        with self.assertRaises(ValueError):
            asyncio.run(read_tool(None, "save_access_policy"))
        with self.assertRaises(ValueError):
            asyncio.run(read_tool(None, "get_system_health", admin=True))

    def test_operator_program_is_adjacent_and_strictly_quoted(self):
        with patch("src.local_panel.shutil.which", return_value="ssh"):
            params = ssh_parameters(validate_connection({"host": "host", "remote_path": "/opt/a b/bin/vps-guardian-mcp"}), admin=True)
        self.assertEqual(params.args[-1], "env VPS_GUARDIAN_MODE=read-only VPS_GUARDIAN_TOOL_PROFILE=full '/opt/a b/bin/vps-guardian-access'")
        self.assertIn("StrictHostKeyChecking=yes", params.args)

    def test_policy_queue_rejects_unknown_fields_and_parallel_requests(self):
        controller = PanelController()
        with self.assertRaises(RuntimeError):
            controller.policy_request()
        controller.state.update(connection="connected", access_supported=True)
        for payload in ({"command": "bad"}, {"policy": {}, "expected_revision": "none"}):
            with self.assertRaises(ValueError):
                controller.policy_request(payload)
        controller.policy_request()
        with self.assertRaises(RuntimeError):
            controller.policy_request()
        controller.disconnect()
        self.assertIsNone(controller.policy_job)

    def test_diagnostics_never_return_raw_stderr_or_exception(self):
        for stderr, expected in (("Permission denied secret-key-path", "authentication"),
                                 ("REMOTE HOST IDENTIFICATION HAS CHANGED", "host_key"),
                                 ("Connection refused", "network"), ("could not resolve hostname", "dns"),
                                 ("guardian: not found", "remote_program"), ("timed out", "timeout")):
            result = connection_error(stderr, RuntimeError("super-secret"))
            self.assertEqual(result["code"], expected)
            self.assertNotIn("secret", json.dumps(result))

    def test_snapshot_is_bounded_and_removes_unknown_fields(self):
        units = [{"unit": "a.service", "description": "x" * 1000, "secret": "token"}] * 100
        result = compact_snapshot({"system": {"hostname": "vps", "password": "bad"}, "cpu": {"usage_percent_total": float("nan")}},
                                  {"status": "ok", "failed_units": units})
        self.assertNotIn("password", result["system"])
        self.assertNotIn("usage_percent_total", result["cpu"])
        self.assertEqual(len(result["services"]["failed_units"]), 30)
        self.assertEqual(len(result["services"]["failed_units"][0]["description"]), 200)

    def test_refresh_needs_connection_and_is_rate_limited(self):
        controller = PanelController()
        with self.assertRaises(RuntimeError):
            controller.refresh()
        controller.state["connection"] = "connected"
        controller.refresh()
        with self.assertRaises(RuntimeError):
            controller.refresh()

    def test_snapshots_are_copied_and_disconnect_clears_metrics(self):
        controller = PanelController()
        controller.state["snapshot"] = {"cpu": {"usage_percent_total": 10}}
        external = controller.status()
        external["snapshot"]["cpu"]["usage_percent_total"] = 90
        self.assertEqual(controller.status()["snapshot"]["cpu"]["usage_percent_total"], 10)
        controller.disconnect()
        self.assertIsNone(controller.status()["snapshot"])

    def fixture_params(self, mode="read-only", changes=False, policy_dir=None):
        return StdioServerParameters(command=sys.executable,
            args=["-u", str(Path(__file__).with_name("panel_fixture.py"))], env={"PANEL_TEST_MODE": mode, "PANEL_TEST_CHANGES": "1" if changes else "0", **({"PANEL_TEST_POLICY_DIR": policy_dir} if policy_dir else {})})

    def wait_policy(self, controller):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            state = controller.status()
            if not state["policy_busy"] and state["access"]:
                return state
            time.sleep(.05)
        self.fail("Policy request did not finish: " + str(controller.status()))

    def test_real_stdio_operator_can_pause_and_restore_agent_access(self):
        with tempfile.TemporaryDirectory() as directory:
            controller = PanelController()
            params = self.fixture_params(policy_dir=str(Path(directory) / "policy"))
            with patch("src.local_panel.ssh_parameters", return_value=params):
                try:
                    controller.connect({"host": "fixture.example"})
                    self.wait_state(controller, "connected")
                    before = self.wait_policy(controller)["access"]
                    controller.policy_request({"policy": {**before["policy"], "enabled": False}, "expected_revision": before["revision"]})
                    paused = self.wait_policy(controller)["access"]
                    self.assertFalse(paused["policy"]["enabled"])
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline and not controller.status().get("monitoring_blocked"):
                        time.sleep(.05)
                    self.assertTrue(controller.status()["monitoring_blocked"])
                    self.assertEqual(controller.status()["connection"], "connected")
                    controller.policy_request({"policy": {**paused["policy"], "enabled": True}, "expected_revision": paused["revision"]})
                    restored = self.wait_policy(controller)["access"]
                    self.assertTrue(restored["policy"]["enabled"])
                    self.assertIsNone(controller.status()["access_error"])
                finally:
                    controller.close()

    def wait_state(self, controller, expected):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if controller.status()["connection"] == expected:
                return
            time.sleep(.05)
        self.fail("Timed out waiting for state: " + str(controller.status()))

    def test_real_stdio_session_snapshot_and_disconnect(self):
        controller = PanelController()
        with patch("src.local_panel.ssh_parameters", return_value=self.fixture_params()):
            try:
                controller.connect({"host": "fixture.example"})
                self.wait_state(controller, "connected")
                state = controller.status()
                self.assertEqual(state["snapshot"]["cpu"]["usage_percent_total"], 12.5)
                self.assertEqual(state["snapshot"]["system"]["hostname"], "fixture-vps")
                self.assertNotIn("key", state["target"])
                with self.assertRaises(RuntimeError):
                    controller.connect({"host": "second.example"})
                controller.disconnect()
                self.wait_state(controller, "disconnected")
            finally:
                controller.close()
        self.assertFalse(controller.thread.is_alive())

    def test_server_must_confirm_readonly_before_metrics(self):
        controller = PanelController()
        with patch("src.local_panel.ssh_parameters", return_value=self.fixture_params("unrestricted")):
            try:
                controller.connect({"host": "fixture.example"})
                self.wait_state(controller, "error")
                state = controller.status()
                self.assertEqual(state["error"]["code"], "safety_mode")
                self.assertIsNone(state["snapshot"])
            finally:
                controller.close()

    def test_contradictory_readonly_status_is_rejected(self):
        controller = PanelController()
        with patch("src.local_panel.ssh_parameters", return_value=self.fixture_params(changes=True)):
            try:
                controller.connect({"host": "fixture.example"})
                self.wait_state(controller, "error")
                self.assertEqual(controller.status()["error"]["code"], "safety_mode")
                self.assertIsNone(controller.status()["snapshot"])
            finally:
                controller.close()


if __name__ == "__main__":
    unittest.main()
