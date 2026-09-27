"""Loopback-only operator access panel; no arbitrary tool/command API."""

from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
import copy
import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
import ipaddress
import json
import math
import os
import posixpath
import re
import secrets
import shlex
import shutil
import threading
import time
from typing import Any
from urllib.parse import urlsplit
import webbrowser

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

DEFAULT_REMOTE = "/opt/vps-guardian-mcp/.venv/bin/vps-guardian-mcp"
ALLOWED_TOOLS = frozenset({"get_safety_status", "get_system_health", "get_failed_systemd_units"})
ADMIN_TOOLS = frozenset({"get_access_policy", "save_access_policy"})
POLL_SECONDS = 30
REQUEST_TIMEOUT = 20
MAX_BODY = 8192


class PanelInputError(ValueError):
    """Public, source-free validation message suitable for the local UI."""


def validate_connection(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or set(data) - {"host", "user", "port", "key", "known_hosts", "remote_path"}:
        raise PanelInputError("Invalid connection fields.")
    config = {"host": "", "user": "root", "port": 22, "key": "", "known_hosts": "", "remote_path": DEFAULT_REMOTE, **data}
    for name in ("host", "user", "key", "known_hosts", "remote_path"):
        value = config[name]
        if not isinstance(value, str) or len(value) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise PanelInputError("Fields must be strings without control characters.")
        config[name] = value.strip()
    host = config["host"]
    try:
        ipaddress.ip_address(host)
        valid_host = True
    except ValueError:
        valid_host = bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", host))
    if not valid_host or len(host) > 253:
        raise PanelInputError("Enter an IP address or hostname, without user@ or commands.")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", config["user"]):
        raise PanelInputError("Invalid SSH username.")
    port = config["port"]
    if isinstance(port, str) and re.fullmatch(r"[0-9]{1,5}", port):
        port = int(port)
    if type(port) is not int or not 1 <= port <= 65535:
        raise PanelInputError("SSH port must be between 1 and 65535.")
    config["port"] = port
    if not config["remote_path"].startswith("/"):
        raise PanelInputError("The Guardian executable path on the VPS must start with /.")
    for name in ("key", "known_hosts"):
        if config[name]:
            config[name] = os.path.abspath(os.path.expanduser(config[name]))
            if not os.path.isfile(config[name]):
                raise PanelInputError("The specified key or known_hosts file was not found on this device.")
    return config


def ssh_parameters(config: dict[str, Any], admin: bool = False) -> StdioServerParameters:
    command = shutil.which("ssh")
    if not command:
        raise PanelInputError("OpenSSH was not found. Install an SSH client on this device.")
    args = ["-F", "none", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
            "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
            "-o", "LogLevel=INFO", "-p", str(config["port"])]
    if config["key"]:
        args += ["-i", config["key"], "-o", "IdentitiesOnly=yes"]
    if config["known_hosts"]:
        # ssh_config treats the -o value as configuration text, not an argv path.
        path = config["known_hosts"].replace("\\", "/")
        if '"' in path:
            raise PanelInputError("The known_hosts path must not contain double quotes.")
        args += ["-o", 'UserKnownHostsFile="' + path + '"']
    remote = posixpath.join(posixpath.dirname(config["remote_path"]), "vps-guardian-access") if admin else config["remote_path"]
    args += [config["user"] + "@" + config["host"],
             "env VPS_GUARDIAN_MODE=read-only VPS_GUARDIAN_TOOL_PROFILE=full " + shlex.quote(remote)]
    # Preserve agent socket support without copying the user's entire environment.
    env = {"SSH_AUTH_SOCK": os.environ["SSH_AUTH_SOCK"]} if os.environ.get("SSH_AUTH_SOCK") else {}
    # Native Windows OpenSSH exits before connecting if ProgramData is absent.
    # The SDK's minimal inherited environment doesn't include this variable.
    if os.name == "nt" and os.environ.get("ProgramData"):
        env["ProgramData"] = os.environ["ProgramData"]
    return StdioServerParameters(command=command, args=args, env=env or None)


def connection_error(stderr: str, exc: Exception) -> dict[str, str]:
    """Expose actionable categories, never raw stderr, key paths or remote output."""
    text = stderr.lower()
    if "host key verification failed" in text or "remote host identification has changed" in text:
        code, message = "host_key", "The server SSH host key is unknown or changed. Verify its fingerprint with your provider and update known_hosts manually; do not disable verification."
    elif "permission denied" in text or "load key" in text:
        code, message = "authentication", "SSH rejected the key. Check the username and key path. Load passphrase-protected keys into ssh-agent first."
    elif "not found" in text or "no such file" in text:
        code, message = "remote_program", "SSH, the key or Guardian was not found. Check the installation and executable path in advanced settings."
    elif "could not resolve hostname" in text:
        code, message = "dns", "Cannot resolve the server hostname. Check the address and DNS."
    elif "connection refused" in text or "no route to host" in text:
        code, message = "network", "SSH is unreachable. Check the address, port, network and firewall."
    elif isinstance(exc, TimeoutError) or "timed out" in text:
        code, message = "timeout", "The server did not respond in time. Check SSH connectivity and VPS load, then reconnect."
    else:
        code, message = "protocol", "MCP disconnected or returned an unexpected reply. Check the Guardian installation and version, and ensure the SSH session has no extra output."
    return {"code": code, "message": message}


@contextmanager
def stderr_tail():
    """Drain SSH stderr continuously into a bounded memory buffer (no log file)."""
    read_fd, write_fd = os.pipe()
    tail = bytearray()
    lock = threading.Lock()

    def drain():
        try:
            while True:
                chunk = os.read(read_fd, 2048)
                if not chunk:
                    return
                with lock:
                    tail.extend(chunk)
                    del tail[:-4096]
        finally:
            os.close(read_fd)

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    writer = os.fdopen(write_fd, "w", encoding="utf-8")

    def value():
        with lock:
            return bytes(tail).decode("utf-8", errors="replace")

    try:
        yield writer, value
    finally:
        writer.close()
        reader.join(timeout=1)


async def read_tool(session: ClientSession, name: str, arguments=None, *, admin=False) -> dict[str, Any]:
    if name not in (ADMIN_TOOLS if admin else ALLOWED_TOOLS):
        raise ValueError("This panel only exposes its fixed operator and monitoring tools.")
    result = await asyncio.wait_for(session.call_tool(name, arguments or {}), REQUEST_TIMEOUT)
    if result.isError:
        raise ValueError("MCP tool failed")
    data = getattr(result, "structuredContent", None)
    if data is None:
        texts = [part.text for part in result.content if getattr(part, "type", None) == "text"]
        if len(texts) != 1 or len(texts[0]) > 256_000:
            raise ValueError("Unexpected MCP reply")
        data = json.loads(texts[0])
    if not isinstance(data, dict) or len(json.dumps(data, ensure_ascii=False)) > 256_000:
        raise ValueError("Unexpected MCP reply")
    return data


def compact_snapshot(health: dict[str, Any], services: dict[str, Any]) -> dict[str, Any]:
    """Copy only display fields; do not relay arbitrary server data or log output."""
    def fields(data, names):
        if not isinstance(data, dict):
            return {}
        result = {}
        for name in names:
            value = data.get(name)
            if isinstance(value, str):
                result[name] = value[:200]
            elif type(value) in (int, float) and abs(value) <= 10**18 and math.isfinite(value):
                result[name] = value
        return result

    memory = health.get("memory")
    memory = memory if isinstance(memory, dict) else {}
    units = services.get("failed_units", [])
    units = units if isinstance(units, list) else []
    return {
        "system": fields(health.get("system"), ("hostname", "os", "platform", "architecture")),
        "cpu": fields(health.get("cpu"), ("status", "usage_percent_total", "logical_cores")),
        "ram": fields(memory.get("ram"), ("used_percent", "used", "total", "available")),
        "swap": fields(memory.get("swap"), ("used_percent", "used", "total")),
        "disk": fields(health.get("disk"), ("status", "used_percent", "used", "total", "free", "root_mount")),
        "uptime": fields(health.get("uptime"), ("uptime_human",)),
        "services": {"status": services.get("status") if services.get("status") in ("ok", "error", "unavailable") else "error",
                     "failed_units": [fields(unit, ("unit", "active", "description")) for unit in units[:30]],
                     "total_failed": len(units), "shown": min(len(units), 30)},
    }


class PanelController:
    def __init__(self):
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.refresh_requested = threading.Event()
        self.thread: threading.Thread | None = None
        self.last_refresh = 0.0
        self.policy_job = None
        self.state: dict[str, Any] = {"connection": "disconnected", "snapshot": None, "error": None,
                                     "updated_at": None, "poll_seconds": POLL_SECONDS, "read_only": True,
                                     "access": None, "access_error": None, "access_supported": False, "policy_busy": False}

    def status(self):
        with self.lock:
            return copy.deepcopy(self.state)

    def connect(self, data):
        config = validate_connection(data)
        params = ssh_parameters(config)
        admin_params = ssh_parameters(config, admin=True)
        with self.lock:
            if self.thread and self.thread.is_alive():
                raise RuntimeError("Wait for the current connection to close.")
            self.stop.clear()
            self.refresh_requested.clear()
            self.last_refresh = 0.0
            self.policy_job = None
            self.state.update(connection="connecting", snapshot=None, error=None, updated_at=None,
                              access=None, access_error=None, access_supported=False, policy_busy=False,
                              target={"host": config["host"], "user": config["user"], "port": config["port"]})
            self.thread = threading.Thread(target=self._worker, args=(params, admin_params), daemon=True)
            self.thread.start()

    def disconnect(self):
        with self.lock:
            self.stop.set()
            self.policy_job = None
            self.state.update(connection="disconnecting" if self.thread and self.thread.is_alive() else "disconnected",
                              snapshot=None, updated_at=None, error=None, access=None, policy_busy=False)

    def policy_request(self, data=None):
        if data is not None:
            if not isinstance(data, dict) or set(data) != {"policy", "expected_revision"}:
                raise PanelInputError("Supply policy and expected_revision only.")
            from src.access_policy import DEFAULT_POLICY, MODES
            policy = data["policy"]
            if (not isinstance(policy, dict) or set(policy) != set(DEFAULT_POLICY)
                    or type(policy["enabled"]) is not bool or not isinstance(policy["mode_cap"], str)
                    or policy["mode_cap"] not in MODES or not isinstance(data["expected_revision"], str)
                    or len(data["expected_revision"]) > 64):
                raise PanelInputError("Invalid access policy.")
            for field, limit in (("allowed_tools", 200), ("project_roots", 16)):
                items = policy[field]
                if items is not None and (not isinstance(items, list) or len(items) > limit
                                          or any(not isinstance(item, str) or len(item) > 1024 for item in items)):
                    raise PanelInputError("Invalid tools or project roots.")
        with self.lock:
            if self.state["connection"] != "connected" or not self.state["access_supported"]:
                raise RuntimeError("Connect to Guardian 0.30.0 or newer before managing access.")
            if self.state["policy_busy"]:
                raise RuntimeError("An operator request is already running.")
            self.policy_job = ("save_access_policy", copy.deepcopy(data)) if data is not None else ("get_access_policy", {})
            self.state.update(policy_busy=True, access_error=None)

    def refresh(self):
        with self.lock:
            if self.state["connection"] != "connected":
                raise RuntimeError("Connect to the VPS first.")
            if time.monotonic() - self.last_refresh < 10:
                raise RuntimeError("Refresh is available once every 10 seconds.")
            self.last_refresh = time.monotonic()
            self.refresh_requested.set()

    def close(self):
        self.disconnect()
        if self.thread:
            self.thread.join(timeout=REQUEST_TIMEOUT + 5)

    def _worker(self, params, admin_params):
        try:
            asyncio.run(self._connection(params, admin_params))
        except Exception as exc:
            if not self.stop.is_set():
                with self.lock:
                    self.state.update(connection="error", error=connection_error("", exc))
        finally:
            if self.stop.is_set():
                with self.lock:
                    self.state.update(connection="disconnected", snapshot=None, updated_at=None, error=None)

    async def _operator(self, params, name, arguments):
        # Short-lived helper: no extra idle MCP process on a small VPS.
        with stderr_tail() as (errlog, tail):
            try:
                async def exchange():
                    async with stdio_client(params, errlog=errlog) as (read, write):
                        async with ClientSession(read, write, read_timeout_seconds=datetime.timedelta(seconds=REQUEST_TIMEOUT)) as session:
                            await session.initialize()
                            return await read_tool(session, name, arguments, admin=True)
                result = await asyncio.wait_for(exchange(), REQUEST_TIMEOUT)
                if result.get("status") == "ok":
                    # Reject malformed helper replies; never render raw server HTML.
                    from src.access_policy import validate_policy
                    validate_policy(result["policy"])
                    if not isinstance(result.get("revision"), str) or not isinstance(result.get("catalog"), list):
                        raise ValueError("Invalid helper reply")
                    with self.lock:
                        if not self.stop.is_set():
                            self.state.update(access=result, access_error=None)
                else:
                    with self.lock:
                        self.state["access_error"] = ("Policy changed elsewhere. Reload before applying your changes."
                                                      if result.get("status") == "conflict" else "Cannot save access policy. Check the values and operator directory permissions.")
            except Exception as exc:
                with self.lock:
                    self.state["access_error"] = "Operator helper unavailable. Install Guardian 0.30.0+ in the same environment as the MCP executable. " + connection_error(tail(), exc)["message"]
            finally:
                with self.lock:
                    self.state["policy_busy"] = False

    async def _connection(self, params, admin_params):
        with stderr_tail() as (errlog, tail):
            try:
                async with stdio_client(params, errlog=errlog) as (read, write):
                    async with ClientSession(read, write, read_timeout_seconds=datetime.timedelta(seconds=REQUEST_TIMEOUT)) as session:
                        await asyncio.wait_for(session.initialize(), REQUEST_TIMEOUT)
                        safety = await read_tool(session, "get_safety_status")
                        if safety.get("status") != "ok" or safety.get("safety_mode") != "read-only" or safety.get("state_changes_enabled") is not False:
                            with self.lock:
                                self.state.update(connection="error", error={"code": "safety_mode", "message": "The server did not confirm read-only mode. The panel disconnected without requesting metrics."})
                            return
                        next_poll = 0.0
                        with self.lock:
                            self.state.update(access_supported=safety.get("access_policy_supported") is True,
                                              access_error=None if safety.get("access_policy_supported") is True else "Upgrade Guardian on the VPS to 0.30.0+ to manage access, then reconnect all agents.")
                        if safety.get("access_policy_supported") is True:
                            with self.lock:
                                self.state["policy_busy"] = True
                            await self._operator(admin_params, "get_access_policy", {})
                        while not self.stop.is_set():
                            with self.lock:
                                job = self.policy_job
                                self.policy_job = None
                            if job:
                                await self._operator(admin_params, *job)
                                next_poll = 0.0
                            if time.monotonic() >= next_poll or self.refresh_requested.is_set():
                                self.refresh_requested.clear()
                                with self.lock:
                                    self.last_refresh = time.monotonic()
                                health = await read_tool(session, "get_system_health")
                                if health.get("status") not in ("ok", "forbidden"):
                                    raise ValueError("Health tool did not succeed")
                                services = await read_tool(session, "get_failed_systemd_units")
                                snapshot = compact_snapshot(health, services) if health.get("status") == "ok" else None
                                with self.lock:
                                    if not self.stop.is_set():
                                        self.state.update(connection="connected", snapshot=snapshot, error=None,
                                                          monitoring_blocked=health.get("status") == "forbidden" or services.get("status") == "forbidden",
                                                          updated_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
                                next_poll = time.monotonic() + POLL_SECONDS
                            await asyncio.sleep(0.25)
            except Exception as exc:
                if not self.stop.is_set():
                    with self.lock:
                        self.state.update(connection="error", error=connection_error(tail(), exc))


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, port=0, controller=None):
        self.controller = controller or PanelController()
        self.token = secrets.token_urlsafe(32)
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(("127.0.0.1", port), PanelHandler)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.expected_host = f"127.0.0.1:{self.server_port}"

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class PanelHandler(BaseHTTPRequestHandler):
    server_version = "VPSGuardianPanel"

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *args):
        pass  # Never write bearer tokens, target addresses or local paths to logs.

    def _send(self, code, payload, content_type="application/json; charset=utf-8"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _authorized(self, api=False, mutation=False):
        if self.headers.get_all("Host") != [self.server.expected_host]:
            self._send(403, {"error": "Invalid Host."})
            return False
        origins = self.headers.get_all("Origin") or []
        if origins and origins != [self.server.origin] or mutation and origins != [self.server.origin]:
            self._send(403, {"error": "The request must originate from the local panel."})
            return False
        if self.headers.get("Sec-Fetch-Site", "none") not in ("none", "same-origin"):
            self._send(403, {"error": "Cross-site request rejected."})
            return False
        if api:
            values = self.headers.get_all("Authorization") or []
            expected = "Bearer " + self.server.token
            if len(values) != 1 or not secrets.compare_digest(values[0].encode(), expected.encode()):
                self._send(401, {"error": "Open the private link printed when the panel starts."})
                return False
        return True

    def do_GET(self):
        path = urlsplit(self.path).path
        if not self._authorized(api=path.startswith("/api/")):
            return
        if path == "/api/status":
            self._send(200, self.server.controller.status())
            return
        assets = {"/": ("index.html", "text/html; charset=utf-8"),
                  "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                  "/style.css": ("style.css", "text/css; charset=utf-8")}
        if path not in assets:
            self._send(404, {"error": "Not found."})
            return
        name, mime = assets[path]
        self._send(200, resources.files("src").joinpath("panel_assets", name).read_bytes(), mime)

    def do_POST(self):
        if not self._authorized(api=True, mutation=True):
            return
        try:
            if self.headers.get_all("Transfer-Encoding"):
                raise ValueError("Streaming request bodies are not supported.")
            lengths = self.headers.get_all("Content-Length") or []
            if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,5}", lengths[0]):
                raise ValueError("Invalid request size.")
            path = urlsplit(self.path).path
            body_limit = 24_000 if path == "/api/policy" else MAX_BODY
            if int(lengths[0]) > body_limit:
                # Drain a small oversized body without retaining/parsing it so
                # Windows doesn't reset the socket before delivering the error.
                remaining = min(int(lengths[0]), MAX_BODY * 8)
                while remaining:
                    chunk = self.rfile.read(min(remaining, 4096))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                raise ValueError("Invalid request size.")
            raw = self.rfile.read(int(lengths[0]))
            if len(raw) != int(lengths[0]):
                raise ValueError("Incomplete request.")
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                raise ValueError("JSON is required.")
            data = json.loads(raw)
            path = urlsplit(self.path).path
            if path == "/api/connect":
                self.server.controller.connect(data)
            elif path == "/api/policy":
                self.server.controller.policy_request(data)
            elif path == "/api/policy/reload" and data == {}:
                self.server.controller.policy_request()
            elif path in ("/api/disconnect", "/api/refresh") and data == {}:
                getattr(self.server.controller, "disconnect" if path.endswith("disconnect") else "refresh")()
            else:
                self._send(404, {"error": "Unknown operation."})
                return
            self._send(202, self.server.controller.status())
        except PanelInputError as exc:
            self._send(400, {"error": str(exc)})
        except (ValueError, UnicodeError, RecursionError):
            self._send(400, {"error": "Invalid JSON request. Check the connection fields or access-policy values."})
        except RuntimeError as exc:
            self._send(409, {"error": str(exc)})
        except TimeoutError:
            self._send(408, {"error": "The request did not finish in time."})


def main():
    parser = argparse.ArgumentParser(description="Local VPS Guardian MCP access panel")
    parser.add_argument("--port", type=int, default=0, help="Loopback port (default: choose an available port)")
    parser.add_argument("--no-browser", action="store_true", help="Print the local URL without opening a browser")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("port must be 0-65535")
    server = PanelServer(port=args.port)
    url = server.origin + "/#" + server.token
    print("VPS Guardian - local MCP access panel\n" + url + "\nKeep this operator link private. Ctrl+C stops the panel.", flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        server.controller.close()


if __name__ == "__main__":
    main()
