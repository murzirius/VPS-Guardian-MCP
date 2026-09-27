"""Shared MCP entry-point policy and separate SSH operator control endpoint."""
from __future__ import annotations

import ast
from contextlib import contextmanager
import functools
import hashlib
import json
import os
from pathlib import Path
import threading
from typing import Any

try:
    from src.safe_io import atomic_replace, open_regular_fd, private_directory, read_bounded
except ImportError:
    from safe_io import atomic_replace, open_regular_fd, private_directory, read_bounded

MAX_POLICY_BYTES = 24_000
MODES = {"read-only": 0, "controlled": 1, "unrestricted": 2}
DEFAULT_POLICY = {"enabled": True, "mode_cap": "unrestricted", "allowed_tools": None, "project_roots": None}
_write_lock = threading.Lock()


def policy_directory() -> str:
    # Deliberately independent of per-session VPS_GUARDIAN_STATE_DIR settings.
    return os.path.abspath(os.path.expanduser("~/.local/share/vps-guardian-access"))


def policy_path() -> str:
    return os.path.join(policy_directory(), "policy.json")


@functools.lru_cache(maxsize=1)
def tool_catalog() -> tuple[dict[str, Any], ...]:
    """Read installed declarations without importing/executing the server."""
    source = read_bounded(str(Path(__file__).with_name("server.py")), 256_000).decode("utf-8")
    entries = []
    for node in ast.parse(source).body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id == "guardian_tool" for d in node.decorator_list):
            continue
        doc = (ast.get_docstring(node) or node.name).splitlines()[0]
        entries.append({"name": node.name, "description": doc[:180],
                        "confirmation_parameter": any(arg.arg == "confirmation_token" for arg in node.args.args + node.args.kwonlyargs),
                        "locked": node.name == "get_safety_status"})
    return tuple(sorted(entries, key=lambda entry: entry["name"]))


def validate_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(DEFAULT_POLICY):
        raise ValueError("Supply enabled, mode_cap, allowed_tools and project_roots only.")
    if type(value["enabled"]) is not bool or not isinstance(value["mode_cap"], str) or value["mode_cap"] not in MODES:
        raise ValueError("Invalid access state or safety-mode cap.")
    tools = value["allowed_tools"]
    if tools is not None:
        names = {entry["name"] for entry in tool_catalog()}
        if not isinstance(tools, list) or len(tools) > 200 or any(not isinstance(name, str) or name not in names for name in tools):
            raise ValueError("Unknown tool name or invalid tool allowlist.")
        tools = sorted(set(tools) | {"get_safety_status"})
    roots = value["project_roots"]
    if roots is not None:
        if not isinstance(roots, list) or len(roots) > 16:
            raise ValueError("Project roots must be a list of at most 16 absolute directories.")
        normalized = []
        for root in roots:
            if not isinstance(root, str) or len(root) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in root) or not os.path.isabs(root):
                raise ValueError("Project roots must be absolute paths without control characters.")
            canonical = os.path.realpath(root)
            if canonical == os.path.dirname(canonical) or os.path.islink(root):
                raise ValueError("Filesystem roots and symlink roots are not permitted.")
            normalized.append(canonical)
        roots = sorted(set(normalized))
    return {"enabled": value["enabled"], "mode_cap": value["mode_cap"], "allowed_tools": tools, "project_roots": roots}


def load_policy() -> dict[str, Any]:
    revision = "none"
    try:
        if os.path.lexists(policy_directory()):
            private_directory(policy_directory())
        raw = read_bounded(policy_path(), MAX_POLICY_BYTES, private=True)
        revision = hashlib.sha256(raw).hexdigest()
        policy = validate_policy(json.loads(raw))
        return {"policy": policy, "revision": revision, "configured": True, "error": None}
    except FileNotFoundError:
        return {"policy": dict(DEFAULT_POLICY), "revision": revision, "configured": False, "error": None}
    except (OSError, ValueError, TypeError, RecursionError):
        return {"policy": {**DEFAULT_POLICY, "enabled": False, "mode_cap": "read-only", "allowed_tools": []},
                "revision": revision if revision != "none" else "unreadable", "configured": True,
                "error": "The stored access policy is invalid or unsafe. MCP access is paused until the operator repairs it."}


def access_denial(name: str) -> dict[str, Any] | None:
    if name == "get_safety_status":
        return None  # Recovery/diagnostic metadata cannot be disabled.
    state = load_policy()
    policy = state["policy"]
    if not policy["enabled"] or policy["allowed_tools"] is not None and name not in policy["allowed_tools"]:
        return {"status": "forbidden", "success": False, "operation": name,
                "error": state["error"] or "This entry point is disabled by the operator's MCP access policy."}
    return None


def mode_cap() -> str:
    policy = load_policy()["policy"]
    return policy["mode_cap"] if policy["enabled"] else "read-only"


def managed_project_roots() -> list[str] | None:
    return load_policy()["policy"]["project_roots"]


def control_path(path: str) -> bool:
    canonical = os.path.realpath(path)
    root = os.path.realpath(policy_directory())
    return canonical == root or canonical.startswith(root + os.sep)


@contextmanager
def _policy_lock():
    with _write_lock:
        directory = private_directory(policy_directory())
        descriptor = open_regular_fd(os.path.join(directory, "policy.lock"), os.O_RDWR | os.O_CREAT, private=True)
        with os.fdopen(descriptor, "r+b") as lock:
            if os.name == "nt":
                import msvcrt
                if not os.fstat(lock.fileno()).st_size:
                    lock.write(b"0")
                    lock.flush()
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                try:
                    yield
                finally:
                    lock.seek(0)
                    msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                try:
                    yield
                finally:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def get_access_policy() -> dict[str, Any]:
    from src import __version__
    from src.resource_policy import get_workspace_settings
    return {"status": "ok", **load_policy(), "catalog": list(tool_catalog()), "version": __version__,
            "workspace_settings_supported": True, "workspace": get_workspace_settings(),
            "scope": "All upgraded Guardian MCP processes running as this SSH user.",
            "human_approval_enforced": False, "os_isolation": False}


def save_access_policy(policy: dict[str, Any], expected_revision: str) -> dict[str, Any]:
    try:
        validated = validate_policy(policy)
        raw = json.dumps(validated, sort_keys=True, separators=(",", ":")).encode()
        if len(raw) > MAX_POLICY_BYTES:
            raise ValueError("Policy is too large.")
        with _policy_lock():
            current = load_policy()
            if expected_revision != current["revision"]:
                return {"status": "conflict", "error": "Policy changed elsewhere. Reload it before applying your changes."}
            atomic_replace(policy_path(), raw, private=True, limit=MAX_POLICY_BYTES)
        from src.safety import record_audit_event
        record_audit_event("operator_update_access_policy", validated, {"status": "ok"})
        return get_access_policy()
    except (OSError, ValueError, TypeError, RecursionError):
        return {"status": "error", "error": "Cannot save policy. Check its values and the operator account's private-directory permissions."}


def main():
    # This endpoint is launched separately by the human operator over SSH. It is
    # intentionally NOT part of the ordinary Guardian agent tool catalog.
    from mcp.server.fastmcp import FastMCP
    server = FastMCP("VPS-Guardian-Operator-Access")
    server.tool()(get_access_policy)
    server.tool()(save_access_policy)
    from src.resource_policy import get_workspace_settings, save_workspace_settings
    from src.operator_projects import list_operator_projects, inspect_operator_project
    server.tool()(get_workspace_settings)
    server.tool()(save_workspace_settings)
    server.tool()(list_operator_projects)
    server.tool()(inspect_operator_project)
    server.run()


if __name__ == "__main__":
    main()
