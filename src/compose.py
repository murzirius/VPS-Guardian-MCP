"""Guarded Docker Compose discovery, inspection, and lifecycle operations."""

from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any, Dict, List, Optional

try:
    from src.files import is_path_permitted
    from src.platform import get_compose_command
    from src.safety import record_audit_event, request_authorization
except ImportError:
    from files import is_path_permitted
    from platform import get_compose_command
    from safety import record_audit_event, request_authorization


COMPOSE_FILE_NAMES = {"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"}
COMPOSE_ACTIONS = {"up", "restart", "stop"}
SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _compose_file_path(compose_file: str) -> tuple[Optional[str], Optional[Dict[str, Any]]]:
    if not isinstance(compose_file, str) or not compose_file.strip():
        return None, {"status": "error", "error": "compose_file must be a non-empty string."}
    allowed, path = is_path_permitted(compose_file.strip())
    if not allowed:
        return None, {"status": "forbidden", "error": "Compose file is outside authorized directories.", "compose_file": path}
    if os.path.basename(path).lower() not in COMPOSE_FILE_NAMES:
        return None, {"status": "error", "error": "compose_file must use a standard Compose filename.", "compose_file": path}
    if not os.path.isfile(path):
        return None, {"status": "error", "error": "Compose file was not found.", "compose_file": path}
    return path, None


def _run_compose(path: str, arguments: List[str], timeout: int = 45) -> Dict[str, Any]:
    command = get_compose_command()
    if not command:
        return {"status": "unavailable", "error": "Docker Compose v2 or docker-compose is not installed."}
    full_command = [*command, "-f", path, *arguments]
    try:
        completed = subprocess.run(full_command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": "Docker Compose command timed out.", "command": full_command}
    except OSError as exc:
        return {"status": "error", "error": str(exc), "command": full_command}
    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    output = (stdout + ("\n" if stdout and stderr else "") + stderr).strip()
    return {"status": "ok" if completed.returncode == 0 else "error", "success": completed.returncode == 0,
            "command": full_command, "exit_code": completed.returncode, "output": output[:4000], "stdout": stdout[:4000],
            "error": None if completed.returncode == 0 else "Docker Compose command failed."}


def list_compose_projects(root_path: str = "/var/www", max_depth: int = 2) -> Dict[str, Any]:
    """Find conventional Compose files under one authorized directory tree."""
    allowed, root = is_path_permitted(root_path)
    if not allowed or not os.path.isdir(root):
        return {"status": "error", "error": "root_path must be an existing authorized directory.", "projects": []}
    try:
        depth_limit = max(0, min(int(max_depth), 4))
    except (TypeError, ValueError):
        depth_limit = 2
    projects = []
    base_depth = root.rstrip(os.sep).count(os.sep)
    for current, dirs, names in os.walk(root, followlinks=False):
        depth = current.rstrip(os.sep).count(os.sep) - base_depth
        if depth >= depth_limit:
            dirs.clear()
        for name in sorted(names):
            if name.lower() in COMPOSE_FILE_NAMES and not os.path.islink(os.path.join(current, name)):
                projects.append({"compose_file": os.path.join(current, name), "project_directory": current})
                if len(projects) >= 100:
                    return {"status": "ok", "projects": projects, "truncated": True}
    return {"status": "ok", "projects": projects, "truncated": False}


def inspect_compose_project(compose_file: str) -> Dict[str, Any]:
    """Resolve a Compose file and return safe service topology without secrets."""
    path, error = _compose_file_path(compose_file)
    if error:
        return error
    result = _run_compose(path, ["config", "--format", "json", "--no-interpolate"])
    if result["status"] != "ok":
        return {**result, "compose_file": path}
    try:
        parsed = json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"status": "error", "compose_file": path, "error": "Compose did not return JSON configuration."}
    services = []
    for name, service in (parsed.get("services") or {}).items():
        services.append({"name": name, "image": service.get("image", ""), "ports": service.get("ports", []),
                         "depends_on": sorted((service.get("depends_on") or {}).keys()) if isinstance(service.get("depends_on"), dict) else service.get("depends_on", []),
                         "has_healthcheck": bool(service.get("healthcheck")), "restart": service.get("restart", ""),
                         "profiles": service.get("profiles", [])})
    return {"status": "ok", "compose_file": path, "service_count": len(services), "services": services}


def compose_project_action(compose_file: str, action: str, services: Optional[List[str]] = None, confirmation_token: Optional[str] = None) -> Dict[str, Any]:
    """Run a limited Compose lifecycle action after safety-gate confirmation."""
    path, error = _compose_file_path(compose_file)
    if error:
        return error
    action_name = action.strip().lower() if isinstance(action, str) else ""
    if action_name not in COMPOSE_ACTIONS:
        return {"status": "error", "error": "action must be one of: up, restart, stop."}
    selected = services or []
    if not isinstance(selected, list) or len(selected) > 20 or any(not isinstance(item, str) or not SERVICE_NAME_RE.fullmatch(item) for item in selected):
        return {"status": "error", "error": "services must contain at most 20 valid Compose service names."}
    parameters = {"compose_file": path, "action": action_name, "services": selected}
    authorization = request_authorization("compose_project_action", parameters, f"Run Docker Compose '{action_name}' for a project.", confirmation_token)
    if authorization is not None:
        return authorization
    args = ["up", "-d", "--no-build"] if action_name == "up" else [action_name]
    result = _run_compose(path, [*args, *selected], timeout=120)
    result.update({"compose_file": path, "action": action_name, "services": selected})
    result["audit_log_path"] = record_audit_event("compose_project_action", parameters, result)
    return result
