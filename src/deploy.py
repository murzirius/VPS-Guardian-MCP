"""Transactional deployment of supported web-server configuration files."""

from __future__ import annotations

import datetime
import difflib
import hashlib
import os
import subprocess
import tempfile
import threading
import time
from typing import Any, Dict, Optional
import secrets

try:
    from src.files import atomic_write_file, is_path_permitted
    from src.safety import record_audit_event, request_authorization
except ImportError:
    from files import atomic_write_file, is_path_permitted
    from safety import record_audit_event, request_authorization


MAX_CONFIG_BYTES = 200_000
MAX_DIFF_CHARS = 20_000
PLAN_TTL_SECONDS = 300
MAX_PLANS = 256
_plans: Dict[str, Dict[str, Any]] = {}
_plans_lock = threading.Lock()


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _truncate_output(value: Any) -> str:
    text = str(value or "").strip()
    return text[:4000] + ("..." if len(text) > 4000 else "")


def _read_file_bytes(path: str) -> bytes:
    with open(path, "rb") as file_handle:
        return file_handle.read()


def _service_for_path(path: str, service_name: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    inferred = None
    normalized = path.replace("\\", "/")
    if normalized.startswith("/etc/nginx/"):
        inferred = "nginx"
    elif normalized.startswith("/etc/caddy/"):
        inferred = "caddy"

    requested = (service_name or inferred or "").strip().lower()
    if not requested:
        return None, "Only /etc/nginx and /etc/caddy configs support transactional deployment."
    if requested not in {"nginx", "caddy"}:
        return None, "Supported transactional services are nginx and caddy."
    if inferred != requested:
        return None, "The service_name must match the configuration directory."
    return requested, None


def _validator_command(service: str, candidate_path: str) -> list[str]:
    if service == "nginx":
        return ["nginx", "-t", "-c", candidate_path]
    return ["caddy", "validate", "--config", candidate_path, "--adapter", "caddyfile"]


def _run_validation(service: str, candidate_path: str) -> Dict[str, Any]:
    command = _validator_command(service, candidate_path)
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=20, check=False
        )
    except FileNotFoundError:
        return {"status": "unavailable", "success": False, "command": command,
                "error": f"Validator for {service} is not installed or not on PATH."}
    except subprocess.TimeoutExpired:
        return {"status": "error", "success": False, "command": command,
                "error": f"Validation timed out for {service}."}
    except OSError as exc:
        return {"status": "error", "success": False, "command": command, "error": str(exc)}

    output = _truncate_output((completed.stdout or "") + (completed.stderr or ""))
    return {
        "status": "ok" if completed.returncode == 0 else "error",
        "success": completed.returncode == 0,
        "command": command,
        "exit_code": completed.returncode,
        "output": output,
        "error": None if completed.returncode == 0 else "Configuration validation failed.",
    }


def _run_systemctl(action: str, service: str) -> Dict[str, Any]:
    command = ["systemctl", action, service]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=30, check=False
        )
    except FileNotFoundError:
        return {"success": False, "command": command, "error": "systemctl is unavailable."}
    except subprocess.TimeoutExpired:
        return {"success": False, "command": command, "error": f"systemctl {action} timed out."}
    except OSError as exc:
        return {"success": False, "command": command, "error": str(exc)}
    return {
        "success": completed.returncode == 0,
        "command": command,
        "exit_code": completed.returncode,
        "output": _truncate_output((completed.stdout or "") + (completed.stderr or "")),
        "error": None if completed.returncode == 0 else f"systemctl {action} failed.",
    }


def _cleanup_plans(now: float) -> None:
    expired = [plan_id for plan_id, plan in _plans.items() if plan["expires_at"] <= now]
    for plan_id in expired:
        _plans.pop(plan_id, None)
    while len(_plans) >= MAX_PLANS:
        oldest = min(_plans, key=lambda item: _plans[item]["expires_at"])
        _plans.pop(oldest, None)


def plan_config_deployment(
    file_path: str, content: str, service_name: Optional[str] = None
) -> Dict[str, Any]:
    """Stage and validate a web-server config without changing the live file."""
    if not isinstance(file_path, str) or not file_path.strip():
        return {"status": "error", "error": "file_path must be a non-empty string."}
    if not isinstance(content, str):
        return {"status": "error", "error": "content must be a string."}
    candidate = content.encode("utf-8")
    if not candidate or len(candidate) > MAX_CONFIG_BYTES or b"\x00" in candidate:
        return {"status": "error", "error": "content must be non-empty text of at most 200,000 bytes."}

    allowed, path = is_path_permitted(file_path.strip())
    if not allowed:
        return {"status": "forbidden", "file_path": path, "error": "Path is outside authorized directories."}
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        return {"status": "error", "file_path": path, "error": "Parent directory does not exist."}
    service, error = _service_for_path(path, service_name)
    if error:
        return {"status": "error", "file_path": path, "error": error}

    existed = os.path.isfile(path)
    try:
        original = _read_file_bytes(path) if existed else b""
    except OSError as exc:
        return {"status": "error", "file_path": path, "error": f"Unable to read current file: {exc}"}
    if len(original) > MAX_CONFIG_BYTES:
        return {"status": "error", "file_path": path, "error": "Current file exceeds the 200,000-byte deployment limit."}

    candidate_path = ""
    validation: Dict[str, Any] = {}
    try:
        with tempfile.NamedTemporaryFile("wb", dir=parent, delete=False, prefix=".guardian_validate_") as staged:
            candidate_path = staged.name
            staged.write(candidate)
            staged.flush()
            os.fsync(staged.fileno())
        validation = _run_validation(service, candidate_path)
    except OSError as exc:
        return {"status": "error", "success": False, "file_path": path,
                "service_name": service, "error": f"Unable to stage candidate for validation: {exc}"}
    finally:
        if candidate_path and os.path.exists(candidate_path):
            try:
                os.remove(candidate_path)
            except OSError:
                pass
    if not validation["success"]:
        return {"status": validation["status"], "success": False, "file_path": path,
                "service_name": service, "validation": validation,
                "error": validation.get("error", "Configuration validation failed.")}

    original_text = original.decode("utf-8", errors="replace").splitlines(keepends=True)
    candidate_text = content.splitlines(keepends=True)
    diff = "".join(difflib.unified_diff(original_text, candidate_text, fromfile=f"{path} (current)", tofile=f"{path} (candidate)"))
    now = time.time()
    plan_id = secrets.token_urlsafe(18)
    baseline_hash = _sha256(original) if existed else None
    plan_parameters = {
        "deployment_id": plan_id,
        "file_path": path,
        "service_name": service,
        "baseline_sha256": baseline_hash,
        "candidate_sha256": _sha256(candidate),
    }
    with _plans_lock:
        _cleanup_plans(now)
        _plans[plan_id] = {
            **plan_parameters, "content": content, "existed": existed,
            "expires_at": now + PLAN_TTL_SECONDS, "state": "ready",
        }

    authorization = request_authorization(
        "deploy_config_change", plan_parameters,
        "Replace a validated web-server configuration, reload its service, and roll back on failure.",
    )
    result = {
        "status": "ok", "success": True, "deployment_id": plan_id, "file_path": path,
        "service_name": service, "baseline_sha256": baseline_hash,
        "candidate_sha256": plan_parameters["candidate_sha256"], "file_exists": existed,
        "validation": validation, "diff": diff[:MAX_DIFF_CHARS],
        "diff_truncated": len(diff) > MAX_DIFF_CHARS,
        "expires_at": datetime.datetime.fromtimestamp(now + PLAN_TTL_SECONDS, datetime.timezone.utc).isoformat(),
        "next_step": "Call deploy_config_change with deployment_id and the confirmation token, if one was issued.",
    }
    if authorization is not None:
        result["execution"] = authorization
        if authorization["status"] == "confirmation_required":
            result["status"] = "confirmation_required"
            result["success"] = False
            result["confirmation_token"] = authorization["confirmation_token"]
    return result


def deploy_config_change(deployment_id: str, confirmation_token: Optional[str] = None) -> Dict[str, Any]:
    """Commit a previously validated plan, reload it, and roll back on failure."""
    with _plans_lock:
        plan = _plans.get(deployment_id)
        if not plan or plan["expires_at"] <= time.time():
            _plans.pop(deployment_id, None)
            return {"status": "forbidden", "success": False, "error": "Deployment plan is invalid or expired."}
        if plan["state"] != "ready":
            return {"status": "forbidden", "success": False, "error": "Deployment plan is already executing or used."}

    path, service = plan["file_path"], plan["service_name"]
    try:
        current = _read_file_bytes(path) if os.path.exists(path) else b""
    except OSError as exc:
        return {"status": "error", "success": False, "error": f"Unable to re-read live file: {exc}"}
    current_hash = _sha256(current) if os.path.exists(path) else None
    if current_hash != plan["baseline_sha256"]:
        return {"status": "conflict", "success": False, "file_path": path,
                "error": "The live configuration changed after planning; create a new plan."}

    parameters = {key: plan[key] for key in ("deployment_id", "file_path", "service_name", "baseline_sha256", "candidate_sha256")}
    authorization = request_authorization(
        "deploy_config_change", parameters,
        "Replace a validated web-server configuration, reload its service, and roll back on failure.",
        confirmation_token,
    )
    if authorization is not None:
        return authorization
    with _plans_lock:
        if plan["state"] != "ready":
            return {"status": "forbidden", "success": False, "error": "Deployment plan is already executing or used."}
        plan["state"] = "executing"

    audit_parameters = {key: plan[key] for key in ("deployment_id", "file_path", "service_name", "baseline_sha256", "candidate_sha256")}
    write_result = atomic_write_file(path, plan["content"], backup=True)
    if not write_result.get("success"):
        result = {**write_result, "deployment_id": deployment_id, "rolled_back": False}
    else:
        reload_result = _run_systemctl("reload", service)
        health_result = _run_systemctl("is-active", service) if reload_result["success"] else None
        if reload_result["success"] and health_result and health_result["success"]:
            result = {"status": "ok", "success": True, "deployment_id": deployment_id,
                      "file_path": path, "service_name": service, "write": write_result,
                      "reload": reload_result, "health": health_result, "rolled_back": False}
        else:
            rollback_error = None
            try:
                if plan["existed"]:
                    rollback_write = atomic_write_file(path, current.decode("utf-8"), backup=False)
                    rollback_error = rollback_write.get("error") if not rollback_write.get("success") else None
                elif os.path.exists(path):
                    os.remove(path)
            except (OSError, UnicodeDecodeError) as exc:
                rollback_error = str(exc)
            rollback_reload = _run_systemctl("reload", service)
            result = {"status": "rolled_back", "success": False, "deployment_id": deployment_id,
                      "file_path": path, "service_name": service, "write": write_result,
                      "reload": reload_result, "health": health_result, "rolled_back": rollback_error is None,
                      "rollback_reload": rollback_reload,
                      "error": rollback_error or "New configuration was not kept because reload or health check failed."}
    with _plans_lock:
        _plans.pop(deployment_id, None)
    result["audit_log_path"] = record_audit_event("deploy_config_change", audit_parameters, result)
    return result
