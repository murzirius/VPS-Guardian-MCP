"""Bounded, reversible multi-file change sets for VPS-Guardian-MCP."""

from __future__ import annotations

import datetime as dt
import difflib
import hashlib
import os
import secrets
import threading
import time
from typing import Any, Dict, List, Optional

try:
    from src.deploy import _run_systemctl
    from src.files import _redact_config_text, atomic_write_file, is_path_permitted
    from src.safety import record_audit_event, request_authorization
    from src.web import test_nginx_config
    from src.resource_policy import get_runtime_budget
except ImportError:
    from deploy import _run_systemctl
    from files import _redact_config_text, atomic_write_file, is_path_permitted
    from safety import record_audit_event, request_authorization
    from web import test_nginx_config
    from resource_policy import get_runtime_budget


MAX_CHANGESETS = 32
MAX_FILES_PER_CHANGESET = 3
MAX_FILE_BYTES = 200_000
MAX_TOTAL_BYTES = 400_000
CHANGESET_TTL_SECONDS = 300
MAX_DIFF_CHARS = 12_000
_sets: Dict[str, Dict[str, Any]] = {}
_lock = threading.RLock()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _cleanup() -> None:
    now = time.time()
    for change_id in [key for key, item in _sets.items() if item["expires_at"] <= now]:
        _sets.pop(change_id, None)
    while len(_sets) >= MAX_CHANGESETS:
        _sets.pop(min(_sets, key=lambda key: _sets[key]["expires_at"]), None)


def _active(change_id: str) -> Optional[Dict[str, Any]]:
    _cleanup()
    item = _sets.get(change_id)
    return item if item and item["state"] == "staging" else None


def _service_for_path(path: str) -> Optional[str]:
    normalized = path.replace("\\", "/")
    if normalized.startswith("/etc/nginx/"):
        return "nginx"
    return None


def begin_change_set(title: str, target: Optional[str] = None) -> Dict[str, Any]:
    if not isinstance(title, str) or not 3 <= len(title.strip()) <= 160:
        return {"status": "error", "error": "title must contain 3 to 160 characters."}
    change_id = f"chg_{secrets.token_urlsafe(12)}"
    now = time.time()
    item = {"change_set_id": change_id, "title": title.strip()[:160], "target": (target or "").strip()[:200] or None,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(), "expires_at": now + CHANGESET_TTL_SECONDS,
            "state": "staging", "files": [], "service": None}
    with _lock:
        _cleanup(); _sets[change_id] = item
    return {"status": "ok", "change_set": _public(item)}


def stage_file_change(change_set_id: str, file_path: str, content: str) -> Dict[str, Any]:
    if not isinstance(content, str):
        return {"status": "error", "error": "content must be a string."}
    candidate = content.encode("utf-8")
    if not candidate or len(candidate) > MAX_FILE_BYTES or b"\x00" in candidate:
        return {"status": "error", "error": "content must be non-empty text of at most 200,000 bytes."}
    allowed, path = is_path_permitted(file_path.strip() if isinstance(file_path, str) else "")
    service = _service_for_path(path) if allowed else None
    if not allowed or not service:
        return {"status": "forbidden", "error": "ChangeSets currently support only authorized Nginx configuration files.", "file_path": path}
    if not os.path.isdir(os.path.dirname(path)) or os.path.islink(path):
        return {"status": "error", "error": "Target parent must exist and target may not be a symlink.", "file_path": path}
    try:
        original = open(path, "rb").read() if os.path.isfile(path) else b""
    except OSError as exc:
        return {"status": "error", "error": f"Unable to read current file: {exc}", "file_path": path}
    if len(original) > MAX_FILE_BYTES:
        return {"status": "error", "error": "Current file exceeds the 200,000-byte ChangeSet limit."}
    with _lock:
        item = _active(change_set_id)
        if not item: return {"status": "not_found", "error": "ChangeSet is missing, expired, or already used."}
        existing = next((entry for entry in item["files"] if entry["file_path"] == path), None)
        limits = get_runtime_budget()["limits"]
        new_total = sum(len(entry["content"].encode("utf-8")) for entry in item["files"] if entry is not existing) + len(candidate)
        if new_total > min(MAX_TOTAL_BYTES, limits["changeset_total_bytes"]) or (existing is None and len(item["files"]) >= min(MAX_FILES_PER_CHANGESET, limits["changeset_files"])):
            return {"status": "error", "error": "ChangeSet exceeds its file-count or 400,000-byte budget."}
        if item["service"] and item["service"] != service:
            return {"status": "error", "error": "All ChangeSet files must belong to the same web-server service."}
        entry = {"file_path": path, "content": content, "original": original, "existed": os.path.isfile(path), "baseline_sha256": _digest(original) if os.path.isfile(path) else None, "candidate_sha256": _digest(candidate)}
        if existing: item["files"].remove(existing)
        item["files"].append(entry); item["service"] = service
    return {"status": "ok", "change_set": _public(item), "file": _public_file(entry)}


def preview_change_set(change_set_id: str) -> Dict[str, Any]:
    with _lock:
        item = _active(change_set_id)
        if not item: return {"status": "not_found", "error": "ChangeSet is missing, expired, or already used."}
        if not item["files"]: return {"status": "error", "error": "Stage at least one file before previewing."}
        diffs: List[Dict[str, Any]] = []
        for entry in item["files"]:
            before, _ = _redact_config_text(entry["original"].decode("utf-8", errors="replace"))
            after, _ = _redact_config_text(entry["content"])
            diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile=f"{entry['file_path']} (current)", tofile=f"{entry['file_path']} (candidate)"))
            diffs.append({"file_path": entry["file_path"], "diff": diff[:MAX_DIFF_CHARS], "diff_truncated": len(diff) > MAX_DIFF_CHARS})
        parameters = _parameters(item)
        auth = request_authorization("apply_change_set", parameters, "Apply bounded web-server configuration changes, validate, reload, and roll back on failure.")
        result = {"status": "confirmation_required" if auth else "ok", "change_set": _public(item), "diffs": diffs, "next_step": "Call apply_change_set with the confirmation token from this preview."}
        if auth: result["execution"] = auth; result["confirmation_token"] = auth.get("confirmation_token")
        return result


def apply_change_set(change_set_id: str, confirmation_token: Optional[str] = None) -> Dict[str, Any]:
    with _lock:
        item = _active(change_set_id)
        if not item: return {"status": "not_found", "success": False, "error": "ChangeSet is missing, expired, or already used."}
        parameters = _parameters(item)
        auth = request_authorization("apply_change_set", parameters, "Apply bounded web-server configuration changes, validate, reload, and roll back on failure.", confirmation_token)
        if auth is not None: return auth
        for entry in item["files"]:
            allowed, stable = is_path_permitted(entry["file_path"])
            current = open(stable, "rb").read() if allowed and os.path.isfile(stable) else b""
            if not allowed or stable != entry["file_path"] or os.path.islink(stable) or (_digest(current) if os.path.isfile(stable) else None) != entry["baseline_sha256"]:
                return {"status": "conflict", "success": False, "error": "A staged file changed after planning; create a new ChangeSet."}
        item["state"] = "applying"

    writes = []
    for entry in item["files"]:
        result = atomic_write_file(entry["file_path"], entry["content"], backup=True)
        writes.append(result)
        if not result.get("success"): break
    validation = test_nginx_config() if item["service"] == "nginx" and all(result.get("success") for result in writes) else {"status": "ok", "success": all(result.get("success") for result in writes)}
    reload_result = _run_systemctl("reload", item["service"]) if validation.get("success", validation.get("test_successful", False)) else {"success": False, "error": "Reload skipped because write or validation failed."}
    healthy = _run_systemctl("is-active", item["service"]) if reload_result.get("success") else {"success": False}
    success = all(result.get("success") for result in writes) and validation.get("test_successful", validation.get("success")) and reload_result.get("success") and healthy.get("success")
    rollback = []
    if not success:
        for entry in reversed(item["files"]):
            if entry["existed"]: rollback.append(atomic_write_file(entry["file_path"], entry["original"].decode("utf-8", errors="replace"), backup=False))
            elif os.path.exists(entry["file_path"]):
                try: os.remove(entry["file_path"]); rollback.append({"success": True, "file_path": entry["file_path"]})
                except OSError as exc: rollback.append({"success": False, "error": str(exc), "file_path": entry["file_path"]})
        _run_systemctl("reload", item["service"])
    with _lock: _sets.pop(change_set_id, None)
    result = {"status": "ok" if success else "rolled_back", "success": success, "change_set_id": change_set_id, "writes": writes, "validation": validation, "reload": reload_result, "health": healthy, "rolled_back": not success and all(entry.get("success") for entry in rollback), "rollback": rollback}
    result["audit_log_path"] = record_audit_event("apply_change_set", parameters, result)
    return result


def _parameters(item: Dict[str, Any]) -> Dict[str, Any]:
    return {"change_set_id": item["change_set_id"], "service": item["service"], "files": [{key: entry[key] for key in ("file_path", "baseline_sha256", "candidate_sha256")} for entry in item["files"]]}


def _public_file(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {key: entry[key] for key in ("file_path", "existed", "baseline_sha256", "candidate_sha256")}


def _public(item: Dict[str, Any]) -> Dict[str, Any]:
    return {"change_set_id": item["change_set_id"], "title": item["title"], "target": item["target"], "service": item["service"], "state": item["state"], "file_count": len(item["files"]), "files": [_public_file(entry) for entry in item["files"]], "expires_at": dt.datetime.fromtimestamp(item["expires_at"], dt.timezone.utc).isoformat()}
