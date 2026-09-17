"""Lightweight coordination and resource-alert tools for VPS Guardian.

The module intentionally has no background worker. Watches are evaluated only
when an MCP client asks for them, which keeps small VPS instances predictable.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
from typing import Any, Dict, List, Optional

import psutil


MAX_WINDOWS = 100
MAX_WATCHES = 50
MAX_RUNBOOKS = 100
METRICS = {"cpu", "memory", "swap", "disk"}
_SAFE_TEXT = re.compile(r"(?i)\b(password|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;]+")

# These are deliberately references to existing guarded MCP tools, never shell commands.
RUNBOOK_TEMPLATES = {
    "incident-triage": ("Collect health", "Inspect failed services", "Review recent events", "Record handoff"),
    "routine-health": ("Collect health", "Inspect resource alerts", "Review backups", "Record handoff"),
    "web-release-check": ("Inspect deployment", "Test HTTP endpoint", "Check TLS certificate", "Record handoff"),
}


def _state_dir() -> str:
    configured = os.environ.get("VPS_GUARDIAN_STATE_DIR", "").strip()
    if configured:
        return os.path.abspath(configured)
    if os.name == "nt":
        return os.path.abspath(".vps-guardian-state")
    return "/var/lib/vps-guardian"


def _path(name: str) -> str:
    os.makedirs(_state_dir(), mode=0o700, exist_ok=True)
    return os.path.join(_state_dir(), name)


def _load(name: str) -> Dict[str, Dict[str, Any]]:
    try:
        with open(_path(name), "r", encoding="utf-8") as file:
            value = json.load(file)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _save(name: str, value: Dict[str, Dict[str, Any]]) -> None:
    path = _path(name)
    temporary = f"{path}.{secrets.token_hex(4)}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as file:
        json.dump(value, file, ensure_ascii=False, indent=2)
    os.replace(temporary, path)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: Optional[dt.datetime] = None) -> str:
    return (value or _now()).isoformat()


def _scrub(value: str, maximum: int = 240) -> str:
    return _SAFE_TEXT.sub("***REDACTED***", value.strip()[:maximum])


def _is_active(record: Dict[str, Any]) -> bool:
    try:
        return record.get("status") == "active" and dt.datetime.fromisoformat(record["ends_at"]) > _now()
    except (KeyError, TypeError, ValueError):
        return False


def _bounded_minutes(value: int, minimum: int, maximum: int, field: str) -> Optional[Dict[str, Any]]:
    if not isinstance(value, int) or not minimum <= value <= maximum:
        return {"status": "error", "error": f"{field} must be between {minimum} and {maximum}."}
    return None


def create_maintenance_window(
    title: str,
    target: Optional[str] = None,
    starts_in_minutes: int = 0,
    duration_minutes: int = 60,
    allowed_actions: Optional[List[str]] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Create expiring coordination metadata for an intended maintenance period.

    A window does not grant permissions or bypass safety confirmation. It makes
    planned work visible to collaborating agents and stays bounded in local state.
    """
    if not isinstance(title, str) or not 3 <= len(title.strip()) <= 160:
        return {"status": "error", "error": "title must contain 3 to 160 characters."}
    if (error := _bounded_minutes(starts_in_minutes, 0, 10080, "starts_in_minutes")):
        return error
    if (error := _bounded_minutes(duration_minutes, 5, 1440, "duration_minutes")):
        return error
    if target is not None and (not isinstance(target, str) or len(target.strip()) > 200):
        return {"status": "error", "error": "target must contain at most 200 characters."}
    if session_id is not None and (not isinstance(session_id, str) or not re.fullmatch(r"ses_[a-f0-9]{16}", session_id)):
        return {"status": "error", "error": "session_id has an invalid format."}
    actions = allowed_actions or []
    if not isinstance(actions, list) or len(actions) > 12 or any(
        not isinstance(action, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", action) for action in actions
    ):
        return {"status": "error", "error": "allowed_actions must contain at most 12 safe action labels."}

    now = _now()
    starts_at = now + dt.timedelta(minutes=starts_in_minutes)
    ends_at = starts_at + dt.timedelta(minutes=duration_minutes)
    windows = _load("maintenance-windows.json")
    window_id = f"mw_{secrets.token_hex(8)}"
    window = {
        "window_id": window_id,
        "title": _scrub(title),
        "target": _scrub(target) if target else None,
        "allowed_actions": actions,
        "session_id": session_id,
        "created_at": _iso(now),
        "starts_at": _iso(starts_at),
        "ends_at": _iso(ends_at),
        "status": "active",
    }
    windows[window_id] = window
    if len(windows) > MAX_WINDOWS:
        oldest = sorted(windows, key=lambda key: windows[key].get("created_at", ""))[: len(windows) - MAX_WINDOWS]
        for key in oldest:
            windows.pop(key, None)
    _save("maintenance-windows.json", windows)
    return {"status": "ok", "window": window, "note": "This coordinates work only; all VPS changes still follow the active safety mode."}


def list_maintenance_windows(include_closed: bool = False) -> Dict[str, Any]:
    """List active maintenance windows and optionally closed/expired history."""
    windows = _load("maintenance-windows.json")
    changed = False
    result = []
    for window in windows.values():
        if window.get("status") == "active" and not _is_active(window):
            window["status"] = "expired"
            changed = True
        if include_closed or window.get("status") == "active":
            result.append(window)
    if changed:
        _save("maintenance-windows.json", windows)
    result.sort(key=lambda item: item.get("starts_at", ""))
    return {"status": "ok", "window_count": len(result), "windows": result}


def close_maintenance_window(window_id: str, outcome: str = "") -> Dict[str, Any]:
    """Close a maintenance window and retain a redacted outcome for handoff."""
    windows = _load("maintenance-windows.json")
    window = windows.get(window_id)
    if not window:
        return {"status": "not_found", "error": "Maintenance window was not found."}
    window["status"] = "closed"
    window["closed_at"] = _iso()
    window["outcome"] = _scrub(outcome or "No outcome supplied.")
    _save("maintenance-windows.json", windows)
    return {"status": "ok", "window": window}


def _metric_value(metric: str) -> float:
    if metric == "cpu":
        return round(float(psutil.cpu_percent(interval=0.1)), 1)
    if metric == "memory":
        return round(float(psutil.virtual_memory().percent), 1)
    if metric == "swap":
        return round(float(psutil.swap_memory().percent), 1)
    return round(float(psutil.disk_usage(os.path.abspath(os.sep)).percent), 1)


def watch_resource_threshold(metric: str, threshold_percent: float, ttl_minutes: int = 60) -> Dict[str, Any]:
    """Create an expiring on-demand system resource threshold watch.

    Watches never spawn a poller. Call get_resource_alerts to evaluate the
    current metrics, keeping CPU and memory use negligible on a small VPS.
    """
    if not isinstance(metric, str) or metric not in METRICS:
        return {"status": "error", "error": f"metric must be one of: {', '.join(sorted(METRICS))}."}
    if not isinstance(threshold_percent, (int, float)) or isinstance(threshold_percent, bool) or not 1 <= threshold_percent <= 100:
        return {"status": "error", "error": "threshold_percent must be a number between 1 and 100."}
    if (error := _bounded_minutes(ttl_minutes, 5, 1440, "ttl_minutes")):
        return error
    now = _now()
    watch = {
        "watch_id": f"rw_{secrets.token_hex(8)}",
        "metric": metric,
        "threshold_percent": round(float(threshold_percent), 1),
        "created_at": _iso(now),
        "ends_at": _iso(now + dt.timedelta(minutes=ttl_minutes)),
        "status": "active",
    }
    watches = _load("resource-watches.json")
    watches[watch["watch_id"]] = watch
    if len(watches) > MAX_WATCHES:
        oldest = sorted(watches, key=lambda key: watches[key].get("created_at", ""))[: len(watches) - MAX_WATCHES]
        for key in oldest:
            watches.pop(key, None)
    _save("resource-watches.json", watches)
    return {"status": "ok", "watch": watch, "note": "This is evaluated on demand; VPS Guardian does not create a background polling worker."}


def get_resource_alerts(limit: int = 50) -> Dict[str, Any]:
    """Evaluate active resource watches once and return only current alerts."""
    if not isinstance(limit, int) or not 1 <= limit <= MAX_WATCHES:
        return {"status": "error", "error": f"limit must be between 1 and {MAX_WATCHES}."}
    watches = _load("resource-watches.json")
    active = []
    changed = False
    for watch in watches.values():
        if watch.get("status") == "active" and not _is_active(watch):
            watch["status"] = "expired"
            changed = True
        if _is_active(watch):
            active.append(watch)
    if changed:
        _save("resource-watches.json", watches)
    samples = {metric: _metric_value(metric) for metric in sorted({item["metric"] for item in active})}
    alerts = [
        {**watch, "current_percent": samples[watch["metric"]], "severity": "warning" if samples[watch["metric"]] < 95 else "critical"}
        for watch in active
        if samples[watch["metric"]] >= watch["threshold_percent"]
    ]
    alerts.sort(key=lambda item: (item["current_percent"] - item["threshold_percent"]), reverse=True)
    return {"status": "ok", "active_watch_count": len(active), "samples": samples, "alert_count": min(len(alerts), limit), "alerts": alerts[:limit], "note": "Metrics are sampled only for this request; no background polling is running."}


def list_runbook_templates() -> Dict[str, Any]:
    """List fixed, command-free agent runbook templates."""
    return {"status": "ok", "templates": [{"template": key, "steps": list(steps)} for key, steps in RUNBOOK_TEMPLATES.items()]}


def start_runbook(template: str, title: str = "", target: Optional[str] = None, session_id: Optional[str] = None) -> Dict[str, Any]:
    """Open a bounded coordination runbook; it does not execute any action."""
    if template not in RUNBOOK_TEMPLATES:
        return {"status": "error", "error": "Unknown runbook template."}
    if title and (not isinstance(title, str) or len(title.strip()) > 160):
        return {"status": "error", "error": "title must contain at most 160 characters."}
    if target is not None and (not isinstance(target, str) or len(target.strip()) > 200):
        return {"status": "error", "error": "target must contain at most 200 characters."}
    if session_id is not None and (not isinstance(session_id, str) or not re.fullmatch(r"ses_[a-f0-9]{16}", session_id)):
        return {"status": "error", "error": "session_id has an invalid format."}
    run_id = f"rb_{secrets.token_hex(8)}"
    run = {"run_id": run_id, "template": template, "title": _scrub(title) or template, "target": _scrub(target) if target else None, "session_id": session_id, "created_at": _iso(), "status": "active", "steps": [{"step_id": index + 1, "title": step, "status": "pending"} for index, step in enumerate(RUNBOOK_TEMPLATES[template])]}
    runs = _load("runbooks.json"); runs[run_id] = run
    if len(runs) > MAX_RUNBOOKS:
        for key in sorted(runs, key=lambda item: runs[item].get("created_at", ""))[:len(runs) - MAX_RUNBOOKS]: runs.pop(key, None)
    _save("runbooks.json", runs)
    return {"status": "ok", "runbook": run, "note": "Runbooks coordinate guarded MCP work; they never run commands or bypass confirmation."}


def update_runbook_step(run_id: str, step_id: int, status: str, note: str = "") -> Dict[str, Any]:
    """Record a runbook step outcome after an agent performs the separate guarded tool call."""
    if status not in {"completed", "skipped", "blocked"} or not isinstance(step_id, int): return {"status": "error", "error": "Use a valid step_id and completed, skipped, or blocked status."}
    runs = _load("runbooks.json"); run = runs.get(run_id)
    if not run or run.get("status") != "active": return {"status": "not_found", "error": "Active runbook was not found."}
    step = next((item for item in run["steps"] if item["step_id"] == step_id), None)
    if not step: return {"status": "error", "error": "step_id was not found."}
    step.update({"status": status, "updated_at": _iso(), "note": _scrub(note)})
    if all(item["status"] in {"completed", "skipped"} for item in run["steps"]): run["status"] = "completed"; run["closed_at"] = _iso()
    _save("runbooks.json", runs); return {"status": "ok", "runbook": run}


def list_runbooks(include_closed: bool = False) -> Dict[str, Any]:
    """List active runbooks and optional completed history."""
    runs = [item for item in _load("runbooks.json").values() if include_closed or item.get("status") == "active"]
    return {"status": "ok", "runbook_count": len(runs), "runbooks": sorted(runs, key=lambda item: item.get("created_at", ""), reverse=True)}
