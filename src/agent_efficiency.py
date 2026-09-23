"""Small, on-demand answers for agents working on low-resource VPS hosts."""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, Optional

import psutil

try:
    from src.agent_runtime import get_recent_server_events
    from src.monitor import read_service_logs
    from src.topology import get_workload_health
    from src.files import _redact_config_text
except ImportError:
    from agent_runtime import get_recent_server_events
    from monitor import read_service_logs
    from topology import get_workload_health
    from files import _redact_config_text


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()[:20]


def get_guardian_launch() -> Dict[str, Any]:
    """Identify how this MCP process was started without returning command lines or env values."""
    parents = []
    try:
        process = psutil.Process(os.getpid())
        for ancestor in process.parents()[:5]:
            parents.append(ancestor.name().lower())
    except (psutil.Error, OSError):
        pass
    if os.environ.get("INVOCATION_ID") or os.environ.get("JOURNAL_STREAM"):
        method, restart = "systemd", "restart_systemd_unit"
    elif os.path.exists("/.dockerenv"):
        method, restart = "container", "restart_container"
    elif os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT") or any("sshd" in name for name in parents):
        method, restart = "ssh_stdio", "reconnect_mcp_client"
    else:
        method, restart = "direct_stdio", "reconnect_mcp_client"
    return {"status": "ok", "launch_method": method, "restart_method": restart, "systemd_unit_known": bool(os.environ.get("INVOCATION_ID")), "note": "Source changes load when the MCP process starts again."}


def _log_key(line: str) -> str:
    line = re.sub(r"^\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?\s*", "", line)
    line = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<ip>", line)
    line = re.sub(r"\b\d{4,}\b", "<number>", line)
    return line[:220]


def summarize_service_logs(service_name: str, lines_count: int = 120, grep_filter: Optional[str] = None, max_groups: int = 12, if_fingerprint: Optional[str] = None) -> Dict[str, Any]:
    if not isinstance(max_groups, int) or not 1 <= max_groups <= 30:
        return {"status": "error", "error": "max_groups must be 1-30."}
    if not isinstance(lines_count, int) or not 1 <= lines_count <= 500:
        return {"status": "error", "error": "lines_count must be 1-500."}
    result = read_service_logs(service_name, lines_count, grep_filter)
    if result.get("status") != "ok": return result
    raw = result.get("logs", "")
    if not isinstance(raw, str): return {"status": "error", "error": "Log reader returned invalid text."}
    fingerprint = _digest(raw)
    if if_fingerprint == fingerprint:
        return {"status": "unchanged", "fingerprint": fingerprint, "service_name": service_name}
    groups: Dict[str, Dict[str, Any]] = {}
    for number, line in enumerate(raw.splitlines(), 1):
        key = _log_key(line)
        clean, _ = _redact_config_text(line[:300])
        item = groups.setdefault(key, {"count": 0, "example": clean, "first_line": number, "last_line": number})
        item["count"] += 1; item["last_line"] = number
    ranked = sorted(groups.values(), key=lambda item: (-item["count"], item["first_line"]))
    return {"status": "ok", "service_name": service_name, "fingerprint": fingerprint, "total_lines": len(raw.splitlines()), "groups": ranked[:max_groups], "groups_omitted": max(0, len(ranked) - max_groups)}


def get_server_event_delta(since_minutes: int = 60, max_events: int = 20, target: Optional[str] = None, after_cursor: Optional[str] = None) -> Dict[str, Any]:
    if not isinstance(max_events, int) or not 1 <= max_events <= 50:
        return {"status": "error", "error": "max_events must be 1-50."}
    timeline = get_recent_server_events(since_minutes, 200, target)
    if timeline.get("status") != "ok": return timeline
    events = timeline.get("events", [])
    ids = [_digest(event) for event in events]
    cursor_missed = bool(after_cursor)
    if after_cursor in ids:
        position = len(ids) - 1 - ids[::-1].index(after_cursor)
        events, ids = events[position + 1:], ids[position + 1:]
        cursor_missed = False
    chosen = events[:max_events]
    new_cursor = _digest(chosen[-1]) if chosen else (after_cursor or (ids[-1] if ids else None))
    bounded = [{"timestamp": item.get("timestamp"), "source": item.get("source"), "event": str(item.get("event", ""))[:400]} for item in chosen]
    return {"status": "ok", "events": bounded, "event_count": len(chosen), "cursor": new_cursor, "cursor_missed": cursor_missed, "has_more": len(events) > max_events, "window_limited": timeline.get("event_count", 0) >= 200}


def get_workload_brief(target: str, sections: str = "health", detail: str = "brief", if_fingerprint: Optional[str] = None, max_chars: int = 4000) -> Dict[str, Any]:
    """Gather selected read-only workload context in one bounded result."""
    requested = {item.strip() for item in sections.split(",") if item.strip()} if isinstance(sections, str) else set()
    if not requested or not requested.issubset({"health", "events", "logs"}):
        return {"status": "error", "error": "sections must be health, events, logs, or a comma-separated subset."}
    if detail not in {"brief", "full"} or not isinstance(max_chars, int) or not 1000 <= max_chars <= 20000:
        return {"status": "error", "error": "detail must be brief/full and max_chars must be 1000-20000."}
    if not isinstance(target, str) or not target.strip() or len(target) > 128:
        return {"status": "error", "error": "target must contain 1-128 characters."}
    health = get_workload_health(target) if requested.intersection({"health", "logs"}) else {"status": "ok", "overall_status": None, "found": None, "matched_components": [], "collection_errors": {}}
    if health.get("status") != "ok": return health
    components = health.get("matched_components", [])
    result: Dict[str, Any] = {"status": "ok", "target": target, "overall_status": health.get("overall_status"), "found": health.get("found"), "collection_errors": health.get("collection_errors", {})}
    if "health" in requested:
        result["health"] = health if detail == "full" else {"host_pressure": health.get("host_pressure"), "components": [{"kind": item.get("kind"), "identity": item.get("identity")} for item in components[:8]], "components_omitted": max(0, len(components) - 8)}
    if "events" in requested:
        result["events"] = get_server_event_delta(30, 15 if detail == "full" else 5, target)
    if "logs" in requested:
        containers = [item.get("identity") for item in components if item.get("kind") == "container" and item.get("identity")]
        result["logs"] = [summarize_service_logs(f"docker:{name}", 100 if detail == "full" else 50, max_groups=8 if detail == "full" else 4) for name in containers[:2]]
        result["logs_omitted"] = max(0, len(containers) - 2)
    fingerprint = _digest(result)
    if if_fingerprint == fingerprint: return {"status": "unchanged", "target": target, "fingerprint": fingerprint}
    result["fingerprint"] = fingerprint
    while len(json.dumps(result, ensure_ascii=False, separators=(",", ":"))) > max_chars:
        if isinstance(result.get("logs"), list) and result["logs"]:
            result["logs"].pop(); result["truncated"] = True
        elif isinstance(result.get("events"), dict) and result["events"].get("events"):
            result["events"]["events"].pop(); result["truncated"] = True
        elif isinstance(result.get("health"), dict) and result["health"].get("components"):
            result["health"]["components"].pop(); result["truncated"] = True
        elif isinstance(result.get("health"), dict) and result["health"].get("matched_components"):
            result["health"]["matched_components"].pop(); result["truncated"] = True
        else:
            result = {"status": "ok", "target": target, "overall_status": health.get("overall_status"), "fingerprint": fingerprint, "truncated": True}
            break
    return result
