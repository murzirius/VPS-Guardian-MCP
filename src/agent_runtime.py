"""Shared, secret-safe working context and event timelines for AI agents."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import secrets
import subprocess
from typing import Any, Dict, List, Optional

try:
    from src.safety import get_audit_events
except ImportError:  # pragma: no cover - direct script compatibility
    from safety import get_audit_events
try:
    from src.resource_policy import get_runtime_budget
except ImportError:
    from resource_policy import get_runtime_budget


MAX_TEXT = 1000
SENSITIVE = re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential|authorization|cookie)\s*[:=]\s*['\"]?[^\s,;\"']+")
URL_CREDENTIALS = re.compile(r"(?i)(://[^\s/:@]+:)[^\s@/]+(@)")
IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9_-]{7,63}$")


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


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: Optional[dt.datetime] = None) -> str:
    return (value or _now()).isoformat()


def _scrub(value: str) -> str:
    redacted = SENSITIVE.sub(lambda item: f"{item.group(1)}=***REDACTED***", value.strip()[:MAX_TEXT])
    return URL_CREDENTIALS.sub(r"\1***REDACTED***\2", redacted)


def _load(name: str, default: Any) -> Any:
    try:
        with open(_path(name), "r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, ValueError, TypeError):
        return default


def _save(name: str, value: Any) -> None:
    path = _path(name)
    temporary = f"{path}.{secrets.token_hex(4)}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as file:
        json.dump(value, file, ensure_ascii=False, indent=2)
    os.replace(temporary, path)


def _expiry(minutes: int, maximum: int = 10080) -> Optional[dt.datetime]:
    if not isinstance(minutes, int) or not 5 <= minutes <= maximum:
        return None
    return _now() + dt.timedelta(minutes=minutes)


def _active(record: Dict[str, Any]) -> bool:
    try:
        return dt.datetime.fromisoformat(record["expires_at"]) > _now()
    except (KeyError, TypeError, ValueError):
        return False


def _sessions() -> Dict[str, Dict[str, Any]]:
    records = _load("agent-sessions.json", {})
    return records if isinstance(records, dict) else {}


def start_agent_session(title: str, target: Optional[str] = None, ttl_minutes: int = 240) -> Dict[str, Any]:
    if not isinstance(title, str) or not 3 <= len(title.strip()) <= 160:
        return {"status": "error", "error": "title must contain 3 to 160 characters."}
    expires = _expiry(ttl_minutes)
    if not expires:
        return {"status": "error", "error": "ttl_minutes must be between 5 and 10080."}
    sessions = _sessions()
    session_id = f"ses_{secrets.token_hex(8)}"
    session = {
        "session_id": session_id, "title": _scrub(title), "target": _scrub(target) if target else None,
        "created_at": _iso(), "updated_at": _iso(), "expires_at": _iso(expires), "status": "active",
        "findings": [], "handoff": None,
    }
    sessions[session_id] = session
    _save("agent-sessions.json", sessions)
    return {"status": "ok", "session": session}


def get_agent_session(session_id: str) -> Dict[str, Any]:
    session = _sessions().get(session_id)
    if not session:
        return {"status": "not_found", "error": "Session was not found."}
    expired = session.get("status") == "active" and not _active(session)
    if expired:
        session["status"] = "expired"
    return {"status": "ok", "session": session, "expired": expired}


def list_agent_sessions(include_closed: bool = False) -> Dict[str, Any]:
    sessions = _sessions()
    result = []
    changed = False
    for session in sessions.values():
        if session.get("status") == "active" and not _active(session):
            session["status"] = "expired"; changed = True
        if include_closed or session.get("status") == "active":
            result.append(session)
    if changed:
        _save("agent-sessions.json", sessions)
    result.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
    return {"status": "ok", "session_count": len(result), "sessions": result}


def record_session_finding(session_id: str, summary: str, kind: str = "finding") -> Dict[str, Any]:
    if not isinstance(summary, str) or not summary.strip():
        return {"status": "error", "error": "summary must be a non-empty string."}
    if not isinstance(kind, str) or not re.fullmatch(r"[a-z_-]{1,32}", kind):
        return {"status": "error", "error": "kind may contain lowercase letters, underscores, and hyphens only."}
    sessions = _sessions(); session = sessions.get(session_id)
    if not session or session.get("status") != "active" or not _active(session):
        return {"status": "not_found", "error": "An active, unexpired session is required."}
    finding = {"timestamp": _iso(), "kind": kind, "summary": _scrub(summary)}
    session.setdefault("findings", []).append(finding)
    session["findings"] = session["findings"][-100:]
    session["updated_at"] = _iso(); _save("agent-sessions.json", sessions)
    return {"status": "ok", "finding": finding}


def handoff_agent_session(session_id: str, next_agent: str, summary: str) -> Dict[str, Any]:
    if not isinstance(next_agent, str) or not 1 <= len(next_agent.strip()) <= 80:
        return {"status": "error", "error": "next_agent must contain 1 to 80 characters."}
    result = record_session_finding(session_id, summary, "handoff")
    if result.get("status") != "ok": return result
    sessions = _sessions(); session = sessions[session_id]
    session["handoff"] = {"timestamp": _iso(), "next_agent": _scrub(next_agent), "summary": result["finding"]["summary"]}
    _save("agent-sessions.json", sessions)
    return {"status": "ok", "session": session}


def close_agent_session(session_id: str, outcome: str) -> Dict[str, Any]:
    sessions = _sessions(); session = sessions.get(session_id)
    if not session: return {"status": "not_found", "error": "Session was not found."}
    session["status"] = "closed"; session["closed_at"] = _iso(); session["outcome"] = _scrub(outcome or "No outcome supplied.")
    session["updated_at"] = _iso(); _save("agent-sessions.json", sessions)
    return {"status": "ok", "session": session}


def lock_workload(session_id: str, target: str, ttl_minutes: int = 30) -> Dict[str, Any]:
    if not isinstance(target, str) or not 1 <= len(target.strip()) <= 200:
        return {"status": "error", "error": "target must contain 1 to 200 characters."}
    session = get_agent_session(session_id).get("session")
    if not session or session.get("status") != "active" or not _active(session):
        return {"status": "not_found", "error": "An active, unexpired session is required."}
    expires = _expiry(ttl_minutes, 240)
    if not expires: return {"status": "error", "error": "ttl_minutes must be between 5 and 240."}
    locks = _load("workload-locks.json", {}); locks = locks if isinstance(locks, dict) else {}
    locks = {key: value for key, value in locks.items() if _active(value)}
    key = hashlib.sha256(target.strip().lower().encode()).hexdigest()[:16]
    existing = locks.get(key)
    if existing and existing.get("session_id") != session_id:
        return {"status": "locked", "target": _scrub(target), "lock": existing, "error": "Workload is reserved by another active agent session."}
    lock = {"session_id": session_id, "target": _scrub(target), "acquired_at": _iso(), "expires_at": _iso(expires)}
    locks[key] = lock; _save("workload-locks.json", locks)
    return {"status": "ok", "lock": lock}


def get_recent_server_events(since_minutes: int = 30, limit: int = 50, target: Optional[str] = None) -> Dict[str, Any]:
    if not isinstance(since_minutes, int) or not 1 <= since_minutes <= 1440:
        return {"status": "error", "error": "since_minutes must be between 1 and 1440."}
    if not isinstance(limit, int) or not 1 <= limit <= 200:
        return {"status": "error", "error": "limit must be between 1 and 200."}
    cutoff = _now() - dt.timedelta(minutes=since_minutes)
    needle = target.strip().lower() if isinstance(target, str) and target.strip() else ""
    events: List[Dict[str, Any]] = []
    for event in get_audit_events(500).get("events", []):
        try: timestamp = dt.datetime.fromisoformat(event["timestamp"])
        except (KeyError, TypeError, ValueError): continue
        description = f"{event.get('operation', 'operation')} {event.get('result', {}).get('status', 'unknown')}"
        if timestamp >= cutoff and (not needle or needle in json.dumps(event).lower()):
            events.append({"timestamp": event["timestamp"], "source": "guardian_audit", "event": _scrub(description)})
    journal = "/usr/bin/journalctl" if os.path.exists("/usr/bin/journalctl") else None
    if journal:
        try:
            journal_lines = get_runtime_budget()["limits"]["journal_lines"]
            result = subprocess.run([journal, "--no-pager", "-o", "short-iso", "--since", f"{since_minutes} minutes ago", "-n", str(journal_lines)], capture_output=True, text=True, timeout=12, check=False)
            pattern = re.compile(r"(?i)\b(failed|error|oom|out of memory|killed|restart|unhealthy|segfault|panic)\b")
            for line in result.stdout.splitlines():
                if pattern.search(line) and (not needle or needle in line.lower()):
                    events.append({"timestamp": line[:32].strip(), "source": "journal", "event": _scrub(line[32:])})
        except (OSError, subprocess.SubprocessError): pass
    events.sort(key=lambda item: item["timestamp"])
    return {"status": "ok", "since_minutes": since_minutes, "target": target, "event_count": min(len(events), limit), "events": events[-limit:]}


def open_event_watch(target: str, session_id: Optional[str] = None, ttl_minutes: int = 60) -> Dict[str, Any]:
    if not isinstance(target, str) or not 1 <= len(target.strip()) <= 200:
        return {"status": "error", "error": "target must contain 1 to 200 characters."}
    expires = _expiry(ttl_minutes, 1440)
    if not expires: return {"status": "error", "error": "ttl_minutes must be between 5 and 1440."}
    if session_id and get_agent_session(session_id).get("status") != "ok":
        return {"status": "not_found", "error": "Session was not found."}
    watches = _load("event-watches.json", {}); watches = watches if isinstance(watches, dict) else {}
    watch_id = f"watch_{secrets.token_hex(8)}"
    watch = {"watch_id": watch_id, "target": _scrub(target), "session_id": session_id, "created_at": _iso(), "expires_at": _iso(expires)}
    watches[watch_id] = watch; _save("event-watches.json", watches)
    return {"status": "ok", "watch": watch, "note": "Call get_event_watch to retrieve events since this watch was opened; MCP does not push notifications by itself."}


def get_event_watch(watch_id: str, limit: int = 50) -> Dict[str, Any]:
    watch = _load("event-watches.json", {}).get(watch_id)
    if not watch or not IDENTIFIER.fullmatch(watch_id.replace("watch_", "")):
        return {"status": "not_found", "error": "Watch was not found."}
    if not _active(watch): return {"status": "expired", "watch": watch, "events": []}
    created = dt.datetime.fromisoformat(watch["created_at"])
    elapsed = max(1, min(int((_now() - created).total_seconds() / 60) + 1, 1440))
    timeline = get_recent_server_events(elapsed, limit, watch["target"])
    return {"status": timeline.get("status"), "watch": watch, "events": timeline.get("events", []), "event_count": timeline.get("event_count", 0)}
