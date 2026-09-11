"""Server-enforced safety gates and audit logging for state-changing tools."""

from __future__ import annotations

import datetime
from collections import deque
import hashlib
import json
import os
import re
import secrets
import tempfile
import threading
import time
from typing import Any, Dict, Optional


VALID_SAFETY_MODES = {"read-only", "controlled", "unrestricted"}
DEFAULT_TOKEN_TTL_SECONDS = 300
_SENSITIVE_KEY_PATTERN = re.compile(
    r"(pass(word)?|secret|token|key|credential|authorization|cookie|content)",
    re.IGNORECASE,
)
_pending_confirmations: Dict[str, Dict[str, Any]] = {}
_confirmation_lock = threading.Lock()
_audit_lock = threading.Lock()
_last_audit_path: Optional[str] = None


def get_safety_mode() -> str:
    """Return the configured safety mode, defaulting to read-only."""
    raw_mode = os.environ.get("VPS_GUARDIAN_MODE", "read-only").strip().lower()
    aliases = {"readonly": "read-only", "confirm": "controlled", "full": "unrestricted"}
    mode = aliases.get(raw_mode, raw_mode)
    return mode if mode in VALID_SAFETY_MODES else "read-only"


def _token_ttl_seconds() -> int:
    try:
        return max(30, min(int(os.environ.get("VPS_GUARDIAN_CONFIRM_TTL", "300")), 3600))
    except (TypeError, ValueError):
        return DEFAULT_TOKEN_TTL_SECONDS


def _fingerprint(operation: str, parameters: Dict[str, Any]) -> str:
    serialized = json.dumps(
        {"operation": operation, "parameters": parameters},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _redact(value: Any, key: str = "") -> Any:
    if key and _SENSITIVE_KEY_PATTERN.search(key):
        if key.lower() == "content" and isinstance(value, str):
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
            return f"<redacted:{len(value.encode('utf-8'))} bytes sha256:{digest}>"
        return "***REDACTED***"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, str) and len(value) > 500:
        return value[:497] + "..."
    return value


def _scrub_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value)[:500]
    return re.sub(
        r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)"
        r"\s*[:=]\s*[^\s,;]+",
        r"\1=***REDACTED***",
        text,
    )


def request_authorization(
    operation: str,
    parameters: Dict[str, Any],
    impact: str,
    confirmation_token: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return a blocking response unless a state-changing operation is authorized.

    None means execution may continue. In controlled mode the first call creates
    a short-lived, single-use token bound to the exact operation and parameters.
    """
    mode = get_safety_mode()
    fingerprint = _fingerprint(operation, parameters)
    now = time.time()

    if mode == "unrestricted":
        return None

    if mode == "read-only":
        return {
            "status": "forbidden",
            "success": False,
            "safety_mode": mode,
            "operation": operation,
            "impact": impact,
            "parameters": _redact(parameters),
            "error": (
                "State-changing operations are disabled. Restart the server with "
                "VPS_GUARDIAN_MODE=controlled to enable token-confirmed execution."
            ),
        }

    with _confirmation_lock:
        expired_tokens = [
            token for token, record in _pending_confirmations.items()
            if record["expires_at"] <= now
        ]
        for token in expired_tokens:
            _pending_confirmations.pop(token, None)

        if len(_pending_confirmations) >= 1024:
            oldest_token = min(
                _pending_confirmations,
                key=lambda item: _pending_confirmations[item]["expires_at"],
            )
            _pending_confirmations.pop(oldest_token, None)

        if confirmation_token:
            record = _pending_confirmations.pop(confirmation_token, None)
            if not record:
                return {
                    "status": "forbidden",
                    "success": False,
                    "safety_mode": mode,
                    "operation": operation,
                    "error": "Confirmation token is invalid, expired, or already used.",
                }
            if record["fingerprint"] != fingerprint:
                return {
                    "status": "forbidden",
                    "success": False,
                    "safety_mode": mode,
                    "operation": operation,
                    "error": "Confirmation token does not match the requested operation and parameters.",
                }
            return None

        ttl = _token_ttl_seconds()
        token = secrets.token_urlsafe(24)
        expires_at = now + ttl
        _pending_confirmations[token] = {
            "fingerprint": fingerprint,
            "operation": operation,
            "expires_at": expires_at,
        }

    return {
        "status": "confirmation_required",
        "success": False,
        "safety_mode": mode,
        "operation": operation,
        "impact": impact,
        "parameters": _redact(parameters),
        "confirmation_token": token,
        "expires_in_seconds": ttl,
        "expires_at": datetime.datetime.fromtimestamp(
            expires_at, datetime.timezone.utc
        ).isoformat(),
        "message": "Review the plan, then repeat the same call with this confirmation_token.",
    }


def _configured_audit_path() -> str:
    configured = os.environ.get("VPS_GUARDIAN_AUDIT_LOG", "").strip()
    if configured:
        return os.path.abspath(configured)
    if os.name == "nt":
        return os.path.abspath(os.path.join(".", "logs", "audit.jsonl"))
    return "/var/log/vps-guardian/audit.jsonl"


def _append_json_line(path: str, event: Dict[str, Any]) -> bool:
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
        return True
    except (OSError, PermissionError):
        return False


def record_audit_event(
    operation: str,
    parameters: Dict[str, Any],
    result: Dict[str, Any],
) -> str:
    """Append a redacted audit record and return the path used."""
    global _last_audit_path

    event = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "operation": operation,
        "safety_mode": get_safety_mode(),
        "parameters": _redact(parameters),
        "result": {
            "status": result.get("status", "unknown"),
            "success": result.get("success", result.get("status") == "ok"),
            "error": _scrub_text(result.get("error")),
        },
    }
    primary_path = _configured_audit_path()
    with _audit_lock:
        if _append_json_line(primary_path, event):
            _last_audit_path = primary_path
            return primary_path
        fallback_path = os.path.join(tempfile.gettempdir(), "vps-guardian-audit.jsonl")
        if _append_json_line(fallback_path, event):
            _last_audit_path = fallback_path
            return fallback_path
        return ""


def get_safety_status() -> Dict[str, Any]:
    """Describe current enforcement mode without exposing pending tokens."""
    with _confirmation_lock:
        active_count = sum(
            1 for record in _pending_confirmations.values()
            if record["expires_at"] > time.time()
        )
    mode = get_safety_mode()
    return {
        "status": "ok",
        "safety_mode": mode,
        "state_changes_enabled": mode != "read-only",
        "confirmation_required": mode == "controlled",
        "confirmation_ttl_seconds": _token_ttl_seconds(),
        "pending_confirmations": active_count,
        "audit_log_path": _last_audit_path or _configured_audit_path(),
        "available_modes": sorted(VALID_SAFETY_MODES),
    }


def get_audit_events(limit: int = 50) -> Dict[str, Any]:
    """Read the latest redacted state-change audit events."""
    try:
        bounded_limit = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        bounded_limit = 50

    primary_path = _configured_audit_path()
    fallback_path = os.path.join(tempfile.gettempdir(), "vps-guardian-audit.jsonl")
    candidates = [_last_audit_path, primary_path, fallback_path]
    path = next((item for item in candidates if item and os.path.isfile(item)), primary_path)
    if not os.path.isfile(path):
        return {"status": "ok", "audit_log_path": path, "event_count": 0, "events": []}

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as audit_file:
            lines = list(deque(audit_file, maxlen=bounded_limit))
        events = []
        for line in lines:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return {
            "status": "ok",
            "audit_log_path": path,
            "event_count": len(events),
            "events": events,
        }
    except (OSError, PermissionError) as exc:
        return {"status": "error", "error": f"Unable to read audit log: {exc}", "events": []}
