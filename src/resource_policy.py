"""Server-enforced cooperative limits; operator settings cannot disable host guards."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from typing import Any, Dict
import psutil

# key: minimum, absolute maximum, legacy/auto value, Small VPS value, label
LIMIT_SPECS = {
    "project_read_bytes": (1000, 300000, 100000, 32000, "Project file read (bytes)"),
    "tool_response_bytes": (16000, 256000, 256000, 32000, "MCP tool/resource JSON (bytes)"),
    "http_response_bytes": (8192, 262144, 262144, 32768, "HTTP diagnostic body (bytes)"),
    "directory_items": (50, 5000, 5000, 500, "Directory entries"),
    "journal_lines": (20, 500, 500, 100, "Journal lines"),
    "project_search_files": (10, 1000, 1000, 200, "Code search files"),
    "project_search_bytes": (64000, 8000000, 8000000, 1000000, "Code search input (bytes)"),
    "project_patch_files": (1, 3, 3, 1, "Files per project patch"),
    "project_patch_bytes": (10000, 300000, 300000, 100000, "Staged patch text (bytes)"),
    "changeset_files": (1, 3, 3, 1, "Files per configuration ChangeSet"),
    "changeset_total_bytes": (10000, 400000, 400000, 100000, "Configuration ChangeSet text (bytes)"),
    "agent_job_concurrency": (0, 2, 2, 1, "Concurrent Agent Job checks"),
    "capsule_concurrency": (0, 1, 1, 0, "Test Capsules (0 disables, 1 allows)"),
}
PRESETS = {
    "auto": {key: spec[2] for key, spec in LIMIT_SPECS.items()},
    "small": {key: spec[3] for key, spec in LIMIT_SPECS.items()},
    "standard": {key: spec[2] for key, spec in LIMIT_SPECS.items()},
}
DEFAULT_SETTINGS = {"profile": "auto", "limits": {}}
MAX_SETTINGS_BYTES = 8192


def validate_settings(value: Any) -> dict:
    if not isinstance(value, dict) or set(value) != {"profile", "limits"}:
        raise ValueError("Supply profile and limits only.")
    profile, limits = value["profile"], value["limits"]
    if not isinstance(profile, str) or profile not in {*PRESETS, "custom"} or not isinstance(limits, dict):
        raise ValueError("Invalid resource profile.")
    if profile != "custom":
        if limits:
            raise ValueError("Preset profiles do not accept custom values.")
    else:
        if set(limits) != set(LIMIT_SPECS):
            raise ValueError("Custom settings must include every supported limit.")
        for key, value in limits.items():
            low, high, *_ = LIMIT_SPECS[key]
            if type(value) is not int or not low <= value <= high:
                raise ValueError("A custom limit is outside its permitted integer range.")
    return {"profile": profile, "limits": dict(limits)}


def settings_path() -> str:
    try:
        from src.access_policy import policy_directory
    except ImportError:
        from access_policy import policy_directory
    return os.path.join(policy_directory(), "limits.json")


def load_settings() -> dict:
    try:
        from src.access_policy import policy_directory
    except ImportError:
        from access_policy import policy_directory
    try:
        from src.safe_io import private_directory, read_bounded
    except ImportError:
        from safe_io import private_directory, read_bounded
    revision = "none"
    try:
        if os.path.lexists(policy_directory()):
            private_directory(policy_directory())
        raw = read_bounded(settings_path(), MAX_SETTINGS_BYTES, private=True)
        revision = hashlib.sha256(raw).hexdigest()
        return {"settings": validate_settings(json.loads(raw)), "revision": revision, "configured": True, "error": None}
    except FileNotFoundError:
        return {"settings": copy.deepcopy(DEFAULT_SETTINGS), "revision": revision, "configured": False, "error": None}
    except (OSError, ValueError, TypeError, RecursionError):
        return {"settings": {"profile": "small", "limits": {}}, "revision": revision if revision != "none" else "unreadable",
                "configured": True, "error": "Invalid or unsafe limits file. Conservative Small VPS limits are active; repair it through the operator panel or manually fix unsafe file permissions."}


def get_runtime_budget(_state=None) -> Dict[str, Any]:
    memory = psutil.virtual_memory()
    cores = psutil.cpu_count(logical=True) or 1
    constrained = memory.available < 512 * 1024 * 1024 or cores <= 1
    critical = memory.available < 256 * 1024 * 1024
    state = load_settings() if _state is None else _state
    settings = state["settings"]
    requested = dict(settings["limits"] if settings["profile"] == "custom" else PRESETS[settings["profile"]])
    ceilings = {key: spec[1] for key, spec in LIMIT_SPECS.items()}
    if constrained:
        ceilings.update(project_read_bytes=64000, tool_response_bytes=64000, http_response_bytes=65536,
                        directory_items=1000, journal_lines=150, project_search_files=400,
                        project_search_bytes=2000000, project_patch_files=2, project_patch_bytes=200000,
                        changeset_files=2, changeset_total_bytes=200000, agent_job_concurrency=1)
    if memory.available < 384 * 1024 * 1024:
        ceilings["capsule_concurrency"] = 0
    if critical:
        ceilings.update(project_search_files=100, project_search_bytes=1000000,
                        project_patch_files=1, project_patch_bytes=100000)
    limits = {key: min(value, ceilings[key]) for key, value in requested.items()}
    return {
        "status": "ok", "profile": "critical" if critical else "constrained" if constrained else "standard",
        "configured_profile": settings["profile"], "settings_revision": state["revision"], "settings_error": state["error"],
        "available_memory_bytes": memory.available,
        "available_memory_percent": round(memory.available / max(memory.total, 1) * 100, 1),
        "logical_cpu_cores": cores, "limits": limits, "requested_limits": requested,
        "reduced_limits": sorted(key for key in limits if limits[key] < requested[key]),
        "background_workers": 0,
        "note": "Cooperative per-operation limits, not an OS sandbox or a global CPU/RAM quota. Host guards always apply; in-flight work is not cancelled.",
    }


def get_workspace_settings() -> dict:
    state = load_settings()
    return {"status": "ok", **state, "runtime": get_runtime_budget(state),
            "specs": [{"key": key, "min": spec[0], "max": spec[1], "label": spec[4]} for key, spec in LIMIT_SPECS.items()],
            "presets": copy.deepcopy(PRESETS),
            "fixed_capsule_limits": {"memory_bytes": 134217728, "cpu_cores": 0.5, "timeout_seconds": 30, "output_bytes": 4096}}


def save_workspace_settings(settings: dict, expected_revision: str) -> dict:
    try:
        from src.access_policy import _policy_lock
        from src.safe_io import atomic_replace
        from src.safety import record_audit_event
    except ImportError:
        from access_policy import _policy_lock
        from safe_io import atomic_replace
        from safety import record_audit_event
    try:
        value = validate_settings(settings)
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        with _policy_lock():
            if expected_revision != load_settings()["revision"]:
                return {"status": "conflict", "error": "Limits changed elsewhere. Reload before applying."}
            atomic_replace(settings_path(), raw, private=True, limit=MAX_SETTINGS_BYTES)
        record_audit_event("operator_update_workspace_limits", value, {"status": "ok"})
        return get_workspace_settings()
    except (OSError, ValueError, TypeError, RecursionError):
        return {"status": "error", "error": "Cannot save limits. Check supported ranges and private-directory permissions."}


def bounded_response(data: dict, operation: str) -> dict:
    """Limit JSON output without repeating an operation or returning broken JSON."""
    limit = get_runtime_budget()["limits"]["tool_response_bytes"]
    raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    size = len(raw.encode("utf-8"))
    if size <= limit:
        return data
    result = {"response_truncated": True, "original_response_bytes": size, "limit_bytes": limit,
              "operation": operation,
              "note": "The operation already returned. Large fields were omitted. Do not repeat a mutation to retrieve output; use a narrower read/status request."}
    keys = sorted(data, key=lambda key: (key not in {"status", "success", "confirmation_token", "execution", "error"}
                                        and not key.endswith("_id"), key))
    omitted = []
    for key in keys:
        if key in result:
            continue
        value = data[key]
        encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        if len(encoded.encode("utf-8")) <= min(4096, limit // 4):
            trial = {**result, key: value}
            if len(json.dumps(trial, separators=(",", ":"), ensure_ascii=False).encode()) < limit - 2048:
                result[key] = value
                continue
        omitted.append(key[:80])
    result["omitted_fields"] = omitted[:20]
    return result


def is_constrained() -> bool:
    return get_runtime_budget()["profile"] != "standard"
