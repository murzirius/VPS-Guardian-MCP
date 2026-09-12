"""Privacy-preserving VPS state snapshots and baseline comparisons."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import secrets
import tempfile
from typing import Any, Callable, Dict, List, Optional

try:
    from src.docker_manager import list_docker_containers
    from src.files import DEFAULT_ALLOWED_DIRECTORIES
    from src.monitor import get_failed_systemd_units, get_system_health
    from src.network import get_open_ports
    from src.scheduler import list_cron_jobs, list_systemd_timers
except ImportError:
    from docker_manager import list_docker_containers
    from files import DEFAULT_ALLOWED_DIRECTORIES
    from monitor import get_failed_systemd_units, get_system_health
    from network import get_open_ports
    from scheduler import list_cron_jobs, list_systemd_timers


SNAPSHOT_SCHEMA_VERSION = 1
MAX_CONFIG_FILES = 500
MAX_CONFIG_FILE_BYTES = 5_000_000
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SNAPSHOT_ID_RE = re.compile(r"^snapshot_[0-9]{8}T[0-9]{6}Z_[A-Za-z0-9_-]{8,32}$")
_last_snapshot_dir: Optional[str] = None


def _sha256(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


def _snapshot_dir() -> str:
    configured = os.environ.get("VPS_GUARDIAN_SNAPSHOT_DIR", "").strip()
    if configured:
        return os.path.abspath(configured)
    if os.name == "nt":
        return os.path.abspath("snapshots")
    return "/var/lib/vps-guardian/snapshots"


def _fallback_snapshot_dir() -> str:
    return os.path.join(tempfile.gettempdir(), "vps-guardian-snapshots")


def _safe_metadata(value: Dict[str, Any], keys: List[str]) -> Dict[str, Any]:
    return {key: value.get(key) for key in keys if key in value}


def _config_manifest() -> Dict[str, Any]:
    """Return config paths and digests, never their content or target secrets."""
    roots = [item for item in DEFAULT_ALLOWED_DIRECTORIES if item != "/var/www"]
    files: List[Dict[str, Any]] = []
    skipped: List[Dict[str, str]] = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for current, dirs, names in os.walk(root, followlinks=False):
            dirs[:] = [name for name in dirs if not os.path.islink(os.path.join(current, name))]
            for name in sorted(names):
                if len(files) >= MAX_CONFIG_FILES:
                    return {"status": "ok", "files": files, "truncated": True, "skipped": skipped}
                path = os.path.join(current, name)
                if os.path.islink(path):
                    continue
                try:
                    size = os.path.getsize(path)
                    if size > MAX_CONFIG_FILE_BYTES:
                        skipped.append({"path": path, "reason": "larger than 5 MB"})
                        continue
                    with open(path, "rb") as config_file:
                        digest = _sha256(config_file.read())
                    files.append({"path": path, "size_bytes": size, "sha256": digest})
                except (OSError, PermissionError) as exc:
                    skipped.append({"path": path, "reason": str(exc)[:160]})
    return {"status": "ok", "files": files, "truncated": False, "skipped": skipped}


def _collect_snapshot(include_config_hashes: bool) -> Dict[str, Any]:
    errors: Dict[str, str] = {}

    def collect(name: str, function: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
        try:
            result = function()
            if result.get("status") != "ok":
                errors[name] = str(result.get("error", result.get("status")))[:300]
            return result
        except Exception as exc:
            errors[name] = str(exc)[:300]
            return {"status": "error", "error": str(exc)}

    health = collect("system_health", get_system_health)
    failed = collect("failed_units", get_failed_systemd_units)
    ports = collect("open_ports", get_open_ports)
    cron = collect("cron_jobs", list_cron_jobs)
    timers = collect("systemd_timers", list_systemd_timers)
    docker = collect("docker", lambda: list_docker_containers(all=True))
    config = _config_manifest() if include_config_hashes else {"status": "skipped", "files": []}

    safe_cron = []
    for job in cron.get("cron_jobs", []):
        fingerprint = _sha256(json.dumps(_safe_metadata(job, ["source", "line_number", "user", "schedule", "command"]), sort_keys=True))
        safe_cron.append({
            **_safe_metadata(job, ["source", "line_number", "user", "schedule", "type"]),
            "command_sha256": fingerprint,
        })
    safe_timers = [_safe_metadata(item, ["timer_unit", "activates_service"]) for item in timers.get("timers", [])]
    safe_ports = [_safe_metadata(item, ["protocol", "ip", "port", "process_name"]) for item in ports.get("ports", [])]
    safe_containers = [_safe_metadata(item, ["name", "image", "status", "health", "ports", "exit_code", "oom_killed"]) for item in docker.get("containers", [])]

    return {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": _safe_metadata(health.get("system", {}), ["hostname", "os", "architecture"]),
        "state": {
            "failed_units": [_safe_metadata(item, ["unit", "active", "sub"]) for item in failed.get("failed_units", [])],
            "open_ports": safe_ports,
            "cron_jobs": safe_cron,
            "systemd_timers": safe_timers,
            "docker_containers": safe_containers,
            "config_files": config,
        },
        "collection_errors": errors,
    }


def _write_snapshot(snapshot: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    global _last_snapshot_dir
    snapshot_id = "snapshot_" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + secrets.token_urlsafe(8)
    snapshot["snapshot_id"] = snapshot_id
    encoded = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    candidates = [_snapshot_dir(), _fallback_snapshot_dir()]
    for directory in candidates:
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            path = os.path.join(directory, f"{snapshot_id}.json")
            with open(path, "x", encoding="utf-8") as snapshot_file:
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
                snapshot_file.write(encoded)
            _last_snapshot_dir = directory
            return path, None
        except (OSError, PermissionError) as exc:
            last_error = str(exc)
    return None, last_error


def create_system_snapshot(label: Optional[str] = None, include_config_hashes: bool = True) -> Dict[str, Any]:
    """Persist a read-only inventory snapshot; saved data contains no file/cron content."""
    normalized_label = (label or "snapshot").strip()
    if not _LABEL_RE.fullmatch(normalized_label):
        return {"status": "error", "error": "label must contain 1-64 letters, digits, dots, dashes, or underscores."}
    snapshot = _collect_snapshot(bool(include_config_hashes))
    snapshot["label"] = normalized_label
    path, error = _write_snapshot(snapshot)
    if not path:
        return {"status": "error", "error": f"Unable to save snapshot: {error}"}
    return {
        "status": "ok", "success": True, "snapshot_id": snapshot["snapshot_id"], "label": normalized_label,
        "captured_at": snapshot["captured_at"], "snapshot_path": path,
        "collection_errors": snapshot["collection_errors"], "config_hashes_included": bool(include_config_hashes),
    }


def _snapshot_candidates() -> List[str]:
    candidates = [_snapshot_dir(), _last_snapshot_dir, _fallback_snapshot_dir()]
    return list(dict.fromkeys(item for item in candidates if item))


def _load_snapshot(snapshot_id: str) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not isinstance(snapshot_id, str) or not _SNAPSHOT_ID_RE.fullmatch(snapshot_id):
        return None, "Invalid snapshot_id."
    for directory in _snapshot_candidates():
        path = os.path.join(directory, f"{snapshot_id}.json")
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as snapshot_file:
                data = json.load(snapshot_file)
            if data.get("snapshot_id") != snapshot_id or data.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
                return None, "Snapshot format is invalid or unsupported."
            return data, None
        except (OSError, json.JSONDecodeError) as exc:
            return None, f"Unable to read snapshot: {exc}"
    return None, "Snapshot not found."


def list_system_snapshots(limit: int = 20) -> Dict[str, Any]:
    try:
        bounded_limit = max(1, min(int(limit), 100))
    except (TypeError, ValueError):
        bounded_limit = 20
    snapshots: List[Dict[str, Any]] = []
    seen = set()
    for directory in _snapshot_candidates():
        if not os.path.isdir(directory):
            continue
        try:
            names = sorted(os.listdir(directory), reverse=True)
        except OSError:
            continue
        for name in names[:bounded_limit]:
            snapshot_id = name[:-5] if name.endswith(".json") else ""
            if snapshot_id in seen or not _SNAPSHOT_ID_RE.fullmatch(snapshot_id):
                continue
            data, error = _load_snapshot(snapshot_id)
            if error or not data:
                continue
            seen.add(snapshot_id)
            snapshots.append(_safe_metadata(data, ["snapshot_id", "label", "captured_at", "host", "collection_errors"]))
    snapshots.sort(key=lambda item: item.get("captured_at", ""), reverse=True)
    return {"status": "ok", "snapshot_count": len(snapshots[:bounded_limit]), "snapshots": snapshots[:bounded_limit]}


def _index(items: List[Dict[str, Any]], key: Callable[[Dict[str, Any]], str]) -> Dict[str, Dict[str, Any]]:
    return {key(item): item for item in items}


def _change(category: str, change_type: str, severity: str, item: Dict[str, Any]) -> Dict[str, Any]:
    return {"category": category, "change": change_type, "severity": severity, "item": item}


def compare_system_snapshots(baseline_id: str, current_id: str) -> Dict[str, Any]:
    """Compare two stored snapshots and return priority-ranked infrastructure drift."""
    baseline, error = _load_snapshot(baseline_id)
    if error:
        return {"status": "error", "error": f"Baseline: {error}"}
    current, error = _load_snapshot(current_id)
    if error:
        return {"status": "error", "error": f"Current: {error}"}
    if baseline["host"].get("hostname") != current["host"].get("hostname"):
        return {"status": "error", "error": "Snapshots belong to different hosts and cannot be compared."}

    before, after = baseline["state"], current["state"]
    changes: List[Dict[str, Any]] = []
    old_ports = _index(before["open_ports"], lambda item: f"{item.get('protocol')}:{item.get('ip')}:{item.get('port')}")
    new_ports = _index(after["open_ports"], lambda item: f"{item.get('protocol')}:{item.get('ip')}:{item.get('port')}")
    for key in sorted(new_ports.keys() - old_ports.keys()):
        public = new_ports[key].get("ip") not in {"127.0.0.1", "::1", "localhost"}
        changes.append(_change("open_ports", "added", "warning" if public else "info", new_ports[key]))
    for key in sorted(old_ports.keys() - new_ports.keys()):
        changes.append(_change("open_ports", "removed", "info", old_ports[key]))

    old_failed = _index(before["failed_units"], lambda item: str(item.get("unit")))
    new_failed = _index(after["failed_units"], lambda item: str(item.get("unit")))
    for key in sorted(new_failed.keys() - old_failed.keys()):
        changes.append(_change("failed_units", "added", "critical", new_failed[key]))
    for key in sorted(old_failed.keys() - new_failed.keys()):
        changes.append(_change("failed_units", "resolved", "info", old_failed[key]))

    old_cron = _index(before["cron_jobs"], lambda item: f"{item.get('source')}:{item.get('line_number')}:{item.get('user')}:{item.get('schedule')}")
    new_cron = _index(after["cron_jobs"], lambda item: f"{item.get('source')}:{item.get('line_number')}:{item.get('user')}:{item.get('schedule')}")
    for key in sorted(new_cron.keys() - old_cron.keys()):
        changes.append(_change("cron_jobs", "added", "warning", new_cron[key]))
    for key in sorted(old_cron.keys() - new_cron.keys()):
        changes.append(_change("cron_jobs", "removed", "warning", old_cron[key]))
    for key in sorted(new_cron.keys() & old_cron.keys()):
        if new_cron[key].get("command_sha256") != old_cron[key].get("command_sha256"):
            changes.append(_change("cron_jobs", "command_changed", "warning", new_cron[key]))

    old_timers = _index(before["systemd_timers"], lambda item: str(item.get("timer_unit")))
    new_timers = _index(after["systemd_timers"], lambda item: str(item.get("timer_unit")))
    for key in sorted(new_timers.keys() - old_timers.keys()):
        changes.append(_change("systemd_timers", "added", "info", new_timers[key]))
    for key in sorted(old_timers.keys() - new_timers.keys()):
        changes.append(_change("systemd_timers", "removed", "info", old_timers[key]))

    old_docker = _index(before["docker_containers"], lambda item: str(item.get("name")))
    new_docker = _index(after["docker_containers"], lambda item: str(item.get("name")))
    for key in sorted(new_docker.keys() - old_docker.keys()):
        changes.append(_change("docker_containers", "added", "warning", new_docker[key]))
    for key in sorted(old_docker.keys() - new_docker.keys()):
        changes.append(_change("docker_containers", "removed", "info", old_docker[key]))
    for key in sorted(new_docker.keys() & old_docker.keys()):
        if new_docker[key] != old_docker[key]:
            changes.append(_change("docker_containers", "changed", "warning", new_docker[key]))

    old_files = _index(before["config_files"].get("files", []), lambda item: str(item.get("path")))
    new_files = _index(after["config_files"].get("files", []), lambda item: str(item.get("path")))
    for key in sorted(new_files.keys() - old_files.keys()):
        changes.append(_change("config_files", "added", "warning", new_files[key]))
    for key in sorted(old_files.keys() - new_files.keys()):
        changes.append(_change("config_files", "removed", "warning", old_files[key]))
    for key in sorted(new_files.keys() & old_files.keys()):
        if new_files[key].get("sha256") != old_files[key].get("sha256"):
            changes.append(_change("config_files", "changed", "warning", new_files[key]))

    rank = {"critical": 0, "warning": 1, "info": 2}
    changes.sort(key=lambda item: (rank[item["severity"]], item["category"], item["change"]))
    severity = changes[0]["severity"] if changes else "none"
    return {"status": "ok", "success": True, "baseline_id": baseline_id, "current_id": current_id,
            "overall_severity": severity, "change_count": len(changes), "changes": changes,
            "baseline_collection_errors": baseline.get("collection_errors", {}),
            "current_collection_errors": current.get("collection_errors", {})}
