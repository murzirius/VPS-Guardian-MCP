"""Agent-oriented application topology, diagnosis, and baselines for a VPS.

This module composes existing bounded diagnostics into workload-level answers. It
never executes a lifecycle action, reads configuration contents, or stores logs.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import secrets
import tempfile
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from src.compose import inspect_compose_project, list_compose_projects
    from src.crash import check_kernel_errors, check_oom_events
    from src.database import get_database_health
    from src.docker_manager import get_docker_container_logs, get_docker_stats, list_docker_containers
    from src.monitor import get_system_health
    from src.network import get_open_ports
    from src.web import check_ssl_certificates, list_virtual_hosts
except ImportError:
    from compose import inspect_compose_project, list_compose_projects
    from crash import check_kernel_errors, check_oom_events
    from database import get_database_health
    from docker_manager import get_docker_container_logs, get_docker_stats, list_docker_containers
    from monitor import get_system_health
    from network import get_open_ports
    from web import check_ssl_certificates, list_virtual_hosts


MAX_QUERY_LENGTH = 128
MAX_COMPOSE_PROJECTS = 30
MAX_LOG_LINES = 300
_BASELINE_ID_RE = re.compile(r"^workload_[0-9]{8}T[0-9]{6}Z_[A-Za-z0-9_-]{8,32}$")
_last_baseline_dir: Optional[str] = None


def _collect(name: str, collector: Callable[[], Dict[str, Any]], errors: Dict[str, str]) -> Dict[str, Any]:
    try:
        result = collector()
        if not isinstance(result, dict):
            result = {"status": "error", "error": f"{name} returned a non-object result."}
    except Exception as exc:
        result = {"status": "error", "error": str(exc)}
    if result.get("status") != "ok":
        errors[name] = str(result.get("error", result.get("status")))[:300]
    return result


def _clean_query(query: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    if not isinstance(query, str):
        return None, {"status": "error", "error": "query must be a string."}
    normalized = query.strip()
    if not normalized or len(normalized) > MAX_QUERY_LENGTH or any(ord(char) < 32 for char in normalized):
        return None, {"status": "error", "error": "query must contain 1-128 printable characters."}
    return normalized.casefold(), None


def _safe_container(item: Dict[str, Any]) -> Dict[str, Any]:
    return {key: item.get(key) for key in ("id", "name", "image", "status", "ports", "health", "exit_code", "oom_killed", "restarting")}


def _safe_port(item: Dict[str, Any]) -> Dict[str, Any]:
    return {key: item.get(key) for key in ("protocol", "ip", "port", "pid", "process_name")}


def _safe_database(item: Dict[str, Any]) -> Dict[str, Any]:
    return {key: item.get(key) for key in ("engine", "status", "latency_ms", "version", "port") if key in item}


def _normalize_proxy_target(value: str) -> str:
    value = str(value).strip().lower()
    return re.sub(r"^[a-z]+://", "", value).split("/")[0]


def _compose_topology(errors: Dict[str, str]) -> List[Dict[str, Any]]:
    listing = _collect("compose_projects", lambda: list_compose_projects("/var/www", 2), errors)
    projects: List[Dict[str, Any]] = []
    for item in (listing.get("projects") or [])[:MAX_COMPOSE_PROJECTS]:
        compose_file = item.get("compose_file")
        if not isinstance(compose_file, str):
            continue
        inspected = _collect(f"compose:{compose_file}", lambda path=compose_file: inspect_compose_project(path), errors)
        if inspected.get("status") != "ok":
            projects.append({"compose_file": compose_file, "project_directory": item.get("project_directory", ""), "status": inspected.get("status")})
            continue
        services = []
        for service in inspected.get("services") or []:
            services.append({key: service.get(key) for key in ("name", "image", "ports", "depends_on", "has_healthcheck", "restart", "profiles")})
        projects.append({"compose_file": compose_file, "project_directory": item.get("project_directory", ""), "status": "ok", "services": services})
    if len(listing.get("projects") or []) > MAX_COMPOSE_PROJECTS:
        errors["compose_projects"] = f"Only the first {MAX_COMPOSE_PROJECTS} Compose projects were inspected."
    return projects


def get_vps_topology() -> Dict[str, Any]:
    """Build a bounded, secret-free map of web, container, and host components."""
    errors: Dict[str, str] = {}
    vhosts = _collect("virtual_hosts", list_virtual_hosts, errors)
    containers = _collect("docker", lambda: list_docker_containers(all=True), errors)
    ports = _collect("open_ports", get_open_ports, errors)
    databases = _collect("databases", get_database_health, errors)
    compose_projects = _compose_topology(errors)

    clean_vhosts = []
    for host in vhosts.get("virtual_hosts") or []:
        clean_vhosts.append({key: host.get(key) for key in ("config_file", "domains", "listen_ports", "has_ssl", "proxy_pass_targets")})
    clean_containers = [_safe_container(item) for item in containers.get("containers") or []]
    clean_ports = [_safe_port(item) for item in ports.get("ports") or []]
    clean_databases = [_safe_database(item) for item in databases.get("databases") or []]

    known_names = {str(item.get("name", "")).casefold() for item in clean_containers}
    for project in compose_projects:
        known_names.update(str(service.get("name", "")).casefold() for service in project.get("services") or [])
    relationships = []
    for host in clean_vhosts:
        for raw_target in host.get("proxy_pass_targets") or []:
            normalized = _normalize_proxy_target(raw_target)
            endpoint_name = normalized.split(":")[0]
            matches = [name for name in known_names if name and (name == endpoint_name or endpoint_name in name)]
            relationships.append({
                "kind": "reverse_proxy",
                "domains": host.get("domains", []),
                "proxy_target": raw_target,
                "matched_component_names": sorted(matches),
            })

    return {
        "status": "ok",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "summary": {
            "virtual_hosts": len(clean_vhosts),
            "compose_projects": len(compose_projects),
            "containers": len(clean_containers),
            "open_ports": len(clean_ports),
            "database_engines": len(clean_databases),
        },
        "websites": clean_vhosts,
        "compose_projects": compose_projects,
        "containers": clean_containers,
        "open_ports": clean_ports,
        "databases": clean_databases,
        "relationships": relationships,
        "collection_errors": errors,
        "safety_note": "Topology is read-only and intentionally excludes configuration content, environment values, and credentials.",
    }


def _match(value: Any, query: str) -> bool:
    if isinstance(value, (list, tuple)):
        return any(_match(item, query) for item in value)
    return query in str(value or "").casefold()


def find_workload(query: str) -> Dict[str, Any]:
    """Find a workload by domain, container, Compose service, port, or path fragment."""
    normalized, error = _clean_query(query)
    if error:
        return error
    topology = get_vps_topology()
    matches: List[Dict[str, Any]] = []
    for website in topology.get("websites", []):
        if _match(website.get("domains"), normalized) or _match(website.get("config_file"), normalized) or _match(website.get("proxy_pass_targets"), normalized):
            matches.append({"kind": "website", "identity": website.get("domains", []), "component": website})
    for project in topology.get("compose_projects", []):
        if _match(project.get("compose_file"), normalized) or _match(project.get("project_directory"), normalized):
            matches.append({"kind": "compose_project", "identity": project.get("compose_file"), "component": project})
        for service in project.get("services") or []:
            if _match(service.get("name"), normalized) or _match(service.get("image"), normalized) or _match(service.get("ports"), normalized):
                matches.append({"kind": "compose_service", "identity": service.get("name"), "compose_file": project.get("compose_file"), "component": service})
    for container in topology.get("containers", []):
        if _match(container.get("name"), normalized) or _match(container.get("image"), normalized) or _match(container.get("ports"), normalized):
            matches.append({"kind": "container", "identity": container.get("name"), "component": container})
    for port in topology.get("open_ports", []):
        if _match(port.get("port"), normalized) or _match(port.get("process_name"), normalized):
            matches.append({"kind": "listening_port", "identity": f"{port.get('protocol')}:{port.get('port')}", "component": port})
    for database in topology.get("databases", []):
        if _match(database.get("engine"), normalized):
            matches.append({"kind": "database", "identity": database.get("engine"), "component": database})

    # The same component can match several fields; return each once.
    unique: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in matches:
        unique[(str(item["kind"]), json.dumps(item.get("identity"), sort_keys=True))] = item
    results = list(unique.values())[:100]
    return {
        "status": "ok", "query": query.strip(), "match_count": len(results), "matches": results,
        "topology_collection_errors": topology.get("collection_errors", {}),
        "next_step": "Use get_workload_health or diagnose_workload with the same target for read-only investigation.",
    }


def get_workload_health(target: str) -> Dict[str, Any]:
    """Return a concise health view for every component that matches a workload target."""
    match_result = find_workload(target)
    if match_result.get("status") != "ok":
        return match_result
    errors: Dict[str, str] = {}
    system = _collect("system_health", get_system_health, errors)
    certificates = _collect("ssl_certificates", check_ssl_certificates, errors)
    stats = _collect("docker_stats", get_docker_stats, errors)
    matched_names = {str(item.get("identity", "")) for item in match_result.get("matches", []) if item.get("kind") == "container"}
    matched_container_stats = [item for item in stats.get("containers", []) if str(item.get("name", "")) in matched_names]
    domains = {domain for item in match_result.get("matches", []) if item.get("kind") == "website" for domain in item.get("component", {}).get("domains", [])}
    matched_certs = [item for item in certificates.get("certificates", []) if domains.intersection(set(item.get("domains") or []))]
    unhealthy = [item for item in match_result.get("matches", []) if item.get("kind") == "container" and (item.get("component", {}).get("status") != "running" or item.get("component", {}).get("health") == "unhealthy")]
    return {
        "status": "ok", "target": target.strip(), "found": match_result.get("match_count", 0),
        "overall_status": "degraded" if unhealthy else "ok",
        "matched_components": match_result.get("matches", []),
        "container_stats": matched_container_stats,
        "ssl_certificates": matched_certs,
        "host_pressure": {
            "cpu_percent": system.get("cpu", {}).get("usage_percent_total"),
            "ram_used_percent": system.get("memory", {}).get("ram", {}).get("used_percent"),
            "disk_used_percent": system.get("disk", {}).get("used_percent"),
        },
        "collection_errors": {**match_result.get("topology_collection_errors", {}), **errors},
    }


def diagnose_workload(target: str, log_lines: int = 100) -> Dict[str, Any]:
    """Collect bounded, read-only diagnostics for a discovered workload."""
    try:
        lines = max(1, min(int(log_lines), MAX_LOG_LINES))
    except (TypeError, ValueError):
        lines = 100
    health = get_workload_health(target)
    if health.get("status") != "ok":
        return health
    errors: Dict[str, str] = {}
    logs = []
    for item in health.get("matched_components", []):
        if item.get("kind") != "container":
            continue
        name = str(item.get("identity", ""))
        if name:
            logs.append(_collect(f"container_log:{name}", lambda container=name: get_docker_container_logs(container, lines), errors))
    oom = _collect("oom_events", lambda: check_oom_events(10), errors)
    kernel = _collect("kernel_errors", lambda: check_kernel_errors(20), errors)
    evidence = []
    if health.get("overall_status") == "degraded":
        evidence.append({"severity": "warning", "code": "unhealthy_component", "message": "At least one matched container is stopped or unhealthy."})
    if oom.get("total_oom_events", 0):
        evidence.append({"severity": "critical", "code": "oom_events", "message": f"{oom.get('total_oom_events')} recent OOM event(s) were detected."})
    if kernel.get("critical_hardware_errors_count", 0):
        evidence.append({"severity": "critical", "code": "kernel_errors", "message": "Critical kernel storage or hardware errors were detected."})
    return {
        "status": "ok", "target": target.strip(), "health": health,
        "container_logs": logs, "oom_events": oom, "kernel_errors": kernel,
        "evidence": evidence, "collection_errors": {**health.get("collection_errors", {}), **errors},
        "safety_note": "Diagnosis is read-only. Use prepare_repair_plan before any token-confirmed lifecycle or configuration action.",
    }


def get_change_impact(target: str, action: str = "inspect") -> Dict[str, Any]:
    """Explain which discovered components may be affected; never perform the action."""
    allowed_actions = {"inspect", "restart", "stop", "deploy_config", "update"}
    normalized_action = action.strip().lower() if isinstance(action, str) else ""
    if normalized_action not in allowed_actions:
        return {"status": "error", "error": "action must be one of: inspect, restart, stop, deploy_config, update."}
    matches = find_workload(target)
    if matches.get("status") != "ok":
        return matches
    affected = matches.get("matches", [])
    warnings = []
    if normalized_action in {"restart", "stop"}:
        warnings.append("A lifecycle action can interrupt requests for every matching container or service.")
    if normalized_action == "deploy_config":
        warnings.append("Validate a configuration candidate with plan_config_deployment before deployment.")
    if normalized_action == "update":
        warnings.append("Review pending package or image changes separately; this tool does not apply updates.")
    return {
        "status": "ok", "target": target.strip(), "action": normalized_action,
        "affected_components": affected, "affected_count": len(affected), "warnings": warnings,
        "required_next_step": "All state changes remain protected by the server safety mode and exact confirmation tokens.",
    }


def prepare_repair_plan(target: str) -> Dict[str, Any]:
    """Produce a non-executing, evidence-backed repair plan for an application."""
    diagnosis = diagnose_workload(target, 100)
    if diagnosis.get("status") != "ok":
        return diagnosis
    steps: List[Dict[str, str]] = [{"order": "1", "tool": "get_change_impact", "reason": "Review the component scope before a mutation."}]
    for component in diagnosis.get("health", {}).get("matched_components", []):
        if component.get("kind") == "container" and component.get("component", {}).get("status") != "running":
            steps.append({"order": str(len(steps) + 1), "tool": "docker_container_action", "reason": f"Consider a token-confirmed restart only after reviewing logs for {component.get('identity')}."})
    if diagnosis.get("oom_events", {}).get("total_oom_events", 0):
        steps.append({"order": str(len(steps) + 1), "tool": "get_system_health", "reason": "Resolve memory pressure before restarting a workload that may be OOM-killed again."})
    if not diagnosis.get("evidence"):
        steps.append({"order": str(len(steps) + 1), "tool": "get_workload_health", "reason": "No direct fault was found; retain the current read-only evidence and investigate application-specific behaviour."})
    steps.append({"order": str(len(steps) + 1), "tool": "create_workload_baseline", "reason": "Save the known-good workload state after a verified repair."})
    return {
        "status": "ok", "target": target.strip(), "diagnosis_evidence": diagnosis.get("evidence", []),
        "plan": steps, "executed": False,
        "safety_note": "This plan never changes the VPS. Any later mutating tool will request its own exact confirmation token in controlled mode.",
    }


def _baseline_dirs() -> List[str]:
    configured = os.environ.get("VPS_GUARDIAN_WORKLOAD_BASELINE_DIR", "").strip()
    default = os.path.join(os.environ.get("VPS_GUARDIAN_SNAPSHOT_DIR", "/var/lib/vps-guardian/snapshots"), "workloads")
    return list(dict.fromkeys(item for item in (configured, default, os.path.join(tempfile.gettempdir(), "vps-guardian-workloads")) if item))


def _baseline_signature(health: Dict[str, Any]) -> Dict[str, Any]:
    components = []
    for item in health.get("matched_components", []):
        component = item.get("component", {})
        components.append({"kind": item.get("kind"), "identity": item.get("identity"), "status": component.get("status"), "health": component.get("health"), "image": component.get("image"), "ports": component.get("ports")})
    return {"components": components, "ssl_certificates": health.get("ssl_certificates", [])}


def create_workload_baseline(target: str, label: Optional[str] = None) -> Dict[str, Any]:
    """Persist a secret-free known-good workload state for later comparison."""
    health = get_workload_health(target)
    if health.get("status") != "ok":
        return health
    baseline_id = "workload_" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + secrets.token_urlsafe(8)
    data = {"schema_version": 1, "baseline_id": baseline_id, "target": target.strip(), "label": (label or "baseline").strip()[:64], "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "signature": _baseline_signature(health)}
    encoded = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    global _last_baseline_dir
    last_error = "unknown error"
    for directory in _baseline_dirs():
        try:
            if not os.path.isdir(directory):
                os.makedirs(directory, mode=0o700 if os.name != "nt" else 0o777, exist_ok=True)
            path = os.path.join(directory, f"{baseline_id}.json")
            with open(path, "x", encoding="utf-8") as handle:
                handle.write(encoded)
            if os.name != "nt":
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
            _last_baseline_dir = directory
            return {"status": "ok", "success": True, "baseline_id": baseline_id, "target": data["target"], "label": data["label"], "captured_at": data["captured_at"], "baseline_path": path}
        except (OSError, PermissionError) as exc:
            last_error = str(exc)
    return {"status": "error", "error": f"Unable to save workload baseline: {last_error}"}


def _load_baseline(baseline_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not isinstance(baseline_id, str) or not _BASELINE_ID_RE.fullmatch(baseline_id):
        return None, "Invalid workload baseline ID."
    for directory in list(dict.fromkeys([_last_baseline_dir, *_baseline_dirs()])):
        if not directory:
            continue
        path = os.path.join(directory, f"{baseline_id}.json")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if data.get("schema_version") == 1 and data.get("baseline_id") == baseline_id:
                return data, None
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            return None, str(exc)
    return None, "Workload baseline was not found."


def compare_workload_baseline(baseline_id: str) -> Dict[str, Any]:
    """Compare a saved workload baseline with the current discovered workload state."""
    baseline, error = _load_baseline(baseline_id)
    if error:
        return {"status": "error", "error": error}
    health = get_workload_health(baseline["target"])
    if health.get("status") != "ok":
        return health
    before = baseline.get("signature", {})
    after = _baseline_signature(health)
    changes = []
    if before.get("components") != after.get("components"):
        changes.append({"category": "workload_components", "severity": "warning", "message": "Matched component state, image, health, or port mapping changed."})
    if before.get("ssl_certificates") != after.get("ssl_certificates"):
        changes.append({"category": "ssl_certificates", "severity": "warning", "message": "Matched SSL certificate metadata changed."})
    return {"status": "ok", "baseline_id": baseline_id, "target": baseline["target"], "changed": bool(changes), "change_count": len(changes), "changes": changes, "baseline_captured_at": baseline.get("captured_at"), "current_signature": after}
