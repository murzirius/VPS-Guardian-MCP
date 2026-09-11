"""Unified, read-only incident report for fast VPS triage."""

from __future__ import annotations

import datetime
import time
from typing import Any, Callable, Dict, List

try:
    from src.crash import check_kernel_errors, check_oom_events
    from src.database import get_database_health
    from src.docker_manager import list_docker_containers
    from src.monitor import get_failed_systemd_units, get_system_health
    from src.network import get_open_ports
    from src.security import audit_ssh_config
    from src.updates import check_system_updates
except ImportError:
    from crash import check_kernel_errors, check_oom_events
    from database import get_database_health
    from docker_manager import list_docker_containers
    from monitor import get_failed_systemd_units, get_system_health
    from network import get_open_ports
    from security import audit_ssh_config
    from updates import check_system_updates


def _collect(name: str, collector: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
    started = time.monotonic()
    try:
        result = collector()
        if not isinstance(result, dict):
            result = {"status": "error", "error": f"{name} returned a non-object result."}
    except Exception as exc:
        result = {"status": "error", "error": f"{name} failed: {exc}"}
    result = dict(result)
    result["collection_duration_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def _add_finding(
    findings: List[Dict[str, str]],
    severity: str,
    code: str,
    message: str,
) -> None:
    findings.append({"severity": severity, "code": code, "message": message})


def generate_incident_report(
    include_updates: bool = True,
    include_security: bool = True,
    include_network: bool = False,
) -> Dict[str, Any]:
    """Collect a prioritized, read-only incident report from existing diagnostics."""
    started = time.monotonic()
    sections: Dict[str, Dict[str, Any]] = {
        "system_health": _collect("system health", get_system_health),
        "failed_systemd_units": _collect("failed systemd units", get_failed_systemd_units),
        "docker": _collect("Docker inventory", list_docker_containers),
        "oom_events": _collect("OOM events", check_oom_events),
        "kernel_errors": _collect("kernel errors", check_kernel_errors),
        "databases": _collect("database health", get_database_health),
    }
    if include_updates:
        sections["system_updates"] = _collect("system updates", check_system_updates)
    if include_security:
        sections["ssh_security"] = _collect("SSH security", audit_ssh_config)
    if include_network:
        sections["open_ports"] = _collect("open ports", get_open_ports)

    findings: List[Dict[str, str]] = []
    health = sections["system_health"]
    cpu_percent = health.get("cpu", {}).get("usage_percent_total")
    ram_percent = health.get("memory", {}).get("ram", {}).get("used_percent")
    disk_percent = health.get("disk", {}).get("used_percent")

    for metric_name, value in (
        ("CPU", cpu_percent),
        ("RAM", ram_percent),
        ("root filesystem", disk_percent),
    ):
        if isinstance(value, (int, float)) and value >= 95:
            _add_finding(
                findings, "critical", f"{metric_name.lower().replace(' ', '_')}_saturation",
                f"{metric_name} utilization is critically high at {value:.1f}%.",
            )
        elif isinstance(value, (int, float)) and value >= 80:
            _add_finding(
                findings, "warning", f"{metric_name.lower().replace(' ', '_')}_pressure",
                f"{metric_name} utilization is elevated at {value:.1f}%.",
            )

    failed_units = sections["failed_systemd_units"].get("failed_units") or []
    if failed_units:
        _add_finding(
            findings,
            "critical",
            "failed_systemd_units",
            f"{len(failed_units)} systemd unit(s) are failed.",
        )

    containers = sections["docker"].get("containers") or []
    unhealthy = [item for item in containers if item.get("health") == "unhealthy"]
    oom_killed = [item for item in containers if item.get("oom_killed")]
    if unhealthy:
        _add_finding(
            findings, "warning", "unhealthy_containers",
            f"{len(unhealthy)} Docker container(s) report an unhealthy state.",
        )
    if oom_killed:
        _add_finding(
            findings, "critical", "oom_killed_containers",
            f"{len(oom_killed)} Docker container(s) were killed by the OOM killer.",
        )

    oom_count = sections["oom_events"].get("total_oom_events", 0)
    if isinstance(oom_count, int) and oom_count > 0:
        _add_finding(
            findings, "critical", "oom_events",
            f"{oom_count} recent system OOM event(s) were detected.",
        )

    kernel_critical = sections["kernel_errors"].get("critical_hardware_errors_count", 0)
    if isinstance(kernel_critical, int) and kernel_critical > 0:
        _add_finding(
            findings, "critical", "kernel_storage_errors",
            f"{kernel_critical} critical storage/filesystem kernel error(s) were detected.",
        )

    updates = sections.get("system_updates", {})
    security_updates = updates.get("security_updates_count", 0)
    if isinstance(security_updates, int) and security_updates > 0:
        _add_finding(
            findings, "warning", "security_updates",
            f"{security_updates} security update(s) are pending.",
        )
    if updates.get("reboot_required"):
        _add_finding(findings, "warning", "reboot_required", "A system reboot is required.")

    ssh_score = sections.get("ssh_security", {}).get("security_score")
    if isinstance(ssh_score, (int, float)) and ssh_score < 60:
        _add_finding(
            findings, "critical", "weak_ssh_configuration",
            f"SSH hardening score is critically low ({ssh_score}/100).",
        )
    elif isinstance(ssh_score, (int, float)) and ssh_score < 80:
        _add_finding(
            findings, "warning", "ssh_configuration",
            f"SSH hardening score should be improved ({ssh_score}/100).",
        )

    databases = sections["databases"].get("databases") or []
    degraded_databases = [db for db in databases if db.get("status") == "degraded"]
    if degraded_databases:
        _add_finding(
            findings, "warning", "degraded_databases",
            f"{len(degraded_databases)} detected database service(s) are degraded.",
        )

    unavailable_sections = [
        name for name, result in sections.items()
        if result.get("status") in {"error", "unavailable"}
    ]
    if unavailable_sections:
        _add_finding(
            findings, "info", "incomplete_telemetry",
            "Some diagnostics were unavailable: " + ", ".join(unavailable_sections) + ".",
        )

    severity_order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda item: severity_order[item["severity"]])
    critical_count = sum(item["severity"] == "critical" for item in findings)
    warning_count = sum(item["severity"] == "warning" for item in findings)
    overall_severity = "critical" if critical_count else "warning" if warning_count else "healthy"

    return {
        "status": "ok",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "overall_severity": overall_severity,
        "summary": {
            "critical_findings": critical_count,
            "warnings": warning_count,
            "informational": sum(item["severity"] == "info" for item in findings),
            "sections_collected": len(sections),
            "sections_unavailable": len(unavailable_sections),
        },
        "findings": findings,
        "sections": sections,
        "collection_duration_ms": round((time.monotonic() - started) * 1000, 2),
        "next_step": (
            "Review critical findings first and use read-only diagnostics before requesting "
            "any token-confirmed recovery action."
        ),
    }
