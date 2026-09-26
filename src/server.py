"""VPS-Guardian-MCP: Secure Model Context Protocol Server for VPS Management.

Exposes safe, isolated tools for:
- System monitoring: CPU per core, RAM, Swap, Disk I/O, Network I/O, Uptime.
- Process tracking: Top CPU/Memory consuming processes.
- Service management: Systemd service health checks, failed units inspector.
- Service logs: Safe log inspection with Python-level grep filtering.
- Docker management: List containers, inspect container logs, live resource statistics.
- Network & firewall: Discover open/listening ports and audit UFW firewall rules.
- File & config management: Whitelisted file viewing, atomic writing with backups, directory inspection.
- Web & SSL diagnostics: Test Nginx configuration syntax, SSL/TLS expiry checks, virtual host listing.
- Security auditing: Audit failed SSH logins, Fail2ban status, SSH daemon config security analysis.
- Emergency recovery & backups: Whitelisted service restarts, cache/log cleanups, process termination, tar.gz backups.
- MCP Resources & Prompts: Auto-updating system summary resource and incident triage prompt template.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import functools
import inspect
from typing import Optional

# Direct all log records to stderr to preserve stdio JSON-RPC communication
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("vps_guardian.server")

try:
    from mcp.server.fastmcp import FastMCP
    from mcp.types import CallToolResult, TextContent
except ImportError:
    logger.error("The 'mcp' library is required. Run: pip install 'mcp<2.0.0,>=1.0.0'")
    raise

# Internal imports with fallback
try:
    from src.monitor import (
        check_service_status as _check_service_status,
        get_failed_systemd_units as _get_failed_systemd_units,
        get_system_health as _get_system_health,
        get_top_processes as _get_top_processes,
        read_service_logs as _read_service_logs,
    )
    from src.docker_manager import (
        clean_docker_garbage as _clean_docker_garbage,
        docker_container_action as _docker_container_action,
        get_docker_container_logs as _get_docker_container_logs,
        get_docker_stats as _get_docker_stats,
        inspect_docker_container as _inspect_docker_container,
        list_docker_containers as _list_docker_containers,
    )
    from src.proc_deep import (
        check_system_limits as _check_system_limits,
        detect_zombie_processes as _detect_zombie_processes,
        get_process_details as _get_process_details,
    )
    from src.files import (
        list_directory as _list_directory,
        set_web_file_mode as _set_web_file_mode,
        view_file_content as _view_file_content,
        write_file_content as _write_file_content,
    )
    from src.network import (
        get_open_ports as _get_open_ports,
        get_ufw_status as _get_ufw_status,
    )
    from src.web import (
        check_http_endpoint as _check_http_endpoint,
        check_http_endpoints as _check_http_endpoints,
        check_ssl_certificates as _check_ssl_certificates,
        get_web_deployment_status as _get_web_deployment_status,
        list_virtual_hosts as _list_virtual_hosts,
        test_nginx_config as _test_nginx_config,
    )
    from src.security import (
        audit_ssh_config as _audit_ssh_config,
        check_failed_logins as _check_failed_logins,
        get_fail2ban_status as _get_fail2ban_status,
    )
    from src.storage import (
        analyze_disk_usage as _analyze_disk_usage,
    )
    from src.scheduler import (
        list_cron_jobs as _list_cron_jobs,
        list_systemd_timers as _list_systemd_timers,
    )
    from src.updates import (
        check_guardian_updates as _check_guardian_updates,
        check_system_updates as _check_system_updates,
    )
    from src.crash import (
        check_kernel_errors as _check_kernel_errors,
        check_oom_events as _check_oom_events,
    )
    from src.net_diag import (
        check_dns_health as _check_dns_health,
        test_network_connectivity as _test_network_connectivity,
    )
    from src.database import (
        get_database_health as _get_database_health,
    )
    from src.recover import (
        create_backup as _create_backup,
        get_backup_status as _get_backup_status,
        run_recovery_action as _run_recovery_action,
        verify_backup as _verify_backup,
    )
    from src.incident import generate_incident_report as _generate_incident_report
    from src.safety import (
        get_audit_events as _get_audit_events,
        get_safety_status as _get_safety_status,
    )
    from src.deploy import (
        deploy_config_change as _deploy_config_change,
        plan_config_deployment as _plan_config_deployment,
    )
    from src.snapshot import (
        compare_system_snapshots as _compare_system_snapshots,
        create_system_snapshot as _create_system_snapshot,
        list_system_snapshots as _list_system_snapshots,
    )
    from src.platform import (
        get_firewall_status as _get_firewall_status,
        get_package_updates as _get_package_updates,
        get_platform_capabilities as _get_platform_capabilities,
    )
    from src.compose import (
        compose_project_action as _compose_project_action,
        inspect_compose_project as _inspect_compose_project,
        list_compose_projects as _list_compose_projects,
    )
    from src.topology import (
        compare_workload_baseline as _compare_workload_baseline,
        create_workload_baseline as _create_workload_baseline,
        diagnose_workload as _diagnose_workload,
        find_workload as _find_workload,
        get_change_impact as _get_change_impact,
        get_vps_topology as _get_vps_topology,
        get_workload_health as _get_workload_health,
        prepare_repair_plan as _prepare_repair_plan,
    )
    from src.agent_runtime import (
        close_agent_session as _close_agent_session,
        get_agent_session as _get_agent_session,
        get_event_watch as _get_event_watch,
        get_recent_server_events as _get_recent_server_events,
        handoff_agent_session as _handoff_agent_session,
        list_agent_sessions as _list_agent_sessions,
        lock_workload as _lock_workload,
        open_event_watch as _open_event_watch,
        record_session_finding as _record_session_finding,
        start_agent_session as _start_agent_session,
        create_agent_task as _create_agent_task,
        claim_agent_task as _claim_agent_task,
        heartbeat_agent_task as _heartbeat_agent_task,
        release_agent_task as _release_agent_task,
        finish_agent_task as _finish_agent_task,
        list_agent_tasks as _list_agent_tasks,
    )
    from src.changeset import (
        apply_change_set as _apply_change_set,
        begin_change_set as _begin_change_set,
        preview_change_set as _preview_change_set,
        stage_file_change as _stage_file_change,
    )
    from src.resource_policy import get_runtime_budget as _get_runtime_budget
    from src.agent_jobs import (
        advance_agent_job as _advance_agent_job,
        cancel_agent_job as _cancel_agent_job,
        create_agent_job as _create_agent_job,
        execute_agent_job_recovery as _execute_agent_job_recovery,
        finish_agent_job as _finish_agent_job,
        get_agent_job as _get_agent_job,
        list_agent_jobs as _list_agent_jobs,
        propose_agent_job_recovery as _propose_agent_job_recovery,
        verify_agent_job_recovery as _verify_agent_job_recovery,
    )
    from src.operations import (
        close_maintenance_window as _close_maintenance_window,
        create_maintenance_window as _create_maintenance_window,
        get_resource_alerts as _get_resource_alerts,
        list_maintenance_windows as _list_maintenance_windows,
        watch_resource_threshold as _watch_resource_threshold,
        list_runbook_templates as _list_runbook_templates,
        start_runbook as _start_runbook,
        update_runbook_step as _update_runbook_step,
        list_runbooks as _list_runbooks,
        create_agent_checkpoint as _create_agent_checkpoint,
        compare_agent_checkpoint as _compare_agent_checkpoint,
        list_agent_checkpoints as _list_agent_checkpoints,
        close_agent_checkpoint as _close_agent_checkpoint,
    )
    from src.project_workspace import (
        begin_project_patch as _begin_project_patch,
        discover_projects as _discover_projects,
        get_project_changes as _get_project_changes,
        inspect_project as _inspect_project,
        preview_project_patch as _preview_project_patch,
        read_project_file as _read_project_file,
        run_project_checks as _run_project_checks,
        search_project_code as _search_project_code,
        stage_project_file_change as _stage_project_file_change,
        apply_project_patch as _apply_project_patch,
    )
    from src.test_capsules import (
        get_test_capsule_status as _get_test_capsule_status,
        test_project_patch as _test_project_patch,
        promote_tested_project_patch as _promote_tested_project_patch,
    )
    from src.environment_doctor import (
        inspect_project_environment as _inspect_project_environment,
        diagnose_project_dependencies as _diagnose_project_dependencies,
        plan_environment_repair as _plan_environment_repair,
        plan_capsule_environment as _plan_capsule_environment,
    )
    from src.code_navigator import (
        get_project_import_map as _get_project_import_map,
        find_project_references as _find_project_references,
        assess_project_change as _assess_project_change,
        get_project_task_context as _get_project_task_context,
    )
except ImportError:
    from monitor import (
        check_service_status as _check_service_status,
        get_failed_systemd_units as _get_failed_systemd_units,
        get_system_health as _get_system_health,
        get_top_processes as _get_top_processes,
        read_service_logs as _read_service_logs,
    )
    from docker_manager import (
        clean_docker_garbage as _clean_docker_garbage,
        docker_container_action as _docker_container_action,
        get_docker_container_logs as _get_docker_container_logs,
        get_docker_stats as _get_docker_stats,
        inspect_docker_container as _inspect_docker_container,
        list_docker_containers as _list_docker_containers,
    )
    from proc_deep import (
        check_system_limits as _check_system_limits,
        detect_zombie_processes as _detect_zombie_processes,
        get_process_details as _get_process_details,
    )
    from files import (
        list_directory as _list_directory,
        set_web_file_mode as _set_web_file_mode,
        view_file_content as _view_file_content,
        write_file_content as _write_file_content,
    )
    from network import (
        get_open_ports as _get_open_ports,
        get_ufw_status as _get_ufw_status,
    )
    from web import (
        check_http_endpoint as _check_http_endpoint,
        check_http_endpoints as _check_http_endpoints,
        check_ssl_certificates as _check_ssl_certificates,
        get_web_deployment_status as _get_web_deployment_status,
        list_virtual_hosts as _list_virtual_hosts,
        test_nginx_config as _test_nginx_config,
    )
    from security import (
        audit_ssh_config as _audit_ssh_config,
        check_failed_logins as _check_failed_logins,
        get_fail2ban_status as _get_fail2ban_status,
    )
    from storage import (
        analyze_disk_usage as _analyze_disk_usage,
    )
    from scheduler import (
        list_cron_jobs as _list_cron_jobs,
        list_systemd_timers as _list_systemd_timers,
    )
    from updates import (
        check_guardian_updates as _check_guardian_updates,
        check_system_updates as _check_system_updates,
    )
    from crash import (
        check_kernel_errors as _check_kernel_errors,
        check_oom_events as _check_oom_events,
    )
    from net_diag import (
        check_dns_health as _check_dns_health,
        test_network_connectivity as _test_network_connectivity,
    )
    from database import (
        get_database_health as _get_database_health,
    )
    from recover import (
        create_backup as _create_backup,
        get_backup_status as _get_backup_status,
        run_recovery_action as _run_recovery_action,
        verify_backup as _verify_backup,
    )
    from incident import generate_incident_report as _generate_incident_report
    from safety import (
        get_audit_events as _get_audit_events,
        get_safety_status as _get_safety_status,
    )
    from deploy import (
        deploy_config_change as _deploy_config_change,
        plan_config_deployment as _plan_config_deployment,
    )
    from snapshot import (
        compare_system_snapshots as _compare_system_snapshots,
        create_system_snapshot as _create_system_snapshot,
        list_system_snapshots as _list_system_snapshots,
    )
    from platform import (
        get_firewall_status as _get_firewall_status,
        get_package_updates as _get_package_updates,
        get_platform_capabilities as _get_platform_capabilities,
    )
    from compose import (
        compose_project_action as _compose_project_action,
        inspect_compose_project as _inspect_compose_project,
        list_compose_projects as _list_compose_projects,
    )
    from topology import (
        compare_workload_baseline as _compare_workload_baseline,
        create_workload_baseline as _create_workload_baseline,
        diagnose_workload as _diagnose_workload,
        find_workload as _find_workload,
        get_change_impact as _get_change_impact,
        get_vps_topology as _get_vps_topology,
        get_workload_health as _get_workload_health,
        prepare_repair_plan as _prepare_repair_plan,
    )
    from agent_runtime import (
        close_agent_session as _close_agent_session,
        get_agent_session as _get_agent_session,
        get_event_watch as _get_event_watch,
        get_recent_server_events as _get_recent_server_events,
        handoff_agent_session as _handoff_agent_session,
        list_agent_sessions as _list_agent_sessions,
        lock_workload as _lock_workload,
        open_event_watch as _open_event_watch,
        record_session_finding as _record_session_finding,
        start_agent_session as _start_agent_session,
        create_agent_task as _create_agent_task,
        claim_agent_task as _claim_agent_task,
        heartbeat_agent_task as _heartbeat_agent_task,
        release_agent_task as _release_agent_task,
        finish_agent_task as _finish_agent_task,
        list_agent_tasks as _list_agent_tasks,
    )
    from changeset import (
        apply_change_set as _apply_change_set,
        begin_change_set as _begin_change_set,
        preview_change_set as _preview_change_set,
        stage_file_change as _stage_file_change,
    )
    from resource_policy import get_runtime_budget as _get_runtime_budget
    from agent_jobs import (
        advance_agent_job as _advance_agent_job,
        cancel_agent_job as _cancel_agent_job,
        create_agent_job as _create_agent_job,
        execute_agent_job_recovery as _execute_agent_job_recovery,
        finish_agent_job as _finish_agent_job,
        get_agent_job as _get_agent_job,
        list_agent_jobs as _list_agent_jobs,
        propose_agent_job_recovery as _propose_agent_job_recovery,
        verify_agent_job_recovery as _verify_agent_job_recovery,
    )
    from operations import (
        close_maintenance_window as _close_maintenance_window,
        create_maintenance_window as _create_maintenance_window,
        get_resource_alerts as _get_resource_alerts,
        list_maintenance_windows as _list_maintenance_windows,
        watch_resource_threshold as _watch_resource_threshold,
        list_runbook_templates as _list_runbook_templates,
        start_runbook as _start_runbook,
        update_runbook_step as _update_runbook_step,
        list_runbooks as _list_runbooks,
        create_agent_checkpoint as _create_agent_checkpoint,
        compare_agent_checkpoint as _compare_agent_checkpoint,
        list_agent_checkpoints as _list_agent_checkpoints,
        close_agent_checkpoint as _close_agent_checkpoint,
    )
    from project_workspace import (
        begin_project_patch as _begin_project_patch,
        discover_projects as _discover_projects,
        get_project_changes as _get_project_changes,
        inspect_project as _inspect_project,
        preview_project_patch as _preview_project_patch,
        read_project_file as _read_project_file,
        run_project_checks as _run_project_checks,
        search_project_code as _search_project_code,
        stage_project_file_change as _stage_project_file_change,
        apply_project_patch as _apply_project_patch,
    )
    from test_capsules import (
        get_test_capsule_status as _get_test_capsule_status,
        test_project_patch as _test_project_patch,
        promote_tested_project_patch as _promote_tested_project_patch,
    )
    from environment_doctor import (
        inspect_project_environment as _inspect_project_environment,
        diagnose_project_dependencies as _diagnose_project_dependencies,
        plan_environment_repair as _plan_environment_repair,
        plan_capsule_environment as _plan_capsule_environment,
    )
    from code_navigator import (
        get_project_import_map as _get_project_import_map,
        find_project_references as _find_project_references,
        assess_project_change as _assess_project_change,
        get_project_task_context as _get_project_task_context,
    )

try:
    from src.agent_efficiency import (
        get_guardian_launch as _get_guardian_launch,
        get_server_event_delta as _get_server_event_delta,
        get_workload_brief as _get_workload_brief,
        summarize_service_logs as _summarize_service_logs,
    )
    from src.project_workspace import (
        get_project_diff as _get_project_diff,
        get_project_symbols as _get_project_symbols,
        read_project_file_range as _read_project_file_range,
        stage_project_line_edit as _stage_project_line_edit,
    )
except ImportError:
    from agent_efficiency import (
        get_guardian_launch as _get_guardian_launch,
        get_server_event_delta as _get_server_event_delta,
        get_workload_brief as _get_workload_brief,
        summarize_service_logs as _summarize_service_logs,
    )
    from project_workspace import (
        get_project_diff as _get_project_diff,
        get_project_symbols as _get_project_symbols,
        read_project_file_range as _read_project_file_range,
        stage_project_line_edit as _stage_project_line_edit,
    )

# Initialize FastMCP Server
mcp = FastMCP(
    name="VPS-Guardian-MCP",
    dependencies=["psutil", "docker", "packaging", "tomli"],
    instructions=(
        "Use VPS-Guardian-MCP tools instead of asking the operator to run shell commands. "
        "For an application problem, begin with get_vps_topology or find_workload, then use "
        "get_workload_health and diagnose_workload. Treat diagnostics and change-impact reports as "
        "evidence, not authorization: use the existing controlled-mode confirmation flow for every "
        "state-changing action. Never expose credentials, configuration content, or confirmation tokens."
    ),
)

_TOOL_PROFILE = os.environ.get("VPS_GUARDIAN_TOOL_PROFILE", "full").strip().lower()
if _TOOL_PROFILE not in {"core", "full"}:
    raise ValueError("VPS_GUARDIAN_TOOL_PROFILE must be core or full.")
_CORE_TOOLS = {
    "get_system_health", "get_top_processes", "check_service_status", "read_service_logs",
    "get_vps_topology", "find_workload", "get_workload_health", "diagnose_workload",
    "get_change_impact", "prepare_repair_plan", "get_runtime_budget", "get_safety_status",
    "discover_projects", "inspect_project", "search_project_code", "read_project_file",
    "read_project_file_range", "get_project_symbols", "get_project_diff", "get_project_changes",
    "begin_project_patch", "stage_project_file_change", "stage_project_line_edit",
    "preview_project_patch", "apply_project_patch", "run_project_checks",
    "get_test_capsule_status", "test_project_patch", "promote_tested_project_patch",
    "inspect_project_environment", "diagnose_project_dependencies",
    "plan_environment_repair", "plan_capsule_environment",
    "get_project_import_map", "find_project_references", "assess_project_change", "get_project_task_context",
    "get_workload_brief", "summarize_service_logs", "get_server_event_delta", "get_guardian_launch",
    "start_agent_session", "get_agent_session", "record_session_finding", "handoff_agent_session",
    "get_recent_server_events", "get_event_watch", "open_event_watch",
    "create_agent_task", "claim_agent_task", "finish_agent_task", "list_agent_tasks",
    "create_agent_job", "get_agent_job", "list_agent_jobs", "advance_agent_job",
    "cancel_agent_job", "finish_agent_job", "propose_agent_job_recovery",
    "execute_agent_job_recovery", "verify_agent_job_recovery",
}


def guardian_tool():
    """Register the full catalog or a smaller agent workspace catalog at startup."""
    def decorate(function):
        if _TOOL_PROFILE == "core" and function.__name__ not in _CORE_TOOLS:
            return function
        @functools.wraps(function)
        def compact_result(*args, **kwargs):
            result = function(*args, **kwargs)
            if isinstance(result, CallToolResult):
                return result
            if isinstance(result, str):
                try: data = json.loads(result)
                except json.JSONDecodeError: return result
            else:
                data = result
            if not isinstance(data, dict):
                return result
            compact = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
            return CallToolResult(content=[TextContent(type="text", text=compact)], structuredContent=data)
        compact_result.__signature__ = inspect.signature(function, eval_str=True).replace(return_annotation=CallToolResult)
        return mcp.tool()(compact_result)
    return decorate


# ============================================================================
# 1. System & Service Monitoring Tools
# ============================================================================

@guardian_tool()
def get_system_health() -> str:
    """Retrieve a complete system health snapshot of the Linux VPS.

    Returns a JSON string containing:
    - CPU: overall percentage, per-core breakdown, core counts, 1/5/15m load averages.
    - RAM & Swap: total, used, available, percentage.
    - Disk: root partition usage, read/write I/O counters.
    - Network: sent/received bytes, packets, and error counts.
    - Uptime: boot timestamp and human-readable duration (e.g. '12d 4h 32m 10s').
    """
    try:
        data = _get_system_health()
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_system_health: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def get_top_processes(sort_by: str = "cpu", limit: int = 10) -> str:
    """Retrieve the top resource-consuming processes running on the VPS.

    Args:
        sort_by: Metric to rank processes by ('cpu' or 'memory'). Default: 'cpu'.
        limit: Number of top processes to return (1 to 50, default: 10).

    Returns:
        JSON string listing process PID, name, user, CPU %, RAM %, RSS memory, and command summary.
    """
    try:
        data = _get_top_processes(sort_by=sort_by, limit=limit)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_top_processes: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def check_service_status(service_name: str) -> str:
    """Check the operational status of a systemd service unit.

    Args:
        service_name: Name of the system service (e.g. 'nginx', 'mysql', 'postgresql', 'ufw', 'docker').

    Returns:
        JSON string with active state ('active', 'inactive', 'failed'), enabled state, and recent status logs.
    """
    try:
        data = _check_service_status(service_name=service_name)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_service_status: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def get_failed_systemd_units() -> str:
    """Find all degraded or failed systemd services across the entire system.

    Returns:
        JSON string with list of failed units ('systemctl --failed') and overall health indicator.
    """
    try:
        data = _get_failed_systemd_units()
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_failed_systemd_units: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def read_service_logs(
    service_name: str,
    lines_count: int = 50,
    grep_filter: Optional[str] = None,
) -> str:
    """Safely fetch and optionally filter recent log lines for a service or Docker container.

    Args:
        service_name: Target unit (e.g. 'nginx', 'systemd:cron', 'docker:my_container').
        lines_count: Number of recent lines to retrieve (default: 50, maximum: 1000).
        grep_filter: Optional case-insensitive keyword to filter lines (e.g. 'ERROR', '403', 'denied').

    Returns:
        JSON string containing the extracted log lines and matching statistics.
    """
    try:
        data = _read_service_logs(
            service_name=service_name,
            lines_count=lines_count,
            grep_filter=grep_filter,
        )
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in read_service_logs: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def get_process_details(pid: int) -> str:
    """In-depth diagnostics for a specific PID: hierarchy, threads, memory, open files, sockets, I/O.

    Args:
        pid: The target process ID to inspect (positive integer).

    Returns:
        JSON string detailing process tree, memory breakdown, sockets, files, and sanitized env.
    """
    try:
        data = _get_process_details(pid=pid)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_process_details: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def detect_zombie_processes() -> str:
    """Scan system process table for defunct/zombie processes and identify non-reaping parents.

    Returns:
        JSON string reporting detected zombies, parent PIDs, and remediation advice.
    """
    try:
        data = _detect_zombie_processes()
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in detect_zombie_processes: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def check_system_limits() -> str:
    """Audit system-wide and user limits: file descriptors, max PIDs, virtual memory, socket backlogs.

    Returns:
        JSON string comparing allocations to kernel limits and highlighting threshold warnings (>80%).
    """
    try:
        data = _check_system_limits()
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_system_limits: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


# ============================================================================
# 2. Docker Management Tools
# ============================================================================

@guardian_tool()
def list_docker_containers(all: bool = True) -> str:
    """List Docker containers with their status, image, port bindings, volumes, and health.

    Args:
        all: Set to True to list all containers (running and stopped), False for running only.

    Returns:
        JSON string with list of containers, port forwards, and mount mappings.
    """
    try:
        data = _list_docker_containers(all=all)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in list_docker_containers: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def get_docker_container_logs(container_name: str, lines_count: int = 50) -> str:
    """Safely read stdout/stderr logs from a specific Docker container.

    Args:
        container_name: Container name or container short/full ID.
        lines_count: Number of recent log lines to retrieve (default: 50, max: 1000).

    Returns:
        JSON string containing the container logs.
    """
    try:
        data = _get_docker_container_logs(container_name=container_name, lines_count=lines_count)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_docker_container_logs: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def get_docker_stats() -> str:
    """Retrieve live resource utilization metrics for all running Docker containers.

    Provides real-time CPU %, Memory %, Network I/O, and Block I/O (equivalent to `docker stats`).

    Returns:
        JSON string listing resource metrics per running container.
    """
    try:
        data = _get_docker_stats()
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_docker_stats: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def docker_container_action(
    container_name: str,
    action: str,
    timeout: int = 10,
    confirmation_token: Optional[str] = None,
) -> str:
    """Safely execute lifecycle operations (start, stop, restart, pause, unpause) on a container.

    Args:
        container_name: Name or short/full ID of the target Docker container.
        action: Desired action ('start', 'stop', 'restart', 'pause', 'unpause').
        timeout: Stop/restart timeout in seconds before forcible kill (default: 10).
        confirmation_token: Single-use token returned by the preceding plan call.

    Returns:
        JSON string detailing previous status, new status, and action outcome.
    """
    try:
        data = _docker_container_action(
            container_name=container_name,
            action=action,
            timeout=timeout,
            confirmation_token=confirmation_token,
        )
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in docker_container_action: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def inspect_docker_container(container_name: str) -> str:
    """Deep inspection of container networks, volume mounts, restart policy, healthcheck, and masked env vars.

    Args:
        container_name: Name or short/full ID of the target container.

    Returns:
        JSON string detailing full container architecture and runtime state.
    """
    try:
        data = _inspect_docker_container(container_name=container_name)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in inspect_docker_container: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def clean_docker_garbage(
    prune_type: str = "all",
    confirmation_token: Optional[str] = None,
) -> str:
    """Safely reclaim disk space by pruning dangling images, stopped containers, unused volumes, and networks.

    Args:
        prune_type: Category to prune ('containers', 'images', 'volumes', 'networks', 'all'). Default is 'all'.
        confirmation_token: Single-use token returned by the preceding plan call.

    Returns:
        JSON string detailing deleted items and total disk capacity reclaimed.
    """
    try:
        data = _clean_docker_garbage(
            prune_type=prune_type,
            confirmation_token=confirmation_token,
        )
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in clean_docker_garbage: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def list_compose_projects(root_path: str = "/var/www", max_depth: int = 2) -> str:
    """Discover conventional Docker Compose files in an authorized directory tree."""
    try:
        return json.dumps(_list_compose_projects(root_path, max_depth), separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in list_compose_projects: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def inspect_compose_project(compose_file: str) -> str:
    """Return Docker Compose service topology, images, ports, dependencies, and healthchecks."""
    try:
        return json.dumps(_inspect_compose_project(compose_file), separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in inspect_compose_project: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def compose_project_action(
    compose_file: str,
    action: str,
    services: Optional[list[str]] = None,
    confirmation_token: Optional[str] = None,
) -> str:
    """Token-confirmed Docker Compose up, restart, or stop for selected project services."""
    try:
        return json.dumps(_compose_project_action(compose_file, action, services, confirmation_token), separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in compose_project_action: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


# ============================================================================
# 2.5 Agent Workload Topology Tools
# ============================================================================

@guardian_tool()
def get_vps_topology() -> str:
    """Map websites, reverse proxies, Compose projects, containers, ports, and databases.

    The map is read-only and excludes configuration content, environment values,
    and credentials. Use it before diagnosing an application whose location on
    the VPS is unknown.
    """
    try:
        return json.dumps(_get_vps_topology(), separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_vps_topology: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def find_workload(query: str) -> str:
    """Find an application by domain, container, Compose service, port, or path fragment."""
    try:
        return json.dumps(_find_workload(query), separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in find_workload: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def get_workload_health(target: str) -> str:
    """Return concise health, resource, container, and matching SSL state for one workload."""
    try:
        return json.dumps(_get_workload_health(target), separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_workload_health: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def diagnose_workload(target: str, log_lines: int = 100) -> str:
    """Gather bounded read-only logs, OOM, kernel, and health evidence for a workload."""
    try:
        return json.dumps(_diagnose_workload(target, log_lines), separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in diagnose_workload: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def get_change_impact(target: str, action: str = "inspect") -> str:
    """Show what a prospective restart, stop, config deployment, or update may affect.

    This tool never executes the action and does not issue a confirmation token.
    """
    try:
        return json.dumps(_get_change_impact(target, action), separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_change_impact: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def prepare_repair_plan(target: str) -> str:
    """Create an evidence-backed repair plan without changing the VPS."""
    try:
        return json.dumps(_prepare_repair_plan(target), separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in prepare_repair_plan: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def create_workload_baseline(target: str, label: Optional[str] = None) -> str:
    """Save a secret-free known-good workload baseline for later drift comparison."""
    try:
        return json.dumps(_create_workload_baseline(target, label), separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in create_workload_baseline: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def compare_workload_baseline(baseline_id: str) -> str:
    """Compare a saved workload baseline with the current workload state."""
    try:
        return json.dumps(_compare_workload_baseline(baseline_id), separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in compare_workload_baseline: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


# ============================================================================
# 2b. Agent Sessions & Live Server Events
# ============================================================================

@guardian_tool()
def start_agent_session(title: str, target: Optional[str] = None, ttl_minutes: int = 240) -> str:
    """Create an expiring, secret-safe shared task context for agents working on this VPS."""
    return json.dumps(_start_agent_session(title, target, ttl_minutes), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def get_agent_session(session_id: str) -> str:
    """Read a session's objective, findings, handoff note, and expiry state."""
    return json.dumps(_get_agent_session(session_id), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def list_agent_sessions(include_closed: bool = False) -> str:
    """List active shared agent sessions; expired sessions are marked automatically."""
    return json.dumps(_list_agent_sessions(include_closed), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def record_session_finding(session_id: str, summary: str, kind: str = "finding") -> str:
    """Save one bounded, secret-redacted finding or decision to an active agent session."""
    return json.dumps(_record_session_finding(session_id, summary, kind), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def handoff_agent_session(session_id: str, next_agent: str, summary: str) -> str:
    """Leave a concise handoff note so another agent can continue without rediscovery."""
    return json.dumps(_handoff_agent_session(session_id, next_agent, summary), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def close_agent_session(session_id: str, outcome: str) -> str:
    """Close a session with an outcome; historical records remain secret-redacted."""
    return json.dumps(_close_agent_session(session_id, outcome), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def lock_workload(session_id: str, target: str, ttl_minutes: int = 30) -> str:
    """Reserve a workload briefly so concurrent agents do not make conflicting changes."""
    return json.dumps(_lock_workload(session_id, target, ttl_minutes), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def get_recent_server_events(since_minutes: int = 30, limit: int = 50, target: Optional[str] = None) -> str:
    """Return a compact timeline of Guardian actions and important journal events."""
    return json.dumps(_get_recent_server_events(since_minutes, limit, target), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def open_event_watch(target: str, session_id: Optional[str] = None, ttl_minutes: int = 60) -> str:
    """Open an expiring workload watch. Use get_event_watch later to retrieve new events."""
    return json.dumps(_open_event_watch(target, session_id, ttl_minutes), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def get_event_watch(watch_id: str, limit: int = 50) -> str:
    """Retrieve events seen since an active event watch was opened; this does not push notifications."""
    return json.dumps(_get_event_watch(watch_id, limit), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def create_agent_task(
    title: str,
    target: Optional[str] = None,
    priority: int = 50,
    depends_on: Optional[list[str]] = None,
    created_by_session: Optional[str] = None,
) -> str:
    """Add a bounded task to the shared agent queue; no server action is executed."""
    return json.dumps(_create_agent_task(title, target, priority, depends_on, created_by_session), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def claim_agent_task(task_id: str, session_id: str, lease_minutes: int = 30) -> str:
    """Lease one dependency-ready task to an active agent session."""
    return json.dumps(_claim_agent_task(task_id, session_id, lease_minutes), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def heartbeat_agent_task(task_id: str, session_id: str, lease_minutes: int = 30) -> str:
    """Extend a task lease while its owning agent session is still working."""
    return json.dumps(_heartbeat_agent_task(task_id, session_id, lease_minutes), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def release_agent_task(task_id: str, session_id: str, reason: str = "") -> str:
    """Return an owned task to the queue with a secret-redacted reason."""
    return json.dumps(_release_agent_task(task_id, session_id, reason), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def finish_agent_task(task_id: str, session_id: str, outcome: str, result: str = "") -> str:
    """Complete or fail an owned task and retain a bounded, redacted result."""
    return json.dumps(_finish_agent_task(task_id, session_id, outcome, result), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def list_agent_tasks(status: Optional[str] = None, include_finished: bool = False, limit: int = 100) -> str:
    """List prioritized tasks and release expired leases on demand."""
    return json.dumps(_list_agent_tasks(status, include_finished, limit), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def create_agent_job(title: str, checks: list[str], target: Optional[str] = None, session_id: Optional[str] = None, ttl_hours: int = 168) -> str:
    """Persist a bounded, read-only Agent Job. Checks: system_health, runtime_budget, workload_brief, event_delta, service_logs, service_status."""
    return json.dumps(_create_agent_job(title, checks, target, session_id, ttl_hours), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def get_agent_job(job_id: str, after_revision: int = 0) -> str:
    """Get job progress and compact results; use after_revision to receive only new steps."""
    return json.dumps(_get_agent_job(job_id, after_revision), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def list_agent_jobs(include_finished: bool = False, limit: int = 25) -> str:
    """List persistent job summaries without returning step outputs."""
    return json.dumps(_list_agent_jobs(include_finished, limit), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def advance_agent_job(job_id: str, session_id: Optional[str] = None, background: bool = False) -> str:
    """Run one bounded read-only step, optionally detached so it can finish after MCP disconnects."""
    return json.dumps(_advance_agent_job(job_id, session_id, background), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def cancel_agent_job(job_id: str, reason: str = "") -> str:
    """Cancel a job; in-flight read-only results cannot revive it."""
    return json.dumps(_cancel_agent_job(job_id, reason), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def finish_agent_job(job_id: str, conclusion: str) -> str:
    """Record the agent's conclusion after all checks or recovery verification."""
    return json.dumps(_finish_agent_job(job_id, conclusion), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def propose_agent_job_recovery(job_id: str, service_name: str, reason: str) -> str:
    """Propose one systemd-service restart after job checks; this does not execute it."""
    return json.dumps(_propose_agent_job_recovery(job_id, service_name, reason), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def execute_agent_job_recovery(job_id: str, confirmation_token: Optional[str] = None) -> str:
    """Execute a proposed restart through the existing safety-mode confirmation gate, then require verification."""
    return json.dumps(_execute_agent_job_recovery(job_id, confirmation_token), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def verify_agent_job_recovery(job_id: str) -> str:
    """Read service health after a job restart; never restart or roll back automatically."""
    return json.dumps(_verify_agent_job_recovery(job_id), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def begin_change_set(title: str, target: Optional[str] = None) -> str:
    """Open a short-lived, bounded, reversible Nginx configuration ChangeSet."""
    return json.dumps(_begin_change_set(title, target), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def stage_file_change(change_set_id: str, file_path: str, content: str) -> str:
    """Stage one Nginx configuration change; content is not applied yet."""
    return json.dumps(_stage_file_change(change_set_id, file_path, content), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def preview_change_set(change_set_id: str) -> str:
    """Show secret-redacted diffs and request one confirmation for a ChangeSet."""
    return json.dumps(_preview_change_set(change_set_id), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def apply_change_set(change_set_id: str, confirmation_token: Optional[str] = None) -> str:
    """Apply, validate, reload, health-check, and automatically roll back one ChangeSet."""
    return json.dumps(_apply_change_set(change_set_id, confirmation_token), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def get_runtime_budget() -> str:
    """Show the active low-resource profile and limits VPS-Guardian applies on this host."""
    return json.dumps(_get_runtime_budget(), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def create_maintenance_window(
    title: str,
    target: Optional[str] = None,
    starts_in_minutes: int = 0,
    duration_minutes: int = 60,
    allowed_actions: Optional[list[str]] = None,
    session_id: Optional[str] = None,
) -> str:
    """Create an expiring maintenance window for agent coordination.

    A window records intent and timing; it never bypasses the active safety
    mode or grants permission for VPS changes.
    """
    return json.dumps(_create_maintenance_window(title, target, starts_in_minutes, duration_minutes, allowed_actions, session_id), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def list_maintenance_windows(include_closed: bool = False) -> str:
    """List active maintenance windows, or include closed and expired history."""
    return json.dumps(_list_maintenance_windows(include_closed), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def close_maintenance_window(window_id: str, outcome: str = "") -> str:
    """Close a maintenance window with a secret-redacted outcome note."""
    return json.dumps(_close_maintenance_window(window_id, outcome), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def watch_resource_threshold(metric: str, threshold_percent: float, ttl_minutes: int = 60) -> str:
    """Create an expiring CPU, memory, swap, or disk threshold watch.

    The watch has no background worker. Call get_resource_alerts to evaluate it
    on demand, which is safe for small VPS instances.
    """
    return json.dumps(_watch_resource_threshold(metric, threshold_percent, ttl_minutes), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def get_resource_alerts(limit: int = 50) -> str:
    """Evaluate active resource watches once and return current threshold alerts."""
    return json.dumps(_get_resource_alerts(limit), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def list_runbook_templates() -> str:
    """List command-free agent runbooks built from existing guarded MCP tools."""
    return json.dumps(_list_runbook_templates(), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def start_runbook(template: str, title: str = "", target: Optional[str] = None, session_id: Optional[str] = None) -> str:
    """Open a bounded agent runbook; it never runs commands or bypasses confirmation."""
    return json.dumps(_start_runbook(template, title, target, session_id), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def update_runbook_step(run_id: str, step_id: int, status: str, note: str = "") -> str:
    """Record the outcome of one runbook step after its separate guarded tool call."""
    return json.dumps(_update_runbook_step(run_id, step_id, status, note), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def list_runbooks(include_closed: bool = False) -> str:
    """List active agent runbooks, with optional completed history."""
    return json.dumps(_list_runbooks(include_closed), separators=(",", ":"), ensure_ascii=False)


def _checkpoint_observation(target: str) -> dict:
    if target == "system":
        return {"health": _get_system_health(), "failed_units": _get_failed_systemd_units()}
    return {"workload_health": _get_workload_health(target)}


@guardian_tool()
def create_agent_checkpoint(target: str, label: str = "", session_id: Optional[str] = None) -> str:
    """Capture a bounded pre-change system or workload observation; no changes are made."""
    return json.dumps(_create_agent_checkpoint(target, _checkpoint_observation(target), label, session_id), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def compare_agent_checkpoint(checkpoint_id: str) -> str:
    """Compare a checkpoint to current state and return a confirmation-gated rollback plan."""
    checkpoints = _list_agent_checkpoints(True).get("checkpoints", [])
    checkpoint = next((item for item in checkpoints if item.get("checkpoint_id") == checkpoint_id), None)
    if not checkpoint:
        return json.dumps({"status": "not_found", "error": "Checkpoint was not found."}, separators=(",", ":"), ensure_ascii=False)
    return json.dumps(_compare_agent_checkpoint(checkpoint_id, _checkpoint_observation(checkpoint["target"])), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def list_agent_checkpoints(include_closed: bool = False) -> str:
    """List active pre-change checkpoints and optional completed history."""
    return json.dumps(_list_agent_checkpoints(include_closed), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def close_agent_checkpoint(checkpoint_id: str, outcome: str = "") -> str:
    """Close a checkpoint with a secret-redacted change outcome."""
    return json.dumps(_close_agent_checkpoint(checkpoint_id, outcome), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def discover_projects(root_path: Optional[str] = None, max_depth: int = 3) -> str:
    """Find bounded Git/application projects in configured VPS project roots."""
    return json.dumps(_discover_projects(root_path, max_depth), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def inspect_project(project_path: str) -> str:
    """Inspect an approved project: stack markers, Git branch/commit, and dirty state."""
    return json.dumps(_inspect_project(project_path), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def search_project_code(project_path: str, query: str, max_matches: int = 50) -> str:
    """Bounded literal code search with ignored dependency folders and redacted output."""
    return json.dumps(_search_project_code(project_path, query, max_matches), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def read_project_file(project_path: str, relative_path: str, max_bytes: int = 50000) -> str:
    """Read one non-binary project file without following symlinks; redact common secrets."""
    return json.dumps(_read_project_file(project_path, relative_path, max_bytes), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def begin_project_patch(project_path: str, title: str) -> str:
    """Open a short-lived, bounded source patch; no project code runs."""
    return json.dumps(_begin_project_patch(project_path, title), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def stage_project_file_change(patch_id: str, relative_path: str, content: str) -> str:
    """Stage one source-file replacement in an active project patch without applying it."""
    return json.dumps(_stage_project_file_change(patch_id, relative_path, content), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def preview_project_patch(patch_id: str) -> str:
    """Show secret-redacted source diff and obtain one confirmation token for a patch."""
    return json.dumps(_preview_project_patch(patch_id), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def apply_project_patch(patch_id: str, confirmation_token: Optional[str] = None) -> str:
    """Apply a confirmed bounded source patch with backups; it never executes project code."""
    return json.dumps(_apply_project_patch(patch_id, confirmation_token), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def get_project_changes(project_path: str) -> str:
    """Read Git working-tree changes and diff statistics without modifying the project."""
    return json.dumps(_get_project_changes(project_path), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def run_project_checks(project_path: str, check: str = "auto") -> str:
    """Run only fixed safe checks: Git whitespace validation or bounded Python syntax parsing."""
    return json.dumps(_run_project_checks(project_path, check), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def get_test_capsule_status() -> str:
    """Inspect local Docker and resource prerequisites for isolated project checks."""
    return json.dumps(_get_test_capsule_status(), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def inspect_project_environment(project_path: str, service_name: Optional[str] = None, environment_path: Optional[str] = None) -> str:
    """Inspect Python venv/package metadata and a running systemd MainPID without executing project code."""
    return json.dumps(_inspect_project_environment(project_path, service_name, environment_path), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def diagnose_project_dependencies(project_path: str, service_name: Optional[str] = None, environment_path: Optional[str] = None, include_dev: bool = False, after_fingerprint: Optional[str] = None) -> str:
    """Return bounded direct-dependency/lockfile issues and runtime mismatch evidence; unchanged fingerprints suppress repeated reports."""
    return json.dumps(_diagnose_project_dependencies(project_path, service_name, environment_path, include_dev, after_fingerprint), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def plan_environment_repair(project_path: str, service_name: Optional[str] = None, environment_path: Optional[str] = None) -> str:
    """Plan an environment repair without installing packages, changing service units or restarting applications."""
    return json.dumps(_plan_environment_repair(project_path, service_name, environment_path), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def plan_capsule_environment(project_path: str, environment_path: Optional[str] = None, include_dev: bool = False) -> str:
    """Prepare reviewed runtime/dependency metadata for a capsule image; this does not build, download or verify the image."""
    return json.dumps(_plan_capsule_environment(project_path, environment_path, include_dev), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def get_project_import_map(project_path: str, relative_path: Optional[str] = None, max_results: int = 30, after_fingerprint: Optional[str] = None) -> str:
    """Map bounded local Python import candidates; unresolved modules and partial scans are explicit."""
    return json.dumps(_get_project_import_map(project_path, relative_path, max_results, after_fingerprint), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def find_project_references(project_path: str, relative_path: str, symbol_name: str, max_results: int = 30, after_fingerprint: Optional[str] = None) -> str:
    """Find Python symbol-use candidates, distinguishing import aliases from name-only matches; never executes code."""
    return json.dumps(_find_project_references(project_path, relative_path, symbol_name, max_results, after_fingerprint), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def assess_project_change(project_path: str, relative_path: str, symbol_name: Optional[str] = None, max_results: int = 20, after_fingerprint: Optional[str] = None) -> str:
    """Find reverse-import impact and related test candidates within three hops; not runtime or coverage proof."""
    return json.dumps(_assess_project_change(project_path, relative_path, symbol_name, max_results, after_fingerprint), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def get_project_task_context(project_path: str, relative_path: str, symbol_name: str, max_chars: int = 6000, after_fingerprint: Optional[str] = None) -> str:
    """Bundle a Python definition, use-site fragments and test candidates; mask literals/comments and cap output."""
    return json.dumps(_get_project_task_context(project_path, relative_path, symbol_name, max_chars, after_fingerprint), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def test_project_patch(patch_id: str, check: str = "auto", confirmation_token: Optional[str] = None) -> str:
    """Test staged code in one temporary, networkless, resource-limited Docker capsule; controlled mode requires confirmation."""
    return json.dumps(_test_project_patch(patch_id, check, confirmation_token), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def promote_tested_project_patch(patch_id: str, confirmation_token: Optional[str] = None) -> str:
    """Apply the exact capsule-tested candidate using existing preview, confirmation and backup rules."""
    return json.dumps(_promote_tested_project_patch(patch_id, confirmation_token), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def read_project_file_range(project_path: str, relative_path: str, start_line: int = 1, max_lines: int = 80, max_bytes: int = 16000, if_sha256: Optional[str] = None, byte_offset: Optional[int] = None) -> dict:
    """Read later lines or bytes of a large project file within a per-call limit; returns a file hash and continuation."""
    return _read_project_file_range(project_path, relative_path, start_line, max_lines, max_bytes, if_sha256, byte_offset)


@guardian_tool()
def get_project_symbols(project_path: str, relative_path: str, max_symbols: int = 100) -> dict:
    """Map Python classes and functions to line ranges without returning their bodies."""
    return _get_project_symbols(project_path, relative_path, max_symbols)


@guardian_tool()
def stage_project_line_edit(patch_id: str, relative_path: str, start_line: int, end_line: int, replacement: str, expected_sha256: Optional[str] = None) -> dict:
    """Stage only changed lines in a bounded project patch; preview and confirmation are still required."""
    return _stage_project_line_edit(patch_id, relative_path, start_line, end_line, replacement, expected_sha256)


@guardian_tool()
def get_project_diff(project_path: str, relative_path: Optional[str] = None, staged: bool = False, context_lines: int = 3, max_bytes: int = 12000) -> dict:
    """Read a bounded, secret-redacted Git diff for a project or one file."""
    return _get_project_diff(project_path, relative_path, staged, context_lines, max_bytes)


@guardian_tool()
def get_guardian_launch() -> dict:
    """Report whether this Guardian runs through SSH/stdio, systemd, or a container and how to reload it."""
    return _get_guardian_launch()


@guardian_tool()
def summarize_service_logs(service_name: str, lines_count: int = 120, grep_filter: Optional[str] = None, max_groups: int = 12, if_fingerprint: Optional[str] = None) -> dict:
    """Group repeated service log lines into a short report; return unchanged for a known fingerprint."""
    return _summarize_service_logs(service_name, lines_count, grep_filter, max_groups, if_fingerprint)


@guardian_tool()
def get_server_event_delta(since_minutes: int = 60, max_events: int = 20, target: Optional[str] = None, after_cursor: Optional[str] = None) -> dict:
    """Return only server events after the supplied cursor, with a bounded response and next cursor."""
    return _get_server_event_delta(since_minutes, max_events, target, after_cursor)


@guardian_tool()
def get_workload_brief(target: str, sections: str = "health", detail: str = "brief", if_fingerprint: Optional[str] = None, max_chars: int = 4000) -> dict:
    """One compact, selectable workload report; request full detail only when needed."""
    return _get_workload_brief(target, sections, detail, if_fingerprint, max_chars)


# ============================================================================
# 3. Network & Firewall Tools
# ============================================================================

@guardian_tool()
def get_open_ports() -> str:
    """Discover all listening network ports (TCP and UDP) and identify bound processes.

    Returns:
        JSON string listing open ports, protocols (TCP/UDP), binding addresses (IPv4/IPv6),
        and process names/PIDs.
    """
    try:
        data = _get_open_ports()
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_open_ports: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def get_ufw_status() -> str:
    """Inspect the status and active filtering rules of the UFW firewall.

    Returns:
        JSON string containing UFW active state, default incoming/outgoing policies,
        and all active firewall rules.
    """
    try:
        data = _get_ufw_status()
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_ufw_status: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def get_platform_capabilities() -> str:
    """Detect package, firewall, service-manager, and Docker Compose backends on this host."""
    return json.dumps(_get_platform_capabilities(), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def get_package_updates() -> str:
    """List available updates via APT, DNF, YUM, Pacman, or Zypper without changing state."""
    return json.dumps(_get_package_updates(), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def get_firewall_status() -> str:
    """Return normalized UFW, firewalld, or nftables firewall state and rules."""
    return json.dumps(_get_firewall_status(), separators=(",", ":"), ensure_ascii=False)


# ============================================================================
# 4. File & Configuration Management Tools
# ============================================================================

@guardian_tool()
def view_file_content(file_path: str, max_bytes: int = 50000) -> str:
    """Safely read the content of an authorized configuration or web file.

    Permitted directories: /etc/nginx/, /etc/mysql/, /etc/postgresql/, /etc/docker/, /etc/caddy/, /var/www/
    Strictly protected against path traversal attacks.

    Args:
        file_path: Canonical path or relative path to the configuration file.
        max_bytes: Maximum bytes to return (default: 50,000, capped at 200,000).

    Returns:
        JSON string with file content, size, and modification timestamp.
    """
    try:
        data = _view_file_content(file_path=file_path, max_bytes=max_bytes)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in view_file_content: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def write_file_content(
    file_path: str,
    content: str,
    backup: bool = True,
    confirmation_token: Optional[str] = None,
) -> str:
    """Atomically write or update a configuration file within authorized directories.

    Creates an automatic timestamped backup (.bak.<timestamp>) before overwriting.
    Permitted directories: /etc/nginx/, /etc/mysql/, /etc/postgresql/, /etc/docker/, /etc/caddy/, /var/www/

    Args:
        file_path: Path to the target configuration file.
        content: Text content to write.
        backup: Create a backup file before writing (default: True).
        confirmation_token: Single-use token returned by the preceding plan call.

    Returns:
        JSON string indicating write status and backup location.
    """
    try:
        data = _write_file_content(
            file_path=file_path,
            content=content,
            backup=backup,
            confirmation_token=confirmation_token,
        )
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in write_file_content: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def set_web_file_mode(
    file_path: str,
    mode: str = "0644",
    confirmation_token: Optional[str] = None,
) -> str:
    """Set a safe web-readable mode (0644 or 0640) for a static file under /var/www.

    The content is untouched; arbitrary chmod modes and paths outside /var/www
    are rejected. Controlled mode requires a confirmation token.
    """
    try:
        data = _set_web_file_mode(file_path, mode, confirmation_token)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in set_web_file_mode: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def list_directory(dir_path: str, max_depth: int = 1) -> str:
    """Inspect file and directory structures within authorized administrative paths.

    Permitted directories: /etc/nginx/, /etc/mysql/, /etc/postgresql/, /etc/docker/, /etc/caddy/, /var/www/

    Args:
        dir_path: Path to the directory to inspect.
        max_depth: Exploration depth (1 to 3, default: 1).

    Returns:
        JSON string with item list (names, types, sizes, modification dates).
    """
    try:
        data = _list_directory(dir_path=dir_path, max_depth=max_depth)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in list_directory: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def plan_config_deployment(
    file_path: str,
    content: str,
    service_name: Optional[str] = None,
) -> str:
    """Validate and preview an Nginx config or Caddyfile deployment.

    The candidate is staged outside the live path, syntax-checked, and shown as
    a bounded unified diff. No live configuration is modified. Nginx configs
    under /etc/nginx and Caddyfiles under /etc/caddy are supported.

    Args:
        file_path: Target config path under /etc/nginx or /etc/caddy.
        content: Complete proposed UTF-8 configuration (at most 200,000 bytes).
        service_name: Optional matching service name (nginx or caddy).

    Returns:
        JSON plan with validation output, diff, expiry, and a confirmation token
        in controlled mode.
    """
    try:
        data = _plan_config_deployment(file_path, content, service_name)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in plan_config_deployment: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def deploy_config_change(
    deployment_id: str,
    confirmation_token: Optional[str] = None,
) -> str:
    """Commit a validated configuration plan, reload its service, and auto-rollback on failure.

    Args:
        deployment_id: Short-lived identifier returned by plan_config_deployment.
        confirmation_token: Required only in controlled mode; bound to this plan.

    Returns:
        JSON outcome with atomic-write, reload, health-check, and rollback details.
    """
    try:
        data = _deploy_config_change(deployment_id, confirmation_token)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in deploy_config_change: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def create_system_snapshot(
    label: Optional[str] = None,
    include_config_hashes: bool = True,
) -> str:
    """Save a privacy-preserving, read-only VPS state baseline.

    Records ports, failed units, cron/timers, Docker inventory, and optional
    configuration file hashes. It never stores config content or cron commands.
    Snapshot storage is configurable with VPS_GUARDIAN_SNAPSHOT_DIR.
    """
    try:
        data = _create_system_snapshot(label, include_config_hashes)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in create_system_snapshot: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def list_system_snapshots(limit: int = 20) -> str:
    """List stored VPS state snapshots without exposing their collected content."""
    try:
        return json.dumps(_list_system_snapshots(limit), separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in list_system_snapshots: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def compare_system_snapshots(baseline_id: str, current_id: str) -> str:
    """Compare two snapshots and rank configuration or infrastructure drift by risk.

    Flags new exposed ports, failed units, cron changes, Docker drift, and
    configuration-hash changes. Both snapshots must be from the same host.
    """
    try:
        return json.dumps(
            _compare_system_snapshots(baseline_id, current_id), separators=(",", ":"), ensure_ascii=False
        )
    except Exception as exc:
        logger.error(f"Error in compare_system_snapshots: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


# ============================================================================
# 5. Web Server & SSL Inspection Tools
# ============================================================================

@guardian_tool()
def test_nginx_config() -> str:
    """Test Nginx configuration for syntax errors ('nginx -t') without reloading.

    Returns:
        JSON string indicating syntax validity, exit code, and syntax error messages.
    """
    try:
        data = _test_nginx_config()
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in test_nginx_config: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def check_http_endpoint(
    url: str,
    expected_status: int = 200,
    expected_text: Optional[str] = None,
    timeout_seconds: int = 10,
) -> str:
    """Check a public HTTP(S) URL: response status, redirects, TLS, latency, and optional text.

    This is read-only and intentionally returns only metadata, never a page body.
    Use it before or after a deployment to verify the public result.
    """
    try:
        data = _check_http_endpoint(url, expected_status, expected_text, timeout_seconds)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_http_endpoint: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def check_http_endpoints(endpoints: list[dict]) -> str:
    """Check up to 20 public HTTP(S) endpoints in one compact deployment health report.

    Each item accepts url, expected_status (default 200), expected_text (optional),
    and timeout_seconds (default 10). This tool is read-only.
    """
    try:
        data = _check_http_endpoints(endpoints)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_http_endpoints: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def get_web_deployment_status(
    domain: str,
    path: str = "/",
    expected_status: int = 200,
    expected_text: Optional[str] = None,
) -> str:
    """Verify one website end to end: public HTTPS response, local Nginx host, and certificate.

    Returns a single diagnosis identifying whether an issue is public availability,
    virtual-host configuration, or the matching TLS certificate.
    """
    try:
        data = _get_web_deployment_status(domain, path, expected_status, expected_text)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_web_deployment_status: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def check_ssl_certificates() -> str:
    """Audit SSL/TLS certificates configured on the host (Let's Encrypt / Certbot).

    Returns:
        JSON string listing domains, expiration dates, days remaining, and warning flags.
    """
    try:
        data = _check_ssl_certificates()
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_ssl_certificates: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def list_virtual_hosts() -> str:
    """Inspect active Nginx virtual hosts, listening ports, SSL, and reverse proxy targets.

    Returns:
        JSON string with parsed virtual hosts from /etc/nginx/sites-enabled/ and conf.d/.
    """
    try:
        data = _list_virtual_hosts()
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in list_virtual_hosts: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


# ============================================================================
# 6. Security & Intrusion Audit Tools
# ============================================================================

@guardian_tool()
def check_failed_logins(limit: int = 20) -> str:
    """Inspect recent failed SSH login attempts to detect brute-force attackers.

    Args:
        limit: Number of recent failed attempts to inspect (default: 20, max: 100).

    Returns:
        JSON string with recent failed logins and top offending attacker IP addresses.
    """
    try:
        data = _check_failed_logins(limit=limit)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_failed_logins: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def get_fail2ban_status() -> str:
    """Check Fail2ban status, active protection jails, and currently banned IP addresses.

    Returns:
        JSON string detailing active jails and banned IP addresses.
    """
    try:
        data = _get_fail2ban_status()
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_fail2ban_status: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def audit_ssh_config() -> str:
    """Audit the SSH daemon configuration against security best practices.

    Returns:
        JSON string with detected settings, security score (0-100), and remediation guidance.
    """
    try:
        data = _audit_ssh_config()
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in audit_ssh_config: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


# ============================================================================
# 7. Storage & Scheduled Tasks Tools
# ============================================================================

@guardian_tool()
def analyze_disk_usage(
    target_path: str = "/var",
    max_depth: int = 2,
    min_size_mb: int = 50,
    top_n: int = 15,
) -> str:
    """Analyze disk usage for a directory to discover space bottlenecks and large files.

    Safely walks the filesystem without following symlinks and automatically skips
    virtual pseudo-filesystems (/proc, /sys, /dev, /run).

    Args:
        target_path: Starting path to inspect (defaults to '/var').
        max_depth: Depth of directory nesting to inspect (1 to 5, default 2).
        min_size_mb: Minimum size threshold in megabytes to include (default 50 MB).
        top_n: Maximum number of largest items to return (1 to 50, default 15).

    Returns:
        JSON string with partition usage, largest directories, and largest files.
    """
    try:
        data = _analyze_disk_usage(
            target_path=target_path,
            max_depth=max_depth,
            min_size_mb=min_size_mb,
            top_n=top_n,
        )
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in analyze_disk_usage: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def list_cron_jobs() -> str:
    """Discover all scheduled cron jobs on the Linux system.

    Audits /etc/crontab, /etc/cron.d/, /etc/cron.* periodic scripts, and user crontabs.

    Returns:
        JSON string containing scheduled jobs with user, schedule expression,
        human-readable timing explanation, and command.
    """
    try:
        data = _list_cron_jobs()
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in list_cron_jobs: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def list_systemd_timers() -> str:
    """Audit active and pending systemd timers via 'systemctl list-timers'.

    Returns:
        JSON string with timer unit names, next execution time, countdown, and target services.
    """
    try:
        data = _list_systemd_timers()
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in list_systemd_timers: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


# ============================================================================
# 8. Updates & Server Maintenance Tools
# ============================================================================

@guardian_tool()
def check_system_updates(force_refresh: bool = False) -> str:
    """Audit available operating system package updates and pending security patches.

    Checks reboot requirements (/var/run/reboot-required), total upgradable packages,
    and security CVE patches. Cached for 5 minutes to minimize CPU and disk usage.

    Args:
        force_refresh: Set to True to bypass the 5-minute cache and query package managers directly.

    Returns:
        JSON string with update counts, security status, reboot flag, and recommended recovery action.
    """
    try:
        data = _check_system_updates(force_refresh=force_refresh)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_system_updates: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def check_guardian_updates(force_refresh: bool = False) -> str:
    """Check if a newer version or commit of VPS-Guardian-MCP is available on GitHub.

    Provides automated version verification and action guidance for self-updating.
    Cached for 5 minutes to minimize network and CPU overhead.

    Args:
        force_refresh: Set to True to bypass cache and query GitHub API directly.

    Returns:
        JSON string with current version, latest commit, update availability,
        and AI warning notice.
    """
    try:
        data = _check_guardian_updates(force_refresh=force_refresh)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_guardian_updates: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


# ============================================================================
# 9. Kernel Diagnostics & OOM Crash Tools
# ============================================================================

@guardian_tool()
def check_oom_events(limit: int = 10) -> str:
    """Inspect kernel logs for Linux Out-Of-Memory (OOM) Killer invocations.

    Surfaces terminated processes, PIDs, and consumed RSS memory at time of termination.

    Args:
        limit: Maximum number of recent OOM events to return (1 to 50, default 10).

    Returns:
        JSON string with detected OOM incidents and diagnostic summary.
    """
    try:
        data = _check_oom_events(limit=limit)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_oom_events: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def check_kernel_errors(limit: int = 20) -> str:
    """Audit kernel logs for hardware failures, storage I/O errors, or application segfaults.

    Args:
        limit: Maximum number of error entries to retrieve (1 to 50, default 20).

    Returns:
        JSON string with categorized kernel errors, root causes, and critical issue counters.
    """
    try:
        data = _check_kernel_errors(limit=limit)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_kernel_errors: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


# ============================================================================
# 10. Network Connectivity & DNS Benchmarking Tools
# ============================================================================

@guardian_tool()
def test_network_connectivity(
    target_host: str,
    port: int = 443,
    timeout_seconds: float = 5.0,
) -> str:
    """Benchmark outbound network connectivity and latency using direct Python sockets.

    Measures DNS resolution latency, TCP handshake time, and TLS handshake latency without shell ping.

    Args:
        target_host: Destination hostname or IP address (e.g. 'api.github.com' or '8.8.8.8').
        port: Destination port (1-65535, default 443).
        timeout_seconds: Network socket timeout (0.5 to 30.0 seconds, default 5.0).

    Returns:
        JSON string with stage latency breakdown, resolved IP addresses, and TLS session details.
    """
    try:
        data = _test_network_connectivity(
            target_host=target_host,
            port=port,
            timeout_seconds=timeout_seconds,
        )
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in test_network_connectivity: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def check_dns_health(domains: Optional[list[str]] = None) -> str:
    """Audit system DNS resolution health, configured nameservers, and query responsiveness.

    Args:
        domains: Optional custom list of domains to probe. Defaults to essential public services.

    Returns:
        JSON string with configured nameservers, individual domain lookup latencies, and health verdict.
    """
    try:
        data = _check_dns_health(domains=domains)
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_dns_health: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


# ============================================================================
# 11. Database & Cache Health Tools
# ============================================================================

@guardian_tool()
def get_database_health() -> str:
    """Discover running databases and verify responsiveness, latency, and socket states.

    Detects Redis, PostgreSQL, MySQL/MariaDB, and SQLite databases in application directories.

    Returns:
        JSON string with operational state, socket accessibility, and ping latency for each engine.
    """
    try:
        data = _get_database_health()
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_database_health: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


# ============================================================================
# 12. Incident Triage, Safety & Audit Tools
# ============================================================================

@guardian_tool()
def generate_incident_report(
    include_updates: bool = True,
    include_security: bool = True,
    include_network: bool = False,
) -> str:
    """Generate one prioritized, read-only VPS incident report.

    Args:
        include_updates: Include operating-system patch and reboot status.
        include_security: Include SSH hardening assessment.
        include_network: Include listening ports; disabled by default to keep reports compact.

    Returns:
        JSON string with severity-ranked findings and the underlying diagnostic sections.
    """
    try:
        data = _generate_incident_report(
            include_updates=include_updates,
            include_security=include_security,
            include_network=include_network,
        )
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in generate_incident_report: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def get_safety_status() -> str:
    """Return the active safety mode, confirmation policy, TTL, and audit destination."""
    return json.dumps(_get_safety_status(), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def get_audit_events(limit: int = 50) -> str:
    """Return recent redacted audit events for state-changing operations.

    Args:
        limit: Number of newest events to return (1-500, default 50).
    """
    return json.dumps(_get_audit_events(limit=limit), separators=(",", ":"), ensure_ascii=False)


# ============================================================================
# 13. Emergency Recovery & Backup Tools
# ============================================================================

@guardian_tool()
def execute_recovery(
    action_name: str,
    target: Optional[str] = None,
    confirmation_token: Optional[str] = None,
) -> str:
    """Execute an emergency recovery operation from a strictly whitelisted list.

    Allowed actions:
    - 'restart_service': Restarts a systemd service (requires target=service_name, e.g. target='nginx').
    - 'clean_docker_cache': Deep prune of unused containers, networks, images, and volumes.
    - 'clean_system_logs': Prunes journal logs older than 3 days and rotated archives in /var/log.
    - 'kill_process': Terminates a runaway process by PID (requires target=PID, e.g. target='12345').
    - 'restart_nginx': Restarts Nginx web server (legacy alias for restart_service target='nginx').
    - 'vacuum_systemd_journal': Truncates journal logs to limit (target defaults to '200M').
    - 'clean_package_cache': Cleans APT archive cache and removes obsolete packages.
    - 'apply_security_updates': Non-interactively applies pending operating system security updates.
    - 'update_guardian': Self-updates VPS-Guardian-MCP from GitHub and refreshes virtual environment.

    Args:
        action_name: The exact recovery action to execute.
        target: Optional target parameter required by certain actions.
        confirmation_token: Single-use token returned by the preceding plan call.

    Returns:
        JSON string with operation outcome, freed resources, or security error.
    """
    try:
        data = _run_recovery_action(
            action_name=action_name,
            target=target,
            confirmation_token=confirmation_token,
        )
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in execute_recovery: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def create_backup(
    backup_type: str,
    source_path: str,
    confirmation_token: Optional[str] = None,
) -> str:
    """Create a compressed tar.gz archive of an authorized website or configuration directory.

    Archives are saved into an isolated backup repository (/var/backups/vps-guardian/).
    Permitted source locations: /var/www/, /etc/nginx/, /etc/mysql/, /etc/postgresql/, /etc/docker/, /etc/caddy/

    Args:
        backup_type: Identifier label for the archive (e.g. 'site', 'config', 'data').
        source_path: Target directory to archive.
        confirmation_token: Single-use token returned by the preceding plan call.

    Returns:
        JSON string with archive file path, size, file count, and duration.
    """
    try:
        data = _create_backup(
            backup_type=backup_type,
            source_path=source_path,
            confirmation_token=confirmation_token,
        )
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in create_backup: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":"))


@guardian_tool()
def get_backup_status(limit: int = 20) -> str:
    """List isolated Guardian backups with sizes and creation times, without reading contents."""
    return json.dumps(_get_backup_status(limit), separators=(",", ":"), ensure_ascii=False)


@guardian_tool()
def verify_backup(archive_path: str) -> str:
    """Verify a Guardian tar.gz archive without extracting it.

    Only regular archives within the isolated Guardian backup directory are
    accepted. Very large member counts return a bounded partial result.
    """
    return json.dumps(_verify_backup(archive_path), separators=(",", ":"), ensure_ascii=False)


# ============================================================================
# 10. MCP Resources & Prompts
# ============================================================================

@mcp.resource("vps://system-overview")
def get_system_overview_resource() -> str:
    """Live JSON resource providing continuous system snapshot and update alerts for AI context."""
    try:
        health_data = _get_system_health()
        # Add live update and reboot status alerts for agent awareness
        try:
            updates_info = _check_system_updates()
            health_data["system_updates"] = {
                "reboot_required": updates_info.get("reboot_required", False),
                "security_updates_count": updates_info.get("security_updates_count", 0),
                "total_upgradable": updates_info.get("total_upgradable", 0),
                "warning": updates_info.get("warning"),
            }
        except Exception:
            pass

        return json.dumps(health_data, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"status": "error", "error": str(exc)})


@mcp.resource("vps://security-dashboard")
def get_security_dashboard_resource() -> str:
    """Live security dashboard aggregating firewall, failed logins, fail2ban, and open ports."""
    try:
        dashboard = {
            "ufw": _get_ufw_status(),
            "fail2ban": _get_fail2ban_status(),
            "failed_logins": _check_failed_logins(limit=10),
            "ssh_audit": _audit_ssh_config(),
            "open_ports": _get_open_ports(),
            "system_updates": _check_system_updates(),
        }
        return json.dumps(dashboard, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"status": "error", "error": str(exc)})


@mcp.resource("vps://docker-overview")
def get_docker_overview_resource() -> str:
    """Live summary resource aggregating Docker engine status, containers inventory, and resource metrics."""
    try:
        containers_summary = _list_docker_containers(all=True)
        stats_summary = _get_docker_stats()
        overview = {
            "containers": containers_summary,
            "stats": stats_summary,
        }
        return json.dumps(overview, separators=(",", ":"), ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"status": "error", "error": str(exc)})


@mcp.prompt("triage_server_incident")
def triage_server_incident_prompt() -> str:
    """Structured incident triage prompt guiding the AI through systematic diagnosis."""
    return (
        "You are an expert Linux Systems Administrator. Investigate the current server incident step-by-step:\n"
        "1. Call `get_system_health` to verify CPU, RAM, and disk utilization.\n"
        "2. Call `get_failed_systemd_units` to check for crashed services.\n"
        "3. If services are degraded, call `read_service_logs` with grep_filter='ERROR' to pinpoint the failure.\n"
        "4. Call `check_failed_logins` and `get_open_ports` to rule out security anomalies or port conflicts.\n"
        "5. Formulate a safe recovery plan and present it to the operator before executing changes."
    )


@mcp.prompt("emergency_disk_cleanup")
def emergency_disk_cleanup_prompt() -> str:
    """Guidance prompt for resolving low disk space emergency on the VPS."""
    return (
        "You are a DevOps engineer responding to a disk space emergency (>90% full):\n"
        "1. Call `analyze_disk_usage` with target_path='/var' to identify runaway logs, cache, or docker data.\n"
        "2. Call `get_docker_stats` and `list_docker_containers` to evaluate container storage.\n"
        "3. Review available cleanup actions: `clean_system_logs`, `vacuum_systemd_journal`, `clean_docker_cache`, `clean_package_cache`.\n"
        "4. Formulate the cleanup plan and propose it to the operator before triggering `execute_recovery`.\n"
        "5. After recovery, verify recovered disk capacity with `get_system_health`."
    )


@mcp.prompt("security_and_update_audit")
def security_and_update_audit_prompt() -> str:
    """Comprehensive routine for auditing VPS security, CVE updates, and authentication logs."""
    return (
        "You are a Cybersecurity and Linux Hardening Auditor:\n"
        "1. Check pending CVEs and kernel reboot status with `check_system_updates`.\n"
        "2. Audit SSH server configuration vulnerabilities with `audit_ssh_config`.\n"
        "3. Inspect intrusion attempts and active bans with `check_failed_logins` and `get_fail2ban_status`.\n"
        "4. Audit network attack surface with `get_open_ports` and `get_ufw_status`.\n"
        "5. Verify background automation integrity with `list_cron_jobs` and `list_systemd_timers`.\n"
        "6. Check VPS-Guardian version currency with `check_guardian_updates`.\n"
        "7. Compile an audit summary with risk ratings and remediation actions."
    )


@mcp.prompt("troubleshoot_application_crash")
def troubleshoot_application_crash_prompt() -> str:
    """Runbook for investigating mysterious application, container, or service terminations."""
    return (
        "You are an expert DevOps SRE diagnosing an unexpected application crash or service exit:\n"
        "1. Call `check_oom_events` to verify if Linux Kernel Out-Of-Memory Killer terminated the process.\n"
        "2. Call `check_kernel_errors` for application segfaults, storage I/O errors, or disk corruption.\n"
        "3. Call `get_failed_systemd_units` and `read_service_logs` with grep_filter='ERROR'.\n"
        "4. If Docker container, inspect `get_docker_container_logs` and `get_docker_stats`.\n"
        "5. Call `get_database_health` to verify if backing databases (Redis, PostgreSQL, MySQL) are operational.\n"
        "6. Call `test_network_connectivity` if outbound API or database connections failed.\n"
        "7. Compile root cause diagnosis and formulate recovery recommendations."
    )


def main() -> None:
    """Run MCP server over stdio."""
    logger.info("Starting VPS-Guardian-MCP server...")
    mcp.run()


if __name__ == "__main__":
    main()
