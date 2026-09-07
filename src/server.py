"""VPS-Guardian-MCP: Secure Model Context Protocol Server for VPS Management.

Exposes safe, isolated tools for:
- System monitoring: CPU per core, RAM, Swap, Disk I/O, Network I/O, Uptime.
- Process tracking: Top CPU/Memory consuming processes.
- Service management: Systemd service health checks, failed units inspector.
- Service logs: Safe log inspection with Python-level grep filtering.
- Whitelisted emergency recovery actions.
"""

from __future__ import annotations

import json
import logging
import sys
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
except ImportError:
    logger.error("The 'mcp' library is required. Run: pip install 'mcp>=1.0.0'")
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
    from src.recover import run_recovery_action as _run_recovery_action
except ImportError:
    from monitor import (
        check_service_status as _check_service_status,
        get_failed_systemd_units as _get_failed_systemd_units,
        get_system_health as _get_system_health,
        get_top_processes as _get_top_processes,
        read_service_logs as _read_service_logs,
    )
    from recover import run_recovery_action as _run_recovery_action

# Initialize FastMCP Server
mcp = FastMCP(
    name="VPS-Guardian-MCP",
    dependencies=["psutil", "docker"],
)


@mcp.tool()
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
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_system_health: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
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
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_top_processes: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
def check_service_status(service_name: str) -> str:
    """Check the operational status of a systemd service unit.

    Args:
        service_name: Name of the system service (e.g. 'nginx', 'mysql', 'postgresql', 'ufw', 'docker').

    Returns:
        JSON string with active state ('active', 'inactive', 'failed'), enabled state, and recent status logs.
    """
    try:
        data = _check_service_status(service_name=service_name)
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_service_status: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
def get_failed_systemd_units() -> str:
    """Find all degraded or failed systemd services across the entire system.

    Returns:
        JSON string with list of failed units ('systemctl --failed') and overall health indicator.
    """
    try:
        data = _get_failed_systemd_units()
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_failed_systemd_units: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
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
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in read_service_logs: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
def execute_recovery(action_name: str) -> str:
    """Execute an emergency recovery operation from a strictly whitelisted list.

    Allowed actions:
    - 'clean_docker_cache': Prunes unused containers, networks, and images.
    - 'restart_nginx': Safely restarts the Nginx web server.

    Any unapproved command will be rejected with an access denied error.
    """
    try:
        data = _run_recovery_action(action_name=action_name)
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in execute_recovery: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


def main() -> None:
    """Run MCP server over stdio."""
    logger.info("Starting VPS-Guardian-MCP server...")
    mcp.run()


if __name__ == "__main__":
    main()
