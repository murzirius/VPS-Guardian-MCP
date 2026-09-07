"""VPS-Guardian-MCP: Secure Model Context Protocol Server for VPS Management.

Exposes safe, isolated tools for monitoring Linux VPS health (CPU, RAM, Disk),
inspecting Docker container states, reading service logs, and executing
whitelisted recovery operations.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

# Important for MCP stdio transport: all logs MUST be written to stderr
# so they do not interfere with JSON-RPC communication on stdout.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("vps_guardian.server")

# Import official FastMCP SDK
try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    logger.error(
        "The 'mcp' SDK is not installed. Please run: pip install 'mcp>=1.0.0'"
    )
    raise

# Resilient internal imports (works as package or direct script)
try:
    from src.monitor import collect_system_health
    from src.recover import fetch_service_logs, run_recovery_action
except ImportError:
    from monitor import collect_system_health
    from recover import fetch_service_logs, run_recovery_action

# Initialize FastMCP Server
mcp = FastMCP(
    name="VPS-Guardian-MCP",
    dependencies=["psutil", "docker"],
)


@mcp.tool()
def get_system_health() -> str:
    """Retrieve structured system health metrics from the Linux VPS.

    Returns a JSON string containing:
    - CPU load percentage, core counts, and load averages
    - RAM and Swap memory usage (total, used, free, percentage)
    - Root filesystem disk capacity (total, used, free, percentage)
    - Docker container status: total count, running count, and details of any
      failed, stopped, or unhealthy containers.

    All errors (e.g. docker daemon unavailable or permission denied) are safely
    returned within the JSON payload without crashing the server.
    """
    try:
        health_data = collect_system_health()
        return json.dumps(health_data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Unexpected error in get_system_health: {exc}", exc_info=True)
        error_payload = {
            "status": "error",
            "error": f"Failed to retrieve system health: {str(exc)}",
        }
        return json.dumps(error_payload, indent=2, ensure_ascii=False)


@mcp.tool()
def read_service_logs(service_name: str, lines_count: int = 50) -> str:
    """Safely fetch the most recent log lines for a specific service or Docker container.

    Protected against shell injection: uses parameter validation and strict non-shell invocation.

    Supported targets:
    - 'nginx': Inspects Nginx web server logs via journalctl, /var/log/nginx/error.log, or Docker.
    - 'docker:<container_name>': Inspects logs of a specific Docker container.
    - 'systemd:<service_name>' or '<service_name>': Inspects logs of a systemd unit via journalctl.

    Args:
        service_name: The name or identifier of the service/container to read logs from.
        lines_count: Number of recent log lines to retrieve (default: 50, maximum: 1000).

    Returns:
        Structured JSON string containing the extracted log lines or clear error details.
    """
    try:
        result = fetch_service_logs(service_name=service_name, lines_count=lines_count)
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Unexpected error in read_service_logs: {exc}", exc_info=True)
        error_payload = {
            "status": "error",
            "error": f"Failed reading service logs: {str(exc)}",
            "logs": "",
        }
        return json.dumps(error_payload, indent=2, ensure_ascii=False)


@mcp.tool()
def execute_recovery(action_name: str) -> str:
    """Execute a strictly whitelisted recovery action on the Linux VPS.

    Security Policy:
    Only predefined, isolated recovery operations are allowed. Arbitrary commands
    are strictly rejected with an access denied response.

    Allowed actions:
    - 'clean_docker_cache': Safely prunes stopped containers, unused networks,
      dangling images, and build cache to free up disk space.
    - 'restart_nginx': Restarts the Nginx web server service via systemctl or Docker.

    Args:
        action_name: The exact name of the recovery action to execute.

    Returns:
        Structured JSON string with execution results, freed disk space, or error messages.
    """
    try:
        result = run_recovery_action(action_name=action_name)
        return json.dumps(result, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Unexpected error in execute_recovery: {exc}", exc_info=True)
        error_payload = {
            "status": "error",
            "success": False,
            "action": action_name,
            "error": f"Failed to execute recovery action: {str(exc)}",
        }
        return json.dumps(error_payload, indent=2, ensure_ascii=False)


def main() -> None:
    """Server entry point."""
    logger.info("Starting VPS-Guardian-MCP server...")
    mcp.run()


if __name__ == "__main__":
    main()
