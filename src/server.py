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
        get_docker_container_logs as _get_docker_container_logs,
        get_docker_stats as _get_docker_stats,
        list_docker_containers as _list_docker_containers,
    )
    from src.files import (
        list_directory as _list_directory,
        view_file_content as _view_file_content,
        write_file_content as _write_file_content,
    )
    from src.network import (
        get_open_ports as _get_open_ports,
        get_ufw_status as _get_ufw_status,
    )
    from src.web import (
        check_ssl_certificates as _check_ssl_certificates,
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
        run_recovery_action as _run_recovery_action,
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
        get_docker_container_logs as _get_docker_container_logs,
        get_docker_stats as _get_docker_stats,
        list_docker_containers as _list_docker_containers,
    )
    from files import (
        list_directory as _list_directory,
        view_file_content as _view_file_content,
        write_file_content as _write_file_content,
    )
    from network import (
        get_open_ports as _get_open_ports,
        get_ufw_status as _get_ufw_status,
    )
    from web import (
        check_ssl_certificates as _check_ssl_certificates,
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
        run_recovery_action as _run_recovery_action,
    )

# Initialize FastMCP Server
mcp = FastMCP(
    name="VPS-Guardian-MCP",
    dependencies=["psutil", "docker"],
)


# ============================================================================
# 1. System & Service Monitoring Tools
# ============================================================================

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


# ============================================================================
# 2. Docker Management Tools
# ============================================================================

@mcp.tool()
def list_docker_containers(all: bool = True) -> str:
    """List Docker containers with their status, image, port bindings, volumes, and health.

    Args:
        all: Set to True to list all containers (running and stopped), False for running only.

    Returns:
        JSON string with list of containers, port forwards, and mount mappings.
    """
    try:
        data = _list_docker_containers(all=all)
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in list_docker_containers: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
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
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_docker_container_logs: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
def get_docker_stats() -> str:
    """Retrieve live resource utilization metrics for all running Docker containers.

    Provides real-time CPU %, Memory %, Network I/O, and Block I/O (equivalent to `docker stats`).

    Returns:
        JSON string listing resource metrics per running container.
    """
    try:
        data = _get_docker_stats()
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_docker_stats: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


# ============================================================================
# 3. Network & Firewall Tools
# ============================================================================

@mcp.tool()
def get_open_ports() -> str:
    """Discover all listening network ports (TCP and UDP) and identify bound processes.

    Returns:
        JSON string listing open ports, protocols (TCP/UDP), binding addresses (IPv4/IPv6),
        and process names/PIDs.
    """
    try:
        data = _get_open_ports()
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_open_ports: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
def get_ufw_status() -> str:
    """Inspect the status and active filtering rules of the UFW firewall.

    Returns:
        JSON string containing UFW active state, default incoming/outgoing policies,
        and all active firewall rules.
    """
    try:
        data = _get_ufw_status()
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_ufw_status: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


# ============================================================================
# 4. File & Configuration Management Tools
# ============================================================================

@mcp.tool()
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
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in view_file_content: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
def write_file_content(file_path: str, content: str, backup: bool = True) -> str:
    """Atomically write or update a configuration file within authorized directories.

    Creates an automatic timestamped backup (.bak.<timestamp>) before overwriting.
    Permitted directories: /etc/nginx/, /etc/mysql/, /etc/postgresql/, /etc/docker/, /etc/caddy/, /var/www/

    Args:
        file_path: Path to the target configuration file.
        content: Text content to write.
        backup: Create a backup file before writing (default: True).

    Returns:
        JSON string indicating write status and backup location.
    """
    try:
        data = _write_file_content(file_path=file_path, content=content, backup=backup)
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in write_file_content: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
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
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in list_directory: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


# ============================================================================
# 5. Web Server & SSL Inspection Tools
# ============================================================================

@mcp.tool()
def test_nginx_config() -> str:
    """Test Nginx configuration for syntax errors ('nginx -t') without reloading.

    Returns:
        JSON string indicating syntax validity, exit code, and syntax error messages.
    """
    try:
        data = _test_nginx_config()
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in test_nginx_config: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
def check_ssl_certificates() -> str:
    """Audit SSL/TLS certificates configured on the host (Let's Encrypt / Certbot).

    Returns:
        JSON string listing domains, expiration dates, days remaining, and warning flags.
    """
    try:
        data = _check_ssl_certificates()
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_ssl_certificates: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
def list_virtual_hosts() -> str:
    """Inspect active Nginx virtual hosts, listening ports, SSL, and reverse proxy targets.

    Returns:
        JSON string with parsed virtual hosts from /etc/nginx/sites-enabled/ and conf.d/.
    """
    try:
        data = _list_virtual_hosts()
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in list_virtual_hosts: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


# ============================================================================
# 6. Security & Intrusion Audit Tools
# ============================================================================

@mcp.tool()
def check_failed_logins(limit: int = 20) -> str:
    """Inspect recent failed SSH login attempts to detect brute-force attackers.

    Args:
        limit: Number of recent failed attempts to inspect (default: 20, max: 100).

    Returns:
        JSON string with recent failed logins and top offending attacker IP addresses.
    """
    try:
        data = _check_failed_logins(limit=limit)
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_failed_logins: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
def get_fail2ban_status() -> str:
    """Check Fail2ban status, active protection jails, and currently banned IP addresses.

    Returns:
        JSON string detailing active jails and banned IP addresses.
    """
    try:
        data = _get_fail2ban_status()
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_fail2ban_status: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
def audit_ssh_config() -> str:
    """Audit the SSH daemon configuration against security best practices.

    Returns:
        JSON string with detected settings, security score (0-100), and remediation guidance.
    """
    try:
        data = _audit_ssh_config()
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in audit_ssh_config: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


# ============================================================================
# 7. Storage & Scheduled Tasks Tools
# ============================================================================

@mcp.tool()
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
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in analyze_disk_usage: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
def list_cron_jobs() -> str:
    """Discover all scheduled cron jobs on the Linux system.

    Audits /etc/crontab, /etc/cron.d/, /etc/cron.* periodic scripts, and user crontabs.

    Returns:
        JSON string containing scheduled jobs with user, schedule expression,
        human-readable timing explanation, and command.
    """
    try:
        data = _list_cron_jobs()
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in list_cron_jobs: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
def list_systemd_timers() -> str:
    """Audit active and pending systemd timers via 'systemctl list-timers'.

    Returns:
        JSON string with timer unit names, next execution time, countdown, and target services.
    """
    try:
        data = _list_systemd_timers()
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in list_systemd_timers: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


# ============================================================================
# 8. Updates & Server Maintenance Tools
# ============================================================================

@mcp.tool()
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
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_system_updates: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
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
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_guardian_updates: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


# ============================================================================
# 9. Kernel Diagnostics & OOM Crash Tools
# ============================================================================

@mcp.tool()
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
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_oom_events: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
def check_kernel_errors(limit: int = 20) -> str:
    """Audit kernel logs for hardware failures, storage I/O errors, or application segfaults.

    Args:
        limit: Maximum number of error entries to retrieve (1 to 50, default 20).

    Returns:
        JSON string with categorized kernel errors, root causes, and critical issue counters.
    """
    try:
        data = _check_kernel_errors(limit=limit)
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_kernel_errors: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


# ============================================================================
# 10. Network Connectivity & DNS Benchmarking Tools
# ============================================================================

@mcp.tool()
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
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in test_network_connectivity: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
def check_dns_health(domains: Optional[list[str]] = None) -> str:
    """Audit system DNS resolution health, configured nameservers, and query responsiveness.

    Args:
        domains: Optional custom list of domains to probe. Defaults to essential public services.

    Returns:
        JSON string with configured nameservers, individual domain lookup latencies, and health verdict.
    """
    try:
        data = _check_dns_health(domains=domains)
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in check_dns_health: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


# ============================================================================
# 11. Database & Cache Health Tools
# ============================================================================

@mcp.tool()
def get_database_health() -> str:
    """Discover running databases and verify responsiveness, latency, and socket states.

    Detects Redis, PostgreSQL, MySQL/MariaDB, and SQLite databases in application directories.

    Returns:
        JSON string with operational state, socket accessibility, and ping latency for each engine.
    """
    try:
        data = _get_database_health()
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in get_database_health: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


# ============================================================================
# 12. Emergency Recovery & Backup Tools
# ============================================================================

@mcp.tool()
def execute_recovery(action_name: str, target: Optional[str] = None) -> str:
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

    Returns:
        JSON string with operation outcome, freed resources, or security error.
    """
    try:
        data = _run_recovery_action(action_name=action_name, target=target)
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in execute_recovery: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


@mcp.tool()
def create_backup(backup_type: str, source_path: str) -> str:
    """Create a compressed tar.gz archive of an authorized website or configuration directory.

    Archives are saved into an isolated backup repository (/var/backups/vps-guardian/).
    Permitted source locations: /var/www/, /etc/nginx/, /etc/mysql/, /etc/postgresql/, /etc/docker/, /etc/caddy/

    Args:
        backup_type: Identifier label for the archive (e.g. 'site', 'config', 'data').
        source_path: Target directory to archive.

    Returns:
        JSON string with archive file path, size, file count, and duration.
    """
    try:
        data = _create_backup(backup_type=backup_type, source_path=source_path)
        return json.dumps(data, indent=2, ensure_ascii=False)
    except Exception as exc:
        logger.error(f"Error in create_backup: {exc}", exc_info=True)
        return json.dumps({"status": "error", "error": str(exc)}, indent=2)


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

        return json.dumps(health_data, indent=2, ensure_ascii=False)
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
        return json.dumps(dashboard, indent=2, ensure_ascii=False)
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
