"""System monitoring module for VPS-Guardian-MCP.

Collects CPU, RAM, Disk, and Docker container metrics using psutil and docker-py.
All operations are safely wrapped in try-except blocks to ensure robust error
reporting without crashing the MCP server.
"""

from __future__ import annotations

import logging
import os
import platform
from typing import Any, Dict, List

import psutil

logger = logging.getLogger("vps_guardian.monitor")


def _format_bytes(bytes_value: int) -> str:
    """Format bytes into a human-readable string (KB, MB, GB, TB)."""
    val = float(bytes_value)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if val < 1024.0 or unit == "TB":
            return f"{val:.2f} {unit}"
        val /= 1024.0
    return f"{val:.2f} TB"


def get_cpu_info() -> Dict[str, Any]:
    """Collect CPU load percentage and core information."""
    try:
        cpu_percent = psutil.cpu_percent(interval=0.5)
        logical_cores = psutil.cpu_count(logical=True)
        physical_cores = psutil.cpu_count(logical=False)

        # Linux load average (1m, 5m, 15m)
        load_avg = None
        if hasattr(psutil, "getloadavg"):
            try:
                load_avg = psutil.getloadavg()
            except (OSError, AttributeError):
                load_avg = None
        elif hasattr(os, "getloadavg"):
            try:
                load_avg = os.getloadavg()
            except (OSError, AttributeError):
                load_avg = None

        return {
            "status": "ok",
            "cpu_usage_percent": cpu_percent,
            "physical_cores": physical_cores,
            "logical_cores": logical_cores,
            "load_average_1_5_15m": load_avg,
        }
    except Exception as exc:
        logger.error(f"Error reading CPU info: {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Failed to retrieve CPU info: {str(exc)}",
            "cpu_usage_percent": None,
        }


def get_memory_info() -> Dict[str, Any]:
    """Collect RAM and Swap memory utilization."""
    try:
        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()

        return {
            "status": "ok",
            "ram": {
                "total": _format_bytes(vm.total),
                "total_bytes": vm.total,
                "used": _format_bytes(vm.used),
                "used_bytes": vm.used,
                "available": _format_bytes(vm.available),
                "available_bytes": vm.available,
                "used_percent": vm.percent,
            },
            "swap": {
                "total": _format_bytes(swap.total),
                "used": _format_bytes(swap.used),
                "free": _format_bytes(swap.free),
                "used_percent": swap.percent,
            },
        }
    except Exception as exc:
        logger.error(f"Error reading memory info: {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Failed to retrieve RAM info: {str(exc)}",
        }


def get_disk_info() -> Dict[str, Any]:
    """Collect root filesystem disk space metrics."""
    try:
        # Select root directory: '/' on POSIX, root drive on Windows
        root_path = "/" if os.name != "nt" else os.path.abspath(os.sep)
        disk = psutil.disk_usage(root_path)

        return {
            "status": "ok",
            "mount_point": root_path,
            "total": _format_bytes(disk.total),
            "total_bytes": disk.total,
            "used": _format_bytes(disk.used),
            "used_bytes": disk.used,
            "free": _format_bytes(disk.free),
            "free_bytes": disk.free,
            "used_percent": disk.percent,
        }
    except Exception as exc:
        logger.error(f"Error reading disk info: {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Failed to retrieve disk usage for root: {str(exc)}",
        }


def get_docker_health() -> Dict[str, Any]:
    """Inspect Docker daemon and list any failed, stopped, or unhealthy containers."""
    try:
        import docker
        from docker.errors import DockerException
    except ImportError:
        return {
            "status": "error",
            "error": "The 'docker' python package is not installed.",
            "failed_containers": [],
        }

    try:
        client = docker.from_env()
        # Verify connectivity
        client.ping()
    except DockerException as exc:
        err_msg = str(exc)
        if "permission denied" in err_msg.lower() or "socket" in err_msg.lower():
            friendly_err = (
                "Permission denied accessing /var/run/docker.sock. "
                "Ensure the current user is added to the 'docker' group "
                "('sudo usermod -aG docker $USER') or run with docker permissions."
            )
        else:
            friendly_err = (
                f"Docker daemon is not accessible or not running: {err_msg}"
            )
        logger.warning(f"Docker health check failed: {friendly_err}")
        return {
            "status": "unavailable",
            "error": friendly_err,
            "total_containers": 0,
            "running_containers": 0,
            "failed_containers": [],
        }
    except Exception as exc:
        logger.error(f"Unexpected error checking Docker status: {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Unexpected error connecting to Docker: {str(exc)}",
            "failed_containers": [],
        }

    try:
        all_containers = client.containers.list(all=True)
        running_count = 0
        failed_containers: List[Dict[str, Any]] = []

        for container in all_containers:
            state = container.attrs.get("State", {})
            status = container.status.lower()
            exit_code = state.get("ExitCode", 0)
            health_status = state.get("Health", {}).get("Status", "none")

            is_running = status == "running"
            if is_running:
                running_count += 1

            # Container is considered failed/problematic if:
            # 1. It exited with non-zero code
            # 2. Status is 'dead', 'restarting', or 'paused'
            # 3. Status is 'exited' and exit code != 0
            # 4. Health status is 'unhealthy'
            is_failed = (
                status in ("dead", "restarting")
                or (status == "exited" and exit_code != 0)
                or health_status == "unhealthy"
            )

            if is_failed:
                failed_containers.append({
                    "id": container.short_id,
                    "name": container.name,
                    "image": container.image.tags if hasattr(container.image, "tags") else str(container.image),
                    "status": status,
                    "exit_code": exit_code,
                    "health": health_status,
                    "error": state.get("Error", ""),
                    "finished_at": state.get("FinishedAt", ""),
                })

        return {
            "status": "connected",
            "total_containers": len(all_containers),
            "running_containers": running_count,
            "failed_containers_count": len(failed_containers),
            "failed_containers": failed_containers,
        }
    except Exception as exc:
        logger.error(f"Failed to inspect containers: {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Failed while listing containers: {str(exc)}",
            "failed_containers": [],
        }


def collect_system_health() -> Dict[str, Any]:
    """Aggregate complete VPS health metrics."""
    return {
        "system": {
            "os": platform.system(),
            "platform": platform.platform(),
            "architecture": platform.machine(),
        },
        "cpu": get_cpu_info(),
        "memory": get_memory_info(),
        "disk": get_disk_info(),
        "docker": get_docker_health(),
    }
