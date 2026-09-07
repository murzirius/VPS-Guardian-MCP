"""Docker management module for VPS-Guardian-MCP.

Provides safe, isolated tools for:
- Listing Docker containers with port bindings, volumes, and health status.
- Inspecting container logs with length constraints.
- Real-time container resource statistics (CPU %, Memory %, Network I/O, Block I/O).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vps_guardian.docker")

# Regex to prevent command/path injection in container identifiers
CONTAINER_NAME_REGEX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")


def _format_bytes(bytes_value: int | float) -> str:
    """Format bytes into human-readable string (B, KB, MB, GB, TB)."""
    val = float(bytes_value)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(val) < 1024.0 or unit == "TB":
            return f"{val:.2f} {unit}"
        val /= 1024.0
    return f"{val:.2f} TB"


def _get_docker_client():
    """Obtain initialized docker-py client with detailed error checking."""
    try:
        import docker
        from docker.errors import DockerException
    except ImportError:
        return None, {
            "status": "unavailable",
            "error": "The 'docker' python package is not installed.",
        }

    try:
        client = docker.from_env()
        client.ping()
        return client, None
    except DockerException as exc:
        err_msg = str(exc)
        if "permission denied" in err_msg.lower() or "socket" in err_msg.lower():
            friendly_err = (
                "Permission denied accessing /var/run/docker.sock. "
                "Ensure user is added to 'docker' group: 'sudo usermod -aG docker $USER'."
            )
        else:
            friendly_err = f"Docker daemon is not running or unreachable: {err_msg}"
        return None, {"status": "unavailable", "error": friendly_err}
    except Exception as exc:
        return None, {"status": "error", "error": f"Unexpected error connecting to Docker: {str(exc)}"}


def list_docker_containers(all: bool = True) -> Dict[str, Any]:
    """List Docker containers with statuses, port bindings, volumes, and health states.

    Args:
        all: When True, shows all containers (running, stopped, exited).
             When False, shows only running containers.

    Returns:
        Structured dictionary with containers list and summary counts.
    """
    client, err = _get_docker_client()
    if err:
        return err

    try:
        containers = client.containers.list(all=all)
        results: List[Dict[str, Any]] = []

        for c in containers:
            attrs = c.attrs or {}
            state = attrs.get("State", {})
            config = attrs.get("Config", {})
            network_settings = attrs.get("NetworkSettings", {})

            # Ports mapping
            ports_raw = network_settings.get("Ports") or {}
            clean_ports = []
            for container_port, host_bindings in ports_raw.items():
                if host_bindings:
                    for b in host_bindings:
                        clean_ports.append(f"{b.get('HostIp', '0.0.0.0')}:{b.get('HostPort')}->{container_port}")
                else:
                    clean_ports.append(container_port)

            # Mounts / Volumes
            mounts_raw = attrs.get("Mounts") or []
            clean_mounts = []
            for m in mounts_raw:
                clean_mounts.append({
                    "type": m.get("Type", "bind"),
                    "source": m.get("Source", ""),
                    "destination": m.get("Destination", ""),
                    "mode": m.get("Mode", "rw"),
                    "rw": m.get("RW", True),
                })

            # Healthcheck
            health = state.get("Health", {}).get("Status", "no_healthcheck")

            image_name = (
                c.image.tags[0] if getattr(c.image, "tags", None) else config.get("Image", str(c.image))
            )

            results.append({
                "id": c.short_id,
                "name": c.name,
                "image": image_name,
                "status": c.status,
                "created": attrs.get("Created", ""),
                "ports": clean_ports,
                "mounts": clean_mounts,
                "health": health,
                "exit_code": state.get("ExitCode", 0),
                "restarting": state.get("Restarting", False),
                "oom_killed": state.get("OOMKilled", False),
                "error": state.get("Error", ""),
            })

        running_count = sum(1 for item in results if item["status"] == "running")

        return {
            "status": "ok",
            "total_containers": len(results),
            "running_containers": running_count,
            "stopped_containers": len(results) - running_count,
            "containers": results,
        }
    except Exception as exc:
        logger.error(f"Error listing containers: {exc}", exc_info=True)
        return {"status": "error", "error": f"Failed listing containers: {str(exc)}", "containers": []}


def get_docker_container_logs(container_name: str, lines_count: int = 50) -> Dict[str, Any]:
    """Safely fetch the last N lines of stdout and stderr logs for a specific Docker container.

    Args:
        container_name: Name or short/full ID of the container.
        lines_count: Number of recent log lines to retrieve (default: 50, maximum: 1000).

    Returns:
        Structured dictionary containing log entries or clear error diagnostics.
    """
    if not isinstance(container_name, str):
        return {"status": "error", "error": "container_name must be a string."}

    clean_name = container_name.strip()
    if not CONTAINER_NAME_REGEX.match(clean_name):
        return {
            "status": "error",
            "error": f"Invalid container name or ID '{clean_name}'. Must contain only alphanumeric, dot, and dash characters.",
        }

    try:
        lines_count = max(1, min(int(lines_count), 1000))
    except (ValueError, TypeError):
        lines_count = 50

    client, err = _get_docker_client()
    if err:
        return err

    try:
        from docker.errors import NotFound
        container = client.containers.get(clean_name)
        raw_logs = container.logs(
            tail=lines_count,
            stdout=True,
            stderr=True,
            timestamps=True,
        )
        decoded = raw_logs.decode("utf-8", errors="replace")

        return {
            "status": "ok",
            "container_name": container.name,
            "container_id": container.short_id,
            "lines_requested": lines_count,
            "logs": decoded if decoded.strip() else "(Container log is empty)",
        }
    except NotFound:
        return {
            "status": "error",
            "error": f"Container '{clean_name}' not found.",
            "container_name": clean_name,
        }
    except Exception as exc:
        logger.error(f"Error fetching logs for container '{clean_name}': {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Failed fetching container logs: {str(exc)}",
            "container_name": clean_name,
        }


def get_docker_stats() -> Dict[str, Any]:
    """Retrieve live resource consumption stats for all running Docker containers.

    Provides a JSON analogue of `docker stats --no-stream`, computing:
    - CPU usage percentage (normalized across available cores).
    - Memory usage, limits, and percentage.
    - Network I/O (received / transmitted bytes).
    - Block I/O (read / written bytes).

    Returns:
        Structured dictionary with stats per running container.
    """
    client, err = _get_docker_client()
    if err:
        return err

    try:
        running_containers = client.containers.list(all=False)
        stats_list: List[Dict[str, Any]] = []

        for c in running_containers:
            try:
                stat = c.stats(stream=False)
            except Exception as e:
                logger.debug(f"Failed to get stats for container {c.name}: {e}")
                continue

            # 1. CPU Calculation
            cpu_percent = 0.0
            try:
                cpu_stats = stat.get("cpu_stats", {})
                precpu_stats = stat.get("precpu_stats", {})

                cpu_delta = (
                    cpu_stats.get("cpu_usage", {}).get("total_usage", 0)
                    - precpu_stats.get("cpu_usage", {}).get("total_usage", 0)
                )
                system_delta = (
                    cpu_stats.get("system_cpu_usage", 0)
                    - precpu_stats.get("system_cpu_usage", 0)
                )

                online_cpus = cpu_stats.get(
                    "online_cpus",
                    len(cpu_stats.get("cpu_usage", {}).get("percpu_usage") or [1]) or 1,
                )

                if system_delta > 0 and cpu_delta > 0:
                    cpu_percent = round((cpu_delta / system_delta) * online_cpus * 100.0, 2)
            except Exception:
                cpu_percent = 0.0

            # 2. Memory Calculation
            mem_stats = stat.get("memory_stats", {})
            mem_usage = mem_stats.get("usage", 0)
            mem_limit = mem_stats.get("limit", 0)
            mem_percent = round((mem_usage / mem_limit) * 100.0, 2) if mem_limit > 0 else 0.0

            # 3. Network I/O
            rx_bytes = 0
            tx_bytes = 0
            networks = stat.get("networks") or {}
            for net in networks.values():
                rx_bytes += net.get("rx_bytes", 0)
                tx_bytes += net.get("tx_bytes", 0)

            # 4. Block I/O
            io_read = 0
            io_write = 0
            blkio_stats = stat.get("blkio_stats", {}).get("io_service_bytes_recursive") or []
            for entry in blkio_stats:
                op = entry.get("op", "")
                if op == "Read":
                    io_read += entry.get("value", 0)
                elif op == "Write":
                    io_write += entry.get("value", 0)

            stats_list.append({
                "id": c.short_id,
                "name": c.name,
                "cpu_percent": cpu_percent,
                "memory_used": _format_bytes(mem_usage),
                "memory_limit": _format_bytes(mem_limit),
                "memory_percent": mem_percent,
                "network_rx": _format_bytes(rx_bytes),
                "network_tx": _format_bytes(tx_bytes),
                "block_io_read": _format_bytes(io_read),
                "block_io_write": _format_bytes(io_write),
            })

        return {
            "status": "ok",
            "containers_count": len(stats_list),
            "stats": stats_list,
        }
    except Exception as exc:
        logger.error(f"Error gathering docker stats: {exc}", exc_info=True)
        return {"status": "error", "error": f"Failed to gather docker stats: {str(exc)}", "stats": []}
