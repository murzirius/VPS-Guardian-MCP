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

# Pattern to identify sensitive environment variables for masking
SENSITIVE_ENV_PATTERN = re.compile(
    r"(pass(word)?|secret|token|key|cred(ential)?|auth|api_key|private|cert)",
    re.IGNORECASE,
)


def _format_bytes(bytes_value: int | float) -> str:
    """Format bytes into human-readable string (B, KB, MB, GB, TB)."""
    val = float(bytes_value)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(val) < 1024.0 or unit == "TB":
            return f"{val:.2f} {unit}"
        val /= 1024.0
    return f"{val:.2f} TB"


try:
    import docker
    from docker.errors import APIError, DockerException, NotFound
except ImportError:
    class DockerException(Exception):
        """Fallback DockerException when docker library is unavailable."""
        pass

    class APIError(DockerException):
        """Fallback APIError when docker library is unavailable."""
        pass

    class NotFound(DockerException):
        """Fallback NotFound when docker library is unavailable."""
        pass


def _get_docker_client():
    """Obtain initialized docker-py client with detailed error checking."""
    try:
        import docker
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


def docker_container_action(container_name: str, action: str, timeout: int = 10) -> Dict[str, Any]:
    """Safely execute a lifecycle action against a specific Docker container.

    Args:
        container_name: Name or short/full ID of the target container.
        action: Lifecycle action to perform ('start', 'stop', 'restart', 'pause', 'unpause').
        timeout: Grace period in seconds before forcible kill on stop/restart (default: 10).

    Returns:
        Structured dictionary reporting previous state, new state, and execution outcome.
    """
    if not isinstance(container_name, str):
        return {"status": "error", "error": "container_name must be a string."}

    clean_name = container_name.strip()
    if not CONTAINER_NAME_REGEX.match(clean_name):
        return {
            "status": "error",
            "error": f"Invalid container name or ID '{clean_name}'. Must contain only alphanumeric, dot, and dash characters.",
        }

    valid_actions = {"start", "stop", "restart", "pause", "unpause"}
    clean_action = str(action).lower().strip()
    if clean_action not in valid_actions:
        return {
            "status": "error",
            "error": f"Invalid action '{action}'. Permitted actions are: {', '.join(sorted(valid_actions))}.",
        }

    try:
        timeout = max(1, min(int(timeout), 60))
    except (ValueError, TypeError):
        timeout = 10

    client, err = _get_docker_client()
    if err:
        return err

    try:
        container = client.containers.get(clean_name)
        prev_status = container.status

        if clean_action == "start":
            container.start()
        elif clean_action == "stop":
            container.stop(timeout=timeout)
        elif clean_action == "restart":
            container.restart(timeout=timeout)
        elif clean_action == "pause":
            container.pause()
        elif clean_action == "unpause":
            container.unpause()

        container.reload()
        new_status = container.status

        logger.info(f"Container '{clean_name}' action '{clean_action}' executed successfully ({prev_status} -> {new_status})")
        return {
            "status": "ok",
            "action": clean_action,
            "container_name": container.name,
            "container_id": container.short_id,
            "previous_status": prev_status,
            "current_status": new_status,
            "message": f"Successfully performed '{clean_action}' on container '{container.name}' ({prev_status} -> {new_status}).",
        }
    except NotFound:
        return {
            "status": "error",
            "error": f"Container '{clean_name}' not found.",
            "container_name": clean_name,
        }
    except APIError as exc:
        logger.error(f"Docker API error during '{clean_action}' on '{clean_name}': {exc}")
        return {
            "status": "error",
            "error": f"Docker API error: {exc.explanation if hasattr(exc, 'explanation') else str(exc)}",
            "container_name": clean_name,
        }
    except Exception as exc:
        logger.error(f"Unexpected error during '{clean_action}' on '{clean_name}': {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Failed to execute '{clean_action}': {str(exc)}",
            "container_name": clean_name,
        }


def inspect_docker_container(container_name: str) -> Dict[str, Any]:
    """Perform a deep architectural and runtime inspection of a specific Docker container.

    Extracts detailed network configuration, volume mounts, healthcheck history,
    restart policies, resource limits, and environment variables (with sensitive keys masked).

    Args:
        container_name: Name or short/full ID of the container.

    Returns:
        Structured dictionary with deep container diagnostics.
    """
    if not isinstance(container_name, str):
        return {"status": "error", "error": "container_name must be a string."}

    clean_name = container_name.strip()
    if not CONTAINER_NAME_REGEX.match(clean_name):
        return {
            "status": "error",
            "error": f"Invalid container name or ID '{clean_name}'. Must contain only alphanumeric, dot, and dash characters.",
        }

    client, err = _get_docker_client()
    if err:
        return err

    try:
        container = client.containers.get(clean_name)
        attrs = container.attrs or {}
        state = attrs.get("State", {})
        config = attrs.get("Config", {})
        host_config = attrs.get("HostConfig", {})
        network_settings = attrs.get("NetworkSettings", {})

        # 1. Ports
        ports_raw = network_settings.get("Ports") or {}
        clean_ports = []
        for c_port, bindings in ports_raw.items():
            if bindings:
                for b in bindings:
                    clean_ports.append(f"{b.get('HostIp', '0.0.0.0')}:{b.get('HostPort')}->{c_port}")
            else:
                clean_ports.append(c_port)

        # 2. Mounts
        mounts_raw = attrs.get("Mounts") or []
        clean_mounts = []
        for m in mounts_raw:
            clean_mounts.append({
                "type": m.get("Type", "bind"),
                "source": m.get("Source", ""),
                "destination": m.get("Destination", ""),
                "mode": m.get("Mode", ""),
                "rw": m.get("RW", True),
                "propagation": m.get("Propagation", ""),
            })

        # 3. Networks
        networks_raw = network_settings.get("Networks") or {}
        clean_networks = {}
        for net_name, net_cfg in networks_raw.items():
            clean_networks[net_name] = {
                "ip_address": net_cfg.get("IPAddress", ""),
                "gateway": net_cfg.get("Gateway", ""),
                "mac_address": net_cfg.get("MacAddress", ""),
                "aliases": net_cfg.get("Aliases", []),
            }

        # 4. Mask sensitive environment variables
        env_raw = config.get("Env") or []
        clean_env = []
        for item in env_raw[:60]:
            if "=" in item:
                k, v = item.split("=", 1)
                if SENSITIVE_ENV_PATTERN.search(k):
                    clean_env.append(f"{k}=***MASKED***")
                elif len(v) > 120:
                    clean_env.append(f"{k}={v[:117]}...")
                else:
                    clean_env.append(item)
            else:
                clean_env.append(item)

        # 5. Resource Limits
        memory_limit = host_config.get("Memory", 0)
        nano_cpus = host_config.get("NanoCpus", 0)
        cpu_shares = host_config.get("CpuShares", 0)

        # 6. Health Log
        health_raw = state.get("Health", {})
        health_status = health_raw.get("Status", "none")
        health_logs_sample = []
        for log_entry in (health_raw.get("Log") or [])[-5:]:
            health_logs_sample.append({
                "start": log_entry.get("Start", ""),
                "end": log_entry.get("End", ""),
                "exit_code": log_entry.get("ExitCode", 0),
                "output": log_entry.get("Output", "").strip()[:200],
            })

        return {
            "status": "ok",
            "id": container.id,
            "short_id": container.short_id,
            "name": container.name,
            "image": config.get("Image", str(container.image)),
            "created": attrs.get("Created", ""),
            "path": attrs.get("Path", ""),
            "args": attrs.get("Args", []),
            "state": {
                "status": state.get("Status", container.status),
                "running": state.get("Running", False),
                "paused": state.get("Paused", False),
                "restarting": state.get("Restarting", False),
                "oom_killed": state.get("OOMKilled", False),
                "dead": state.get("Dead", False),
                "pid": state.get("Pid", 0),
                "exit_code": state.get("ExitCode", 0),
                "error": state.get("Error", ""),
                "started_at": state.get("StartedAt", ""),
                "finished_at": state.get("FinishedAt", ""),
                "health_status": health_status,
                "recent_health_checks": health_logs_sample,
            },
            "network": {
                "ip_address": network_settings.get("IPAddress", ""),
                "gateway": network_settings.get("Gateway", ""),
                "mac_address": network_settings.get("MacAddress", ""),
                "ports": clean_ports,
                "networks": clean_networks,
            },
            "mounts": clean_mounts,
            "host_config": {
                "restart_policy": host_config.get("RestartPolicy", {}).get("Name", "no"),
                "auto_remove": host_config.get("AutoRemove", False),
                "memory_limit": _format_bytes(memory_limit) if memory_limit > 0 else "unlimited",
                "nano_cpus": nano_cpus,
                "cpu_shares": cpu_shares,
                "network_mode": host_config.get("NetworkMode", "default"),
            },
            "environment_variables": clean_env,
        }
    except NotFound:
        return {
            "status": "error",
            "error": f"Container '{clean_name}' not found.",
            "container_name": clean_name,
        }
    except Exception as exc:
        logger.error(f"Error inspecting container '{clean_name}': {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Failed inspecting container '{clean_name}': {str(exc)}",
            "container_name": clean_name,
        }


def clean_docker_garbage(prune_type: str = "all") -> Dict[str, Any]:
    """Safely reclaim disk space by pruning unused Docker resources.

    Args:
        prune_type: Category to prune ('containers', 'images', 'volumes', 'networks', 'all'). Default is 'all'.

    Returns:
        Structured breakdown of deleted items and total disk capacity reclaimed.
    """
    valid_types = {"containers", "images", "volumes", "networks", "all"}
    clean_type = str(prune_type).lower().strip()
    if clean_type not in valid_types:
        return {
            "status": "error",
            "error": f"Invalid prune_type '{prune_type}'. Permitted options: {', '.join(sorted(valid_types))}.",
        }

    client, err = _get_docker_client()
    if err:
        return err

    total_reclaimed_bytes = 0
    containers_deleted: List[str] = []
    images_deleted: List[str] = []
    volumes_deleted: List[str] = []
    networks_deleted: List[str] = []

    try:
        # 1. Containers
        if clean_type in ("containers", "all"):
            try:
                res = client.containers.prune()
                containers_deleted = res.get("ContainersDeleted") or []
                total_reclaimed_bytes += res.get("SpaceReclaimed", 0)
            except Exception as e:
                logger.warning(f"Containers prune error: {e}")

        # 2. Images (dangling untagged layers)
        if clean_type in ("images", "all"):
            try:
                res = client.images.prune(filters={"dangling": True})
                del_imgs = res.get("ImagesDeleted") or []
                for item in del_imgs:
                    if isinstance(item, dict):
                        images_deleted.append(item.get("Deleted", item.get("Untagged", "unknown")))
                    else:
                        images_deleted.append(str(item))
                total_reclaimed_bytes += res.get("SpaceReclaimed", 0)
            except Exception as e:
                logger.warning(f"Images prune error: {e}")

        # 3. Volumes
        if clean_type in ("volumes", "all"):
            try:
                res = client.volumes.prune()
                volumes_deleted = res.get("VolumesDeleted") or []
                total_reclaimed_bytes += res.get("SpaceReclaimed", 0)
            except Exception as e:
                logger.warning(f"Volumes prune error: {e}")

        # 4. Networks
        if clean_type in ("networks", "all"):
            try:
                res = client.networks.prune()
                networks_deleted = res.get("NetworksDeleted") or []
            except Exception as e:
                logger.warning(f"Networks prune error: {e}")

        return {
            "status": "ok",
            "prune_type": clean_type,
            "total_space_reclaimed": _format_bytes(total_reclaimed_bytes),
            "total_space_reclaimed_bytes": total_reclaimed_bytes,
            "containers_deleted_count": len(containers_deleted),
            "containers_deleted": containers_deleted[:20],
            "images_deleted_count": len(images_deleted),
            "images_deleted": images_deleted[:20],
            "volumes_deleted_count": len(volumes_deleted),
            "volumes_deleted": volumes_deleted[:20],
            "networks_deleted_count": len(networks_deleted),
            "networks_deleted": networks_deleted[:20],
            "summary": (
                f"Docker cleanup completed ({clean_type}). "
                f"Reclaimed {_format_bytes(total_reclaimed_bytes)} across "
                f"{len(containers_deleted)} containers, {len(images_deleted)} images, and {len(volumes_deleted)} volumes."
            ),
        }
    except Exception as exc:
        logger.error(f"Error during docker cleanup: {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Docker cleanup failed: {str(exc)}",
            "prune_type": clean_type,
        }
