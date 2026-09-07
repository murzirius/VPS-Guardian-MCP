"""Safe recovery and log extraction module for VPS-Guardian-MCP.

Provides strictly isolated, secure methods for reading service logs and executing
predefined recovery actions without risking arbitrary command execution.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from typing import Any, Dict, List

logger = logging.getLogger("vps_guardian.recover")

# Allowed recovery actions whitelist
ALLOWED_RECOVERY_ACTIONS = {
    "clean_docker_cache": "Cleans unused Docker containers, networks, images, and build cache.",
    "restart_nginx": "Safely restarts the Nginx web server service.",
}

# Regex to prevent command injection: only alphanumeric, underscore, hyphen, and optional prefix
SERVICE_NAME_REGEX = re.compile(r"^(?:(docker|systemd):)?([a-zA-Z0-9_-]{1,64})$")


def fetch_service_logs(service_name: str, lines_count: int = 50) -> Dict[str, Any]:
    """Safely fetch the last N lines of logs for a permitted service or Docker container.

    Supported targets:
    - 'nginx' (checks systemd journal and fallback to /var/log/nginx/error.log)
    - 'docker:<container_name>' or container name matching a Docker container
    - 'systemd:<service_name>' or '<service_name>' via journalctl

    Args:
        service_name: Target service or container name (e.g., 'nginx', 'docker:web_app', 'systemd:redis')
        lines_count: Number of log lines to retrieve (clamped between 1 and 1000)

    Returns:
        Structured dictionary containing log entries or clear error messages.
    """
    # 1. Validate & clamp lines_count
    try:
        lines_count = int(lines_count)
        if lines_count <= 0:
            lines_count = 50
        elif lines_count > 1000:
            lines_count = 1000
    except (ValueError, TypeError):
        lines_count = 50

    # 2. Strict validation of service_name to prevent command injection
    if not isinstance(service_name, str):
        return {
            "status": "error",
            "error": "Invalid service_name format. Expected a string.",
            "logs": "",
        }

    cleaned_name = service_name.strip()
    match = SERVICE_NAME_REGEX.match(cleaned_name)
    if not match:
        return {
            "status": "error",
            "error": (
                f"Invalid service_name '{cleaned_name}'. "
                "Only alphanumeric characters, dashes, and underscores are allowed "
                "(optional prefix 'docker:' or 'systemd:')."
            ),
            "logs": "",
        }

    prefix, target = match.groups()

    # 3. Handle Docker container logs
    if prefix == "docker":
        return _fetch_docker_logs(target, lines_count)

    # 4. Handle Nginx logs (specialized handling)
    if cleaned_name == "nginx" or target == "nginx":
        return _fetch_nginx_logs(lines_count)

    # 5. Handle systemd service logs
    return _fetch_systemd_logs(target, lines_count)


def _fetch_docker_logs(container_name: str, lines_count: int) -> Dict[str, Any]:
    """Read logs from a Docker container safely using the Docker SDK."""
    try:
        import docker
        from docker.errors import DockerException, NotFound
    except ImportError:
        return {
            "status": "error",
            "error": "The 'docker' python package is not available.",
            "logs": "",
        }

    try:
        client = docker.from_env()
        container = client.containers.get(container_name)
        raw_logs = container.logs(
            tail=lines_count,
            stdout=True,
            stderr=True,
            timestamps=True,
        )
        decoded_logs = raw_logs.decode("utf-8", errors="replace")
        return {
            "status": "ok",
            "target_type": "docker",
            "target": container_name,
            "lines_requested": lines_count,
            "logs": decoded_logs if decoded_logs else "(No logs found for this container)",
        }
    except NotFound:
        return {
            "status": "error",
            "error": f"Docker container '{container_name}' was not found.",
            "logs": "",
        }
    except DockerException as exc:
        err_str = str(exc)
        if "permission denied" in err_str.lower() or "socket" in err_str.lower():
            msg = (
                f"Permission denied accessing Docker daemon while reading logs for '{container_name}'. "
                "Ensure user is in 'docker' group."
            )
        else:
            msg = f"Docker error reading logs for '{container_name}': {err_str}"
        return {"status": "error", "error": msg, "logs": ""}
    except Exception as exc:
        return {
            "status": "error",
            "error": f"Unexpected error reading Docker logs: {str(exc)}",
            "logs": "",
        }


def _fetch_nginx_logs(lines_count: int) -> Dict[str, Any]:
    """Read Nginx logs from journalctl or directly from /var/log/nginx/error.log."""
    # First, try journalctl
    if shutil.which("journalctl"):
        cmd = ["journalctl", "-u", "nginx.service", "--no-pager", "-n", str(lines_count)]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            if res.returncode == 0 and res.stdout.strip():
                return {
                    "status": "ok",
                    "target_type": "systemd",
                    "target": "nginx",
                    "lines_requested": lines_count,
                    "logs": res.stdout,
                }
        except subprocess.TimeoutExpired:
            return {"status": "error", "error": "Timeout reading journalctl for nginx.", "logs": ""}
        except Exception as exc:
            logger.debug(f"journalctl nginx failed, attempting log file: {exc}")

    # Fallback to reading /var/log/nginx/error.log directly
    error_log_path = "/var/log/nginx/error.log"
    try:
        with open(error_log_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            tail_lines = "".join(lines[-lines_count:])
            return {
                "status": "ok",
                "target_type": "file",
                "target": error_log_path,
                "lines_requested": lines_count,
                "logs": tail_lines if tail_lines else "(Nginx error log is empty)",
            }
    except PermissionError:
        return {
            "status": "error",
            "error": f"Permission denied reading '{error_log_path}'. Check user permissions.",
            "logs": "",
        }
    except FileNotFoundError:
        pass
    except Exception as exc:
        return {"status": "error", "error": f"Error reading '{error_log_path}': {str(exc)}", "logs": ""}

    # Check if maybe nginx runs as a Docker container
    try:
        docker_result = _fetch_docker_logs("nginx", lines_count)
        if docker_result["status"] == "ok":
            return docker_result
    except Exception:
        pass

    return {
        "status": "error",
        "error": "Could not find Nginx logs via journalctl, /var/log/nginx/error.log, or Docker container 'nginx'.",
        "logs": "",
    }


def _fetch_systemd_logs(service: str, lines_count: int) -> Dict[str, Any]:
    """Read systemd service logs using journalctl."""
    journalctl_bin = shutil.which("journalctl")
    if not journalctl_bin:
        # If journalctl is not available (e.g. on non-systemd systems or Windows during development)
        return {
            "status": "error",
            "error": "journalctl utility is not available on this system. Is this a systemd Linux VPS?",
            "logs": "",
        }

    # Safe invocation: arguments passed as list, no shell=True
    unit_name = service if service.endswith(".service") else f"{service}.service"
    cmd = [journalctl_bin, "-u", unit_name, "--no-pager", "-n", str(lines_count)]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        if result.returncode != 0:
            err_output = result.stderr.strip() or result.stdout.strip()
            if "permission" in err_output.lower() or "access" in err_output.lower():
                err_msg = (
                    f"Permission denied reading journal logs for '{unit_name}'. "
                    "The user running vps-guardian-mcp needs to be in 'systemd-journal' or 'adm' group."
                )
            else:
                err_msg = f"journalctl exited with code {result.returncode}: {err_output}"
            return {"status": "error", "error": err_msg, "logs": ""}

        return {
            "status": "ok",
            "target_type": "systemd",
            "target": unit_name,
            "lines_requested": lines_count,
            "logs": result.stdout if result.stdout.strip() else f"(No logs found for unit '{unit_name}')",
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": f"Timed out reading logs for '{unit_name}'.", "logs": ""}
    except PermissionError as exc:
        return {
            "status": "error",
            "error": f"Permission denied executing journalctl: {str(exc)}",
            "logs": "",
        }
    except Exception as exc:
        logger.error(f"Error fetching systemd logs: {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Failed to read systemd logs: {str(exc)}",
            "logs": "",
        }


def run_recovery_action(action_name: str) -> Dict[str, Any]:
    """Execute an isolated, predefined VPS recovery action.

    Strict whitelist policy: Only 'clean_docker_cache' and 'restart_nginx' are allowed.
    Any other action returns an explicit Access Denied error.

    Args:
        action_name: Name of the recovery action to perform.

    Returns:
        Structured result dict with operation status and execution output.
    """
    if not isinstance(action_name, str):
        return {
            "status": "error",
            "error": "Action name must be a string.",
            "success": False,
        }

    action_clean = action_name.strip().lower()

    # Enforce strict whitelist
    if action_clean not in ALLOWED_RECOVERY_ACTIONS:
        allowed_list = list(ALLOWED_RECOVERY_ACTIONS.keys())
        logger.warning(f"Unauthorized recovery action rejected: '{action_name}'")
        return {
            "status": "forbidden",
            "success": False,
            "error": (
                f"Access denied: Action '{action_name}' is not permitted. "
                f"Allowed recovery actions: {allowed_list}"
            ),
        }

    if action_clean == "clean_docker_cache":
        return _action_clean_docker_cache()
    elif action_clean == "restart_nginx":
        return _action_restart_nginx()

    return {
        "status": "error",
        "success": False,
        "error": f"Action handler not implemented for '{action_clean}'.",
    }


def _action_clean_docker_cache() -> Dict[str, Any]:
    """Perform safe Docker cache cleaning (pruning stopped containers, unused networks, and dangling images)."""
    try:
        import docker
        from docker.errors import DockerException
    except ImportError:
        return {
            "status": "error",
            "success": False,
            "error": "The 'docker' python library is not installed.",
        }

    details = {}
    try:
        client = docker.from_env()

        # 1. Prune containers
        c_prune = client.containers.prune()
        containers_deleted = len(c_prune.get("ContainersDeleted") or [])
        space_reclaimed = c_prune.get("SpaceReclaimed", 0)

        # 2. Prune networks
        n_prune = client.networks.prune()
        networks_deleted = len(n_prune.get("NetworksDeleted") or [])

        # 3. Prune dangling images
        i_prune = client.images.prune(filters={"dangling": True})
        images_deleted = len(i_prune.get("ImagesDeleted") or [])
        space_reclaimed += i_prune.get("SpaceReclaimed", 0)

        # 4. Prune build cache if supported
        build_cache_reclaimed = 0
        if hasattr(client, "build_cache"):
            try:
                b_prune = client.build_cache.prune()
                build_cache_reclaimed = b_prune.get("SpaceReclaimed", 0)
                space_reclaimed += build_cache_reclaimed
            except Exception:
                pass

        details = {
            "containers_pruned": containers_deleted,
            "networks_pruned": networks_deleted,
            "images_pruned": images_deleted,
            "space_reclaimed_bytes": space_reclaimed,
            "space_reclaimed_mb": round(space_reclaimed / (1024 * 1024), 2),
        }

        return {
            "status": "ok",
            "success": True,
            "action": "clean_docker_cache",
            "message": f"Docker cache cleanup completed. Freed approximately {details['space_reclaimed_mb']} MB.",
            "details": details,
        }

    except DockerException as exc:
        err_str = str(exc)
        if "permission denied" in err_str.lower() or "socket" in err_str.lower():
            msg = (
                "Permission denied accessing /var/run/docker.sock. "
                "Grant the running user docker permissions ('sudo usermod -aG docker $USER')."
            )
        else:
            msg = f"Docker cleanup failed: {err_str}"
        logger.error(f"Docker cleanup error: {msg}")
        return {
            "status": "error",
            "success": False,
            "action": "clean_docker_cache",
            "error": msg,
        }
    except Exception as exc:
        logger.error(f"Unexpected error during Docker cleanup: {exc}", exc_info=True)
        return {
            "status": "error",
            "success": False,
            "action": "clean_docker_cache",
            "error": f"Unexpected error during docker cache cleanup: {str(exc)}",
        }


def _action_restart_nginx() -> Dict[str, Any]:
    """Safely restart Nginx web server using systemctl or docker container restart."""
    systemctl_bin = shutil.which("systemctl")

    # 1. Try systemctl restart nginx
    if systemctl_bin:
        try:
            cmd = [systemctl_bin, "restart", "nginx"]
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            if res.returncode == 0:
                return {
                    "status": "ok",
                    "success": True,
                    "action": "restart_nginx",
                    "method": "systemctl",
                    "message": "Nginx service successfully restarted via systemctl.",
                }
            else:
                err_output = res.stderr.strip() or res.stdout.strip()
                if "interactive authentication" in err_output.lower() or "permission denied" in err_output.lower() or "access denied" in err_output.lower():
                    friendly_err = (
                        "Permission denied restarting Nginx via systemctl. "
                        "The server requires sudo/root privileges. "
                        "Tip: Add '%sudo ALL=NOPASSWD: /bin/systemctl restart nginx' to /etc/sudoers.d/vps-guardian."
                    )
                else:
                    friendly_err = f"Failed to restart Nginx (exit code {res.returncode}): {err_output}"
                return {
                    "status": "error",
                    "success": False,
                    "action": "restart_nginx",
                    "error": friendly_err,
                }
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "success": False,
                "action": "restart_nginx",
                "error": "Timeout while executing 'systemctl restart nginx'.",
            }
        except PermissionError as exc:
            return {
                "status": "error",
                "success": False,
                "action": "restart_nginx",
                "error": f"Permission denied executing systemctl: {str(exc)}",
            }

    # 2. If systemctl is not present or failed, check if Nginx is running as a Docker container
    try:
        import docker
        client = docker.from_env()
        containers = client.containers.list(filters={"name": "nginx"})
        if containers:
            nginx_c = containers[0]
            nginx_c.restart()
            return {
                "status": "ok",
                "success": True,
                "action": "restart_nginx",
                "method": "docker",
                "message": f"Docker container '{nginx_c.name}' (Nginx) successfully restarted.",
            }
    except Exception:
        pass

    return {
        "status": "error",
        "success": False,
        "action": "restart_nginx",
        "error": "Could not restart Nginx: systemctl was not found and no running 'nginx' Docker container was detected.",
    }
