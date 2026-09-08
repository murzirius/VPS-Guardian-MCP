"""Safe recovery and backup module for VPS-Guardian-MCP.

Provides strictly isolated, secure recovery actions and archive generation:
- Whitelist-enforced system recovery:
  * 'restart_service' (restarts permitted systemd services)
  * 'clean_docker_cache' (deep Docker prune: containers, networks, images, volumes)
  * 'clean_system_logs' (prunes old journal logs with journalctl vacuum and rotated logs)
  * 'kill_process' (safely terminates non-critical runaway processes by PID)
  * 'restart_nginx' (legacy alias for restart_service target=nginx)
- Isolated backup creation (tar.gz compression) of authorized website and config directories.
"""

from __future__ import annotations

import datetime
import logging
import os
import re
import shutil
import subprocess
import tarfile
import time
from typing import Any, Dict, List, Optional

import psutil

logger = logging.getLogger("vps_guardian.recover")

# Whitelist of permitted recovery actions
ALLOWED_RECOVERY_ACTIONS = {
    "restart_service": "Restart a specific system service (requires target=service_name).",
    "clean_docker_cache": "Prunes unused Docker containers, networks, dangling/unused images, and build cache.",
    "clean_system_logs": "Prunes old systemd journal entries (>3 days) and rotated archived logs in /var/log.",
    "kill_process": "Terminates a runaway or stuck process (requires target=PID).",
    "restart_nginx": "Safely restarts the Nginx web server service (alias for restart_service target=nginx).",
    "vacuum_systemd_journal": "Reduces systemd journal size to limit (target defaults to '200M').",
    "clean_package_cache": "Cleans APT package cache and removes obsolete packages (apt-get clean & autoremove).",
    "apply_security_updates": "Applies available operating system security patches non-interactively.",
    "update_guardian": "Updates VPS-Guardian-MCP from GitHub repository and refreshes virtual environment.",
}

# Regex to prevent command injection in service names
SERVICE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")

# Protected critical system processes that must NEVER be terminated via kill_process
PROTECTED_PROCESS_NAMES = {
    "systemd",
    "init",
    "kthreadd",
    "sshd",
    "vps-guardian",
    "vps-guardian-mc",
    "python",
    "python3",
}

# Permitted backup source directory roots
ALLOWED_BACKUP_ROOTS = [
    "/var/www",
    "/etc/nginx",
    "/etc/mysql",
    "/etc/postgresql",
    "/etc/docker",
    "/etc/caddy",
]


def _format_bytes(bytes_value: int | float) -> str:
    """Format bytes into a human-readable string (B, KB, MB, GB)."""
    val = float(bytes_value)
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(val) < 1024.0 or unit == "GB":
            return f"{val:.2f} {unit}"
        val /= 1024.0
    return f"{val:.2f} GB"


# ============================================================================
# Log Inspection Helper (Used by monitor.py & server.py)
# ============================================================================

def fetch_service_logs(service_name: str, lines_count: int = 50) -> Dict[str, Any]:
    """Safely fetch the last N lines of logs for a permitted service or Docker container."""
    try:
        lines_count = max(1, min(int(lines_count), 1000))
    except (ValueError, TypeError):
        lines_count = 50

    if not isinstance(service_name, str) or not service_name.strip():
        return {"status": "error", "error": "Invalid service_name.", "logs": ""}

    cleaned_name = service_name.strip()
    match = re.match(r"^(?:(docker|systemd):)?([a-zA-Z0-9_-]{1,64})$", cleaned_name)
    if not match:
        return {
            "status": "error",
            "error": f"Invalid service_name '{cleaned_name}'. Only alphanumeric characters, dashes, and dots allowed.",
            "logs": "",
        }

    prefix, target = match.groups()

    if prefix == "docker":
        return _fetch_docker_logs(target, lines_count)

    if cleaned_name == "nginx" or target == "nginx":
        return _fetch_nginx_logs(lines_count)

    return _fetch_systemd_logs(target, lines_count)


def _fetch_docker_logs(container_name: str, lines_count: int) -> Dict[str, Any]:
    """Read logs from a Docker container safely."""
    try:
        import docker
        from docker.errors import DockerException, NotFound
        client = docker.from_env()
        container = client.containers.get(container_name)
        raw_logs = container.logs(tail=lines_count, stdout=True, stderr=True, timestamps=True)
        return {
            "status": "ok",
            "target_type": "docker",
            "target": container_name,
            "lines_requested": lines_count,
            "logs": raw_logs.decode("utf-8", errors="replace"),
        }
    except Exception as exc:
        return {"status": "error", "error": f"Docker logs error: {str(exc)}", "logs": ""}


def _fetch_nginx_logs(lines_count: int) -> Dict[str, Any]:
    """Read Nginx logs from journalctl or file."""
    if shutil.which("journalctl"):
        try:
            res = subprocess.run(
                ["journalctl", "-u", "nginx.service", "--no-pager", "-n", str(lines_count)],
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
        except Exception:
            pass

    for log_path in ["/var/log/nginx/error.log", "/var/log/nginx/access.log"]:
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                    return {
                        "status": "ok",
                        "target_type": "file",
                        "target": log_path,
                        "lines_requested": lines_count,
                        "logs": "".join(lines[-lines_count:]),
                    }
            except Exception:
                continue

    return {"status": "error", "error": "Could not read Nginx logs.", "logs": ""}


def _fetch_systemd_logs(service: str, lines_count: int) -> Dict[str, Any]:
    """Read systemd logs using journalctl."""
    journalctl_bin = shutil.which("journalctl")
    if not journalctl_bin:
        return {"status": "unavailable", "error": "journalctl utility is not available.", "logs": ""}

    unit_name = service if service.endswith(".service") else f"{service}.service"
    try:
        res = subprocess.run(
            [journalctl_bin, "-u", unit_name, "--no-pager", "-n", str(lines_count)],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        return {
            "status": "ok",
            "target_type": "systemd",
            "target": unit_name,
            "lines_requested": lines_count,
            "logs": res.stdout if res.stdout.strip() else f"(No logs found for {unit_name})",
        }
    except Exception as exc:
        return {"status": "error", "error": f"Failed reading journalctl: {str(exc)}", "logs": ""}


# ============================================================================
# Whitelisted Recovery Operations
# ============================================================================

def run_recovery_action(
    action_name: str, target: Optional[str] = None
) -> Dict[str, Any]:
    """Execute an isolated, predefined VPS recovery action.

    Args:
        action_name: One of 'restart_service', 'clean_docker_cache',
                     'clean_system_logs', 'kill_process', 'restart_nginx'.
        target: Parameter required by certain actions (e.g. service name or PID).

    Returns:
        Structured result dictionary.
    """
    if not isinstance(action_name, str):
        return {"status": "error", "error": "action_name must be a string.", "success": False}

    action_clean = action_name.strip().lower()
    if action_clean not in ALLOWED_RECOVERY_ACTIONS:
        return {
            "status": "forbidden",
            "success": False,
            "error": (
                f"Access denied: Action '{action_name}' is not permitted. "
                f"Allowed recovery actions: {list(ALLOWED_RECOVERY_ACTIONS.keys())}"
            ),
        }

    # Dispatch to specific action handlers
    if action_clean == "restart_service":
        return _action_restart_service(target)
    elif action_clean == "restart_nginx":
        return _action_restart_service("nginx")
    elif action_clean == "clean_docker_cache":
        return _action_clean_docker_cache()
    elif action_clean == "clean_system_logs":
        return _action_clean_system_logs()
    elif action_clean == "kill_process":
        return _action_kill_process(target)
    elif action_clean == "vacuum_systemd_journal":
        return _action_vacuum_journal(target)
    elif action_clean == "clean_package_cache":
        return _action_clean_package_cache()
    elif action_clean == "apply_security_updates":
        return _action_apply_security_updates()
    elif action_clean == "update_guardian":
        return _action_update_guardian()

    return {"status": "error", "success": False, "error": f"Handler not implemented for '{action_clean}'."}


def _action_restart_service(service_name: Optional[str]) -> Dict[str, Any]:
    """Safely restart a specific system service using systemctl."""
    if not service_name or not isinstance(service_name, str):
        return {
            "status": "error",
            "success": False,
            "error": "The 'restart_service' action requires a valid 'target' parameter (e.g. target='nginx').",
        }

    clean_name = service_name.strip()
    if not SERVICE_NAME_REGEX.match(clean_name):
        return {
            "status": "error",
            "success": False,
            "error": f"Invalid service name '{clean_name}'. Only alphanumeric characters, dots, and hyphens allowed.",
        }

    systemctl_bin = shutil.which("systemctl")
    if not systemctl_bin:
        return {
            "status": "unavailable",
            "success": False,
            "error": "systemctl command not found. Host is not systemd-based.",
        }

    unit_name = clean_name if clean_name.endswith(".service") else f"{clean_name}.service"
    cmd = [systemctl_bin, "restart", unit_name]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)
        if res.returncode == 0:
            return {
                "status": "ok",
                "success": True,
                "action": "restart_service",
                "target": unit_name,
                "message": f"Service '{unit_name}' successfully restarted.",
            }
        else:
            err_msg = res.stderr.strip() or res.stdout.strip()
            if "permission denied" in err_msg.lower() or "interactive authentication" in err_msg.lower():
                err_msg = (
                    f"Permission denied restarting '{unit_name}'. Superuser privileges are required. "
                    "Grant sudo permissions for systemctl restart in /etc/sudoers.d/."
                )
            return {
                "status": "error",
                "success": False,
                "action": "restart_service",
                "target": unit_name,
                "error": err_msg,
            }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "success": False,
            "action": "restart_service",
            "target": unit_name,
            "error": f"Timeout while restarting service '{unit_name}'.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "success": False,
            "action": "restart_service",
            "target": unit_name,
            "error": f"Unexpected error restarting service: {str(exc)}",
        }


def _action_clean_docker_cache() -> Dict[str, Any]:
    """Perform deep Docker cleanup: containers, images, volumes, and build cache."""
    try:
        import docker
        from docker.errors import DockerException
        client = docker.from_env()

        c_prune = client.containers.prune()
        containers_deleted = len(c_prune.get("ContainersDeleted") or [])
        space_reclaimed = c_prune.get("SpaceReclaimed", 0)

        n_prune = client.networks.prune()
        networks_deleted = len(n_prune.get("NetworksDeleted") or [])

        i_prune = client.images.prune(filters={"dangling": False})
        images_deleted = len(i_prune.get("ImagesDeleted") or [])
        space_reclaimed += i_prune.get("SpaceReclaimed", 0)

        v_prune = client.volumes.prune()
        volumes_deleted = len(v_prune.get("VolumesDeleted") or [])
        space_reclaimed += v_prune.get("SpaceReclaimed", 0)

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
            "volumes_pruned": volumes_deleted,
            "space_reclaimed_bytes": space_reclaimed,
            "space_reclaimed_human": _format_bytes(space_reclaimed),
        }

        return {
            "status": "ok",
            "success": True,
            "action": "clean_docker_cache",
            "message": f"Docker deep cleanup completed. Freed {details['space_reclaimed_human']}.",
            "details": details,
        }
    except Exception as exc:
        err_str = str(exc)
        if "permission denied" in err_str.lower() or "socket" in err_str.lower():
            friendly_err = "Permission denied accessing /var/run/docker.sock. Add user to docker group."
        else:
            friendly_err = f"Docker cleanup failed: {err_str}"
        return {"status": "error", "success": False, "action": "clean_docker_cache", "error": friendly_err}


def _action_clean_system_logs() -> Dict[str, Any]:
    """Clean systemd journal logs older than 3 days and prune rotated logs in /var/log."""
    reclaimed_journal = "0 B"
    journalctl_bin = shutil.which("journalctl")
    journal_msg = ""

    if journalctl_bin:
        try:
            res = subprocess.run(
                [journalctl_bin, "--vacuum-time=3d"],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            if res.returncode == 0:
                journal_msg = res.stdout.strip()
            else:
                journal_msg = res.stderr.strip() or f"exit code {res.returncode}"
        except Exception as exc:
            journal_msg = f"Failed to vacuum journal: {str(exc)}"

    # Clean old rotated compressed archives in /var/log (*.gz, *.1, *.old)
    pruned_files_count = 0
    pruned_bytes = 0
    var_log = "/var/log"

    if os.path.exists(var_log) and os.path.isdir(var_log):
        for root, _, files in os.walk(var_log):
            for file_name in files:
                if (
                    file_name.endswith(".gz")
                    or file_name.endswith(".1")
                    or file_name.endswith(".old")
                ):
                    file_path = os.path.join(root, file_name)
                    try:
                        f_size = os.path.getsize(file_path)
                        os.remove(file_path)
                        pruned_files_count += 1
                        pruned_bytes += f_size
                    except Exception:
                        continue

    return {
        "status": "ok",
        "success": True,
        "action": "clean_system_logs",
        "journalctl_output": journal_msg,
        "pruned_log_files_count": pruned_files_count,
        "pruned_log_bytes": pruned_bytes,
        "pruned_log_human": _format_bytes(pruned_bytes),
        "message": f"System log cleanup complete. Deleted {pruned_files_count} rotated log files ({_format_bytes(pruned_bytes)}).",
    }


def _action_kill_process(target_pid: Optional[str | int]) -> Dict[str, Any]:
    """Safely terminate a stuck or runaway process by PID."""
    if not target_pid:
        return {
            "status": "error",
            "success": False,
            "error": "The 'kill_process' action requires target=PID (e.g. target='12345').",
        }

    try:
        pid = int(target_pid)
    except (ValueError, TypeError):
        return {
            "status": "error",
            "success": False,
            "error": f"Invalid PID '{target_pid}'. PID must be an integer.",
        }

    # Safety: Protect PID 1 and critical core processes
    if pid <= 1:
        return {
            "status": "forbidden",
            "success": False,
            "error": f"Access denied: Terminating PID {pid} (init/systemd) is forbidden.",
        }

    try:
        proc = psutil.Process(pid)
        proc_name = proc.name().lower()

        # Check protected names
        if proc_name in PROTECTED_PROCESS_NAMES or "systemd" in proc_name:
            return {
                "status": "forbidden",
                "success": False,
                "error": f"Access denied: Process '{proc.name()}' (PID {pid}) is critical to system operation.",
            }

        proc.terminate()
        try:
            proc.wait(timeout=3)
            terminated_cleanly = True
        except psutil.TimeoutExpired:
            proc.kill()
            terminated_cleanly = False

        return {
            "status": "ok",
            "success": True,
            "action": "kill_process",
            "pid": pid,
            "process_name": proc_name,
            "force_killed": not terminated_cleanly,
            "message": f"Process '{proc_name}' (PID {pid}) was successfully terminated.",
        }
    except psutil.NoSuchProcess:
        return {
            "status": "error",
            "success": False,
            "error": f"No active process found with PID {pid}.",
        }
    except psutil.AccessDenied as exc:
        return {
            "status": "error",
            "success": False,
            "error": f"Permission denied terminating PID {pid}: {str(exc)}. Root privileges required.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "success": False,
            "error": f"Failed to terminate PID {pid}: {str(exc)}",
        }


def _action_vacuum_journal(target: Optional[str]) -> Dict[str, Any]:
    """Prune systemd journal logs to a specified size threshold."""
    journalctl_bin = shutil.which("journalctl")
    if not journalctl_bin:
        return {
            "status": "unavailable",
            "success": False,
            "error": "journalctl is not installed or not in PATH.",
        }

    size_limit = "200M"
    if target and isinstance(target, str):
        cleaned_target = target.strip()
        if re.match(r"^[0-9]{1,5}[KMGkmg]$", cleaned_target):
            size_limit = cleaned_target

    try:
        res = subprocess.run(
            [journalctl_bin, f"--vacuum-size={size_limit}"],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        return {
            "status": "ok",
            "success": res.returncode == 0,
            "action": "vacuum_systemd_journal",
            "target_size_limit": size_limit,
            "output": res.stdout.strip() or res.stderr.strip(),
            "message": f"Systemd journal vacuumed to {size_limit}.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "success": False,
            "error": f"Failed to vacuum systemd journal: {str(exc)}",
        }


def _action_clean_package_cache() -> Dict[str, Any]:
    """Clean APT package cache and remove orphaned packages."""
    apt_get_bin = shutil.which("apt-get")
    if not apt_get_bin:
        return {
            "status": "unavailable",
            "success": False,
            "error": "apt-get package manager is not available on this system.",
        }

    env = dict(os.environ)
    env["DEBIAN_FRONTEND"] = "noninteractive"

    clean_out = ""
    autoremove_out = ""
    try:
        c_res = subprocess.run(
            [apt_get_bin, "clean"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
            env=env,
        )
        clean_out = c_res.stdout.strip() or c_res.stderr.strip()

        ar_res = subprocess.run(
            [apt_get_bin, "-y", "autoremove"],
            capture_output=True,
            text=True,
            check=False,
            timeout=90,
            env=env,
        )
        autoremove_out = ar_res.stdout.strip() or ar_res.stderr.strip()

        return {
            "status": "ok",
            "success": True,
            "action": "clean_package_cache",
            "clean_output": clean_out or "(APT archives cleaned)",
            "autoremove_output": autoremove_out,
            "message": "APT package cache cleaned and obsolete packages purged.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "success": False,
            "error": f"Error cleaning package cache: {str(exc)}",
        }


def _action_apply_security_updates() -> Dict[str, Any]:
    """Safely apply available operating system security updates non-interactively."""
    apt_get_bin = shutil.which("apt-get")
    if not apt_get_bin:
        return {
            "status": "unavailable",
            "success": False,
            "error": "apt-get is not available on this system.",
        }

    env = dict(os.environ)
    env["DEBIAN_FRONTEND"] = "noninteractive"

    try:
        # Step 1: Refresh package index
        subprocess.run(
            [apt_get_bin, "update"],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
            env=env,
        )

        # Step 2: Run unattended-upgrade if installed or safe non-interactive upgrade
        unattended_bin = shutil.which("unattended-upgrade")
        if unattended_bin:
            up_res = subprocess.run(
                [unattended_bin, "-v"],
                capture_output=True,
                text=True,
                check=False,
                timeout=240,
                env=env,
            )
            output_msg = up_res.stdout.strip() or up_res.stderr.strip()
        else:
            up_res = subprocess.run(
                [
                    apt_get_bin,
                    "-y",
                    "-o",
                    "Dpkg::Options::=--force-confdef",
                    "-o",
                    "Dpkg::Options::=--force-confold",
                    "--only-upgrade",
                    "upgrade",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=240,
                env=env,
            )
            output_msg = up_res.stdout.strip() or up_res.stderr.strip()

        return {
            "status": "ok",
            "success": up_res.returncode == 0,
            "action": "apply_security_updates",
            "output": output_msg[-1000:] if len(output_msg) > 1000 else output_msg,
            "message": "Security updates applied successfully." if up_res.returncode == 0 else "Upgrade process encountered non-fatal notices.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "success": False,
            "error": f"Failed applying security updates: {str(exc)}",
        }


def _action_update_guardian() -> Dict[str, Any]:
    """Self-update VPS-Guardian-MCP from GitHub and reload virtual environment."""
    git_bin = shutil.which("git")
    if not git_bin:
        return {
            "status": "unavailable",
            "success": False,
            "error": "git is not installed or not in PATH.",
        }

    # Identify repo directory
    candidate_dirs = ["/opt/vps-guardian-mcp", os.getcwd()]
    repo_dir = None
    for cdir in candidate_dirs:
        if os.path.isdir(os.path.join(cdir, ".git")):
            repo_dir = cdir
            break

    if not repo_dir:
        return {
            "status": "error",
            "success": False,
            "error": "Could not locate VPS-Guardian-MCP git repository directory.",
        }

    try:
        # Step 1: Record pre-update commit
        pre_commit = "unknown"
        pre_res = subprocess.run(
            [git_bin, "-C", repo_dir, "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if pre_res.returncode == 0:
            pre_commit = pre_res.stdout.strip()

        # Step 2: Git pull origin main
        pull_res = subprocess.run(
            [git_bin, "-C", repo_dir, "pull", "origin", "main"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        pull_out = pull_res.stdout.strip() or pull_res.stderr.strip()
        if pull_res.returncode != 0:
            return {
                "status": "error",
                "success": False,
                "error": f"git pull failed: {pull_out}",
            }

        # Step 3: Record post-update commit
        post_commit = pre_commit
        post_res = subprocess.run(
            [git_bin, "-C", repo_dir, "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
        if post_res.returncode == 0:
            post_commit = post_res.stdout.strip()

        # Step 4: Reinstall package in virtualenv
        pip_candidates = [
            os.path.join(repo_dir, ".venv", "bin", "pip"),
            os.path.join(repo_dir, ".venv", "Scripts", "pip.exe"),
        ]
        pip_bin = None
        for cand in pip_candidates:
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                pip_bin = cand
                break

        pip_out = ""
        if pip_bin:
            pip_res = subprocess.run(
                [pip_bin, "install", "-e", repo_dir],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            pip_out = pip_res.stdout.strip() or pip_res.stderr.strip()

        return {
            "status": "ok",
            "success": True,
            "action": "update_guardian",
            "previous_commit": pre_commit,
            "updated_commit": post_commit,
            "git_output": pull_out,
            "pip_reinstalled": pip_bin is not None,
            "message": (
                f"VPS-Guardian-MCP updated from {pre_commit} to {post_commit}. "
                "New MCP sessions will use the updated codebase."
            ),
        }
    except Exception as exc:
        return {
            "status": "error",
            "success": False,
            "error": f"Update failed: {str(exc)}",
        }


# ============================================================================
# Safe Backup Generation
# ============================================================================

def create_backup(backup_type: str, source_path: str) -> Dict[str, Any]:
    """Create a compressed tar.gz archive of an authorized directory.

    Archives are stored in an isolated, restricted directory (/var/backups/vps-guardian/).
    Uses pure Python tarfile module with no shell invocation.

    Args:
        backup_type: Label for backup ('site', 'config', 'database', etc.).
        source_path: Target directory to back up (must be within authorized paths).

    Returns:
        Structured dictionary with archive location, size, and file count.
    """
    if not isinstance(source_path, str) or not source_path.strip():
        return {"status": "error", "error": "source_path must be a non-empty string."}

    # Verify canonical source path
    try:
        canonical_source = os.path.realpath(os.path.abspath(source_path.strip()))
    except Exception as exc:
        return {"status": "error", "error": f"Invalid source path: {str(exc)}"}

    # Allowed backup source boundaries
    allowed_roots = list(ALLOWED_BACKUP_ROOTS)
    if os.name == "nt":
        allowed_roots.append(os.path.realpath("."))

    is_permitted = False
    for root_path in allowed_roots:
        canonical_root = os.path.realpath(root_path)
        if canonical_source == canonical_root or canonical_source.startswith(canonical_root + os.sep):
            is_permitted = True
            break

    if not is_permitted:
        return {
            "status": "forbidden",
            "error": (
                f"Access denied: Source path '{canonical_source}' is outside allowed backup "
                f"directories: {ALLOWED_BACKUP_ROOTS}"
            ),
        }

    if not os.path.exists(canonical_source):
        return {"status": "error", "error": f"Source path '{canonical_source}' does not exist."}

    # Setup isolated backup directory
    backup_dest_dir = "/var/backups/vps-guardian" if os.name != "nt" else os.path.join(".", "backups")
    try:
        os.makedirs(backup_dest_dir, exist_ok=True)
    except PermissionError:
        backup_dest_dir = os.path.join(tempfile.gettempdir(), "vps-guardian-backups")
        os.makedirs(backup_dest_dir, exist_ok=True)

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", os.path.basename(canonical_source) or "root")
    archive_filename = f"backup_{safe_name}_{timestamp}.tar.gz"
    archive_filepath = os.path.join(backup_dest_dir, archive_filename)

    start_time = time.time()
    file_count = 0

    try:
        with tarfile.open(archive_filepath, "w:gz") as tar:
            if os.path.isdir(canonical_source):
                for root, _, files in os.walk(canonical_source):
                    for f in files:
                        full_f = os.path.join(root, f)
                        arcname = os.path.relpath(full_f, os.path.dirname(canonical_source))
                        tar.add(full_f, arcname=arcname)
                        file_count += 1
            else:
                tar.add(canonical_source, arcname=os.path.basename(canonical_source))
                file_count = 1

        archive_size = os.path.getsize(archive_filepath)
        duration = round(time.time() - start_time, 2)

        return {
            "status": "ok",
            "success": True,
            "backup_type": backup_type,
            "source_path": canonical_source,
            "archive_path": archive_filepath.replace("\\", "/"),
            "archive_size_bytes": archive_size,
            "archive_size_human": _format_bytes(archive_size),
            "files_archived": file_count,
            "duration_seconds": duration,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
    except PermissionError as exc:
        if os.path.exists(archive_filepath):
            try:
                os.remove(archive_filepath)
            except Exception:
                pass
        return {
            "status": "error",
            "error": f"Permission denied creating backup archive: {str(exc)}",
        }
    except Exception as exc:
        logger.error(f"Error creating backup for '{canonical_source}': {exc}", exc_info=True)
        if os.path.exists(archive_filepath):
            try:
                os.remove(archive_filepath)
            except Exception:
                pass
        return {
            "status": "error",
            "error": f"Failed creating backup: {str(exc)}",
        }
