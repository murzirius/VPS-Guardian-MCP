"""Deep process profiling and kernel limits module for VPS-Guardian-MCP.

Provides comprehensive, low-overhead tools for:
- Detailed single-process inspection (threads, memory maps, open file descriptors, sockets, I/O counters).
- Zombie/defunct process detection and parent process diagnosis.
- Linux system-wide and user limits auditing (file descriptors, process limits, virtual memory, network backlogs).
"""

from __future__ import annotations

import datetime
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

import psutil

logger = logging.getLogger("vps_guardian.proc_deep")

# Pattern to identify sensitive environment variables for masking
SENSITIVE_ENV_PATTERN = re.compile(
    r"(pass(word)?|secret|token|key|cred(ential)?|auth|api_key|private|cert)",
    re.IGNORECASE,
)


def _format_bytes(bytes_value: int | float) -> str:
    """Format bytes into a human-readable string (B, KB, MB, GB, TB)."""
    val = float(bytes_value)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(val) < 1024.0 or unit == "TB":
            return f"{val:.2f} {unit}"
        val /= 1024.0
    return f"{val:.2f} TB"


def _read_proc_sys(path: str) -> Optional[str]:
    """Safely read a /proc/sys kernel parameter without spawning subshells."""
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read().strip()
    except Exception as exc:
        logger.debug(f"Could not read {path}: {exc}")
    return None


def get_process_details(pid: int) -> Dict[str, Any]:
    """Retrieve in-depth performance, security, and resource diagnostics for a specific PID.

    Args:
        pid: The target process ID to inspect (must be > 0).

    Returns:
        Structured dictionary detailing process hierarchy, threads, memory, open files,
        active network sockets, I/O statistics, and sanitized environment.
    """
    try:
        target_pid = int(pid)
        if target_pid <= 0:
            return {"status": "error", "error": f"Invalid PID {pid}. PID must be a positive integer."}
    except (ValueError, TypeError):
        return {"status": "error", "error": f"Invalid PID '{pid}'. Expected an integer."}

    if not psutil.pid_exists(target_pid):
        return {
            "status": "not_found",
            "error": f"Process with PID {target_pid} does not exist or has already terminated.",
            "pid": target_pid,
        }

    try:
        proc = psutil.Process(target_pid)
    except psutil.NoSuchProcess:
        return {
            "status": "not_found",
            "error": f"Process with PID {target_pid} does not exist or terminated.",
            "pid": target_pid,
        }
    except psutil.AccessDenied as exc:
        return {
            "status": "access_denied",
            "error": f"Access denied inspecting PID {target_pid}: {exc}",
            "pid": target_pid,
        }

    # Gather data with defensive exception handling per attribute
    try:
        name = proc.name()
    except Exception:
        name = "unknown"

    try:
        status = proc.status()
    except Exception:
        status = "unknown"

    try:
        cmdline = proc.cmdline()
    except Exception:
        cmdline = []

    try:
        exe = proc.exe()
    except Exception:
        exe = ""

    try:
        cwd = proc.cwd()
    except Exception:
        cwd = ""

    try:
        username = proc.username()
    except Exception:
        username = "unknown"

    try:
        uids = proc.uids()._asdict() if hasattr(proc.uids(), "_asdict") else {"real": getattr(proc.uids(), "real", None)}
    except Exception:
        uids = {}

    # Hierarchy: Parent & Children
    ppid = None
    parent_name = "none"
    try:
        ppid = proc.ppid()
        parent = proc.parent()
        if parent:
            parent_name = parent.name()
    except Exception:
        pass

    children_info: List[Dict[str, Any]] = []
    try:
        for child in proc.children(recursive=False):
            try:
                children_info.append({"pid": child.pid, "name": child.name(), "status": child.status()})
            except Exception:
                continue
    except Exception:
        pass

    # Timing
    runtime_seconds = 0
    create_time_iso = ""
    try:
        create_time = proc.create_time()
        runtime_seconds = max(0, int(time.time() - create_time))
        create_time_iso = datetime.datetime.fromtimestamp(create_time, datetime.timezone.utc).isoformat()
    except Exception:
        pass

    # CPU & Threads
    cpu_percent = 0.0
    try:
        cpu_percent = proc.cpu_percent(interval=None)
    except Exception:
        pass

    cpu_times_dict = {}
    try:
        c_times = proc.cpu_times()
        cpu_times_dict = {
            "user_seconds": round(c_times.user, 3),
            "system_seconds": round(c_times.system, 3),
        }
    except Exception:
        pass

    num_threads = 1
    try:
        num_threads = proc.num_threads()
    except Exception:
        pass

    # Memory
    memory_percent = 0.0
    mem_info_dict = {}
    try:
        memory_percent = round(proc.memory_percent(), 2)
        m_info = proc.memory_info()
        mem_info_dict = {
            "rss": _format_bytes(m_info.rss),
            "rss_bytes": m_info.rss,
            "vms": _format_bytes(m_info.vms),
            "vms_bytes": m_info.vms,
        }
        # Shared memory if available on Linux
        if hasattr(m_info, "shared"):
            mem_info_dict["shared"] = _format_bytes(m_info.shared)
        if hasattr(m_info, "data"):
            mem_info_dict["data"] = _format_bytes(m_info.data)
    except Exception:
        pass

    # File Descriptors
    num_fds = None
    if hasattr(proc, "num_fds"):
        try:
            num_fds = proc.num_fds()
        except Exception:
            num_fds = None

    open_files_sample: List[str] = []
    try:
        open_files = proc.open_files()
        for of in open_files[:25]:
            open_files_sample.append(of.path)
    except Exception:
        pass

    # Sockets & Network Connections
    connections_list: List[Dict[str, Any]] = []
    try:
        conns = proc.net_connections(kind="all")
        for conn in conns[:25]:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            connections_list.append({
                "fd": conn.fd,
                "family": str(conn.family).split(".")[-1] if hasattr(conn.family, "name") else str(conn.family),
                "type": str(conn.type).split(".")[-1] if hasattr(conn.type, "name") else str(conn.type),
                "local_address": laddr,
                "remote_address": raddr,
                "status": conn.status,
            })
    except Exception:
        pass

    # I/O Counters
    io_dict = {}
    if hasattr(proc, "io_counters"):
        try:
            io = proc.io_counters()
            io_dict = {
                "read_bytes": _format_bytes(io.read_bytes),
                "write_bytes": _format_bytes(io.write_bytes),
                "read_count": io.read_count,
                "write_count": io.write_count,
            }
        except Exception:
            pass

    # Sanitized Environment Variables (capped at 40 keys, values masked if sensitive)
    sanitized_environ: Dict[str, str] = {}
    try:
        environ = proc.environ()
        for k, v in list(environ.items())[:40]:
            if SENSITIVE_ENV_PATTERN.search(k):
                sanitized_environ[k] = "***MASKED***"
            elif len(v) > 120:
                sanitized_environ[k] = v[:117] + "..."
            else:
                sanitized_environ[k] = v
    except Exception:
        pass

    days, remainder = divmod(runtime_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    runtime_human = f"{days}d {hours}h {minutes}m {seconds}s" if days > 0 else f"{hours}h {minutes}m {seconds}s"

    return {
        "status": "ok",
        "pid": target_pid,
        "name": name,
        "status_description": status,
        "exe": exe,
        "cwd": cwd,
        "cmdline": " ".join(cmdline) if cmdline else name,
        "user": username,
        "uids": uids,
        "hierarchy": {
            "parent_pid": ppid,
            "parent_name": parent_name,
            "children_count": len(children_info),
            "children": children_info,
        },
        "timing": {
            "create_time": create_time_iso,
            "runtime_seconds": runtime_seconds,
            "runtime_human": runtime_human,
        },
        "cpu": {
            "cpu_percent": cpu_percent,
            "cpu_times": cpu_times_dict,
            "num_threads": num_threads,
        },
        "memory": {
            "memory_percent": memory_percent,
            "details": mem_info_dict,
        },
        "file_descriptors": {
            "open_fds_count": num_fds,
            "open_files_sample": open_files_sample,
        },
        "network_connections": {
            "total_open_sockets": len(connections_list),
            "sockets": connections_list,
        },
        "io_counters": io_dict,
        "environment_variables": sanitized_environ,
    }


def detect_zombie_processes() -> Dict[str, Any]:
    """Scan the system for defunct/zombie processes and identify non-reaping parent processes.

    Returns:
        Structured report detailing any detected zombie processes, their parent PIDs,
        parent command lines, and suggested remediation steps.
    """
    zombies: List[Dict[str, Any]] = []

    try:
        for proc in psutil.process_iter(["pid", "ppid", "name", "status", "create_time"]):
            try:
                # Check status defensively
                status = proc.info.get("status") or (proc.status() if hasattr(proc, "status") else None)
                is_zombie = (
                    status == psutil.STATUS_ZOMBIE
                    or status == "zombie"
                    or (isinstance(status, str) and "zombie" in status.lower())
                )
                if not is_zombie:
                    continue

                z_pid = proc.info["pid"]
                z_ppid = proc.info.get("ppid") or proc.ppid()
                z_name = proc.info.get("name") or "defunct"

                # Parent resolution
                parent_name = "unknown"
                parent_status = "unknown"
                parent_cmdline = ""
                try:
                    if z_ppid and psutil.pid_exists(z_ppid):
                        parent_proc = psutil.Process(z_ppid)
                        parent_name = parent_proc.name()
                        parent_status = parent_proc.status()
                        parent_cmdline = " ".join(parent_proc.cmdline()[:5])
                except Exception:
                    pass

                zombies.append({
                    "zombie_pid": z_pid,
                    "zombie_name": z_name,
                    "parent_pid": z_ppid,
                    "parent_name": parent_name,
                    "parent_status": parent_status,
                    "parent_cmdline": parent_cmdline,
                    "diagnosis": (
                        f"Parent process '{parent_name}' (PID: {z_ppid}) failed to reap child process "
                        f"'{z_name}' (PID: {z_pid}) via wait()/waitpid(). If the parent is stuck, "
                        f"restarting the parent service will cause init/systemd (PID 1) to reap the zombie."
                    ),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as exc:
        logger.error(f"Error scanning for zombie processes: {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Failed scanning process table: {str(exc)}",
            "zombie_count": 0,
            "zombies": [],
        }

    return {
        "status": "ok",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "zombie_count": len(zombies),
        "status_summary": "Clean (No zombie processes found)" if not zombies else f"Alert: {len(zombies)} zombie process(es) detected!",
        "zombies": zombies,
    }


def check_system_limits() -> Dict[str, Any]:
    """Audit system-wide and per-process limits (file descriptors, max PIDs, virtual memory, network backlogs).

    Returns:
        Structured dictionary comparing current allocations against maximum kernel thresholds,
        flagging any limits that exceed safe operating margins (>80%).
    """
    report: Dict[str, Any] = {
        "status": "ok",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "warnings": [],
        "file_descriptors": {},
        "processes_and_threads": {},
        "virtual_memory": {},
        "network_backlog": {},
    }

    warnings: List[str] = []

    # 1. File Descriptors
    file_nr_raw = _read_proc_sys("/proc/sys/fs/file-nr")
    file_max_raw = _read_proc_sys("/proc/sys/fs/file-max")

    if file_nr_raw:
        parts = file_nr_raw.split()
        if len(parts) >= 3:
            try:
                allocated = int(parts[0])
                unused = int(parts[1])
                max_fds = int(parts[2])
                active_fds = max(0, allocated - unused)
                usage_pct = round((active_fds / max_fds) * 100, 2) if max_fds > 0 else 0.0

                report["file_descriptors"] = {
                    "system_allocated": allocated,
                    "system_active": active_fds,
                    "system_max": max_fds,
                    "usage_percent": usage_pct,
                }
                if usage_pct > 80.0:
                    warnings.append(f"System-wide file descriptor usage is high: {usage_pct}% ({active_fds}/{max_fds})")
            except ValueError:
                pass
    elif file_max_raw:
        try:
            report["file_descriptors"]["system_max"] = int(file_max_raw)
        except ValueError:
            pass

    # Process NOFILE soft/hard limits
    try:
        import resource
        soft_nofile, hard_nofile = resource.getrlimit(resource.RLIMIT_NOFILE)
        report["file_descriptors"]["process_soft_limit"] = soft_nofile
        report["file_descriptors"]["process_hard_limit"] = hard_nofile
    except Exception:
        pass

    # 2. Process & Thread Limits
    pid_max_raw = _read_proc_sys("/proc/sys/kernel/pid_max")
    current_pids_count = len(psutil.pids())

    report["processes_and_threads"] = {
        "current_process_count": current_pids_count,
    }

    if pid_max_raw:
        try:
            pid_max = int(pid_max_raw)
            pid_usage_pct = round((current_pids_count / pid_max) * 100, 2) if pid_max > 0 else 0.0
            report["processes_and_threads"]["kernel_pid_max"] = pid_max
            report["processes_and_threads"]["usage_percent"] = pid_usage_pct
            if pid_usage_pct > 80.0:
                warnings.append(f"Process table usage is high: {pid_usage_pct}% ({current_pids_count}/{pid_max})")
        except ValueError:
            pass

    try:
        import resource
        soft_nproc, hard_nproc = resource.getrlimit(resource.RLIMIT_NPROC)
        report["processes_and_threads"]["process_max_threads_soft"] = soft_nproc
        report["processes_and_threads"]["process_max_threads_hard"] = hard_nproc
    except Exception:
        pass

    # 3. Virtual Memory & Kernel Parameters
    vm_swappiness = _read_proc_sys("/proc/sys/vm/swappiness")
    vm_vfs_cache_pressure = _read_proc_sys("/proc/sys/vm/vfs_cache_pressure")
    vm_overcommit = _read_proc_sys("/proc/sys/vm/overcommit_memory")
    vm_max_map_count = _read_proc_sys("/proc/sys/vm/max_map_count")

    report["virtual_memory"] = {
        "swappiness": int(vm_swappiness) if vm_swappiness and vm_swappiness.isdigit() else vm_swappiness,
        "vfs_cache_pressure": int(vm_vfs_cache_pressure) if vm_vfs_cache_pressure and vm_vfs_cache_pressure.isdigit() else vm_vfs_cache_pressure,
        "overcommit_memory": int(vm_overcommit) if vm_overcommit and vm_overcommit.isdigit() else vm_overcommit,
        "max_map_count": int(vm_max_map_count) if vm_max_map_count and vm_max_map_count.isdigit() else vm_max_map_count,
    }

    # 4. Network Socket Backlogs
    somaxconn = _read_proc_sys("/proc/sys/net/core/somaxconn")
    syn_backlog = _read_proc_sys("/proc/sys/net/ipv4/tcp_max_syn_backlog")

    report["network_backlog"] = {
        "somaxconn": int(somaxconn) if somaxconn and somaxconn.isdigit() else somaxconn,
        "tcp_max_syn_backlog": int(syn_backlog) if syn_backlog and syn_backlog.isdigit() else syn_backlog,
    }

    report["warnings"] = warnings
    report["healthy"] = len(warnings) == 0

    return report
