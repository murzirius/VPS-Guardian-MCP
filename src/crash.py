"""Kernel crash and Out-Of-Memory (OOM) incident diagnostics module for VPS-Guardian-MCP.

Provides safe kernel journal parsing to inspect:
- Linux Kernel Out-Of-Memory (OOM) Killer events (killed processes, PIDs, consumed RSS memory).
- Kernel hardware, storage I/O, filesystem, and segfault error messages.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vps_guardian.crash")

OOM_KILLED_REGEX = re.compile(
    r"(?:Out of memory: Kill process|Killed process|oom-killer:.*task=)\s*(\d+)?\s*\(?([a-zA-Z0-9_.-]+)\)?.*?(?:total-vm:(\d+)kB,\s*anon-rss:(\d+)kB)?",
    re.IGNORECASE,
)

SEGFAULT_REGEX = re.compile(
    r"([a-zA-Z0-9_.-]+)\[(\d+)\]:\s*segfault at\s*([0-9a-fA-F]+)\s*ip\s*([0-9a-fA-F]+)\s*sp\s*([0-9a-fA-F]+)\s*error\s*(\d+)",
    re.IGNORECASE,
)


def _format_kb(kb_val: int | float) -> str:
    """Format kilobytes into human-readable string (KB, MB, GB)."""
    val = float(kb_val)
    for unit in ["KB", "MB", "GB"]:
        if abs(val) < 1024.0 or unit == "GB":
            return f"{val:.2f} {unit}"
        val /= 1024.0
    return f"{val:.2f} GB"


def check_oom_events(limit: int = 10) -> Dict[str, Any]:
    """Inspect kernel logs for Linux Out-Of-Memory (OOM) Killer invocations.

    Identifies which processes were terminated by the kernel due to memory exhaustion,
    including timestamps, process names, PIDs, and RSS memory consumption.

    Args:
        limit: Maximum number of recent OOM events to return (1 to 50, default 10).

    Returns:
        Structured dictionary with detected OOM incidents and diagnostic summary.
    """
    try:
        limit = max(1, min(int(limit), 50))
    except (ValueError, TypeError):
        limit = 10

    journalctl_bin = shutil.which("journalctl")
    dmesg_bin = shutil.which("dmesg")

    log_lines: List[str] = []

    # Priority 1: journalctl kernel log
    if journalctl_bin:
        try:
            res = subprocess.run(
                [journalctl_bin, "-k", "--no-pager", "-n", "3000"],
                capture_output=True,
                text=True,
                check=False,
                timeout=12,
            )
            if res.returncode == 0 and res.stdout.strip():
                log_lines = res.stdout.splitlines()
        except Exception as exc:
            logger.debug(f"journalctl -k failed: {exc}")

    # Priority 2: dmesg fallback
    if not log_lines and dmesg_bin:
        try:
            res = subprocess.run(
                [dmesg_bin, "-T"],
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
            if res.returncode == 0 and res.stdout.strip():
                log_lines = res.stdout.splitlines()
        except Exception as exc:
            logger.debug(f"dmesg -T failed: {exc}")

    if not log_lines:
        return {
            "status": "ok",
            "total_oom_events": 0,
            "events": [],
            "summary": "No kernel logs available or no OOM events recorded.",
        }

    oom_events: List[Dict[str, Any]] = []

    # Parse lines backwards (newest first)
    for raw_line in reversed(log_lines):
        line = raw_line.strip()
        if not line:
            continue

        is_oom_line = any(
            pattern in line.lower()
            for pattern in ["out of memory:", "oom-killer", "invoked oom-killer", "killed process"]
        )

        if not is_oom_line:
            continue

        match = OOM_KILLED_REGEX.search(line)
        killed_proc = None
        pid = None
        rss_kb = None

        if match:
            g1, g2, g3, g4 = match.groups()
            pid = g1 if g1 and g1.isdigit() else None
            killed_proc = g2 or "unknown"
            if g4 and g4.isdigit():
                rss_kb = int(g4)

        event = {
            "raw_log": line,
            "killed_process": killed_proc,
            "pid": int(pid) if pid else None,
            "rss_consumed": _format_kb(rss_kb) if rss_kb else None,
        }
        oom_events.append(event)
        if len(oom_events) >= limit:
            break

    summary = (
        f"Detected {len(oom_events)} Out-Of-Memory (OOM) killer incident(s) in kernel log."
        if oom_events
        else "No Out-Of-Memory (OOM) killer events detected in kernel history."
    )

    return {
        "status": "ok",
        "total_oom_events": len(oom_events),
        "events": oom_events,
        "has_oom_kills": len(oom_events) > 0,
        "summary": summary,
    }


def check_kernel_errors(limit: int = 20) -> Dict[str, Any]:
    """Audit kernel error logs for storage I/O failures, filesystem degradation, or segfaults.

    Args:
        limit: Maximum number of error entries to retrieve (1 to 50, default 20).

    Returns:
        Structured dictionary with categorized kernel errors and severity summary.
    """
    try:
        limit = max(1, min(int(limit), 50))
    except (ValueError, TypeError):
        limit = 20

    journalctl_bin = shutil.which("journalctl")
    dmesg_bin = shutil.which("dmesg")

    error_lines: List[str] = []

    # Try journalctl with priority err (levels 0-3: emerg, alert, crit, err)
    if journalctl_bin:
        try:
            res = subprocess.run(
                [journalctl_bin, "-k", "-p", "err..emerg", "--no-pager", "-n", str(limit * 2)],
                capture_output=True,
                text=True,
                check=False,
                timeout=12,
            )
            if res.returncode == 0 and res.stdout.strip():
                error_lines = res.stdout.splitlines()
        except Exception as exc:
            logger.debug(f"journalctl -p err failed: {exc}")

    # Fallback to dmesg with level err,crit,alert,emerg
    if not error_lines and dmesg_bin:
        try:
            res = subprocess.run(
                [dmesg_bin, "--level=err,crit,alert,emerg", "-T"],
                capture_output=True,
                text=True,
                check=False,
                timeout=8,
            )
            if res.returncode == 0 and res.stdout.strip():
                error_lines = res.stdout.splitlines()
        except Exception as exc:
            logger.debug(f"dmesg --level failed: {exc}")

    parsed_errors: List[Dict[str, Any]] = []

    for raw_line in reversed(error_lines):
        line = raw_line.strip()
        if not line:
            continue

        category = "general_kernel_error"
        line_lower = line.lower()
        if any(w in line_lower for w in ["ext4-fs", "btrfs", "xfs", "filesystem"]):
            category = "filesystem_warning"
        elif any(w in line_lower for w in ["i/o error", "buffer i/o", "blk_update_request", "ata", "nvme"]):
            category = "storage_io_error"
        elif "segfault" in line_lower:
            category = "application_segfault"
        elif "oom" in line_lower:
            category = "out_of_memory"

        # Check for segfault details
        seg_match = SEGFAULT_REGEX.search(line)
        details: Dict[str, Any] = {}
        if seg_match:
            pname, pid, addr, ip, sp, err = seg_match.groups()
            details = {
                "process": pname,
                "pid": int(pid),
                "fault_address": addr,
                "error_code": err,
            }

        parsed_errors.append(
            {
                "category": category,
                "raw_message": line,
                "details": details if details else None,
            }
        )
        if len(parsed_errors) >= limit:
            break

    critical_count = sum(1 for e in parsed_errors if e["category"] in ["filesystem_warning", "storage_io_error"])

    return {
        "status": "ok",
        "total_errors": len(parsed_errors),
        "critical_hardware_errors_count": critical_count,
        "errors": parsed_errors,
        "summary": (
            f"Retrieved {len(parsed_errors)} recent kernel error messages "
            f"({critical_count} critical storage/filesystem errors)."
            if parsed_errors
            else "Clean kernel status: No recent hardware or filesystem errors reported."
        ),
    }
