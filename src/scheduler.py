"""Scheduler and background task inspection module for VPS-Guardian-MCP.

Provides safe auditing of recurring scheduled jobs:
- System and user Cron tables (/etc/crontab, /etc/cron.d/, /etc/cron.*, user crontabs).
- Systemd active and inactive timers (systemctl list-timers).
"""

from __future__ import annotations

import glob
import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vps_guardian.scheduler")


def _explain_cron_schedule(min_val: str, hour_val: str, dom: str, mon: str, dow: str) -> str:
    """Provide a friendly human-readable interpretation of standard 5-part cron schedules."""
    if min_val == "*" and hour_val == "*" and dom == "*" and mon == "*" and dow == "*":
        return "Every minute"
    if min_val.startswith("*/") and hour_val == "*" and dom == "*" and mon == "*" and dow == "*":
        step = min_val.replace("*/", "")
        return f"Every {step} minutes"
    if min_val == "0" and hour_val == "*" and dom == "*" and mon == "*" and dow == "*":
        return "Every hour on the hour"
    if min_val.isdigit() and hour_val == "*" and dom == "*" and mon == "*" and dow == "*":
        return f"Hourly at minute {min_val}"
    if min_val.isdigit() and hour_val.isdigit() and dom == "*" and mon == "*" and dow == "*":
        return f"Every day at {int(hour_val):02d}:{int(min_val):02d}"
    if min_val.isdigit() and hour_val.isdigit() and dom == "*" and mon == "*" and dow in ["0", "7", "sun", "Sun"]:
        return f"Every Sunday at {int(hour_val):02d}:{int(min_val):02d}"
    if min_val.isdigit() and hour_val.isdigit() and dom == "1" and mon == "*" and dow == "*":
        return f"1st day of every month at {int(hour_val):02d}:{int(min_val):02d}"
    return f"Custom ({min_val} {hour_val} {dom} {mon} {dow})"


def list_cron_jobs() -> Dict[str, Any]:
    """Discover all scheduled cron jobs on the Linux system.

    Scans:
    - /etc/crontab (system crontab)
    - /etc/cron.d/ (modular packages and services crontabs)
    - /etc/cron.{hourly,daily,weekly,monthly}/ (periodic scripts)
    - /var/spool/cron/crontabs/ (user crontabs)

    Returns:
        Structured dictionary containing cron entries organized by source,
        with user, timing schedule, command, and human explanation.
    """
    cron_entries: List[Dict[str, Any]] = []

    # 1. Parse /etc/crontab
    if os.path.exists("/etc/crontab"):
        try:
            with open("/etc/crontab", "r", encoding="utf-8", errors="replace") as f:
                for line_idx, raw_line in enumerate(f, start=1):
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 7 and parts[0] not in ["SHELL", "PATH", "MAILTO", "HOME"]:
                        min_v, hour_v, dom, mon, dow, user = parts[:6]
                        cmd = " ".join(parts[6:])
                        cron_entries.append(
                            {
                                "source": "/etc/crontab",
                                "line_number": line_idx,
                                "user": user,
                                "schedule": f"{min_v} {hour_v} {dom} {mon} {dow}",
                                "explanation": _explain_cron_schedule(min_v, hour_v, dom, mon, dow),
                                "command": cmd,
                                "type": "system_crontab",
                            }
                        )
        except Exception as exc:
            logger.warning(f"Error reading /etc/crontab: {exc}")

    # 2. Parse /etc/cron.d/*
    if os.path.isdir("/etc/cron.d"):
        for filepath in sorted(glob.glob("/etc/cron.d/*")):
            if os.path.isfile(filepath):
                try:
                    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                        for line_idx, raw_line in enumerate(f, start=1):
                            line = raw_line.strip()
                            if not line or line.startswith("#"):
                                continue
                            parts = line.split()
                            if len(parts) >= 7 and parts[0] not in ["SHELL", "PATH", "MAILTO", "HOME"]:
                                min_v, hour_v, dom, mon, dow, user = parts[:6]
                                cmd = " ".join(parts[6:])
                                cron_entries.append(
                                    {
                                        "source": filepath,
                                        "line_number": line_idx,
                                        "user": user,
                                        "schedule": f"{min_v} {hour_v} {dom} {mon} {dow}",
                                        "explanation": _explain_cron_schedule(min_v, hour_v, dom, mon, dow),
                                        "command": cmd,
                                        "type": "cron.d",
                                    }
                                )
                except Exception as exc:
                    logger.warning(f"Error reading {filepath}: {exc}")

    # 3. Parse /etc/cron.{hourly,daily,weekly,monthly}
    for interval in ["hourly", "daily", "weekly", "monthly"]:
        dir_path = f"/etc/cron.{interval}"
        if os.path.isdir(dir_path):
            for script_path in sorted(glob.glob(os.path.join(dir_path, "*"))):
                if os.path.isfile(script_path):
                    script_name = os.path.basename(script_path)
                    cron_entries.append(
                        {
                            "source": dir_path,
                            "line_number": None,
                            "user": "root",
                            "schedule": f"@{interval}",
                            "explanation": f"Runs on an {interval} interval",
                            "command": script_path,
                            "type": f"cron.{interval}",
                        }
                    )

    # 4. Parse user crontabs in /var/spool/cron/crontabs
    user_crontab_dir = "/var/spool/cron/crontabs"
    if os.path.isdir(user_crontab_dir):
        for user_crontab in sorted(glob.glob(os.path.join(user_crontab_dir, "*"))):
            if os.path.isfile(user_crontab):
                user_name = os.path.basename(user_crontab)
                try:
                    with open(user_crontab, "r", encoding="utf-8", errors="replace") as f:
                        for line_idx, raw_line in enumerate(f, start=1):
                            line = raw_line.strip()
                            if not line or line.startswith("#"):
                                continue
                            parts = line.split()
                            if len(parts) >= 6 and parts[0] not in ["SHELL", "PATH", "MAILTO", "HOME"]:
                                min_v, hour_v, dom, mon, dow = parts[:5]
                                cmd = " ".join(parts[5:])
                                cron_entries.append(
                                    {
                                        "source": user_crontab,
                                        "line_number": line_idx,
                                        "user": user_name,
                                        "schedule": f"{min_v} {hour_v} {dom} {mon} {dow}",
                                        "explanation": _explain_cron_schedule(min_v, hour_v, dom, mon, dow),
                                        "command": cmd,
                                        "type": "user_crontab",
                                    }
                                )
                except Exception as exc:
                    logger.warning(f"Error reading user crontab {user_crontab}: {exc}")

    return {
        "status": "ok",
        "total_cron_jobs": len(cron_entries),
        "cron_jobs": cron_entries,
        "summary": f"Discovered {len(cron_entries)} scheduled cron job entries across system and user crontabs.",
    }


def list_systemd_timers() -> Dict[str, Any]:
    """Audit active and pending systemd timers using 'systemctl list-timers'.

    Returns:
        Structured dictionary with timer units, trigger countdowns, last run timestamps,
        and target services activated by each timer.
    """
    systemctl_bin = shutil.which("systemctl")
    if not systemctl_bin:
        return {
            "status": "unavailable",
            "error": "systemctl utility is not installed or not in PATH.",
            "timers": [],
        }

    try:
        res = subprocess.run(
            [systemctl_bin, "list-timers", "--all", "--no-pager"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except Exception as exc:
        return {
            "status": "error",
            "error": f"Failed executing systemctl list-timers: {str(exc)}",
            "timers": [],
        }

    if res.returncode != 0:
        return {
            "status": "error",
            "error": res.stderr.strip() or f"systemctl exited with code {res.returncode}",
            "timers": [],
        }

    lines = [line.rstrip() for line in res.stdout.splitlines() if line.strip()]
    if not lines:
        return {
            "status": "ok",
            "total_timers": 0,
            "timers": [],
            "summary": "No systemd timers found.",
        }

    # Find the header line
    header_idx = -1
    for idx, line in enumerate(lines):
        if "NEXT" in line and "UNIT" in line and "ACTIVATES" in line:
            header_idx = idx
            break

    if header_idx == -1:
        # Fallback: return raw output lines
        return {
            "status": "ok",
            "total_timers": len(lines),
            "raw_output": lines,
            "summary": "Retrieved systemd timers output (raw).",
        }

    timer_entries: List[Dict[str, Any]] = []
    # Column positions from header
    for line in lines[header_idx + 1 :]:
        if not line or line.startswith("—") or line.startswith("-") or "timers listed" in line:
            continue

        # Standard systemctl list-timers format:
        # NEXT                         LEFT          LAST                         PASSED       UNIT                         ACTIVATES
        # Tue 2026-09-08 18:00:00 UTC  1h 15min left Tue 2026-09-08 17:00:00 UTC  44min ago    sysstat-collect.timer        sysstat-collect.service
        # Split tokens from the right: ACTIVATES, UNIT
        parts = line.split()
        if len(parts) >= 2:
            activates = parts[-1]
            unit = parts[-2]
            timer_entries.append(
                {
                    "timer_unit": unit,
                    "activates_service": activates,
                    "raw_details": line,
                }
            )

    return {
        "status": "ok",
        "total_timers": len(timer_entries),
        "timers": timer_entries,
        "summary": f"Found {len(timer_entries)} systemd timers active on the system.",
    }
