"""Security auditing and intrusion detection module for VPS-Guardian-MCP.

Provides safe diagnostic tools for:
- Auditing recent failed SSH login attempts and brute-force IP sources.
- Checking Fail2ban jail states and active IP bans.
- Analyzing SSH server configuration (/etc/ssh/sshd_config) against security best practices.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vps_guardian.security")


def check_failed_logins(limit: int = 20) -> Dict[str, Any]:
    """Inspect recent failed SSH authentication attempts to identify brute-force attacks.

    Parses /var/log/auth.log or journalctl for sshd units, grouping failed attempts by IP.

    Args:
        limit: Maximum number of recent failed records to retrieve (default: 20, max: 100).

    Returns:
        Structured dictionary with recent failed login events and top offending IP addresses.
    """
    try:
        limit = max(1, min(int(limit), 100))
    except (ValueError, TypeError):
        limit = 20

    raw_lines: List[str] = []

    # 1. Try journalctl for ssh / sshd
    journalctl_bin = shutil.which("journalctl")
    if journalctl_bin:
        try:
            res = subprocess.run(
                [journalctl_bin, "-u", "ssh", "-u", "sshd", "--no-pager", "-n", "200"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if res.returncode == 0 and res.stdout.strip():
                raw_lines = res.stdout.splitlines()
        except Exception:
            pass

    # 2. Fallback to /var/log/auth.log
    if not raw_lines:
        for auth_path in ["/var/log/auth.log", "/var/log/secure"]:
            if os.path.exists(auth_path):
                try:
                    with open(auth_path, "r", encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()
                        raw_lines = [l.strip() for l in lines[-200:]]
                    break
                except Exception:
                    continue

    failed_events: List[Dict[str, str]] = []
    ip_counter: Dict[str, int] = {}

    # Regex patterns for SSH failure messages
    # E.g.: "Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2"
    fail_pattern = re.compile(
        r"(?:Failed password|Invalid user|authentication failure).*?(?:from|rhost=)\s*([0-9a-fA-F.:]+)"
    )
    user_pattern = re.compile(r"(?:for invalid user|for user|for)\s+([a-zA-Z0-9_-]+)")

    for line in reversed(raw_lines):
        if "failed" in line.lower() or "invalid user" in line.lower():
            match = fail_pattern.search(line)
            if match:
                src_ip = match.group(1).strip()
                user_match = user_pattern.search(line)
                target_user = user_match.group(1) if user_match else "unknown"

                ip_counter[src_ip] = ip_counter.get(src_ip, 0) + 1

                if len(failed_events) < limit:
                    failed_events.append({
                        "raw_line": line[-160:],
                        "source_ip": src_ip,
                        "target_user": target_user,
                    })

    # Sort top offending IPs by attempt count
    top_offenders = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:10]
    top_offenders_list = [{"ip": ip, "failed_attempts": count} for ip, count in top_offenders]

    return {
        "status": "ok",
        "total_failed_detected": len(failed_events),
        "unique_attacker_ips": len(ip_counter),
        "top_offender_ips": top_offenders_list,
        "recent_failed_events": failed_events[:limit],
    }


def get_fail2ban_status() -> Dict[str, Any]:
    """Check the operational status of Fail2ban and list currently banned IPs.

    Returns:
        Structured dictionary indicating whether Fail2ban is active, active jails,
        and currently banned IP counts.
    """
    fail2ban_bin = shutil.which("fail2ban-client")
    if not fail2ban_bin:
        return {
            "status": "unavailable",
            "error": "fail2ban-client utility is not installed on this host.",
            "is_running": False,
            "jails": [],
        }

    try:
        proc = subprocess.run(
            [fail2ban_bin, "status"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

        if proc.returncode != 0:
            err_msg = proc.stderr.strip() or proc.stdout.strip()
            if "permission denied" in err_msg.lower() or "socket" in err_msg.lower():
                return {
                    "status": "error",
                    "error": "Permission denied accessing Fail2ban socket. Root privileges are required.",
                    "is_running": False,
                    "jails": [],
                }
            return {
                "status": "error",
                "error": f"Fail2ban is not running or error occurred: {err_msg}",
                "is_running": False,
                "jails": [],
            }

        # Parse active jails from "Jail list: sshd, nginx-http-auth"
        jails_match = re.search(r"Jail list:\s*([^\n]+)", proc.stdout)
        jail_names = [j.strip() for j in jails_match.group(1).split(",")] if jails_match else []

        jail_details: List[Dict[str, Any]] = []
        total_banned = 0

        for jail in jail_names:
            if not jail:
                continue
            j_proc = subprocess.run(
                [fail2ban_bin, "status", jail],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if j_proc.returncode == 0:
                out = j_proc.stdout
                curr_banned_m = re.search(r"Currently banned:\s*(\d+)", out)
                total_banned_m = re.search(r"Total banned:\s*(\d+)", out)
                banned_ips_m = re.search(r"Banned IP list:\s*([^\n]*)", out)

                curr_banned = int(curr_banned_m.group(1)) if curr_banned_m else 0
                banned_ips = banned_ips_m.group(1).split() if banned_ips_m and banned_ips_m.group(1).strip() else []
                total_banned += curr_banned

                jail_details.append({
                    "jail": jail,
                    "currently_banned": curr_banned,
                    "total_banned_historical": int(total_banned_m.group(1)) if total_banned_m else 0,
                    "banned_ips": banned_ips,
                })

        return {
            "status": "ok",
            "is_running": True,
            "total_active_jails": len(jail_names),
            "total_currently_banned_ips": total_banned,
            "jails": jail_details,
        }
    except Exception as exc:
        logger.error(f"Error querying Fail2ban: {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Failed checking Fail2ban status: {str(exc)}",
            "is_running": False,
            "jails": [],
        }


def audit_ssh_config() -> Dict[str, Any]:
    """Audit the SSH daemon configuration (/etc/ssh/sshd_config) against security best practices.

    Checks:
    - Root login policy (PermitRootLogin)
    - Password authentication (PasswordAuthentication)
    - Non-standard port usage (Port)
    - Public key authentication (PubkeyAuthentication)
    - Empty passwords disallowed (PermitEmptyPasswords)

    Returns:
        Structured dictionary with detected settings, security recommendations, and safety score.
    """
    config_paths = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d"]
    primary_config = "/etc/ssh/sshd_config"

    if not os.path.exists(primary_config):
        return {
            "status": "unavailable",
            "error": f"SSH configuration file not found at '{primary_config}'.",
        }

    settings: Dict[str, str] = {
        "Port": "22",
        "PermitRootLogin": "prohibit-password",
        "PasswordAuthentication": "yes",
        "PubkeyAuthentication": "yes",
        "PermitEmptyPasswords": "no",
        "X11Forwarding": "no",
    }

    try:
        with open(primary_config, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        for line in lines:
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#"):
                continue
            parts = cleaned.split(None, 1)
            if len(parts) == 2:
                key, val = parts[0], parts[1].strip()
                for known_key in settings:
                    if key.lower() == known_key.lower():
                        settings[known_key] = val

        # Evaluate recommendations and calculate score
        recommendations: List[str] = []
        score = 100

        # 1. PasswordAuthentication
        if settings["PasswordAuthentication"].lower() in ("yes", "true"):
            score -= 30
            recommendations.append(
                "Disable password authentication ('PasswordAuthentication no') in favor of SSH key pairs to prevent brute-force attacks."
            )

        # 2. PermitRootLogin
        if settings["PermitRootLogin"].lower() in ("yes", "true"):
            score -= 30
            recommendations.append(
                "Disable direct root login ('PermitRootLogin prohibit-password' or 'PermitRootLogin no')."
            )

        # 3. PermitEmptyPasswords
        if settings["PermitEmptyPasswords"].lower() in ("yes", "true"):
            score -= 40
            recommendations.append(
                "CRITICAL: Set 'PermitEmptyPasswords no' to prevent accounts without passwords from logging in."
            )

        # 4. Port usage
        if settings["Port"] == "22":
            score -= 5
            recommendations.append(
                "Consider changing the default SSH port from 22 to reduce automated scanning noise."
            )

        return {
            "status": "ok",
            "config_file": primary_config,
            "security_score": max(0, score),
            "current_settings": settings,
            "recommendations": recommendations,
            "is_secure": score >= 80,
        }
    except PermissionError as exc:
        return {
            "status": "error",
            "error": f"Permission denied reading '{primary_config}': {str(exc)}",
        }
    except Exception as exc:
        logger.error(f"Error auditing sshd_config: {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Failed auditing SSH config: {str(exc)}",
        }
