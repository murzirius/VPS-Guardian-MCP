"""Network security and port diagnostics module for VPS-Guardian-MCP.

Provides safe inspection tools for:
- Discovering all listening network ports (TCP/UDP, IPv4/IPv6) and identifying bound processes.
- Querying UFW (Uncomplicated Firewall) rules and operational status.
"""

from __future__ import annotations

import logging
import re
import shutil
import socket
import subprocess
from typing import Any, Dict, List, Optional

import psutil

logger = logging.getLogger("vps_guardian.network")


def get_open_ports() -> Dict[str, Any]:
    """Retrieve all open listening network ports (TCP and UDP) along with their processes.

    Inspects both IPv4 and IPv6 sockets using psutil and falls back to system `ss`
    utility if required.

    Returns:
        Structured dictionary containing a list of listening ports, protocols,
        binding addresses, process PIDs, and process names.
    """
    listening_ports: List[Dict[str, Any]] = []
    seen_keys = set()

    # 1. Primary method: psutil.net_connections
    try:
        connections = psutil.net_connections(kind="inet")
        for conn in connections:
            is_listening = False
            proto = "tcp"

            if conn.type == socket.SOCK_STREAM and conn.status == psutil.CONN_LISTEN:
                is_listening = True
                proto = "tcp"
            elif conn.type == socket.SOCK_DGRAM:
                # UDP sockets are connectionless; bound sockets receive datagrams
                is_listening = True
                proto = "udp"

            if is_listening and conn.laddr:
                ip = conn.laddr.ip
                port = conn.laddr.port
                pid = conn.pid
                proc_name = "unknown"

                if pid:
                    try:
                        p = psutil.Process(pid)
                        proc_name = p.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = "restricted"

                unique_key = (proto, ip, port)
                if unique_key not in seen_keys:
                    seen_keys.add(unique_key)
                    listening_ports.append({
                        "protocol": proto,
                        "ip": ip,
                        "port": port,
                        "pid": pid,
                        "process_name": proc_name,
                    })
    except (psutil.AccessDenied, PermissionError) as exc:
        logger.debug(f"psutil.net_connections access denied: {exc}, falling back to ss")
    except Exception as exc:
        logger.error(f"Unexpected error in psutil.net_connections: {exc}")

    # 2. Secondary fallback/enrichment: Linux `ss -tulnp`
    if not listening_ports and shutil.which("ss"):
        try:
            ss_proc = subprocess.run(
                ["ss", "-tulnp"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if ss_proc.returncode == 0:
                lines = ss_proc.stdout.strip().splitlines()
                # Skip header
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 5:
                        proto = parts[0].lower()
                        local_addr_part = parts[4]

                        # Parse IP and port
                        r_idx = local_addr_part.rfind(":")
                        if r_idx != -1:
                            ip = local_addr_part[:r_idx].strip("[]")
                            port_str = local_addr_part[r_idx + 1:]
                            try:
                                port = int(port_str)
                            except ValueError:
                                continue

                            pid = None
                            proc_name = "unknown"

                            # Parse process info if present e.g. users:(("nginx",pid=409114,fd=6))
                            if len(parts) >= 7 and "users:" in parts[6]:
                                user_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', parts[6])
                                if user_match:
                                    proc_name = user_match.group(1)
                                    pid = int(user_match.group(2))

                            unique_key = (proto, ip, port)
                            if unique_key not in seen_keys:
                                seen_keys.add(unique_key)
                                listening_ports.append({
                                    "protocol": proto,
                                    "ip": ip or "0.0.0.0",
                                    "port": port,
                                    "pid": pid,
                                    "process_name": proc_name,
                                })
        except Exception as exc:
            logger.debug(f"ss fallback failed: {exc}")

    # Sort ports ascending
    listening_ports.sort(key=lambda x: (x["port"], x["protocol"]))

    return {
        "status": "ok",
        "total_open_ports": len(listening_ports),
        "ports": listening_ports,
    }


def get_ufw_status() -> Dict[str, Any]:
    """Inspect the status and active filtering rules of UFW (Uncomplicated Firewall).

    Returns:
        Structured dictionary detailing whether UFW is active, its default policies,
        and the full list of configured firewall rules.
    """
    ufw_bin = shutil.which("ufw") or "/usr/sbin/ufw"
    if not shutil.which(ufw_bin):
        return {
            "status": "unavailable",
            "error": "UFW utility is not installed on this host.",
            "is_active": False,
            "rules": [],
        }

    cmd = [ufw_bin, "status", "verbose"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

        output = proc.stdout.strip()
        error_output = proc.stderr.strip()

        if proc.returncode != 0:
            if "permission denied" in error_output.lower() or "must be root" in error_output.lower():
                return {
                    "status": "error",
                    "error": "Permission denied: Root or sudo privileges are required to inspect UFW firewall rules.",
                    "is_active": False,
                    "rules": [],
                }
            return {
                "status": "error",
                "error": f"UFW command exited with code {proc.returncode}: {error_output or output}",
                "is_active": False,
                "rules": [],
            }

        # Parse verbose UFW output
        is_active = "Status: active" in output
        default_policy = ""
        logging_level = ""
        rules: List[Dict[str, str]] = []

        lines = output.splitlines()
        parsing_rules = False

        for line in lines:
            line_str = line.strip()
            if line_str.startswith("Default:"):
                default_policy = line_str.replace("Default:", "").strip()
            elif line_str.startswith("Logging:"):
                logging_level = line_str.replace("Logging:", "").strip()
            elif line_str.startswith("To") and "Action" in line_str and "From" in line_str:
                parsing_rules = True
                continue
            elif line_str.startswith("--"):
                continue
            elif parsing_rules and line_str:
                # Rule line format: <To>  <Action>  <From>
                # E.g. "22/tcp                     ALLOW IN    Anywhere"
                parts = re.split(r"\s{2,}", line_str)
                if len(parts) >= 3:
                    rules.append({
                        "to": parts[0].strip(),
                        "action": parts[1].strip(),
                        "from": parts[2].strip(),
                    })
                elif len(parts) == 2:
                    rules.append({
                        "to": parts[0].strip(),
                        "action": parts[1].strip(),
                        "from": "Anywhere",
                    })

        return {
            "status": "ok",
            "is_active": is_active,
            "state_text": "active" if is_active else "inactive",
            "default_policy": default_policy,
            "logging": logging_level,
            "total_rules": len(rules),
            "rules": rules,
            "raw_output": output,
        }

    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": "Timeout while querying UFW firewall status.",
            "is_active": False,
            "rules": [],
        }
    except PermissionError as exc:
        return {
            "status": "error",
            "error": f"Permission denied executing UFW: {str(exc)}",
            "is_active": False,
            "rules": [],
        }
    except Exception as exc:
        logger.error(f"Error checking UFW status: {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Unexpected error checking UFW status: {str(exc)}",
            "is_active": False,
            "rules": [],
        }
