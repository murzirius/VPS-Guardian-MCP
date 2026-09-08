"""System and package updates auditor for VPS-Guardian-MCP.

Provides:
- Operating system package updates audit (APT security patches, kernel reboot checks).
- VPS-Guardian-MCP self-version verification against remote GitHub repository.
- Prominent actionable warnings for AI agents when security updates or server updates are pending.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vps_guardian.updates")

REBOOT_REQUIRED_FILE = "/var/run/reboot-required"
REBOOT_REQUIRED_PKGS_FILE = "/var/run/reboot-required.pkgs"
APT_CHECK_BIN = "/usr/lib/update-notifier/apt-check"
GITHUB_REPO_API = "https://api.github.com/repos/murzirius/VPS-Guardian-MCP/releases/latest"
GITHUB_COMMITS_API = "https://api.github.com/repos/murzirius/VPS-Guardian-MCP/commits/main"


def check_system_updates() -> Dict[str, Any]:
    """Audit available operating system package updates and pending security patches.

    Checks:
    - Kernel/system reboot flag (/var/run/reboot-required).
    - Total upgradable packages.
    - Security-specific updates (CVE patches).
    - Generates actionable alerts for AI agents to inform the administrator.

    Returns:
        Structured dictionary with update counts, security status, reboot flag,
        and recommended recovery action.
    """
    reboot_required = os.path.exists(REBOOT_REQUIRED_FILE)
    reboot_packages: List[str] = []
    if reboot_required and os.path.exists(REBOOT_REQUIRED_PKGS_FILE):
        try:
            with open(REBOOT_REQUIRED_PKGS_FILE, "r", encoding="utf-8", errors="replace") as f:
                reboot_packages = [line.strip() for line in f if line.strip()]
        except Exception as exc:
            logger.warning(f"Error reading {REBOOT_REQUIRED_PKGS_FILE}: {exc}")

    total_upgradable = 0
    security_updates = 0
    upgradable_list: List[Dict[str, Any]] = []

    # 1. Fast check via apt-check if available
    used_apt_check = False
    if os.path.isfile(APT_CHECK_BIN) and os.access(APT_CHECK_BIN, os.X_OK):
        try:
            res = subprocess.run(
                [APT_CHECK_BIN],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            # apt-check outputs to stderr: "total;security" (e.g. "12;4")
            raw_out = res.stderr.strip() or res.stdout.strip()
            if ";" in raw_out:
                parts = raw_out.split(";")
                total_upgradable = int(parts[0])
                security_updates = int(parts[1])
                used_apt_check = True
        except Exception as exc:
            logger.debug(f"apt-check execution skipped or failed: {exc}")

    # 2. Detailed check via 'apt list --upgradable'
    apt_bin = shutil.which("apt") or shutil.which("apt-get")
    if apt_bin:
        try:
            res = subprocess.run(
                [apt_bin, "list", "--upgradable"],
                capture_output=True,
                text=True,
                check=False,
                timeout=25,
            )
            if res.returncode == 0:
                lines = res.stdout.splitlines()
                pkg_count = 0
                sec_count = 0
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("Listing...") or "upgradable from" not in line:
                        continue
                    pkg_count += 1
                    is_security = "security" in line.lower() or "-security" in line
                    if is_security:
                        sec_count += 1

                    # Extract package name and version
                    # e.g.: nginx/jammy-updates,jammy-security 1.18.0-6ubuntu14.5 amd64 [upgradable from: 1.18.0-6ubuntu14.4]
                    pkg_name = line.split("/")[0] if "/" in line else line.split()[0]
                    upgradable_list.append(
                        {
                            "package": pkg_name,
                            "is_security": is_security,
                            "details": line,
                        }
                    )

                if not used_apt_check:
                    total_upgradable = pkg_count
                    security_updates = sec_count
        except Exception as exc:
            logger.warning(f"apt list execution failed: {exc}")

    # Formulate AI warnings and recommendations
    warnings: List[str] = []
    if reboot_required:
        warnings.append(
            "System reboot is REQUIRED to apply kernel or core library updates "
            f"({len(reboot_packages)} package(s) requested restart)."
        )

    if security_updates > 0:
        warnings.append(
            f"SECURITY ALERT: {security_updates} critical security update(s) available. "
            "It is strongly recommended to apply security updates using execute_recovery(action_name='apply_security_updates')."
        )
    elif total_upgradable > 0:
        warnings.append(f"{total_upgradable} routine package update(s) available.")

    return {
        "status": "ok",
        "reboot_required": reboot_required,
        "reboot_packages": reboot_packages,
        "total_upgradable": total_upgradable,
        "security_updates_count": security_updates,
        "packages_sample": upgradable_list[:30],
        "has_pending_updates": (total_upgradable > 0 or security_updates > 0),
        "recovery_action_available": "apply_security_updates" if security_updates > 0 or total_upgradable > 0 else None,
        "warning": " | ".join(warnings) if warnings else "System packages are up to date. No reboot required.",
        "summary": (
            f"Updates: {total_upgradable} upgradable ({security_updates} security). "
            f"Reboot required: {reboot_required}."
        ),
    }


def check_guardian_updates() -> Dict[str, Any]:
    """Check if a newer version of VPS-Guardian-MCP is available.

    Compares local version and git commit with remote GitHub repository.
    Provides actionable guidance and recovery command to self-update.

    Returns:
        Structured dictionary with current version, latest version/commit,
        update availability flag, and warning message for AI agents.
    """
    try:
        from src import __version__ as current_version
    except ImportError:
        try:
            from __init__ import __version__ as current_version
        except ImportError:
            current_version = "0.7.0"

    current_commit: Optional[str] = None
    git_bin = shutil.which("git")

    # Attempt to read local git commit hash
    repo_dirs = ["/opt/vps-guardian-mcp", os.getcwd()]
    active_repo_dir = None
    for rdir in repo_dirs:
        if os.path.isdir(os.path.join(rdir, ".git")):
            active_repo_dir = rdir
            break

    if git_bin and active_repo_dir:
        try:
            c_res = subprocess.run(
                [git_bin, "-C", active_repo_dir, "rev-parse", "--short", "HEAD"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            if c_res.returncode == 0:
                current_commit = c_res.stdout.strip()
        except Exception:
            pass

    # Check remote version from GitHub
    latest_remote_version: Optional[str] = None
    latest_remote_commit: Optional[str] = None
    update_available = False

    try:
        # Fast query of remote GitHub commits
        req = urllib.request.Request(
            GITHUB_COMMITS_API,
            headers={
                "User-Agent": f"VPS-Guardian-MCP/{current_version}",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                if isinstance(data, dict) and "sha" in data:
                    latest_remote_commit = data["sha"][:7]
                    if current_commit and latest_remote_commit != current_commit:
                        update_available = True
    except Exception as exc:
        logger.debug(f"GitHub API update query skipped or timed out: {exc}")

    # Fallback to git ls-remote if git is available
    if not latest_remote_commit and git_bin and active_repo_dir:
        try:
            res_ls = subprocess.run(
                [git_bin, "-C", active_repo_dir, "ls-remote", "origin", "main"],
                capture_output=True,
                text=True,
                check=False,
                timeout=6,
            )
            if res_ls.returncode == 0 and res_ls.stdout.strip():
                remote_sha = res_ls.stdout.strip().split()[0][:7]
                latest_remote_commit = remote_sha
                if current_commit and remote_sha != current_commit:
                    update_available = True
        except Exception as exc:
            logger.debug(f"git ls-remote failed: {exc}")

    warning_msg = None
    if update_available:
        warning_msg = (
            f"UPDATE AVAILABLE: VPS-Guardian-MCP is at commit {current_commit or 'unknown'}, "
            f"but a newer commit ({latest_remote_commit}) is available on GitHub. "
            "You can update automatically using execute_recovery(action_name='update_guardian')."
        )
    else:
        warning_msg = f"VPS-Guardian-MCP is running the latest version (v{current_version}, {current_commit or 'HEAD'})."

    return {
        "status": "ok",
        "current_version": current_version,
        "current_commit": current_commit,
        "latest_remote_commit": latest_remote_commit,
        "update_available": update_available,
        "recovery_action": "update_guardian" if update_available else None,
        "warning": warning_msg,
        "summary": (
            f"VPS-Guardian-MCP v{current_version} ({current_commit or 'local'}). "
            f"Update available: {update_available}."
        ),
    }
