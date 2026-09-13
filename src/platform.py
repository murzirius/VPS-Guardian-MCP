"""Capability-based adapters for common Linux distributions and init systems."""

from __future__ import annotations

import platform as stdlib_platform
import shutil
import subprocess
from typing import Any, Dict, List, Optional


PACKAGE_MANAGERS = ("apt", "dnf", "yum", "pacman", "zypper")


def _read_os_release() -> Dict[str, str]:
    result: Dict[str, str] = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as release_file:
            for line in release_file:
                key, separator, value = line.strip().partition("=")
                if separator and key in {"ID", "ID_LIKE", "NAME", "VERSION_ID"}:
                    result[key.lower()] = value.strip('"')
    except OSError:
        pass
    return result


def get_service_manager() -> Optional[str]:
    if shutil.which("systemctl"):
        return "systemd"
    if shutil.which("rc-service"):
        return "openrc"
    if shutil.which("service"):
        return "sysvinit"
    return None


def build_service_command(action: str, service_name: str) -> tuple[Optional[str], Optional[List[str]], str]:
    """Build a shell-free service command for the detected init system."""
    manager = get_service_manager()
    normalized = service_name[:-8] if service_name.endswith(".service") else service_name
    if manager == "systemd":
        unit = service_name if service_name.endswith(".service") else f"{service_name}.service"
        return manager, [shutil.which("systemctl") or "systemctl", action, unit], unit
    if manager == "openrc":
        return manager, [shutil.which("rc-service") or "rc-service", normalized, action], normalized
    if manager == "sysvinit":
        return manager, [shutil.which("service") or "service", normalized, action], normalized
    return None, None, normalized


def get_package_manager() -> Optional[str]:
    return next((item for item in PACKAGE_MANAGERS if shutil.which(item)), None)


def get_firewall_backend() -> Optional[str]:
    if shutil.which("ufw"):
        return "ufw"
    if shutil.which("firewall-cmd"):
        return "firewalld"
    if shutil.which("nft"):
        return "nftables"
    return None


def get_compose_command() -> Optional[List[str]]:
    docker = shutil.which("docker")
    if docker:
        try:
            result = subprocess.run([docker, "compose", "version"], capture_output=True, text=True, timeout=8, check=False)
            if result.returncode == 0:
                return [docker, "compose"]
        except OSError:
            pass
    legacy = shutil.which("docker-compose")
    return [legacy] if legacy else None


def get_platform_capabilities() -> Dict[str, Any]:
    """Describe detected OS administration backends without changing state."""
    os_release = _read_os_release()
    package_manager = get_package_manager()
    firewall = get_firewall_backend()
    service_manager = get_service_manager()
    compose_command = get_compose_command()
    return {
        "status": "ok",
        "operating_system": {
            "name": os_release.get("name") or stdlib_platform.system(),
            "id": os_release.get("id", "unknown"),
            "id_like": os_release.get("id_like", ""),
            "version": os_release.get("version_id", ""),
            "architecture": stdlib_platform.machine(),
        },
        "package_manager": package_manager,
        "firewall_backend": firewall,
        "service_manager": service_manager,
        "docker_compose_available": compose_command is not None,
        "docker_compose_command": compose_command,
        "supported_backends": {
            "package_managers": list(PACKAGE_MANAGERS),
            "firewalls": ["ufw", "firewalld", "nftables"],
            "service_managers": ["systemd", "openrc", "sysvinit"],
        },
    }


def get_package_updates() -> Dict[str, Any]:
    """Check available package updates through the detected package manager."""
    manager = get_package_manager()
    if not manager:
        return {"status": "unavailable", "error": "No supported package manager found.", "packages": []}
    command_map = {
        "apt": [shutil.which("apt") or shutil.which("apt-get") or "apt", "list", "--upgradable"],
        "dnf": [shutil.which("dnf") or "dnf", "check-update", "--quiet"],
        "yum": [shutil.which("yum") or "yum", "check-update", "--quiet"],
        "pacman": [shutil.which("pacman") or "pacman", "-Qu"],
        "zypper": [shutil.which("zypper") or "zypper", "--non-interactive", "list-updates"],
    }
    try:
        result = subprocess.run(command_map[manager], capture_output=True, text=True, timeout=30, check=False)
    except OSError as exc:
        return {"status": "error", "package_manager": manager, "error": str(exc), "packages": []}
    # dnf/yum return 100 when updates exist; the others use zero for a normal query.
    accepted = {0, 100} if manager in {"dnf", "yum"} else {0}
    if result.returncode not in accepted:
        return {"status": "error", "package_manager": manager, "error": (result.stderr or result.stdout).strip()[:500], "packages": []}
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    lines = [line for line in lines if not line.startswith("Listing...") and not line.startswith("Last metadata")]
    return {"status": "ok", "package_manager": manager, "update_count": len(lines), "packages": lines[:100], "truncated": len(lines) > 100}


def get_firewall_status() -> Dict[str, Any]:
    """Return a normalized read-only firewall status across supported backends."""
    backend = get_firewall_backend()
    if not backend:
        return {"status": "unavailable", "error": "No supported firewall backend found.", "backend": None, "rules": []}
    if backend == "ufw":
        try:
            from src.network import get_ufw_status
        except ImportError:
            from network import get_ufw_status
        result = get_ufw_status()
        return {**result, "backend": "ufw"}
    command = [shutil.which("firewall-cmd") or "firewall-cmd", "--state"] if backend == "firewalld" else [shutil.which("nft") or "nft", "list", "ruleset"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    except OSError as exc:
        return {"status": "error", "backend": backend, "error": str(exc), "rules": []}
    if result.returncode != 0:
        return {"status": "error", "backend": backend, "error": (result.stderr or result.stdout).strip()[:500], "rules": []}
    if backend == "firewalld":
        firewall_cmd = shutil.which("firewall-cmd") or "firewall-cmd"
        details = subprocess.run([firewall_cmd, "--get-default-zone"], capture_output=True, text=True, timeout=10, check=False)
        zone = details.stdout.strip() if details.returncode == 0 else ""
        rules = []
        if zone:
            zone_result = subprocess.run([firewall_cmd, "--zone", zone, "--list-all"], capture_output=True, text=True, timeout=10, check=False)
            rules = zone_result.stdout.splitlines()[:100] if zone_result.returncode == 0 else []
        return {"status": "ok", "backend": backend, "is_active": result.stdout.strip() == "running", "default_zone": zone, "rules": rules}
    rules = result.stdout.splitlines()[:300]
    return {"status": "ok", "backend": backend, "is_active": True, "rules": rules, "truncated": len(result.stdout.splitlines()) > 300}
