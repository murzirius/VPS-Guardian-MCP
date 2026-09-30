"""Opt-in, SSH-key-bound agent accounts for a least-privilege MCP gateway.

The gateway does not expose a listening port or grant filesystem privileges.
Each agent has a different, password-locked Unix account. Its SSH key can only
start the forced MCP command, and a root-owned policy is rechecked on each call.
"""

from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
import datetime as dt
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any

try:
    import pwd
except ImportError:  # Windows development/test hosts cannot serve the Linux gateway.
    pwd = None


AGENT_ID = re.compile(r"[a-z][a-z0-9-]{0,23}\Z")
POLICY_BASE = Path("/etc/vps-guardian/gateway")
HOME_BASE = Path("/var/lib/vps-guardian-agents")
MAX_POLICY_BYTES = 24_000
MAX_AGENTS = 32
DEFAULT_TOOLS = ["get_safety_status", "get_system_health", "get_vps_topology", "discover_projects", "inspect_project", "read_project_file"]
EDITOR_TOOLS = DEFAULT_TOOLS + ["search_project_code", "begin_project_patch", "stage_project_file_change",
                                "preview_project_patch", "run_project_checks", "apply_project_patch",
                                "list_operations", "get_operation"]


def _account(agent_id: str) -> str:
    if not isinstance(agent_id, str) or not AGENT_ID.fullmatch(agent_id):
        raise ValueError("Agent ID must be 1–24 lowercase letters, digits or hyphens, starting with a letter.")
    return "vg_" + agent_id.replace("-", "_")


def _public_key(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or len(value) > 1024:
        raise ValueError("Supply one Ed25519 SSH public key, never a private key.")
    value = value.strip()
    if "\n" in value or "\r" in value or '"' in value:
        raise ValueError("Supply one Ed25519 SSH public key, never a private key.")
    parts = value.split(maxsplit=2)
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValueError("Only a plain ssh-ed25519 public key is supported.")
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except binascii.Error as exc:
        raise ValueError("Invalid SSH public key encoding.") from exc
    if len(raw) != 51 or raw[:4] != b"\x00\x00\x00\x0b" or raw[4:15] != b"ssh-ed25519" or raw[15:19] != b"\x00\x00\x00\x20":
        raise ValueError("Invalid Ed25519 SSH public key structure.")
    canonical = "ssh-ed25519 " + base64.b64encode(raw).decode("ascii")
    fingerprint = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    return canonical, "SHA256:" + fingerprint


def _trusted_directory(path: Path, *, create: bool = False, administrator: bool = False) -> None:
    """Every existing component must be root-owned and not writable by others."""
    if os.name != "posix" or administrator and os.geteuid() != 0:
        raise PermissionError("Gateway administration requires root on Linux.")
    current = Path("/")
    for component in path.parts[1:]:
        current /= component
        if create and not current.exists() and not current.is_symlink():
            if os.geteuid() != 0:
                raise PermissionError("Only root can create gateway directories.")
            current.mkdir(mode=0o755)
            current.chmod(0o755)
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError("Gateway directory is not root-owned and protected.")


def _policy_path(agent_id: str) -> Path:
    _account(agent_id)
    return POLICY_BASE / (agent_id + ".json")


def _read_policy(agent_id: str) -> dict[str, Any]:
    path = _policy_path(agent_id)
    _trusted_directory(POLICY_BASE)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > MAX_POLICY_BYTES:
            raise PermissionError("Gateway policy has unsafe ownership, permissions or size.")
        raw = os.read(fd, MAX_POLICY_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_POLICY_BYTES:
        raise ValueError("Gateway policy exceeds its read budget.")
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("agent_id") != agent_id or value.get("account") != _account(agent_id):
        raise ValueError("Gateway policy is invalid.")
    if (type(value.get("enabled")) is not bool or not isinstance(value.get("mode_cap"), str)
            or value["mode_cap"] not in {"read-only", "controlled"}):
        raise ValueError("Gateway policy is invalid.")
    if (type(value.get("uid")) is not int or value["uid"] <= 0
            or not isinstance(value.get("profile"), str) or value["profile"] not in {"observer", "project-editor"}
            or not isinstance(value.get("expires_at"), str)
            or not isinstance(value.get("key_fingerprint"), str)
            or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", value["key_fingerprint"])):
        raise ValueError("Gateway policy is invalid.")
    if dt.datetime.fromisoformat(value["expires_at"]).tzinfo is None:
        raise ValueError("Gateway expiry must include its timezone.")
    if (not isinstance(value.get("allowed_tools"), list) or len(value["allowed_tools"]) > 80
            or not all(isinstance(t, str) and len(t) <= 100 for t in value["allowed_tools"])):
        raise ValueError("Gateway policy is invalid.")
    roots = value.get("project_roots")
    if (not isinstance(roots, list) or len(roots) > 8
            or not all(isinstance(root, str) and len(root) <= 1024 and os.path.isabs(root)
                       and root != "/" and not any(ord(c) < 32 or ord(c) == 127 for c in root) for root in roots)):
        raise ValueError("Gateway policy is invalid.")
    return value


def _write_policy(agent_id: str, value: dict[str, Any]) -> None:
    _trusted_directory(POLICY_BASE, create=True, administrator=True)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_POLICY_BYTES:
        raise ValueError("Gateway policy is too large.")
    # A root-owned temporary file in the same directory makes replacement atomic.
    fd, temporary = tempfile.mkstemp(prefix=".gateway-", dir=POLICY_BASE)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        path = _policy_path(agent_id)
        if os.path.lexists(path):
            _read_policy(agent_id)
        os.replace(temporary, path)
        parent = os.open(POLICY_BASE, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _active_policy() -> dict[str, Any] | None:
    agent_id = os.environ.get("VPS_GUARDIAN_GATEWAY_AGENT")
    if agent_id is None:
        return None
    try:
        value = _read_policy(agent_id)
        if value["uid"] != os.geteuid() or value["account"] != pwd.getpwuid(os.geteuid()).pw_name:
            raise PermissionError("Gateway identity mismatch.")
        expiry = dt.datetime.fromisoformat(value["expires_at"])
        if expiry.tzinfo is None or not value["enabled"] or expiry <= dt.datetime.now(dt.timezone.utc):
            raise PermissionError("Gateway access expired or revoked.")
        return value
    except (OSError, ValueError, KeyError, TypeError, PermissionError, RecursionError):
        return {}  # Fail closed if a gateway environment is present but invalid.


def access_denial(name: str) -> dict[str, Any] | None:
    policy = _active_policy()
    if policy is None or name == "get_safety_status":
        return None
    if not policy or name not in policy["allowed_tools"]:
        return {"status": "forbidden", "success": False, "operation": name,
                "error": "This agent is not permitted to use this Guardian tool."}
    return None


def mode_cap() -> str | None:
    policy = _active_policy()
    return None if policy is None else policy.get("mode_cap", "read-only")


def project_roots() -> list[str] | None:
    policy = _active_policy()
    return None if policy is None else list(policy.get("project_roots", []))


def catalog_tools() -> set[str] | None:
    policy = _active_policy()
    return None if policy is None else set(policy.get("allowed_tools", [])) | {"get_safety_status"}


@contextmanager
def _administration_lock():
    import fcntl
    _trusted_directory(POLICY_BASE, create=True, administrator=True)
    fd = os.open(POLICY_BASE / ".admin.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
            raise PermissionError("Unsafe gateway administration lock.")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def _serialized_administration(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            if os.name != "posix":
                raise PermissionError("Linux is required.")
            with _administration_lock():
                return function(*args, **kwargs)
        except (OSError, PermissionError):
            return {"status": "error", "error": "Gateway administration requires root, safe directories and no other pending enrollment/revocation."}
    return wrapped


def _validate_roots(roots: list[str]) -> list[str]:
    if not isinstance(roots, list) or len(roots) > 8:
        raise ValueError("Choose at most eight project roots.")
    result = []
    for root in roots:
        if not isinstance(root, str) or len(root) > 1024 or not root.startswith("/") or any(ord(c) < 32 or ord(c) == 127 for c in root):
            raise ValueError("Project roots must be absolute Linux paths.")
        path = Path(root)
        if path.is_symlink() or not path.is_dir() or path == Path("/"):
            raise ValueError("Each project root must be an existing non-symlink directory below /.")
        result.append(str(path.resolve()))
    return sorted(set(result))


def _check_installation(executable: Path) -> None:
    """Reject root-home/agent-writable installs before creating any OS account."""
    def check_file(path: Path, executable_file: bool = False) -> None:
        path = path.resolve(strict=True)
        _trusted_directory(path.parent)
        for parent in path.parents:
            if not parent.stat().st_mode & 0o001:
                raise PermissionError("Gateway installation must be traversable by agent accounts.")
        info = path.stat()
        required = 0o005 if executable_file else 0o004
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or info.st_mode & required != required):
            raise PermissionError("Gateway installation must be root-owned, readable and protected.")

    check_file(executable, True)
    check_file(Path(__file__))
    # Console entry points must use an absolute, protected Python interpreter;
    # an env/PATH shebang would choose an uncontrolled interpreter after SSH.
    with executable.open("rb") as stream:
        shebang = stream.readline(1024).decode("ascii").strip()
    if not re.fullmatch(r"#!/[A-Za-z0-9_./-]+", shebang):
        raise ValueError("Install Gateway in a root-owned venv at a plain absolute path.")
    check_file(Path(shebang[2:]), True)


@_serialized_administration
def create_agent(agent_id: str, public_key: str, project_roots: list[str],
                 profile: str = "observer", expires_hours: int = 24) -> dict[str, Any]:
    """Create a dedicated, locked OS account. Only the operator helper calls this."""
    try:
        _trusted_directory(POLICY_BASE, create=True, administrator=True)
        _trusted_directory(HOME_BASE, create=True, administrator=True)
        account = _account(agent_id)
        key, fingerprint = _public_key(public_key)
        roots = _validate_roots(project_roots)
        from src.access_policy import tool_catalog
        names = {entry["name"] for entry in tool_catalog()}
        if not isinstance(profile, str) or profile not in {"observer", "project-editor"}:
            raise ValueError("Choose an observer or project-editor profile.")
        tools = DEFAULT_TOOLS if profile == "observer" else EDITOR_TOOLS
        if any(t not in names for t in tools):
            raise ValueError("The installed Guardian tool catalog is incompatible with this profile.")
        if type(expires_hours) is not int or not 1 <= expires_hours <= 168:
            raise ValueError("Expiry must be between 1 and 168 hours.")
        if os.path.lexists(_policy_path(agent_id)) or (HOME_BASE / agent_id).exists():
            raise ValueError("Agent already exists. Create a new ID rather than overwriting access.")
        try:
            pwd.getpwnam(account)
        except KeyError:
            pass
        else:
            raise ValueError("Unix account name is already in use.")
        if len(list(POLICY_BASE.glob("*.json"))) >= MAX_AGENTS:
            raise ValueError("Gateway agent capacity reached.")
        home = HOME_BASE / agent_id
        executable = Path(sys.argv[0]).resolve().with_name("vps-guardian-gateway")
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(executable)) or not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("Install the vps-guardian-gateway executable before enrolling an agent.")
        try:
            _check_installation(executable)
        except (OSError, ValueError, UnicodeError):
            return {"status": "error", "error": "Install Gateway in a root-owned, protected venv outside /root (for example /opt/vps-guardian-mcp/.venv). Agent accounts must be able to read and execute it."}
        subprocess.run(["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir", str(home),
                        "--shell", "/bin/sh", account], check=True, timeout=10, capture_output=True)
        user = pwd.getpwnam(account)
        if user.pw_uid <= 0 or user.pw_gid <= 0 or user.pw_dir != str(home) or user.pw_shell != "/bin/sh":
            raise PermissionError("New Unix account did not match the requested unprivileged identity.")
        home.mkdir(mode=0o755)
        home.chmod(0o755)
        ssh = home / ".ssh"
        # sshd opens authorized_keys as this unprivileged user. Root ownership
        # prevents changes; world-read/traverse allows authentication to work.
        ssh.mkdir(mode=0o755)
        ssh.chmod(0o755)
        # Never inherit client-supplied Python, shell or tool configuration.
        command = ("/usr/bin/env -i HOME=" + str(home) + " USER=" + account
                   + " LOGNAME=" + account + " PATH=/usr/sbin:/usr/bin:/bin "
                   + str(executable) + " serve " + agent_id)
        if '"' in command or "\n" in command:
            raise ValueError("Unsafe gateway executable path.")
        line = f'restrict,command="{command}" {key} gateway-{agent_id}\n'
        keys_path = ssh / "authorized_keys"
        fd = os.open(keys_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
        local = home / ".local"
        local.mkdir(mode=0o700)
        local.chmod(0o700)
        os.chown(local, user.pw_uid, user.pw_gid)
        expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=expires_hours)
        policy = {"agent_id": agent_id, "account": account, "uid": user.pw_uid, "enabled": True,
                  "profile": profile, "mode_cap": "read-only" if profile == "observer" else "controlled",
                  "allowed_tools": sorted(set(tools) | {"get_safety_status"}),
                  "project_roots": roots, "expires_at": expires.isoformat(), "key_fingerprint": fingerprint}
        _write_policy(agent_id, policy)
        return {"status": "ok", "agent": _summary(policy), "note": "Grant this Unix account access to selected project files separately. Never give it sudo or Docker group access."}
    except (OSError, ValueError, subprocess.SubprocessError, PermissionError, KeyError):
        return {"status": "error", "error": "Could not enroll agent. Check root access, account availability and project paths. If the account was created, inspect it before retrying."}


def _summary(policy: dict[str, Any]) -> dict[str, Any]:
    return {field: policy[field] for field in ("agent_id", "account", "enabled", "profile", "mode_cap", "allowed_tools", "project_roots", "expires_at", "key_fingerprint")}


def list_agents() -> dict[str, Any]:
    try:
        _trusted_directory(POLICY_BASE, administrator=True)
        agents = []
        for path in sorted(POLICY_BASE.glob("*.json"))[:MAX_AGENTS]:
            agents.append(_summary(_read_policy(path.stem)))
        return {"status": "ok", "agents": agents, "os_isolation": True,
                "note": "Each agent is a separate Unix account. Filesystem and service access still depend on Linux permissions."}
    except FileNotFoundError:
        return {"status": "ok", "agents": [], "os_isolation": True}
    except (OSError, ValueError, PermissionError, KeyError, TypeError, RecursionError):
        return {"status": "error", "error": "Gateway records are unavailable or unsafe."}


@_serialized_administration
def revoke_agent(agent_id: str) -> dict[str, Any]:
    try:
        _trusted_directory(POLICY_BASE, administrator=True)
        policy = _read_policy(agent_id)
        policy["enabled"] = False
        _write_policy(agent_id, policy)
        # Existing sessions see the policy on the next call; their in-flight
        # work is not cancelled. The root-owned key file blocks new logins.
        keys = HOME_BASE / agent_id / ".ssh" / "authorized_keys"
        _trusted_directory(keys.parent)
        if keys.is_symlink() or keys.exists() and (keys.stat().st_uid != 0 or not keys.is_file()):
            raise PermissionError("Unsafe authorized_keys file.")
        if keys.exists():
            keys.unlink()
        return {"status": "ok", "agent": _summary(policy), "note": "New calls are denied; existing in-flight work is not cancelled."}
    except (OSError, ValueError, PermissionError, KeyError, TypeError, RecursionError):
        return {"status": "error", "error": "Agent policy was not safely revoked or its SSH key could not be removed. Inspect the account manually."}


def serve(agent_id: str) -> None:
    # SSH authorized_keys must force this exact command. A locked, unprivileged
    # account is the OS boundary; this environment marker is only MCP routing.
    _account(agent_id)
    policy = _read_policy(agent_id)
    if os.geteuid() == 0 or os.geteuid() != policy["uid"] or pwd.getpwuid(os.geteuid()).pw_name != policy["account"]:
        raise PermissionError("Gateway account mismatch.")
    if not policy["enabled"] or dt.datetime.fromisoformat(policy["expires_at"]) <= dt.datetime.now(dt.timezone.utc):
        raise PermissionError("Gateway access expired or revoked.")
    os.environ["VPS_GUARDIAN_GATEWAY_AGENT"] = agent_id
    os.environ["VPS_GUARDIAN_MODE"] = "unrestricted"  # Root-owned policy supplies the effective cap.
    os.environ["VPS_GUARDIAN_TOOL_PROFILE"] = "full"
    home = HOME_BASE / agent_id
    # Each account gets private writable state, never the administrator's
    # /var/lib state or /var/log audit file. No shared root data is exposed.
    private = home / ".local" / "share" / "vps-guardian"
    os.environ["VPS_GUARDIAN_STATE_DIR"] = str(private / "state")
    os.environ["VPS_GUARDIAN_AUDIT_LOG"] = str(private / "audit" / "audit.jsonl")
    os.environ["VPS_GUARDIAN_SNAPSHOT_DIR"] = str(private / "snapshots")
    os.environ["VPS_GUARDIAN_WORKLOAD_BASELINE_DIR"] = str(private / "workloads")
    from src.server import main
    main()


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="VPS Guardian per-agent SSH gateway")
    parser.add_argument("command", choices=["serve"])
    parser.add_argument("agent_id")
    args = parser.parse_args()
    if args.command == "serve":
        serve(args.agent_id)


if __name__ == "__main__":
    main()
