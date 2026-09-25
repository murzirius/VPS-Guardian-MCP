"""Bounded, fail-closed container checks for staged project patches.

The source project is never mounted into a container. A small, filtered snapshot
receives the candidate patch and is removed after one synchronous check.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Linux development host
    fcntl = None

try:
    from src.agent_runtime import _scrub, _state_dir
    from src.files import _redact_config_text
    from src.project_workspace import (
        MAX_LARGE_FILE, _line_edit_candidate, _patch_lock, _patches,
        _project_file, _within, _cleanup_patches, _public_file,
        apply_project_patch,
    )
    from src.resource_policy import get_runtime_budget
    from src.safety import record_audit_event, request_authorization
except ImportError:  # pragma: no cover - direct script compatibility
    from agent_runtime import _scrub, _state_dir
    from files import _redact_config_text
    from project_workspace import (
        MAX_LARGE_FILE, _line_edit_candidate, _patch_lock, _patches,
        _project_file, _within, _cleanup_patches, _public_file,
        apply_project_patch,
    )
    from resource_policy import get_runtime_budget
    from safety import record_audit_event, request_authorization


MAX_SNAPSHOT_FILES = 250
MAX_SNAPSHOT_DIRS = 500
MAX_SNAPSHOT_ENTRIES = 2000
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 4096
CHECK_TIMEOUT_SECONDS = 30
MIN_AVAILABLE_MEMORY = 384 * 1024 * 1024
MIN_AVAILABLE_DISK = 64 * 1024 * 1024
CHECKS = {"auto", "python_syntax", "python_unittest", "node_syntax", "npm_test"}
EXCLUDED_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", ".next", "logs", "backups", ".ssh", "secrets"}
EXCLUDED_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".log", ".bak", ".sqlite", ".sqlite3", ".db", ".pyc")
SENSITIVE_NAME = re.compile(r"(?i)(^\.env(?:\.|$)|^id_(?:rsa|ed25519|ecdsa)|secret|credential|password|private[_-]?key|^\.npmrc$|^\.pypirc$)")
_check_lock = threading.Lock()


def _allowed_name(name: str, directory: bool = False) -> bool:
    return not (name.startswith(".") or SENSITIVE_NAME.search(name) or (directory and name in EXCLUDED_DIRS) or (not directory and name.lower().endswith(EXCLUDED_SUFFIXES)))


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fingerprint(item: Dict[str, Any]) -> str:
    parts = [f"{entry['relative_path']}\0{entry['baseline_sha256']}\0{entry['candidate_sha256']}" for entry in item["files"]]
    return _sha("\n".join(sorted(parts)).encode("utf-8"))


def _check_name(item: Dict[str, Any], check: str) -> Optional[str]:
    if check != "auto":
        return check
    paths = [entry["relative_path"] for entry in item["files"]]
    python = any(path.endswith(".py") for path in paths)
    node = any(path.endswith((".js", ".cjs", ".mjs")) for path in paths)
    if python and node:
        return None
    if python:
        return "python_syntax"
    if node:
        return "node_syntax"
    return None


def _preflight(check: str) -> tuple[Optional[str], Optional[str]]:
    if not sys.platform.startswith("linux") or fcntl is None:
        return None, "Test Capsules require Linux and flock; no host execution fallback is available."
    budget = get_runtime_budget()
    if budget["available_memory_bytes"] < MIN_AVAILABLE_MEMORY:
        return None, "At least 384 MiB of available memory is required for a capsule."
    if shutil.disk_usage(tempfile.gettempdir()).free < MIN_AVAILABLE_DISK:
        return None, "At least 64 MiB of free temporary disk space is required."
    docker = shutil.which("docker")
    if not docker:
        return None, "Docker CLI is unavailable; no host execution fallback is available."
    configured_host = os.environ.get("DOCKER_HOST", "")
    if configured_host and not configured_host.startswith("unix://"):
        return None, "Capsules require a local Unix Docker daemon, not a remote Docker host."
    try:
        endpoint = subprocess.run([docker, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return None, "Docker context inspection failed."
    if endpoint.returncode != 0 or not endpoint.stdout.strip().startswith("unix://"):
        return None, "Capsules require a local Unix Docker daemon."
    image = os.environ.get("VPS_GUARDIAN_CAPSULE_PYTHON_IMAGE" if check.startswith("python_") else "VPS_GUARDIAN_CAPSULE_NODE_IMAGE", "python:3.12-alpine" if check.startswith("python_") else "node:20-alpine")
    if not image or not re.fullmatch(r"[A-Za-z0-9_./:@-]{1,200}", image) or image.startswith("-"):
        return None, "Capsule image name is invalid."
    try:
        result = subprocess.run([docker, "image", "inspect", image, "--format", "{{.Id}}"], capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return None, "Docker image inspection failed."
    if result.returncode != 0:
        return None, "The configured capsule image is not available locally; Guardian never pulls images automatically."
    return image, None


def _snapshot_parent(snapshot: str, relative: str) -> str:
    """Make copied source traversable by the unprivileged container user."""
    parent = snapshot
    for part in relative.split("/")[:-1]:
        parent = os.path.join(parent, part)
        os.makedirs(parent, mode=0o755, exist_ok=True)
        os.chmod(parent, 0o755)
    return parent


def _open_project_regular(project: str, relative: str) -> int:
    """Open each path component without following symlinks on Linux."""
    parts = relative.split("/")
    if os.name != "posix":  # pragma: no cover - capsules never run on Windows
        return os.open(os.path.join(project, *parts), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    directory = os.open(project, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    finally:
        os.close(directory)


def _copy_snapshot(project: str, destination: str) -> Dict[str, Any]:
    count = 0
    total = 0
    directories = 0
    entries_seen = 0
    deadline = time.monotonic() + 10
    pending = [(project, "")]
    while pending:
        current, relative_dir = pending.pop()
        directories += 1
        if directories > MAX_SNAPSHOT_DIRS or time.monotonic() > deadline:
            raise ValueError("Project exceeds the capsule directory or scan-time budget.")
        if not _within(os.path.realpath(current), project):
            raise ValueError("Project directory changed during snapshot.")
        with os.scandir(current) as listing:
            for entry in listing:
                entries_seen += 1
                if entries_seen > MAX_SNAPSHOT_ENTRIES or time.monotonic() > deadline:
                    raise ValueError("Project exceeds the capsule entry or scan-time budget.")
                if entry.is_symlink():
                    continue
                name = entry.name
                relative = name if not relative_dir else f"{relative_dir}/{name}"
                if entry.is_dir(follow_symlinks=False):
                    if _allowed_name(name, True):
                        pending.append((entry.path, relative))
                    continue
                if not _allowed_name(name) or not entry.is_file(follow_symlinks=False):
                    continue
                descriptor = _open_project_regular(project, relative)
                try:
                    info = os.fstat(descriptor)
                    if not stat.S_ISREG(info.st_mode):
                        continue
                    if info.st_size > MAX_LARGE_FILE or count >= MAX_SNAPSHOT_FILES or total + info.st_size > MAX_SNAPSHOT_BYTES:
                        raise ValueError("Project exceeds the capsule snapshot budget (250 files / 8 MiB).")
                    target_dir = _snapshot_parent(destination, relative)
                    target = os.path.join(target_dir, name)
                    with os.fdopen(os.dup(descriptor), "rb") as input_file, open(target, "wb") as output_file:
                        remaining = info.st_size
                        while remaining:
                            block = input_file.read(min(64 * 1024, remaining))
                            if not block:
                                raise ValueError("Project file changed during snapshot.")
                            output_file.write(block)
                            remaining -= len(block)
                    if os.path.getsize(target) != info.st_size:
                        raise ValueError("Project file changed during snapshot.")
                    after = os.fstat(descriptor)
                    if after.st_size != info.st_size or after.st_mtime_ns != info.st_mtime_ns:
                        raise ValueError("Project file changed during snapshot.")
                    os.chmod(target, 0o644)
                    count += 1
                    total += info.st_size
                finally:
                    os.close(descriptor)
    if count == 0:
        raise ValueError("No eligible project files were found for a capsule.")
    return {"files": count, "bytes": total}


def _apply_candidates(item: Dict[str, Any], snapshot: str, summary: Dict[str, int]) -> list[str]:
    changed = []
    project = item["project_path"]
    for entry in item["files"]:
        relative = entry["relative_path"]
        if any(not _allowed_name(part, index < len(relative.split("/")) - 1) for index, part in enumerate(relative.split("/"))):
            raise ValueError("A staged path is excluded from capsule snapshots.")
        path, error = _project_file(project, relative)
        if error or path != entry["path"] or os.path.islink(path):
            raise ValueError("A staged project path changed before the capsule check.")
        exists = os.path.isfile(path)
        if exists != entry["existed"]:
            raise ValueError("A staged project file changed before the capsule check.")
        if exists:
            if os.path.getsize(path) > MAX_LARGE_FILE:
                raise ValueError("A staged file now exceeds the capsule budget.")
            descriptor = _open_project_regular(project, relative)
            with os.fdopen(descriptor, "rb") as handle:
                current = handle.read(MAX_LARGE_FILE + 1)
            if _sha(current) != entry["baseline_sha256"]:
                raise ValueError("A staged project file changed before the capsule check.")
        else:
            current = b""
        candidate = _line_edit_candidate(current, entry["edit"]["start_line"], entry["edit"]["end_line"], entry["edit"]["replacement"])[0] if "edit" in entry else entry["content"].encode("utf-8")
        if _sha(candidate) != entry["candidate_sha256"]:
            raise ValueError("The staged candidate fingerprint changed.")
        target = os.path.join(snapshot, *relative.split("/"))
        if exists and not os.path.isfile(target):
            raise ValueError("The staged source was not included in the capsule snapshot.")
        if not exists and os.path.lexists(target):
            raise ValueError("A staged new file conflicts with the capsule snapshot.")
        previous_bytes = os.path.getsize(target) if exists else 0
        new_files = summary["files"] + (0 if exists else 1)
        new_bytes = summary["bytes"] - previous_bytes + len(candidate)
        if new_files > MAX_SNAPSHOT_FILES or new_bytes > MAX_SNAPSHOT_BYTES:
            raise ValueError("The candidate exceeds the capsule snapshot budget (250 files / 8 MiB).")
        _snapshot_parent(snapshot, relative)
        with open(target, "wb") as handle:
            handle.write(candidate)
        os.chmod(target, 0o644)
        summary.update(files=new_files, bytes=new_bytes)
        changed.append(relative)
    return changed


_PYTHON_SYNTAX = "import ast,pathlib,sys; [ast.parse(pathlib.Path(p).read_text(encoding='utf-8'),filename=p) for p in sys.argv[1:]]"
_NODE_SYNTAX = "const cp=require('child_process');for(const p of process.argv.slice(1)){const r=cp.spawnSync(process.execPath,['--check','./'+p],{encoding:'utf8',timeout:5000});if(r.status!==0){process.stderr.write((r.stderr||r.stdout||'syntax check failed')+'\\n');process.exitCode=1;}}"


def _command(check: str, changed: list[str]) -> list[str]:
    if check == "python_syntax":
        paths = [path for path in changed if path.endswith(".py")]
        if not paths:
            raise ValueError("No staged Python file is available for python_syntax.")
        return ["python", "-I", "-B", "-c", _PYTHON_SYNTAX, *paths]
    if check == "node_syntax":
        paths = [path for path in changed if path.endswith((".js", ".mjs", ".cjs"))]
        if not paths:
            raise ValueError("No staged JavaScript file is available for node_syntax.")
        return ["node", "-e", _NODE_SYNTAX, "--", *paths]
    if check == "python_unittest":
        return ["python", "-B", "-m", "unittest", "discover", "-s", "tests", "-v"]
    if check == "npm_test":
        return ["npm", "--offline", "--no-audit", "--no-fund", "test"]
    raise ValueError("Unsupported capsule check.")


def _run_container(docker: str, image: str, snapshot: str, command: list[str]) -> Dict[str, Any]:
    import secrets

    name = f"vps-guardian-capsule-{secrets.token_hex(8)}"
    args = [docker, "run", "--rm", "--pull=never", "--name", name, "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=65534:65534", "--cpus=0.5", "--memory=128m", "--memory-swap=128m", "--pids-limit=64", "--ulimit=nofile=128:128", "--log-driver=none", "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m", "--mount", f"type=bind,src={snapshot},dst=/workspace,readonly", "--workdir=/workspace", "--env=HOME=/tmp", "--env=TMPDIR=/tmp", "--env=PYTHONDONTWRITEBYTECODE=1", image, *command]
    output = bytearray()
    process = None
    timed_out = False
    cleanup_uncertain = False
    try:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        def drain() -> None:
            assert process is not None and process.stdout is not None
            while True:
                block = process.stdout.read(4096)
                if not block:
                    break
                remaining = MAX_OUTPUT_BYTES - len(output)
                if remaining > 0:
                    output.extend(block[:remaining])

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            returncode = process.wait(timeout=CHECK_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
            returncode = None
        reader.join(timeout=2)
    except OSError:
        return {"status": "unavailable", "success": False, "error": "Docker failed to start the capsule."}
    finally:
        if timed_out and process is not None:
            try:
                cleanup = subprocess.run([docker, "rm", "-f", "--volumes", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
                cleanup_uncertain = cleanup.returncode != 0
            except (OSError, subprocess.SubprocessError):
                cleanup_uncertain = True
        if process is not None and process.stdout is not None:
            process.stdout.close()
    clean, _ = _redact_config_text(output.decode("utf-8", errors="replace"))
    result = {"status": "ok" if returncode == 0 else "timeout" if timed_out else "unavailable" if returncode == 125 else "failed", "success": returncode == 0, "exit_code": returncode, "output_truncated": len(output) >= MAX_OUTPUT_BYTES}
    if cleanup_uncertain:
        result["cleanup_uncertain"] = True
    if returncode != 0:
        result["output"] = _scrub(clean)
    return result


def get_test_capsule_status() -> Dict[str, Any]:
    """Report prerequisites without pulling images or running project code."""
    return {"status": "ok", "linux": sys.platform.startswith("linux") and fcntl is not None, "docker_cli": bool(shutil.which("docker")), "available_memory_bytes": get_runtime_budget()["available_memory_bytes"], "checks": sorted(CHECKS), "limits": {"snapshot_files": MAX_SNAPSHOT_FILES, "snapshot_directories": MAX_SNAPSHOT_DIRS, "snapshot_entries": MAX_SNAPSHOT_ENTRIES, "snapshot_bytes": MAX_SNAPSHOT_BYTES, "container_memory_bytes": 128 * 1024 * 1024, "timeout_seconds": CHECK_TIMEOUT_SECONDS, "concurrent_capsules": 1}, "note": "Images must already be local. No source project is mounted; no network or production environment is passed."}


def test_project_patch(patch_id: str, check: str = "auto", confirmation_token: Optional[str] = None) -> Dict[str, Any]:
    """Test a staged candidate in a temporary copy; never touch the live project."""
    if not isinstance(patch_id, str) or not isinstance(check, str) or check not in CHECKS:
        return {"status": "error", "error": "An active patch_id and an allowlisted check are required.", "checks": sorted(CHECKS)}
    with _patch_lock:
        _cleanup_patches()
        item = _patches.get(patch_id)
        if not item or item["state"] != "staging" or not item["files"]:
            return {"status": "not_found", "error": "An active staged project patch is required."}
        selected = _check_name(item, check)
        if selected is None:
            return {"status": "error", "error": "auto requires staged source in one language (Python or JavaScript); choose an explicit check otherwise."}
        image, error = _preflight(selected)
        if error:
            return {"status": "unavailable", "error": error}
        fingerprint = _fingerprint(item)
        params = {"patch_id": patch_id, "project_path": item["project_path"], "fingerprint": fingerprint, "check": selected}
        auth = request_authorization("test_project_patch", params, "Execute staged project code only inside one resource-limited Docker capsule.", confirmation_token)
        if auth is not None:
            return auth
        if not _check_lock.acquire(blocking=False):
            return {"status": "busy", "error": "Another capsule check is running."}
        item["state"] = "testing"
        item["capsule_result"] = None
    descriptor = None
    started = time.monotonic()
    result: Dict[str, Any] = {}
    try:
        os.makedirs(_state_dir(), mode=0o700, exist_ok=True)
        lock_path = os.path.join(_state_dir(), "test-capsule.lock")
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"status": "busy", "error": "Another Guardian process is running a capsule."}
        with tempfile.TemporaryDirectory(prefix="vps-guardian-capsule-") as snapshot:
            os.chmod(snapshot, 0o755)
            summary = _copy_snapshot(item["project_path"], snapshot)
            changed = _apply_candidates(item, snapshot, summary)
            if selected == "python_unittest" and not any(name.startswith("test") and name.endswith(".py") for _, _, files in os.walk(os.path.join(snapshot, "tests")) for name in files):
                raise ValueError("No Python unittest files were included in the capsule snapshot.")
            if selected == "npm_test" and not os.path.isfile(os.path.join(snapshot, "package.json")):
                raise ValueError("No package.json was included in the capsule snapshot.")
            command = _command(selected, changed)
            result = _run_container(shutil.which("docker") or "docker", image, snapshot, command)
            result.update({"patch_id": patch_id, "check": selected, "candidate_fingerprint": fingerprint, "snapshot": summary, "duration_seconds": round(time.monotonic() - started, 2)})
            return result
    except (OSError, ValueError, UnicodeError) as exc:
        result = {"status": "error", "success": False, "patch_id": patch_id, "check": selected, "error": _scrub(str(exc))}
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if result:
            result["audit_log_path"] = record_audit_event("test_project_patch", params, {key: result.get(key) for key in ("status", "success", "check", "candidate_fingerprint", "duration_seconds")})
        with _patch_lock:
            current = _patches.get(patch_id)
            if current is item:
                item["state"] = "staging"
                item["capsule_result"] = {key: result.get(key) for key in ("status", "success", "check", "candidate_fingerprint", "duration_seconds")}
        _check_lock.release()


def promote_tested_project_patch(patch_id: str, confirmation_token: Optional[str] = None) -> Dict[str, Any]:
    """Apply only the same candidate that passed a capsule, using patch confirmation/backups."""
    with _patch_lock:
        _cleanup_patches()
        item = _patches.get(patch_id) if isinstance(patch_id, str) else None
        if not item or item["state"] != "staging":
            return {"status": "not_found", "error": "An active staged project patch is required."}
        tested = item.get("capsule_result") or {}
        if not tested.get("success") or tested.get("candidate_fingerprint") != _fingerprint(item):
            return {"status": "forbidden", "error": "This exact candidate has not passed a capsule check."}
        return apply_project_patch(patch_id, confirmation_token)
