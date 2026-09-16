"""Structured, bounded workspace tools for application projects on a VPS."""

from __future__ import annotations

import datetime as dt
import difflib
import hashlib
import os
import secrets
import shutil
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

try:
    from src.files import _redact_config_text, atomic_write_file
    from src.safety import record_audit_event, request_authorization
except ImportError:
    from files import _redact_config_text, atomic_write_file
    from safety import record_audit_event, request_authorization


MAX_PROJECTS = 50
MAX_FILES_SCANNED = 1000
MAX_MATCHES = 100
MAX_FILE_READ = 100_000
MAX_PATCHES = 24
MAX_PATCH_FILES = 3
MAX_PATCH_BYTES = 300_000
PATCH_TTL_SECONDS = 300
MAX_DIFF_CHARS = 12_000
IGNORED_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next"}
_patches: Dict[str, Dict[str, Any]] = {}
_patch_lock = threading.RLock()


def _roots() -> List[str]:
    configured = [item.strip() for item in os.environ.get("VPS_GUARDIAN_PROJECT_ROOTS", "").split(os.pathsep) if item.strip()]
    defaults = configured or (["/var/www", "/opt", "/srv"] if os.name != "nt" else [os.path.realpath(".")])
    return [os.path.realpath(path) for path in defaults if os.path.isdir(path)]


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root + os.sep)


def _project_path(value: str) -> tuple[Optional[str], Optional[Dict[str, Any]]]:
    if not isinstance(value, str) or not value.strip():
        return None, {"status": "error", "error": "project_path must be a non-empty string."}
    path = os.path.realpath(os.path.abspath(value.strip()))
    if not any(_within(path, root) for root in _roots()):
        return None, {"status": "forbidden", "error": "Project is outside configured project roots.", "project_path": path}
    if not os.path.isdir(path) or os.path.islink(path):
        return None, {"status": "error", "error": "project_path must be an existing non-symlink directory.", "project_path": path}
    return path, None


def _git(path: str, args: List[str], timeout: int = 8) -> Dict[str, Any]:
    git = shutil.which("git")
    if not git: return {"available": False, "output": ""}
    try:
        result = subprocess.run([git, "-C", path, *args], capture_output=True, text=True, timeout=timeout, check=False)
        return {"available": True, "success": result.returncode == 0, "output": ((result.stdout or "") + (result.stderr or ""))[:4000]}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": True, "success": False, "output": str(exc)}


def discover_projects(root_path: Optional[str] = None, max_depth: int = 3) -> Dict[str, Any]:
    roots = _roots() if root_path is None else [_project_path(root_path)[0]]
    if not roots or any(root is None for root in roots):
        return {"status": "error", "error": "No valid project root is available.", "projects": []}
    depth = max(0, min(int(max_depth), 4))
    projects: List[Dict[str, Any]] = []
    markers = {"package.json": "node", "pyproject.toml": "python", "requirements.txt": "python", "go.mod": "go", "Cargo.toml": "rust"}
    for root in roots:
        base = root.rstrip(os.sep).count(os.sep)
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [item for item in dirs if item not in IGNORED_DIRS and not os.path.islink(os.path.join(current, item))]
            if current.rstrip(os.sep).count(os.sep) - base >= depth: dirs.clear()
            stack = sorted({kind for marker, kind in markers.items() if marker in files})
            if ".git" in dirs or stack:
                projects.append({"project_path": current, "name": os.path.basename(current), "stacks": stack, "is_git_repository": ".git" in dirs})
                dirs.clear()
                if len(projects) >= MAX_PROJECTS:
                    return {"status": "ok", "projects": projects, "truncated": True}
    return {"status": "ok", "projects": projects, "truncated": False}


def inspect_project(project_path: str) -> Dict[str, Any]:
    path, error = _project_path(project_path)
    if error: return error
    files = set(os.listdir(path))
    stack = []
    for marker, kind in (("package.json", "node"), ("pyproject.toml", "python"), ("requirements.txt", "python"), ("go.mod", "go"), ("Cargo.toml", "rust")):
        if marker in files: stack.append(kind)
    git_status = _git(path, ["status", "--porcelain=v1"])
    git_commit = _git(path, ["rev-parse", "--short", "HEAD"])
    git_branch = _git(path, ["branch", "--show-current"])
    return {"status": "ok", "project_path": path, "name": os.path.basename(path), "stacks": sorted(set(stack)), "files": sorted(item for item in files if item in {"package.json", "pyproject.toml", "requirements.txt", "go.mod", "Cargo.toml", "docker-compose.yml", "compose.yaml", "Dockerfile"}), "git": {"available": git_status["available"], "dirty": bool(git_status.get("output", "").strip()) if git_status.get("success") else None, "commit": git_commit.get("output", "").strip() if git_commit.get("success") else None, "branch": git_branch.get("output", "").strip() if git_branch.get("success") else None}}


def _safe_relative(path: str) -> Optional[str]:
    if not isinstance(path, str) or not path or os.path.isabs(path): return None
    normalized = os.path.normpath(path)
    return normalized if normalized != ".." and not normalized.startswith(f"..{os.sep}") else None


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _project_file(project: str, relative_path: str) -> tuple[Optional[str], Optional[Dict[str, Any]]]:
    relative = _safe_relative(relative_path)
    if not relative: return None, {"status": "error", "error": "relative_path must stay inside the project."}
    candidate = os.path.realpath(os.path.join(project, relative))
    if not _within(candidate, project) or os.path.islink(candidate):
        return None, {"status": "forbidden", "error": "Path escapes the project or is a symlink."}
    return candidate, None


def read_project_file(project_path: str, relative_path: str, max_bytes: int = 50_000) -> Dict[str, Any]:
    project, error = _project_path(project_path)
    if error: return error
    path, error = _project_file(project, relative_path)
    if error: return error
    if not os.path.isfile(path): return {"status": "error", "error": "Project file was not found."}
    limit = max(100, min(int(max_bytes), MAX_FILE_READ))
    try:
        with open(path, "rb") as handle: raw = handle.read(limit)
        if b"\0" in raw[:1024]: return {"status": "error", "error": "Binary project files are not readable."}
        text, count = _redact_config_text(raw.decode("utf-8", errors="replace"))
        return {"status": "ok", "relative_path": os.path.relpath(path, project).replace("\\", "/"), "content": text, "bytes_read": len(raw), "redacted_fields": count, "is_truncated": os.path.getsize(path) > limit}
    except OSError as exc: return {"status": "error", "error": str(exc)}


def search_project_code(project_path: str, query: str, max_matches: int = 50) -> Dict[str, Any]:
    project, error = _project_path(project_path)
    if error: return error
    if not isinstance(query, str) or not 1 <= len(query.strip()) <= 200 or any(ord(item) < 32 for item in query):
        return {"status": "error", "error": "query must contain 1 to 200 printable characters."}
    limit = max(1, min(int(max_matches), MAX_MATCHES)); matches = []; scanned = 0; needle = query.lower()
    for current, dirs, files in os.walk(project, followlinks=False):
        dirs[:] = [item for item in dirs if item not in IGNORED_DIRS and not os.path.islink(os.path.join(current, item))]
        for name in sorted(files):
            if scanned >= MAX_FILES_SCANNED or len(matches) >= limit: break
            path = os.path.join(current, name)
            if os.path.islink(path) or os.path.getsize(path) > MAX_FILE_READ: continue
            scanned += 1
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    for number, line in enumerate(handle, 1):
                        if needle in line.lower():
                            clean, _ = _redact_config_text(line.strip())
                            matches.append({"relative_path": os.path.relpath(path, project).replace("\\", "/"), "line": number, "text": clean[:500]})
                            if len(matches) >= limit: break
            except OSError: continue
    return {"status": "ok", "query": query, "scanned_files": scanned, "matches": matches, "truncated": scanned >= MAX_FILES_SCANNED or len(matches) >= limit}


def _cleanup_patches() -> None:
    now = time.time()
    for patch_id in [key for key, item in _patches.items() if item["expires_at"] <= now]: _patches.pop(patch_id, None)
    while len(_patches) >= MAX_PATCHES: _patches.pop(min(_patches, key=lambda key: _patches[key]["expires_at"]), None)


def begin_project_patch(project_path: str, title: str) -> Dict[str, Any]:
    project, error = _project_path(project_path)
    if error: return error
    if not isinstance(title, str) or not 3 <= len(title.strip()) <= 160: return {"status": "error", "error": "title must contain 3 to 160 characters."}
    patch_id = f"patch_{secrets.token_urlsafe(10)}"; now = time.time()
    item = {"patch_id": patch_id, "project_path": project, "title": title.strip(), "created_at": dt.datetime.now(dt.timezone.utc).isoformat(), "expires_at": now + PATCH_TTL_SECONDS, "state": "staging", "files": []}
    with _patch_lock: _cleanup_patches(); _patches[patch_id] = item
    return {"status": "ok", "patch": _public_patch(item)}


def stage_project_file_change(patch_id: str, relative_path: str, content: str) -> Dict[str, Any]:
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_FILE_READ: return {"status": "error", "error": "content must be text up to 100,000 bytes."}
    with _patch_lock:
        _cleanup_patches(); item = _patches.get(patch_id)
        if not item or item["state"] != "staging": return {"status": "not_found", "error": "Patch is missing, expired, or already used."}
        path, error = _project_file(item["project_path"], relative_path)
        if error: return error
        try:
            original = _read_bytes(path) if os.path.isfile(path) else b""
        except OSError as exc: return {"status": "error", "error": str(exc)}
        existing = next((entry for entry in item["files"] if entry["path"] == path), None)
        total = sum(len(entry["content"].encode("utf-8")) for entry in item["files"] if entry is not existing) + len(content.encode("utf-8"))
        if total > MAX_PATCH_BYTES or (existing is None and len(item["files"]) >= MAX_PATCH_FILES): return {"status": "error", "error": "Patch exceeds its file-count or size budget."}
        entry = {"path": path, "relative_path": os.path.relpath(path, item["project_path"]).replace("\\", "/"), "original": original, "content": content, "existed": os.path.isfile(path), "baseline_sha256": hashlib.sha256(original).hexdigest() if os.path.isfile(path) else None, "candidate_sha256": hashlib.sha256(content.encode()).hexdigest()}
        if existing: item["files"].remove(existing)
        item["files"].append(entry)
        return {"status": "ok", "file": _public_file(entry), "patch": _public_patch(item)}


def preview_project_patch(patch_id: str) -> Dict[str, Any]:
    with _patch_lock:
        _cleanup_patches(); item = _patches.get(patch_id)
        if not item or item["state"] != "staging" or not item["files"]: return {"status": "error", "error": "An active patch with staged files is required."}
        diffs = []
        for entry in item["files"]:
            before, _ = _redact_config_text(entry["original"].decode("utf-8", errors="replace")); after, _ = _redact_config_text(entry["content"])
            diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile=f"{entry['relative_path']} (current)", tofile=f"{entry['relative_path']} (candidate)"))
            diffs.append({"relative_path": entry["relative_path"], "diff": diff[:MAX_DIFF_CHARS], "diff_truncated": len(diff) > MAX_DIFF_CHARS})
        params = {"patch_id": patch_id, "project_path": item["project_path"], "files": [_public_file(entry) for entry in item["files"]]}
        auth = request_authorization("apply_project_patch", params, "Apply a bounded source patch with backups; no code is executed.")
        return {"status": "confirmation_required" if auth else "ok", "patch": _public_patch(item), "diffs": diffs, "execution": auth, "confirmation_token": auth.get("confirmation_token") if auth else None}


def apply_project_patch(patch_id: str, confirmation_token: Optional[str] = None) -> Dict[str, Any]:
    with _patch_lock:
        _cleanup_patches(); item = _patches.get(patch_id)
        if not item or item["state"] != "staging" or not item["files"]: return {"status": "not_found", "success": False, "error": "An active patch with staged files is required."}
        params = {"patch_id": patch_id, "project_path": item["project_path"], "files": [_public_file(entry) for entry in item["files"]]}
        auth = request_authorization("apply_project_patch", params, "Apply a bounded source patch with backups; no code is executed.", confirmation_token)
        if auth is not None: return auth
        for entry in item["files"]:
            stable = os.path.realpath(entry["path"])
            if stable != entry["path"] or not _within(stable, item["project_path"]) or os.path.islink(entry["path"]):
                return {"status": "forbidden", "success": False, "error": "Project file path changed after staging; refusing to write."}
            current = _read_bytes(stable) if os.path.isfile(stable) else b""
            if (hashlib.sha256(current).hexdigest() if os.path.isfile(entry["path"]) else None) != entry["baseline_sha256"]: return {"status": "conflict", "success": False, "error": "Project file changed after staging; prepare a new patch."}
        item["state"] = "applying"
    writes = [atomic_write_file(entry["path"], entry["content"], backup=True) for entry in item["files"]]
    success = all(item.get("success") for item in writes)
    with _patch_lock: _patches.pop(patch_id, None)
    result = {"status": "ok" if success else "error", "success": success, "patch_id": patch_id, "writes": writes, "note": "Use run_project_checks after applying; source code was not executed automatically."}
    result["audit_log_path"] = record_audit_event("apply_project_patch", params, result)
    return result


def get_project_changes(project_path: str) -> Dict[str, Any]:
    project, error = _project_path(project_path)
    if error: return error
    status = _git(project, ["status", "--porcelain=v1"]); diff = _git(project, ["diff", "--stat"])
    return {"status": "ok", "project_path": project, "git_available": status["available"], "changes": status.get("output", "")[:4000], "diff_stat": diff.get("output", "")[:4000]}


def run_project_checks(project_path: str, check: str = "auto") -> Dict[str, Any]:
    project, error = _project_path(project_path)
    if error: return error
    selected = check.strip().lower() if isinstance(check, str) else ""
    if selected not in {"auto", "python_compile", "git_diff_check"}: return {"status": "error", "error": "check must be auto, python_compile, or git_diff_check."}
    if selected == "auto": selected = "python_compile" if os.path.isfile(os.path.join(project, "pyproject.toml")) else "git_diff_check"
    if selected == "git_diff_check": return {"status": "ok", "check": selected, "result": _git(project, ["diff", "--check"])}
    python = shutil.which("python3") or shutil.which("python")
    if not python: return {"status": "unavailable", "error": "Python is unavailable for syntax checking."}
    files: List[str] = []
    for current, dirs, names in os.walk(project, followlinks=False):
        dirs[:] = [item for item in dirs if item not in IGNORED_DIRS and not os.path.islink(os.path.join(current, item))]
        for name in names:
            path = os.path.join(current, name)
            if name.endswith(".py") and not os.path.islink(path): files.append(path)
            if len(files) >= 200: break
        if len(files) >= 200: break
    checker = "import ast,pathlib,sys; [ast.parse(pathlib.Path(p).read_text(encoding='utf-8'), filename=p) for p in sys.argv[1:]]"
    try:
        result = subprocess.run([python, "-B", "-c", checker, *files], capture_output=True, text=True, timeout=20, check=False)
        return {"status": "ok" if result.returncode == 0 else "error", "check": selected, "success": result.returncode == 0, "checked_files": len(files), "truncated": len(files) >= 200, "output": ((result.stdout or "") + (result.stderr or ""))[:4000]}
    except (OSError, subprocess.SubprocessError) as exc: return {"status": "error", "check": selected, "success": False, "error": str(exc)}


def _public_file(entry: Dict[str, Any]) -> Dict[str, Any]: return {key: entry[key] for key in ("relative_path", "existed", "baseline_sha256", "candidate_sha256")}
def _public_patch(item: Dict[str, Any]) -> Dict[str, Any]: return {"patch_id": item["patch_id"], "project_path": item["project_path"], "title": item["title"], "state": item["state"], "file_count": len(item["files"]), "files": [_public_file(entry) for entry in item["files"]], "expires_at": dt.datetime.fromtimestamp(item["expires_at"], dt.timezone.utc).isoformat()}
