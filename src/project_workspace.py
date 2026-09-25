"""Structured, bounded workspace tools for application projects on a VPS."""

from __future__ import annotations

import datetime as dt
import difflib
import hashlib
import ast
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
MAX_LARGE_FILE = 2_000_000
MAX_SEARCH_BYTES = 8_000_000
MAX_RANGE_LINES = 200
MAX_SYMBOLS = 200
MAX_EDIT_REPLACEMENT = 50_000
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
    current = project
    for part in relative.split(os.sep):
        current = os.path.join(current, part)
        if os.path.islink(current):
            return None, {"status": "forbidden", "error": "Project paths cannot contain symlinks."}
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
        return {"status": "ok", "relative_path": os.path.relpath(path, project).replace("\\", "/"), "content": text, "bytes_read": len(raw), "redacted_fields": count, "is_truncated": os.path.getsize(path) > limit, "next_step": "Use read_project_file_range for later lines." if os.path.getsize(path) > limit else None}
    except OSError as exc: return {"status": "error", "error": str(exc)}


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_project_file_range(project_path: str, relative_path: str, start_line: int = 1, max_lines: int = 80, max_bytes: int = 16_000, if_sha256: Optional[str] = None, byte_offset: Optional[int] = None) -> Dict[str, Any]:
    """Read a bounded line range without loading a large source file into memory."""
    project, error = _project_path(project_path)
    if error: return error
    path, error = _project_file(project, relative_path)
    if error: return error
    if not isinstance(start_line, int) or isinstance(start_line, bool) or start_line < 1:
        return {"status": "error", "error": "start_line must be a positive integer."}
    if not isinstance(max_lines, int) or not 1 <= max_lines <= MAX_RANGE_LINES:
        return {"status": "error", "error": f"max_lines must be 1-{MAX_RANGE_LINES}."}
    if not isinstance(max_bytes, int) or not 100 <= max_bytes <= MAX_FILE_READ:
        return {"status": "error", "error": f"max_bytes must be 100-{MAX_FILE_READ}."}
    if byte_offset is not None and (not isinstance(byte_offset, int) or isinstance(byte_offset, bool) or byte_offset < 0):
        return {"status": "error", "error": "byte_offset must be a non-negative integer."}
    try:
        size = os.path.getsize(path)
        if not os.path.isfile(path): return {"status": "error", "error": "Project file was not found."}
        if size > MAX_LARGE_FILE: return {"status": "error", "error": f"File exceeds the {MAX_LARGE_FILE}-byte range-read budget."}
        sha256 = _file_sha256(path)
        if if_sha256 == sha256: return {"status": "unchanged", "sha256": sha256, "size_bytes": size}
        if byte_offset is not None:
            if byte_offset > size: return {"status": "error", "error": "byte_offset exceeds file size."}
            with open(path, "rb") as handle:
                handle.seek(byte_offset); raw = handle.read(max_bytes)
            if b"\0" in raw[:1024]: return {"status": "error", "error": "Binary project files are not readable."}
            content, redacted = _redact_config_text(raw.decode("utf-8", errors="replace"))
            end = byte_offset + len(raw)
            return {"status": "ok", "relative_path": relative_path, "byte_offset": byte_offset, "next_byte_offset": end if end < size else None, "content": content, "bytes_read": len(raw), "size_bytes": size, "sha256": sha256, "redacted_fields": redacted, "is_truncated": end < size}
        selected = []; used = 0; next_line = start_line; more = False; scanned = 0
        with open(path, "rb") as handle:
            for number, line in enumerate(handle, 1):
                scanned += len(line)
                if number < start_line: continue
                if b"\0" in line[:1024]: return {"status": "error", "error": "Binary project files are not readable."}
                if len(selected) >= max_lines or used + len(line) > max_bytes:
                    more = True
                    if not selected:
                        selected.append(line[:max_bytes]); used = len(selected[0]); next_line = number + 1
                    break
                selected.append(line); used += len(line); next_line = number + 1
        content, redacted = _redact_config_text(b"".join(selected).decode("utf-8", errors="replace"))
        return {"status": "ok", "relative_path": relative_path, "start_line": start_line, "next_line": next_line if more else None, "content": content, "bytes_read": used, "size_bytes": size, "sha256": sha256, "redacted_fields": redacted, "is_truncated": more, "scanned_bytes": scanned}
    except OSError as exc: return {"status": "error", "error": str(exc)}


def get_project_symbols(project_path: str, relative_path: str, max_symbols: int = 100) -> Dict[str, Any]:
    """Return Python class/function locations without returning the source body."""
    project, error = _project_path(project_path)
    if error: return error
    path, error = _project_file(project, relative_path)
    if error: return error
    if not path.endswith(".py"): return {"status": "error", "error": "Symbol maps currently support Python files."}
    if not isinstance(max_symbols, int) or not 1 <= max_symbols <= MAX_SYMBOLS:
        return {"status": "error", "error": f"max_symbols must be 1-{MAX_SYMBOLS}."}
    try:
        if os.path.getsize(path) > MAX_LARGE_FILE: return {"status": "error", "error": "File exceeds the symbol-map budget."}
        with open(path, encoding="utf-8") as handle: source = handle.read(MAX_LARGE_FILE + 1)
        tree = ast.parse(source, filename=path)
        symbols = []
        def walk(body: List[ast.stmt], prefix: str = "") -> None:
            for node in body:
                if len(symbols) >= max_symbols: return
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    name = f"{prefix}{node.name}"
                    symbols.append({"name": name, "kind": "class" if isinstance(node, ast.ClassDef) else "async_function" if isinstance(node, ast.AsyncFunctionDef) else "function", "start_line": node.lineno, "end_line": node.end_lineno})
                    walk(node.body, name + ".")
        walk(tree.body)
        return {"status": "ok", "relative_path": relative_path, "sha256": hashlib.sha256(source.encode()).hexdigest(), "symbols": symbols, "truncated": len(symbols) >= max_symbols}
    except (OSError, UnicodeError, SyntaxError) as exc: return {"status": "error", "error": str(exc)[:300]}


def search_project_code(project_path: str, query: str, max_matches: int = 50) -> Dict[str, Any]:
    project, error = _project_path(project_path)
    if error: return error
    if not isinstance(query, str) or not 1 <= len(query.strip()) <= 200 or any(ord(item) < 32 for item in query):
        return {"status": "error", "error": "query must contain 1 to 200 printable characters."}
    limit = max(1, min(int(max_matches), MAX_MATCHES)); matches = []; scanned = 0; scanned_bytes = 0; needle = query.lower(); truncated = False
    for current, dirs, files in os.walk(project, followlinks=False):
        if truncated or scanned >= MAX_FILES_SCANNED or len(matches) >= limit: break
        dirs[:] = [item for item in dirs if item not in IGNORED_DIRS and not os.path.islink(os.path.join(current, item))]
        for name in sorted(files):
            if scanned >= MAX_FILES_SCANNED or len(matches) >= limit: break
            path = os.path.join(current, name)
            if os.path.islink(path): continue
            try: size = os.path.getsize(path)
            except OSError: continue
            if size > MAX_LARGE_FILE: continue
            if scanned_bytes + size > MAX_SEARCH_BYTES:
                truncated = True; break
            scanned_bytes += size
            scanned += 1
            try:
                with open(path, encoding="utf-8", errors="replace") as handle:
                    for number, line in enumerate(handle, 1):
                        if needle in line.lower():
                            clean, _ = _redact_config_text(line.strip())
                            matches.append({"relative_path": os.path.relpath(path, project).replace("\\", "/"), "line": number, "text": clean[:500]})
                            if len(matches) >= limit: break
            except OSError: continue
    return {"status": "ok", "query": query, "scanned_files": scanned, "scanned_bytes": scanned_bytes, "matches": matches, "truncated": truncated or scanned >= MAX_FILES_SCANNED or len(matches) >= limit}


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
            if os.path.isfile(path) and os.path.getsize(path) > MAX_LARGE_FILE:
                return {"status": "error", "error": "Existing file exceeds the patch budget; use a smaller file."}
            original = _read_bytes(path) if os.path.isfile(path) else b""
        except OSError as exc: return {"status": "error", "error": str(exc)}
        existing = next((entry for entry in item["files"] if entry["path"] == path), None)
        total = sum(entry.get("staged_bytes", len(entry.get("content", "").encode("utf-8"))) for entry in item["files"] if entry is not existing) + len(content.encode("utf-8"))
        if total > MAX_PATCH_BYTES or (existing is None and len(item["files"]) >= MAX_PATCH_FILES): return {"status": "error", "error": "Patch exceeds its file-count or size budget."}
        entry = {"path": path, "relative_path": os.path.relpath(path, item["project_path"]).replace("\\", "/"), "original": original, "content": content, "staged_bytes": len(content.encode("utf-8")), "existed": os.path.isfile(path), "baseline_sha256": hashlib.sha256(original).hexdigest() if os.path.isfile(path) else None, "candidate_sha256": hashlib.sha256(content.encode()).hexdigest()}
        if existing: item["files"].remove(existing)
        item["files"].append(entry)
        item["capsule_result"] = None
        return {"status": "ok", "file": _public_file(entry), "patch": _public_patch(item)}


def _line_edit_candidate(raw: bytes, start_line: int, end_line: int, replacement: str) -> tuple[bytes, str]:
    source = raw.decode("utf-8")
    lines = source.splitlines(keepends=True)
    if start_line < 1 or end_line < start_line - 1 or end_line > len(lines) or start_line > len(lines) + 1:
        raise ValueError("Line range is outside the file; an insertion uses end_line=start_line-1.")
    original = "".join(lines[start_line - 1:end_line])
    candidate = "".join(lines[:start_line - 1]) + replacement + "".join(lines[end_line:])
    return candidate.encode("utf-8"), original


def stage_project_line_edit(patch_id: str, relative_path: str, start_line: int, end_line: int, replacement: str, expected_sha256: Optional[str] = None) -> Dict[str, Any]:
    """Stage a source edit by line range; the model only sends the changed text."""
    if not isinstance(replacement, str) or len(replacement.encode("utf-8")) > MAX_EDIT_REPLACEMENT:
        return {"status": "error", "error": f"replacement must be text up to {MAX_EDIT_REPLACEMENT} bytes."}
    if not isinstance(start_line, int) or isinstance(start_line, bool) or not isinstance(end_line, int) or isinstance(end_line, bool):
        return {"status": "error", "error": "start_line and end_line must be integers."}
    with _patch_lock:
        _cleanup_patches(); item = _patches.get(patch_id)
        if not item or item["state"] != "staging": return {"status": "not_found", "error": "Patch is missing, expired, or already used."}
        path, error = _project_file(item["project_path"], relative_path)
        if error: return error
        if not os.path.isfile(path): return {"status": "error", "error": "Project file was not found."}
        try:
            if os.path.getsize(path) > MAX_LARGE_FILE: return {"status": "error", "error": "File exceeds the line-edit budget."}
            original = _read_bytes(path)
            if b"\0" in original[:1024]: return {"status": "error", "error": "Binary files cannot be edited."}
            baseline = hashlib.sha256(original).hexdigest()
            if expected_sha256 is not None and expected_sha256 != baseline:
                return {"status": "conflict", "error": "File changed since it was inspected."}
            candidate, old_lines = _line_edit_candidate(original, start_line, end_line, replacement)
        except (OSError, UnicodeError, ValueError) as exc: return {"status": "error", "error": str(exc)[:300]}
        if len(candidate) > MAX_LARGE_FILE: return {"status": "error", "error": "Edited file exceeds the line-edit budget."}
        existing = next((entry for entry in item["files"] if entry["path"] == path), None)
        total = sum(entry.get("staged_bytes", len(entry.get("content", "").encode("utf-8"))) for entry in item["files"] if entry is not existing) + len(replacement.encode("utf-8"))
        if total > MAX_PATCH_BYTES or (existing is None and len(item["files"]) >= MAX_PATCH_FILES):
            return {"status": "error", "error": "Patch exceeds its file-count or size budget."}
        entry = {"path": path, "relative_path": os.path.relpath(path, item["project_path"]).replace("\\", "/"), "existed": True, "baseline_sha256": baseline, "candidate_sha256": hashlib.sha256(candidate).hexdigest(), "staged_bytes": len(replacement.encode("utf-8")), "edit": {"start_line": start_line, "end_line": end_line, "replacement": replacement, "old_lines": old_lines[:MAX_DIFF_CHARS], "old_truncated": len(old_lines) > MAX_DIFF_CHARS}}
        if existing: item["files"].remove(existing)
        item["files"].append(entry)
        item["capsule_result"] = None
        return {"status": "ok", "file": _public_file(entry), "patch": _public_patch(item)}


def preview_project_patch(patch_id: str) -> Dict[str, Any]:
    with _patch_lock:
        _cleanup_patches(); item = _patches.get(patch_id)
        if not item or item["state"] != "staging" or not item["files"]: return {"status": "error", "error": "An active patch with staged files is required."}
        diffs = []
        for entry in item["files"]:
            if "edit" in entry:
                before, _ = _redact_config_text(entry["edit"]["old_lines"])
                after, _ = _redact_config_text(entry["edit"]["replacement"])
            else:
                before, _ = _redact_config_text(entry["original"].decode("utf-8", errors="replace")); after, _ = _redact_config_text(entry["content"])
            diff = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile=f"{entry['relative_path']} (current)", tofile=f"{entry['relative_path']} (candidate)"))
            if "edit" in entry:
                diff = f"Line range {entry['edit']['start_line']}-{entry['edit']['end_line']}\n" + diff
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
        pending_writes = []
        for entry in item["files"]:
            stable = os.path.realpath(entry["path"])
            if stable != entry["path"] or not _within(stable, item["project_path"]) or os.path.islink(entry["path"]):
                return {"status": "forbidden", "success": False, "error": "Project file path changed after staging; refusing to write."}
            current = _read_bytes(stable) if os.path.isfile(stable) else b""
            if (hashlib.sha256(current).hexdigest() if os.path.isfile(entry["path"]) else None) != entry["baseline_sha256"]: return {"status": "conflict", "success": False, "error": "Project file changed after staging; prepare a new patch."}
            if "edit" in entry:
                try:
                    candidate, _ = _line_edit_candidate(current, entry["edit"]["start_line"], entry["edit"]["end_line"], entry["edit"]["replacement"])
                    if hashlib.sha256(candidate).hexdigest() != entry["candidate_sha256"]:
                        return {"status": "conflict", "success": False, "error": "Line edit candidate changed after staging."}
                    pending_writes.append((entry["path"], candidate.decode("utf-8")))
                except (UnicodeError, ValueError) as exc: return {"status": "error", "success": False, "error": str(exc)[:300]}
            else:
                pending_writes.append((entry["path"], entry["content"]))
        item["state"] = "applying"
    writes = [atomic_write_file(path, content, backup=True) for path, content in pending_writes]
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


def get_project_diff(project_path: str, relative_path: Optional[str] = None, staged: bool = False, context_lines: int = 3, max_bytes: int = 12_000) -> Dict[str, Any]:
    project, error = _project_path(project_path)
    if error: return error
    if not isinstance(context_lines, int) or not 0 <= context_lines <= 10 or not isinstance(max_bytes, int) or not 500 <= max_bytes <= 30_000:
        return {"status": "error", "error": "context_lines must be 0-10 and max_bytes must be 500-30000."}
    path_args = []
    if relative_path is not None:
        _, error = _project_file(project, relative_path)
        if error: return error
        path_args = ["--", relative_path]
    git = shutil.which("git")
    if not git: return {"status": "unavailable", "error": "Git is not installed."}
    args = [git, "-C", project, "diff", "--no-ext-diff", "--no-textconv", f"--unified={context_lines}"]
    if staged: args.append("--cached")
    try:
        process = subprocess.Popen([*args, *path_args], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        timed_out = False
        def stop_if_running() -> None:
            nonlocal timed_out
            if process.poll() is None:
                timed_out = True; process.kill()
        timer = threading.Timer(8, stop_if_running); timer.daemon = True; timer.start()
        try:
            raw = process.stdout.read(max_bytes + 1) if process.stdout else b""
            if len(raw) > max_bytes and process.poll() is None: process.kill()
            process.wait(timeout=2)
        finally:
            timer.cancel()
            if process.stdout: process.stdout.close()
        clean, redacted = _redact_config_text(raw.decode("utf-8", errors="replace"))
        return {"status": "ok" if not timed_out and (process.returncode == 0 or len(raw) > max_bytes) else "error", "diff": clean[:max_bytes], "redacted_fields": redacted, "is_truncated": len(raw) > max_bytes, "relative_path": relative_path, "staged": staged, "error": "Git diff timed out." if timed_out else f"Git diff exited {process.returncode}." if process.returncode and len(raw) <= max_bytes else None}
    except (OSError, subprocess.SubprocessError) as exc: return {"status": "error", "error": str(exc)[:300]}


def run_project_checks(project_path: str, check: str = "auto") -> Dict[str, Any]:
    project, error = _project_path(project_path)
    if error: return error
    selected = check.strip().lower() if isinstance(check, str) else ""
    choices = {"auto", "python_compile", "node_check", "compose_config", "git_diff_check"}
    if selected not in choices: return {"status": "error", "error": "check must be auto, python_compile, node_check, compose_config, or git_diff_check."}
    if selected == "auto":
        selected = "python_compile" if os.path.isfile(os.path.join(project, "pyproject.toml")) else "node_check" if os.path.isfile(os.path.join(project, "package.json")) else "git_diff_check"
    if selected == "git_diff_check": return {"status": "ok", "check": selected, "result": _git(project, ["diff", "--check"])}
    if selected == "compose_config":
        from_file = next((os.path.join(project, name) for name in ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml") if os.path.isfile(os.path.join(project, name))), None)
        docker = shutil.which("docker")
        if not from_file or not docker: return {"status": "unavailable", "check": selected, "error": "Compose file or Docker CLI is unavailable."}
        try:
            result = subprocess.run([docker, "compose", "-f", from_file, "config", "--quiet"], cwd=project, capture_output=True, text=True, timeout=15, check=False)
            return {"status": "ok" if result.returncode == 0 else "error", "check": selected, "success": result.returncode == 0, "output": ((result.stdout or "") + (result.stderr or ""))[:1000]}
        except (OSError, subprocess.SubprocessError) as exc: return {"status": "error", "check": selected, "error": str(exc)[:300]}
    if selected == "node_check":
        node = shutil.which("node")
        if not node: return {"status": "unavailable", "check": selected, "error": "Node.js is unavailable."}
        files = []
        for current, dirs, names in os.walk(project, followlinks=False):
            dirs[:] = [name for name in dirs if name not in IGNORED_DIRS and not os.path.islink(os.path.join(current, name))]
            for name in names:
                path = os.path.join(current, name)
                if name.endswith((".js", ".mjs", ".cjs")) and not os.path.islink(path) and os.path.getsize(path) <= MAX_LARGE_FILE: files.append(path)
                if len(files) >= 30: break
            if len(files) >= 30: break
        deadline = time.monotonic() + 20; failures = []
        for path in files:
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0: return {"status": "error", "check": selected, "error": "Node syntax check timed out.", "checked_files": len(files) - len(failures)}
                result = subprocess.run([node, "--check", path], cwd=project, capture_output=True, text=True, timeout=min(remaining, 5), check=False)
                if result.returncode: failures.append({"file": os.path.relpath(path, project), "output": ((result.stdout or "") + (result.stderr or ""))[:500]})
            except (OSError, subprocess.SubprocessError) as exc: failures.append({"file": os.path.relpath(path, project), "output": str(exc)[:300]})
        return {"status": "ok" if not failures else "error", "check": selected, "success": not failures, "checked_files": len(files), "truncated": len(files) >= 30, "failures": failures[:10]}
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
def _public_patch(item: Dict[str, Any]) -> Dict[str, Any]: return {"patch_id": item["patch_id"], "project_path": item["project_path"], "title": item["title"], "state": item["state"], "file_count": len(item["files"]), "files": [_public_file(entry) for entry in item["files"]], "capsule_result": item.get("capsule_result"), "expires_at": dt.datetime.fromtimestamp(item["expires_at"], dt.timezone.utc).isoformat()}
