"""Bounded operator-only project metadata. Never read source or execute Git/code."""
from __future__ import annotations

import os
import re
import time
from types import SimpleNamespace
from src.access_policy import access_denial, control_path, load_policy
from src.project_workspace import IGNORED_DIRS, _project_path, _roots
from src.safe_io import directory_fd

MARKERS = {"package.json": "Node.js", "pyproject.toml": "Python", "requirements.txt": "Python",
           "go.mod": "Go", "Cargo.toml": "Rust", "compose.yaml": "Docker Compose", "docker-compose.yml": "Docker Compose"}
HIDDEN = re.compile(r"(?i)(^\.env(?:\.|$)|secret|credential|password|^id_(?:rsa|ed25519)|\.(?:pem|key|db|sqlite|log|bak)$)")
MAX_ENTRIES = 1000
MAX_DIRECTORIES = 100
MAX_PROJECTS = 50


def _entries(path, budget, deadline):
    # Linux metadata is relative to a pinned, no-follow directory descriptor.
    with directory_fd(path) as descriptor:
        with os.scandir(path if descriptor is None else descriptor) as iterator:
            for entry in iterator:
                if budget[0] >= MAX_ENTRIES or time.monotonic() >= deadline:
                    budget[1] = True
                    break
                budget[0] += 1
                absolute = os.path.join(path, entry.name)
                if entry.is_symlink() or control_path(absolute):
                    continue
                yield SimpleNamespace(name=entry.name, path=absolute, is_file=entry.is_file,
                                      is_dir=entry.is_dir, stat=entry.stat)


def list_operator_projects() -> dict:
    roots = _roots()[:16]
    pending = [(root, 0) for root in roots]
    projects, errors, visited = [], 0, 0
    budget, deadline = [0, False], time.monotonic() + 2
    while pending and len(projects) < MAX_PROJECTS and visited < MAX_DIRECTORIES and not budget[1]:
        current, depth = pending.pop()
        visited += 1
        if control_path(current) or os.path.islink(current):
            continue
        names, directories, git = set(), [], False
        try:
            for entry in _entries(current, budget, deadline):
                if entry.name == ".git":
                    git = True
                if entry.is_file(follow_symlinks=False):
                    names.add(entry.name)
                elif entry.is_dir(follow_symlinks=False) and entry.name not in IGNORED_DIRS and not entry.name.startswith(".") and not HIDDEN.search(entry.name):
                    directories.append(entry.path)
        except OSError:
            errors += 1
            continue
        stacks = sorted({kind for name, kind in MARKERS.items() if name in names})
        if stacks or git:
            projects.append({"path": current, "name": os.path.basename(current)[:128], "stacks": stacks, "git": git})
        if depth < 3:
            pending.extend((directory, depth + 1) for directory in directories[:MAX_DIRECTORIES])
    return {"status": "ok", "projects": sorted(projects, key=lambda item: item["path"]), "roots": roots,
            "roots_source": "managed" if load_policy()["policy"]["project_roots"] is not None else "operator_launch_defaults",
            "truncated": budget[1] or bool(pending), "scanned_entries": budget[0], "unavailable_directories": errors,
            "note": "Bounded metadata scan only. Missing projects may be outside roots, beyond the scan budget, or have no recognized marker. Inherited roots can differ between agent launch environments."}


def inspect_operator_project(project_path: str) -> dict:
    if not isinstance(project_path, str) or len(project_path) > 1024 or any(ord(c) < 32 for c in project_path):
        return {"status": "error", "error": "Supply an absolute project directory."}
    if not os.path.isabs(project_path) or os.path.islink(project_path):
        return {"status": "forbidden", "error": "An absolute non-symlink directory inside configured project roots is required."}
    path, error = _project_path(project_path)
    if error:
        return error
    files, budget, deadline = [], [0, False], time.monotonic() + 2
    try:
        for entry in _entries(path, budget, deadline):
            if entry.name.startswith(".") or HIDDEN.search(entry.name) or entry.name in IGNORED_DIRS:
                continue
            if not entry.is_file(follow_symlinks=False) and not entry.is_dir(follow_symlinks=False):
                continue
            info = entry.stat(follow_symlinks=False)
            files.append({"name": entry.name[:128], "kind": "directory" if entry.is_dir(follow_symlinks=False) else "file",
                          "size_bytes": info.st_size if entry.is_file(follow_symlinks=False) else None,
                          "readable_by_ssh_user": os.access(entry.path, os.R_OK)})
            if len(files) >= 80:
                budget[1] = True
                break
    except OSError:
        return {"status": "unavailable", "error": "Project metadata is not readable by this SSH user."}
    names = {item["name"] for item in files}
    return {"status": "ok", "path": path, "name": os.path.basename(path)[:128],
            "stacks": sorted({kind for name, kind in MARKERS.items() if name in names}),
            "files": sorted(files, key=lambda item: (item["kind"] != "directory", item["name"])), "truncated": budget[1],
            "agent_tools": {name: access_denial(name) is None for name in
                            ("discover_projects", "inspect_project", "read_project_file", "search_project_code", "begin_project_patch", "apply_project_patch")},
            "mode_cap": load_policy()["policy"]["mode_cap"],
            "note": "Top-level metadata only; hidden/sensitive names and links are excluded. Selecting a project does not change agent access. Read permission also depends on each agent's launch roots and OS rights."}
