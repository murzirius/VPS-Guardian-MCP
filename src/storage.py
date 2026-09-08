"""Storage and disk usage analysis module for VPS-Guardian-MCP.

Provides safe, recursive disk usage inspection to help AI agents pinpoint
space bottlenecks (bloated logs, old docker images, large cache files)
without executing dangerous shell commands or entering pseudo-filesystems.
"""

from __future__ import annotations

import logging
import os
import shutil
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("vps_guardian.storage")

# Forbidden directories to scan (pseudo-filesystems and virtual mounts)
FORBIDDEN_SCAN_ROOTS: Set[str] = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/sys/fs/cgroup",
}


def _format_bytes(bytes_value: int | float) -> str:
    """Format bytes into a human-readable string (B, KB, MB, GB, TB)."""
    val = float(bytes_value)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(val) < 1024.0 or unit == "TB":
            return f"{val:.2f} {unit}"
        val /= 1024.0
    return f"{val:.2f} TB"


def _get_dir_size_fast(
    dir_path: str, max_depth: int = 4, current_depth: int = 0
) -> int:
    """Recursively calculate total size of directory contents in bytes."""
    if current_depth > max_depth:
        return 0

    total_size = 0
    try:
        with os.scandir(dir_path) as entries:
            for entry in entries:
                try:
                    # Never follow symlinks to avoid recursion loops or scanning external mounts
                    if entry.is_symlink():
                        continue
                    if entry.is_file(follow_symlinks=False):
                        total_size += entry.stat(follow_symlinks=False).st_size
                    elif entry.is_dir(follow_symlinks=False):
                        # Avoid descending into forbidden directories
                        if entry.path in FORBIDDEN_SCAN_ROOTS:
                            continue
                        total_size += _get_dir_size_fast(
                            entry.path, max_depth, current_depth + 1
                        )
                except (PermissionError, FileNotFoundError, OSError):
                    continue
    except (PermissionError, FileNotFoundError, OSError):
        pass

    return total_size


def analyze_disk_usage(
    target_path: str = "/var",
    max_depth: int = 2,
    min_size_mb: int = 50,
    top_n: int = 15,
) -> Dict[str, Any]:
    """Analyze disk usage for a directory to find largest consumers of storage.

    Safely walks the filesystem without following symlinks and automatically
    skips virtual/pseudo-filesystems (/proc, /sys, /dev, /run).

    Args:
        target_path: Starting path to inspect (defaults to '/var').
        max_depth: Depth of directory nesting to inspect (1 to 5, default 2).
        min_size_mb: Minimum size threshold in megabytes to include (default 50 MB).
        top_n: Maximum number of largest items to return (1 to 50, default 15).

    Returns:
        Structured dictionary with partition statistics, largest directories,
        and largest files.
    """
    try:
        max_depth = max(1, min(int(max_depth), 5))
        min_size_mb = max(0, int(min_size_mb))
        top_n = max(1, min(int(top_n), 50))
    except (ValueError, TypeError):
        max_depth = 2
        min_size_mb = 50
        top_n = 15

    min_size_bytes = min_size_mb * 1024 * 1024

    if not isinstance(target_path, str) or not target_path.strip():
        target_path = "/var"

    clean_path = os.path.abspath(target_path.strip())

    if clean_path in FORBIDDEN_SCAN_ROOTS:
        return {
            "status": "error",
            "error": f"Scanning virtual pseudo-filesystem '{clean_path}' is forbidden.",
            "target_path": clean_path,
        }

    if not os.path.exists(clean_path):
        return {
            "status": "error",
            "error": f"Path '{clean_path}' does not exist.",
            "target_path": clean_path,
        }

    if not os.path.isdir(clean_path):
        return {
            "status": "error",
            "error": f"Path '{clean_path}' is a file, not a directory.",
            "target_path": clean_path,
        }

    # Gather partition information for the target mount point
    partition_info: Dict[str, Any] = {}
    try:
        usage = shutil.disk_usage(clean_path)
        partition_info = {
            "total_bytes": usage.total,
            "total_human": _format_bytes(usage.total),
            "used_bytes": usage.used,
            "used_human": _format_bytes(usage.used),
            "free_bytes": usage.free,
            "free_human": _format_bytes(usage.free),
            "used_percentage": round((usage.used / usage.total) * 100, 1)
            if usage.total > 0
            else 0.0,
        }
    except Exception as exc:
        logger.warning(f"Could not read partition info for {clean_path}: {exc}")

    # Discover directories and files
    discovered_dirs: List[Dict[str, Any]] = []
    discovered_files: List[Dict[str, Any]] = []

    clean_path_len = len(clean_path.rstrip(os.sep).split(os.sep))

    try:
        # Traverse with controlled depth
        for root, dirs, files in os.walk(clean_path, followlinks=False):
            current_depth = len(root.split(os.sep)) - clean_path_len
            if current_depth > max_depth:
                dirs.clear()  # Do not descend deeper
                continue

            # Filter out forbidden subdirectories and symlinks in-place
            dirs[:] = [
                d
                for d in dirs
                if os.path.join(root, d) not in FORBIDDEN_SCAN_ROOTS
                and not os.path.islink(os.path.join(root, d))
            ]

            # Inspect files in the current directory
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    if os.path.islink(fpath):
                        continue
                    st = os.stat(fpath, follow_symlinks=False)
                    fsize = st.st_size
                    if fsize >= min_size_bytes:
                        discovered_files.append(
                            {
                                "path": fpath,
                                "size_bytes": fsize,
                                "size_human": _format_bytes(fsize),
                            }
                        )
                except (PermissionError, FileNotFoundError, OSError):
                    continue

            # If current directory is within requested depth and not root target
            if current_depth > 0:
                dir_size = _get_dir_size_fast(root, max_depth=3)
                if dir_size >= min_size_bytes:
                    discovered_dirs.append(
                        {
                            "path": root,
                            "depth": current_depth,
                            "size_bytes": dir_size,
                            "size_human": _format_bytes(dir_size),
                        }
                    )

    except Exception as exc:
        logger.error(f"Error scanning directory {clean_path}: {exc}")
        return {
            "status": "error",
            "error": f"Failed scanning directory: {str(exc)}",
            "target_path": clean_path,
        }

    # Sort items descending by size
    discovered_dirs.sort(key=lambda x: x["size_bytes"], reverse=True)
    discovered_files.sort(key=lambda x: x["size_bytes"], reverse=True)

    top_dirs = discovered_dirs[:top_n]
    top_files = discovered_files[:top_n]

    # Summary generation
    summary_parts = [
        f"Analyzed '{clean_path}' (depth <= {max_depth}, min_size >= {min_size_mb} MB)."
    ]
    if partition_info:
        summary_parts.append(
            f"Mount utilization: {partition_info.get('used_percentage')}% "
            f"({partition_info.get('used_human')} used of {partition_info.get('total_human')})."
        )
    if top_dirs:
        summary_parts.append(
            f"Largest directory: '{top_dirs[0]['path']}' ({top_dirs[0]['size_human']})."
        )
    if top_files:
        summary_parts.append(
            f"Largest file: '{top_files[0]['path']}' ({top_files[0]['size_human']})."
        )

    return {
        "status": "ok",
        "target_path": clean_path,
        "partition": partition_info,
        "min_size_mb": min_size_mb,
        "max_depth": max_depth,
        "top_directories_count": len(top_dirs),
        "largest_directories": top_dirs,
        "top_files_count": len(top_files),
        "largest_files": top_files,
        "summary": " ".join(summary_parts),
    }
