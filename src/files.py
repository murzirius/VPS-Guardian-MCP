"""File and configuration management module for VPS-Guardian-MCP.

Provides strictly isolated, safe filesystem operations for server configurations:
- Path verification against an immutable directory whitelist to prevent directory traversal.
- Safe file viewing with context-protective size caps.
- Atomic file writing with automated timestamped backup copies (.bak).
- Directory structure inspection within authorized administrative directories.
"""

from __future__ import annotations

import datetime
import logging
import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vps_guardian.files")

try:
    from src.safety import record_audit_event, request_authorization
except ImportError:
    from safety import record_audit_event, request_authorization

# Immutable whitelist of authorized configuration and web directories
DEFAULT_ALLOWED_DIRECTORIES = [
    "/etc/nginx",
    "/etc/mysql",
    "/etc/postgresql",
    "/etc/docker",
    "/etc/caddy",
    "/var/www",
]


def _format_bytes(bytes_value: int | float) -> str:
    """Format bytes into a human-readable string (B, KB, MB, GB)."""
    val = float(bytes_value)
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(val) < 1024.0 or unit == "GB":
            return f"{val:.2f} {unit}"
        val /= 1024.0
    return f"{val:.2f} GB"


def get_allowed_directories() -> List[str]:
    """Retrieve canonical list of authorized directories."""
    allowed = list(DEFAULT_ALLOWED_DIRECTORIES)
    # When running on Windows during development or testing, permit current working directory
    if os.name == "nt":
        allowed.append(os.path.realpath("."))
    return allowed


def is_path_permitted(target_path: str) -> tuple[bool, str]:
    """Verify whether target_path resolves strictly within an authorized directory.

    Protects against directory traversal (../), relative path bypasses, and symlink escapes.

    Returns:
        tuple (is_allowed, canonical_path)
    """
    try:
        canonical_target = os.path.realpath(os.path.abspath(target_path))
    except Exception as exc:
        return False, str(exc)

    allowed_dirs = get_allowed_directories()
    for allowed_dir in allowed_dirs:
        canonical_allowed = os.path.realpath(allowed_dir)
        # Check exact directory match or sub-path boundary
        if canonical_target == canonical_allowed or canonical_target.startswith(
            canonical_allowed + os.sep
        ):
            return True, canonical_target

    return False, canonical_target


def view_file_content(file_path: str, max_bytes: int = 50000) -> Dict[str, Any]:
    """Safely read the content of an authorized configuration or web file.

    Args:
        file_path: Absolute or relative path to the configuration file.
                   Permitted locations: /etc/nginx/, /etc/mysql/, /etc/postgresql/,
                   /etc/docker/, /etc/caddy/, /var/www/
        max_bytes: Maximum number of bytes to read (default: 50,000, capped at 200,000).

    Returns:
        Structured dictionary containing file metadata, text content, or error diagnostics.
    """
    if not isinstance(file_path, str) or not file_path.strip():
        return {"status": "error", "error": "file_path must be a non-empty string."}

    allowed, canonical_path = is_path_permitted(file_path.strip())
    if not allowed:
        return {
            "status": "forbidden",
            "error": (
                f"Access denied: Path '{file_path}' resolves to '{canonical_path}', which is outside "
                f"authorized directories: {DEFAULT_ALLOWED_DIRECTORIES}"
            ),
            "file_path": canonical_path,
        }

    if not os.path.exists(canonical_path):
        return {
            "status": "error",
            "error": f"File not found: '{canonical_path}'",
            "file_path": canonical_path,
        }

    if os.path.isdir(canonical_path):
        return {
            "status": "error",
            "error": f"Path '{canonical_path}' is a directory. Use list_directory to inspect contents.",
            "file_path": canonical_path,
        }

    # Bounded byte reading
    try:
        max_bytes = max(100, min(int(max_bytes), 200000))
    except (ValueError, TypeError):
        max_bytes = 50000

    try:
        file_stat = os.stat(canonical_path)
        total_size = file_stat.st_size

        with open(canonical_path, "rb") as f:
            raw_data = f.read(max_bytes)

        # Detect binary files (null bytes)
        if b"\x00" in raw_data[:1024]:
            return {
                "status": "error",
                "error": f"File '{canonical_path}' appears to be binary. Raw binary viewing is restricted.",
                "file_path": canonical_path,
                "size_bytes": total_size,
            }

        text_content = raw_data.decode("utf-8", errors="replace")
        is_truncated = total_size > max_bytes

        return {
            "status": "ok",
            "file_path": canonical_path,
            "size_bytes": total_size,
            "size_human": _format_bytes(total_size),
            "bytes_read": len(raw_data),
            "is_truncated": is_truncated,
            "modified_time": datetime.datetime.fromtimestamp(
                file_stat.st_mtime, datetime.timezone.utc
            ).isoformat(),
            "content": text_content,
        }
    except PermissionError as exc:
        return {
            "status": "error",
            "error": f"Permission denied reading '{canonical_path}': {str(exc)}",
            "file_path": canonical_path,
        }
    except Exception as exc:
        logger.error(f"Error reading file '{canonical_path}': {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Failed reading file: {str(exc)}",
            "file_path": canonical_path,
        }


def atomic_write_file(
    canonical_path: str,
    content: str,
    backup: bool = True,
) -> Dict[str, Any]:
    """Write a known-safe path atomically, optionally retaining a backup.

    This low-level primitive intentionally performs no authorization or path
    policy checks.  It is for internal transactional workflows only; public
    callers must use :func:`write_file_content`.
    """
    parent_dir = os.path.dirname(canonical_path)
    if not os.path.exists(parent_dir):
        return {
            "status": "error",
            "success": False,
            "error": f"Parent directory '{parent_dir}' does not exist.",
            "file_path": canonical_path,
        }

    backup_path = None
    existing_file = os.path.exists(canonical_path)

    if existing_file and backup:
        timestamp_suffix = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%d_%H%M%S"
        )
        backup_path = f"{canonical_path}.bak.{timestamp_suffix}"
        try:
            shutil.copy2(canonical_path, backup_path)
            shutil.copy2(canonical_path, f"{canonical_path}.bak")
        except Exception as exc:
            logger.error(f"Failed to create backup of '{canonical_path}': {exc}")
            return {
                "status": "error",
                "success": False,
                "error": f"Failed to create backup before writing: {str(exc)}",
                "file_path": canonical_path,
            }

    try:
        content_bytes = content.encode("utf-8")
        temp_file = tempfile.NamedTemporaryFile(
            mode="wb", dir=parent_dir, delete=False, prefix=".guardian_tmp_"
        )
        temp_path = temp_file.name
        try:
            temp_file.write(content_bytes)
            temp_file.flush()
            os.fsync(temp_file.fileno())
            temp_file.close()
            if existing_file:
                try:
                    os.chmod(temp_path, os.stat(canonical_path).st_mode)
                except OSError:
                    pass
            os.replace(temp_path, canonical_path)
        except Exception:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise

        return {
            "status": "ok",
            "success": True,
            "file_path": canonical_path,
            "bytes_written": len(content_bytes),
            "size_human": _format_bytes(len(content_bytes)),
            "is_new_file": not existing_file,
            "backup_created": backup_path,
            "message": "File written atomically and successfully.",
        }
    except PermissionError as exc:
        return {
            "status": "error",
            "success": False,
            "error": f"Permission denied writing to '{canonical_path}': {str(exc)}",
            "file_path": canonical_path,
        }
    except Exception as exc:
        logger.error(f"Unexpected write error for '{canonical_path}': {exc}", exc_info=True)
        return {
            "status": "error",
            "success": False,
            "error": f"Failed writing file: {str(exc)}",
            "file_path": canonical_path,
        }


def write_file_content(
    file_path: str,
    content: str,
    backup: bool = True,
    confirmation_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Atomically write or update a configuration file within authorized directories.

    If the file exists and backup=True, creates a timestamped backup copy (.bak.<timestamp>)
    prior to overwriting. Writes to a temporary file first before atomic replacement.

    Args:
        file_path: Path to the target configuration file.
        content: String content to write into the file.
        backup: Whether to create a .bak backup of the existing file (default: True).

    Returns:
        Structured dictionary indicating success, backup status, and bytes written.
    """
    if not isinstance(file_path, str) or not file_path.strip():
        return {"status": "error", "error": "file_path must be a non-empty string."}
    if not isinstance(content, str):
        return {"status": "error", "error": "content must be a string."}

    allowed, canonical_path = is_path_permitted(file_path.strip())
    if not allowed:
        return {
            "status": "forbidden",
            "error": (
                f"Access denied: Writing to '{canonical_path}' is outside authorized "
                f"directories: {DEFAULT_ALLOWED_DIRECTORIES}"
            ),
            "file_path": canonical_path,
        }

    parent_dir = os.path.dirname(canonical_path)
    if not os.path.exists(parent_dir):
        return {
            "status": "error",
            "error": f"Parent directory '{parent_dir}' does not exist.",
            "file_path": canonical_path,
        }

    operation_parameters = {
        "file_path": canonical_path,
        "content": content,
        "backup": bool(backup),
    }
    authorization = request_authorization(
        operation="write_file_content",
        parameters=operation_parameters,
        impact="Create or replace a configuration file on disk.",
        confirmation_token=confirmation_token,
    )
    if authorization is not None:
        return authorization

    def audited(result: Dict[str, Any]) -> Dict[str, Any]:
        result["audit_log_path"] = record_audit_event(
            "write_file_content", operation_parameters, result
        )
        return result

    return audited(atomic_write_file(canonical_path, content, backup=backup))


def list_directory(dir_path: str, max_depth: int = 1) -> Dict[str, Any]:
    """Inspect file and directory structures within authorized administrative paths.

    Args:
        dir_path: Path to the directory to inspect.
                  Permitted paths: /etc/nginx, /etc/mysql, /etc/postgresql,
                  /etc/docker, /etc/caddy, /var/www
        max_depth: Exploration depth (1 or 2, default: 1).

    Returns:
        Structured dictionary listing contained files, directories, sizes, and timestamps.
    """
    if not isinstance(dir_path, str) or not dir_path.strip():
        return {"status": "error", "error": "dir_path must be a non-empty string."}

    allowed, canonical_path = is_path_permitted(dir_path.strip())
    if not allowed:
        return {
            "status": "forbidden",
            "error": (
                f"Access denied: Path '{canonical_path}' is outside authorized directories: "
                f"{DEFAULT_ALLOWED_DIRECTORIES}"
            ),
            "dir_path": canonical_path,
            "items": [],
        }

    if not os.path.exists(canonical_path):
        return {
            "status": "error",
            "error": f"Directory not found: '{canonical_path}'",
            "dir_path": canonical_path,
            "items": [],
        }

    if not os.path.isdir(canonical_path):
        return {
            "status": "error",
            "error": f"Path '{canonical_path}' is a file, not a directory. Use view_file_content.",
            "dir_path": canonical_path,
            "items": [],
        }

    max_depth = max(1, min(int(max_depth), 3))
    items: List[Dict[str, Any]] = []

    try:
        base_depth = canonical_path.rstrip(os.sep).count(os.sep)

        for root, dirs, files in os.walk(canonical_path):
            current_depth = root.rstrip(os.sep).count(os.sep) - base_depth
            if current_depth >= max_depth:
                dirs.clear()
                continue

            rel_root = os.path.relpath(root, canonical_path)
            prefix = "" if rel_root == "." else rel_root.replace("\\", "/") + "/"

            for d in sorted(dirs):
                full_dir = os.path.join(root, d)
                items.append({
                    "name": f"{prefix}{d}/",
                    "type": "directory",
                    "path": full_dir.replace("\\", "/"),
                    "size_bytes": 0,
                    "size_human": "0 B",
                    "modified": "",
                })

            for f in sorted(files):
                full_file = os.path.join(root, f)
                try:
                    f_stat = os.stat(full_file)
                    items.append({
                        "name": f"{prefix}{f}",
                        "type": "file",
                        "path": full_file.replace("\\", "/"),
                        "size_bytes": f_stat.st_size,
                        "size_human": _format_bytes(f_stat.st_size),
                        "modified": datetime.datetime.fromtimestamp(
                            f_stat.st_mtime, datetime.timezone.utc
                        ).isoformat(),
                    })
                except Exception:
                    items.append({
                        "name": f"{prefix}{f}",
                        "type": "file",
                        "path": full_file.replace("\\", "/"),
                        "size_bytes": 0,
                        "size_human": "unknown",
                        "modified": "",
                    })

        return {
            "status": "ok",
            "dir_path": canonical_path,
            "total_items": len(items),
            "items": items,
        }

    except PermissionError as exc:
        return {
            "status": "error",
            "error": f"Permission denied listing directory '{canonical_path}': {str(exc)}",
            "dir_path": canonical_path,
            "items": [],
        }
    except Exception as exc:
        logger.error(f"Error listing directory '{canonical_path}': {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Failed listing directory: {str(exc)}",
            "dir_path": canonical_path,
            "items": [],
        }
