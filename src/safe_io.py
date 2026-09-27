"""Descriptor-based regular-file I/O. Callers still enforce their own path policy."""

from __future__ import annotations

import os
import stat
import secrets
from contextlib import contextmanager


@contextmanager
def directory_fd(path: str):
    """Pin a POSIX directory without following any symlink component."""
    absolute = os.path.abspath(path)
    if os.name != "posix":
        current = os.path.splitdrive(absolute)[0] + os.sep
        for part in absolute[len(current):].split(os.sep):
            current = os.path.join(current, part)
            if os.path.islink(current):
                raise OSError("Symlinked path component refused.")
        yield None
        return
    descriptor = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in absolute.split(os.sep):
            if not part:
                continue
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


def open_regular_fd(path: str, flags: int = os.O_RDONLY, mode: int = 0o600, private: bool = False) -> int:
    """Open without blocking on FIFOs, then reject non-regular files and unsafe private files."""
    absolute = os.path.abspath(path)
    with directory_fd(os.path.dirname(absolute)) as parent:
        # Windows CRT text-mode O_RDWR can truncate a trailing 0x1a on OPEN,
        # even when no write follows. SQLite/state files must always be binary.
        options = flags | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        if parent is None:
            if os.path.islink(absolute):
                raise OSError("Symlinked file refused.")
            descriptor = os.open(absolute, options, mode)
        else:
            descriptor = os.open(os.path.basename(absolute), options, mode, dir_fd=parent)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("A regular file is required.")
        if private and (info.st_nlink != 1 or (os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o077))):
            raise OSError("Private file ownership, links or permissions are unsafe.")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def regular_file(path: str, mode: str = "rb", private: bool = False):
    if mode not in {"rb", "r"}:
        raise ValueError("Only read modes are supported.")
    descriptor = open_regular_fd(path, private=private)
    with os.fdopen(descriptor, mode, **({"encoding": "utf-8", "errors": "replace"} if mode == "r" else {})) as handle:
        yield handle


def read_bounded(path: str, limit: int, private: bool = False) -> bytes:
    with regular_file(path, private=private) as handle:
        if os.fstat(handle.fileno()).st_size > limit:
            raise OSError("File exceeds its read budget.")
        value = handle.read(limit + 1)
        if len(value) > limit:
            raise OSError("File grew beyond its read budget.")
        return value


def private_directory(path: str) -> str:
    absolute = os.path.abspath(path)
    os.makedirs(absolute, mode=0o700, exist_ok=True)
    with directory_fd(absolute) as descriptor:
        info = os.fstat(descriptor) if descriptor is not None else os.stat(absolute, follow_symlinks=False)
        if os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise OSError("State directory must be owned by the current user with mode 0700.")
    return absolute


def atomic_replace(path: str, data: bytes, backup: bool = False, limit: int = 2 * 1024 * 1024, private: bool = False):
    """Replace within a pinned directory; never follow target or backup symlinks.

    Preserve ordinary target permissions/ownership, not setuid/setgid bits.
    Backups use fresh exclusive names and owner-only permissions.
    """
    if len(data) > limit:
        raise OSError("Write exceeds its byte budget.")
    absolute = os.path.abspath(path)
    parent_path, name = os.path.split(absolute)
    temporaries = set()
    backup_path = None
    with directory_fd(parent_path) as parent:
        def target(item):
            return os.path.join(parent_path, item) if parent is None else item

        def inspect(item):
            return os.stat(target(item), follow_symlinks=False, **({"dir_fd": parent} if parent is not None else {}))

        def replace(source, destination):
            os.replace(target(source), target(destination), **({"src_dir_fd": parent, "dst_dir_fd": parent} if parent is not None else {}))
            temporaries.discard(source)

        def create(raw, info=None):
            item = ".guardian_tmp_" + secrets.token_hex(12)
            descriptor = os.open(target(item), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, **({"dir_fd": parent} if parent is not None else {}))
            temporaries.add(item)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                if info is not None:
                    if hasattr(os, "fchown"):
                        os.fchown(handle.fileno(), info.st_uid, info.st_gid)
                    if hasattr(os, "fchmod"):
                        os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode) & 0o777)
                    else:
                        os.chmod(target(item), stat.S_IMODE(info.st_mode) & 0o777)
                os.fsync(handle.fileno())
            return item

        try:
            try:
                before = inspect(name)
            except FileNotFoundError:
                before = None
            if before is not None and not stat.S_ISREG(before.st_mode):
                raise OSError("Target must be a regular non-symlink file.")
            if before is not None and private and (before.st_nlink != 1 or (os.name == "posix" and (before.st_uid != os.geteuid() or before.st_mode & 0o077))):
                raise OSError("Unsafe private state file ownership, links or permissions.")
            original = None
            if before is not None:
                descriptor = os.open(target(name), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), **({"dir_fd": parent} if parent is not None else {}))
                with os.fdopen(descriptor, "rb") as handle:
                    actual = os.fstat(handle.fileno())
                    if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino) or actual.st_size > limit:
                        raise OSError("Target changed or exceeds its backup/read budget.")
                    original = handle.read(limit + 1)
                    if len(original) > limit:
                        raise OSError("Target grew beyond its read budget.")
            if before is not None and backup:
                try:
                    existing_backup = inspect(name + ".bak")
                    if not stat.S_ISREG(existing_backup.st_mode) or existing_backup.st_nlink != 1:
                        raise OSError("Unsafe existing backup path.")
                except FileNotFoundError:
                    pass
                unique = name + ".bak." + secrets.token_hex(12)
                descriptor = os.open(target(unique), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, **({"dir_fd": parent} if parent is not None else {}))
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(original)
                    handle.flush()
                    os.fsync(handle.fileno())
                backup_path = os.path.join(parent_path, unique)
                latest = create(original)
                replace(latest, name + ".bak")
            temporary = create(data, before)
            try:
                current = inspect(name)
            except FileNotFoundError:
                current = None
            identity = lambda value: None if value is None else (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
            if identity(current) != identity(before):
                raise OSError("Target changed during the write; replacement refused.")
            if parent is not None:
                pinned = os.fstat(parent)
                current_parent = os.stat(parent_path, follow_symlinks=False)
                if (pinned.st_dev, pinned.st_ino) != (current_parent.st_dev, current_parent.st_ino):
                    raise OSError("Parent directory changed during the write.")
            replace(temporary, name)
            if parent is not None:
                os.fsync(parent)
            return backup_path, before is None
        finally:
            for item in temporaries:
                try:
                    os.unlink(target(item), **({"dir_fd": parent} if parent is not None else {}))
                except OSError:
                    pass
