"""Database health and status inspector for VPS-Guardian-MCP.

Provides non-invasive health checks for local database engines:
- Redis (in-memory cache & queue): Pure socket ping and operational check.
- PostgreSQL (relational database): Socket readiness via pg_isready or local port probe.
- MySQL / MariaDB (relational database): Socket ping via mysqladmin or port probe.
- SQLite (embedded databases): Integrity and size verification in authorized directories.
"""

from __future__ import annotations

import glob
import logging
import os
import shutil
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional

import psutil

logger = logging.getLogger("vps_guardian.database")


def _format_bytes(bytes_value: int | float) -> str:
    """Format bytes into human-readable string (B, KB, MB, GB)."""
    val = float(bytes_value)
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(val) < 1024.0 or unit == "GB":
            return f"{val:.2f} {unit}"
        val /= 1024.0
    return f"{val:.2f} GB"


def _check_redis() -> Optional[Dict[str, Any]]:
    """Non-invasively probe local Redis service."""
    # Check if process exists
    redis_procs = [p for p in psutil.process_iter(["pid", "name"]) if "redis" in (p.info["name"] or "").lower()]
    socket_path = "/var/run/redis/redis-server.sock"
    has_sock = os.path.exists(socket_path)

    if not redis_procs and not has_sock:
        # Check port 6379
        try:
            with socket.create_connection(("127.0.0.1", 6379), timeout=0.5):
                pass
        except Exception:
            return None

    pid = redis_procs[0].info["pid"] if redis_procs else None

    # Probe ping via pure socket (independent of redis-cli tool)
    start_t = time.perf_counter()
    responsive = False
    ping_latency_ms = None
    try:
        if has_sock:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect(socket_path)
        else:
            s = socket.create_connection(("127.0.0.1", 6379), timeout=1.0)

        s.sendall(b"PING\r\n")
        resp = s.recv(1024)
        s.close()
        if b"PONG" in resp:
            responsive = True
            ping_latency_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
    except Exception as exc:
        logger.debug(f"Redis socket probe notice: {exc}")

    # Memory usage via psutil if PID known
    memory_human = None
    if pid:
        try:
            proc = psutil.Process(pid)
            memory_human = _format_bytes(proc.memory_info().rss)
        except Exception:
            pass

    return {
        "engine": "redis",
        "running": True,
        "pid": pid,
        "responsive": responsive,
        "ping_latency_ms": ping_latency_ms,
        "memory_rss": memory_human,
        "socket_file": socket_path if has_sock else None,
        "status": "active" if responsive else "degraded",
    }


def _check_postgresql() -> Optional[Dict[str, Any]]:
    """Probe local PostgreSQL service."""
    pg_procs = [p for p in psutil.process_iter(["pid", "name"]) if "postgres" in (p.info["name"] or "").lower()]
    has_sock = any(os.path.exists(p) for p in glob.glob("/var/run/postgresql/.s.PGSQL.*"))

    if not pg_procs and not has_sock:
        # Check port 5432
        try:
            with socket.create_connection(("127.0.0.1", 5432), timeout=0.5):
                pass
        except Exception:
            return None

    pid = pg_procs[0].info["pid"] if pg_procs else None

    # Check readiness via pg_isready if available
    pg_isready_bin = shutil.which("pg_isready")
    responsive = False
    details_str = None
    start_t = time.perf_counter()
    ping_latency_ms = None

    if pg_isready_bin:
        try:
            res = subprocess.run(
                [pg_isready_bin, "-h", "127.0.0.1", "-p", "5432"],
                capture_output=True,
                text=True,
                check=False,
                timeout=3,
            )
            ping_latency_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
            responsive = res.returncode == 0
            details_str = res.stdout.strip() or res.stderr.strip()
        except Exception:
            pass
    else:
        # Fallback TCP check
        try:
            with socket.create_connection(("127.0.0.1", 5432), timeout=1.0):
                ping_latency_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
                responsive = True
                details_str = "TCP connection accepted on port 5432"
        except Exception as exc:
            details_str = str(exc)

    return {
        "engine": "postgresql",
        "running": True,
        "pid": pid,
        "responsive": responsive,
        "ping_latency_ms": ping_latency_ms,
        "details": details_str,
        "status": "active" if responsive else "degraded",
    }


def _check_mysql() -> Optional[Dict[str, Any]]:
    """Probe local MySQL or MariaDB service."""
    mysql_procs = [
        p
        for p in psutil.process_iter(["pid", "name"])
        if any(name in (p.info["name"] or "").lower() for name in ["mysqld", "mariadbd"])
    ]
    sock_candidates = ["/var/run/mysqld/mysqld.sock", "/run/mysqld/mysqld.sock"]
    found_sock = next((s for s in sock_candidates if os.path.exists(s)), None)

    if not mysql_procs and not found_sock:
        # Check port 3306
        try:
            with socket.create_connection(("127.0.0.1", 3306), timeout=0.5):
                pass
        except Exception:
            return None

    pid = mysql_procs[0].info["pid"] if mysql_procs else None

    # Check ping via mysqladmin if available
    mysqladmin_bin = shutil.which("mysqladmin")
    responsive = False
    details_str = None
    start_t = time.perf_counter()
    ping_latency_ms = None

    if mysqladmin_bin and found_sock:
        try:
            res = subprocess.run(
                [mysqladmin_bin, f"--socket={found_sock}", "ping"],
                capture_output=True,
                text=True,
                check=False,
                timeout=3,
            )
            ping_latency_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
            responsive = res.returncode == 0 and "alive" in res.stdout.lower()
            details_str = res.stdout.strip() or res.stderr.strip()
        except Exception:
            pass

    if not responsive:
        # Fallback TCP check
        try:
            with socket.create_connection(("127.0.0.1", 3306), timeout=1.0):
                ping_latency_ms = round((time.perf_counter() - start_t) * 1000.0, 2)
                responsive = True
                details_str = "TCP connection accepted on port 3306"
        except Exception as exc:
            if not details_str:
                details_str = str(exc)

    return {
        "engine": "mysql",
        "running": True,
        "pid": pid,
        "responsive": responsive,
        "ping_latency_ms": ping_latency_ms,
        "socket_file": found_sock,
        "details": details_str,
        "status": "active" if responsive else "degraded",
    }


def _check_sqlite() -> List[Dict[str, Any]]:
    """Scan authorized directories for active SQLite database files."""
    sqlite_files: List[Dict[str, Any]] = []
    search_dirs = ["/var/www", "/opt"]

    for sdir in search_dirs:
        if not os.path.isdir(sdir):
            continue
        try:
            for ext in ["*.sqlite", "*.sqlite3", "*.db"]:
                for fpath in glob.glob(os.path.join(sdir, "**", ext), recursive=True):
                    if os.path.isfile(fpath) and not os.path.islink(fpath):
                        try:
                            st = os.stat(fpath)
                            with open(fpath, "rb") as f:
                                header = f.read(16)
                            is_valid_sqlite = header.startswith(b"SQLite format 3")
                            if is_valid_sqlite:
                                sqlite_files.append(
                                    {
                                        "path": fpath,
                                        "size_bytes": st.st_size,
                                        "size_human": _format_bytes(st.st_size),
                                    }
                                )
                                if len(sqlite_files) >= 5:
                                    return sqlite_files
                        except (PermissionError, FileNotFoundError, OSError):
                            continue
        except Exception:
            continue

    return sqlite_files


def get_database_health() -> Dict[str, Any]:
    """Discover running databases and verify responsiveness, latency, and socket states.

    Detects:
    - Redis (key-value cache / message broker)
    - PostgreSQL (relational database)
    - MySQL / MariaDB (relational database)
    - SQLite (embedded database files in /var/www and /opt)

    Returns:
        Structured dictionary listing detected database engines, ping latency,
        and operational health.
    """
    detected_engines: List[Dict[str, Any]] = []

    # 1. Redis
    try:
        redis_status = _check_redis()
        if redis_status:
            detected_engines.append(redis_status)
    except Exception as exc:
        logger.warning(f"Error checking Redis: {exc}")

    # 2. PostgreSQL
    try:
        pg_status = _check_postgresql()
        if pg_status:
            detected_engines.append(pg_status)
    except Exception as exc:
        logger.warning(f"Error checking PostgreSQL: {exc}")

    # 3. MySQL / MariaDB
    try:
        mysql_status = _check_mysql()
        if mysql_status:
            detected_engines.append(mysql_status)
    except Exception as exc:
        logger.warning(f"Error checking MySQL: {exc}")

    # 4. SQLite
    sqlite_dbs = []
    try:
        sqlite_dbs = _check_sqlite()
    except Exception as exc:
        logger.warning(f"Error checking SQLite files: {exc}")

    summary_parts = []
    if detected_engines:
        names = [f"{e['engine'].capitalize()} ({e['status']})" for e in detected_engines]
        summary_parts.append(f"Detected {len(detected_engines)} active database service(s): {', '.join(names)}.")
    else:
        summary_parts.append("No active daemon database engines (Redis, PostgreSQL, MySQL) detected.")

    if sqlite_dbs:
        summary_parts.append(f"Found {len(sqlite_dbs)} SQLite database file(s) in application directories.")

    return {
        "status": "ok",
        "total_active_engines": len(detected_engines),
        "databases": detected_engines,
        "sqlite_databases": sqlite_dbs,
        "summary": " ".join(summary_parts),
    }
