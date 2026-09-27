"""Shared, private, bounded operation state; never automatically replay writes."""
from __future__ import annotations

import base64
from collections.abc import MutableMapping
from contextlib import contextmanager
import functools
import json
import os
import re
import sqlite3
import threading
import time

from src import access_policy
from src.safe_io import open_regular_fd, private_directory
from src.safety import _scrub_text

MAX_PAYLOAD_BYTES = 9_000_000
MAX_ACTIVE_BYTES = 32_000_000
MAX_HISTORY = 200
HISTORY_SECONDS = 30 * 86400
OPERATION_ID = re.compile(r"^(?:patch_[A-Za-z0-9_-]{10,32}|chg_[A-Za-z0-9_-]{10,32}|job_[0-9a-f]{16})$")
# POSIX close() of ANY descriptor for a database drops that process's fcntl
# locks. Serialize descriptor validation AND SQLite lifetime across threads.
DATABASE_LOCK = threading.RLock()


def job_directory():
    # Independent of the agent's VPS_GUARDIAN_STATE_DIR / launch environment.
    return os.path.join(private_directory(access_policy.policy_directory()), "operations")


@contextmanager
def transaction():
    with DATABASE_LOCK:
        with _database_transaction() as connection:
            yield connection


@contextmanager
def _database_transaction():
    directory = private_directory(job_directory())
    path = os.path.join(directory, "operations.sqlite3")
    descriptor = open_regular_fd(path, os.O_RDWR | os.O_CREAT, private=True)
    try:
        if os.fstat(descriptor).st_size > 48 * 1024 * 1024:
            raise OSError("Operation database exceeds its size limit.")
        for suffix in ("-journal", "-wal", "-shm"):
            if os.path.lexists(path + suffix):
                sidecar = open_regular_fd(path + suffix, private=True)
                os.close(sidecar)
        connection = sqlite3.connect(path, timeout=2)
        try:
            connection.execute("PRAGMA secure_delete=ON")
            connection.execute("PRAGMA max_page_count=12288")
            connection.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT, summary TEXT NOT NULL, updated REAL NOT NULL, expires REAL NOT NULL)")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
    finally:
        os.close(descriptor)


def _encode(value):
    def binary(item):
        if not isinstance(item, bytes):
            raise TypeError("Unsupported operation payload value.")
        return {"__bytes__": base64.b64encode(item).decode("ascii")}
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                      default=binary)


def _decode(raw):
    return json.loads(raw, object_hook=lambda item: base64.b64decode(item["__bytes__"], validate=True) if set(item) == {"__bytes__"} else item)


def summary(kind, item, previous=None):
    """Allowlisted metadata only: no source, original bytes, outputs or tokens."""
    value = {"operation_id": item.get("patch_id", item.get("change_set_id")), "kind": kind,
             "title": _scrub_text(str(item.get("title", ""))[:160]), "state": item["state"],
             "target": _scrub_text(str(item.get("project_path", item.get("target") or item.get("service") or ""))[:1024]),
             "created_at": item.get("created_at"), "expires_at": item["expires_at"],
             "file_count": len(item.get("files", [])),
             "files": [{key: _scrub_text(str(entry[key])[:1024]) if isinstance(entry[key], str) else entry[key]
                        for key in ("relative_path", "file_path", "existed", "baseline_sha256", "candidate_sha256") if key in entry}
                       for entry in item.get("files", [])[:3]],
             "result": {key: item.get("result", {}).get(key) for key in ("status", "success", "rolled_back") if key in item.get("result", {})}}
    if item.get("capsule_result"):
        value["check"] = {key: item["capsule_result"].get(key) for key in ("status", "success", "check", "duration_seconds")}
    # Small event timeline contains state names/counts, never arbitrary payload.
    events = list((previous or {}).get("events", []))[-19:]
    signature = (value["state"], value["file_count"], [(f.get("candidate_sha256")) for f in value["files"]], value.get("check"), value["result"])
    old = previous or {}
    old_signature = (old.get("state"), old.get("file_count"), [(f.get("candidate_sha256")) for f in old.get("files", [])], old.get("check"), old.get("result"))
    if signature != old_signature:
        events.append({"at": time.time(), "state": value["state"], "file_count": value["file_count"]})
    value["events"] = events
    value["updated_at"] = time.time()
    return value


def storage_errors(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (OSError, sqlite3.Error, ValueError) as exc:
            # Never imply that an already-started external operation was rolled back.
            return {"status": "storage_error", "success": False,
                    "error": "Shared operation state is unavailable or full. Check private-directory permissions and capacity. Inspect live files before retrying a write.",
                    "error_type": type(exc).__name__}
    return wrapped


class PersistentDrafts(MutableMapping):
    """Lazy per-record mapping. Its context serializes read-modify-write across processes."""
    def __init__(self, kind, capacity):
        self.kind, self.capacity = kind, capacity
        self.mutex = threading.RLock()
        self.local = threading.local()

    def __enter__(self):
        self.mutex.acquire()
        if getattr(self.local, "depth", 0):
            self.local.depth += 1
            return self
        try:
            self.local.connection = None
            self.local.manager = transaction()
            self.local.connection = self.local.manager.__enter__()
            self.local.cache, self.local.original, self.local.removed = {}, {}, set()
            self.local.depth = 1
            self.cleanup()
            return self
        except BaseException:
            if getattr(self.local, "connection", None) is not None:
                import sys
                self.local.manager.__exit__(*sys.exc_info())
            self.local.depth = 0
            self.mutex.release()
            raise

    def __exit__(self, kind, error, traceback):
        self.local.depth -= 1
        try:
            if self.local.depth:
                return False
            try:
                if kind is None:
                    self._flush()
            except BaseException as exc:
                self.local.manager.__exit__(type(exc), exc, exc.__traceback__)
                raise
            else:
                return self.local.manager.__exit__(kind, error, traceback)
        finally:
            if not self.local.depth:
                # MCP tools run in a thread pool. Do not retain source payloads
                # in every idle worker's thread-local cache on a small VPS.
                self.local.cache = {}
                self.local.original = {}
                self.local.removed = set()
                self.local.connection = None
                self.local.manager = None
            self.mutex.release()

    def _flush(self):
        connection = self.local.connection
        for key, item in self.local.cache.items():
            raw = _encode(item)
            if raw == self.local.original.get(key) and key not in self.local.removed:
                continue
            row = connection.execute("SELECT summary FROM operations WHERE id=?", (key,)).fetchone()
            public = summary(self.kind, item, json.loads(row[0]) if row else None)
            if key in self.local.removed:
                raw = None
            elif len(raw.encode()) > MAX_PAYLOAD_BYTES:
                raise ValueError("Operation payload exceeds its storage budget.")
            connection.execute("INSERT OR REPLACE INTO operations VALUES (?, ?, ?, ?, ?, ?)",
                               (key, self.kind, raw, json.dumps(public, separators=(",", ":")), public["updated_at"], item["expires_at"]))
        size = connection.execute("SELECT COALESCE(SUM(length(CAST(payload AS BLOB))),0) FROM operations").fetchone()[0]
        if size > MAX_ACTIVE_BYTES:
            raise ValueError("Shared draft storage is full.")
        connection.execute("DELETE FROM operations WHERE payload IS NULL AND (updated<? OR id IN (SELECT id FROM operations WHERE payload IS NULL ORDER BY updated DESC LIMIT -1 OFFSET ?))", (time.time() - HISTORY_SECONDS, MAX_HISTORY))

    def cleanup(self):
        connection = self.local.connection
        now = time.time()
        rows = connection.execute("SELECT id, summary, expires FROM operations WHERE payload IS NOT NULL AND expires<=?", (now,)).fetchall()
        for key, raw, expires in rows:
            public = json.loads(raw)
            public["state"] = "uncertain" if public["state"] in {"applying", "testing"} else "expired"
            public["updated_at"] = now
            public["events"] = (public.get("events", []) + [{"at": now, "state": public["state"], "file_count": public["file_count"]}])[-20:]
            connection.execute("UPDATE operations SET payload=NULL, summary=?, updated=? WHERE id=?", (json.dumps(public), now, key))
        connection.execute("DELETE FROM operations WHERE payload IS NULL AND (updated<? OR id IN (SELECT id FROM operations WHERE payload IS NULL ORDER BY updated DESC,id DESC LIMIT -1 OFFSET ?))", (now - HISTORY_SECONDS, MAX_HISTORY))

    def __getitem__(self, key):
        if not getattr(self.local, "depth", 0):
            with self:
                return self[key]
        if key in self.local.removed:
            raise KeyError(key)
        if key not in self.local.cache:
            row = self.local.connection.execute("SELECT payload FROM operations WHERE id=? AND kind=? AND payload IS NOT NULL", (key, self.kind)).fetchone()
            if not row:
                raise KeyError(key)
            self.local.cache[key] = _decode(row[0])
            self.local.original[key] = row[0]
        return self.local.cache[key]

    def __setitem__(self, key, value):
        if not getattr(self.local, "depth", 0):
            with self:
                self[key] = value
            return
        if key not in self and len(self) >= self.capacity:
            raise ValueError("Active drafts are never evicted. Wait for expiry or complete a draft.")
        self.local.cache[key] = value
        self.local.removed.discard(key)

    def __delitem__(self, key):
        if not getattr(self.local, "depth", 0):
            with self:
                del self[key]
            return
        item = self[key]
        if item["state"] not in {"completed", "failed", "rolled_back", "uncertain", "expired"}:
            item["state"] = "expired"
        self.local.removed.add(key)

    def __iter__(self):
        if not getattr(self.local, "depth", 0):
            with self:
                return iter(list(self))
        rows = self.local.connection.execute("SELECT id FROM operations WHERE kind=? AND payload IS NOT NULL", (self.kind,)).fetchall()
        return iter((set(key for key, in rows) | set(self.local.cache)) - self.local.removed)

    def __len__(self):
        return sum(1 for _ in self)

    def clear(self):
        with self:
            self.local.connection.execute("DELETE FROM operations WHERE kind=?", (self.kind,))
            self.local.cache.clear()
            self.local.original.clear()
            self.local.removed.clear()


@storage_errors
def list_operations(limit: int = 25, before: str | None = None) -> dict:
    if type(limit) is not int or not 1 <= limit <= 50:
        return {"status": "error", "error": "limit must be 1-50."}
    stamp, identity = 1e12, "z" * 100
    if before is not None:
        try:
            if not isinstance(before, str) or len(before) > 90:
                raise ValueError("Invalid cursor")
            raw_stamp, identity = before.split(":", 1)
            stamp = float(raw_stamp)
            if not 0 < stamp < 1e12 or not OPERATION_ID.fullmatch(identity):
                raise ValueError("Invalid cursor")
        except (ValueError, TypeError):
            return {"status": "error", "error": "before must be a next_before cursor returned by this tool."}
    with transaction() as connection:
        store = PersistentDrafts("patch", 24)
        store.local.connection = connection
        store.cleanup()
        rows = connection.execute("SELECT summary,updated,id FROM operations WHERE updated<? OR (updated=? AND id<?) ORDER BY updated DESC,id DESC LIMIT ?", (stamp, stamp, identity, limit + 1)).fetchall()
    values = [json.loads(raw) for raw, _, _ in rows[:limit]]
    from src.agent_jobs import list_agent_jobs
    jobs = list_agent_jobs(include_finished=True, limit=limit)
    return {"status": "ok", "operations": values, "jobs": jobs.get("jobs", []),
            "jobs_error": None if jobs.get("status") == "ok" else "Shared jobs unavailable.",
            "next_before": f"{rows[limit - 1][1]}:{rows[limit - 1][2]}" if len(rows) > limit else None,
            "scope": "This server and SSH user. Metadata only; no source, raw outputs or confirmation tokens.",
            "retention": {"draft_hours": 24, "history_days": 30, "history_records": MAX_HISTORY, "active_payload_bytes": MAX_ACTIVE_BYTES}}


@storage_errors
def get_operation(operation_id: str) -> dict:
    if not isinstance(operation_id, str) or not OPERATION_ID.fullmatch(operation_id):
        return {"status": "error", "error": "Invalid operation ID."}
    if operation_id.startswith("job_"):
        from src.agent_jobs import get_agent_job
        job = get_agent_job(operation_id)
        # Job results were redacted when persisted; return only selected metadata.
        return {"status": job["status"], "job": job.get("job"),
                "checks": [{key: check.get(key) for key in ("name", "status", "attempts", "revision")} for check in job.get("checks", [])],
                "action_status": (job.get("action") or {}).get("status")}
    with transaction() as connection:
        store = PersistentDrafts("patch", 24)
        store.local.connection = connection
        store.cleanup()
        row = connection.execute("SELECT summary FROM operations WHERE id=?", (operation_id,)).fetchone()
    return {"status": "ok", "operation": json.loads(row[0])} if row else {"status": "not_found", "error": "Operation not found or outside retention."}
