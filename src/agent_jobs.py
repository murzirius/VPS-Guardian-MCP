"""Durable, bounded agent-led workflows. No model or polling worker runs on the VPS."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import secrets
import signal
import sqlite3
import subprocess
import sys
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

try:
    from src.agent_runtime import _scrub, _state_dir, get_agent_session
    from src.agent_efficiency import get_server_event_delta, get_workload_brief, summarize_service_logs
    from src.monitor import SERVICE_NAME_REGEX, check_service_status, get_system_health
    from src.recover import run_recovery_action
    from src.resource_policy import get_runtime_budget
    from src.safety import _redact
except ImportError:  # pragma: no cover - direct script compatibility
    from agent_runtime import _scrub, _state_dir, get_agent_session
    from agent_efficiency import get_server_event_delta, get_workload_brief, summarize_service_logs
    from monitor import SERVICE_NAME_REGEX, check_service_status, get_system_health
    from recover import run_recovery_action
    from resource_policy import get_runtime_budget
    from safety import _redact


MAX_JOBS = 100
MAX_CHECKS = 8
MAX_RESULT_CHARS = 2400
LEASE_SECONDS = 120
JOB_ID = re.compile(r"^job_[0-9a-f]{16}$")
CHECKS = {"system_health", "runtime_budget", "workload_brief", "event_delta", "service_logs", "service_status"}
TARGET_CHECKS = {"workload_brief", "event_delta", "service_logs", "service_status"}
FINAL_STATES = {"completed", "cancelled", "expired"}


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: Optional[dt.datetime] = None) -> str:
    return (value or _now()).isoformat()


@contextmanager
def _transaction() -> Iterator[sqlite3.Connection]:
    directory = _state_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    path = os.path.join(directory, "agent-jobs.sqlite3")
    if os.path.islink(path):
        raise OSError("Agent Jobs database must not be a symlink.")
    connection = sqlite3.connect(path, timeout=5)
    try:
        if os.name != "nt":
            os.chmod(path, 0o600)
        connection.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, record TEXT NOT NULL)")
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def _load(connection: sqlite3.Connection, job_id: str) -> Optional[Dict[str, Any]]:
    row = connection.execute("SELECT record FROM jobs WHERE id = ?", (job_id,)).fetchone()
    return json.loads(row[0]) if row else None


def _save(connection: sqlite3.Connection, job: Dict[str, Any]) -> None:
    connection.execute("INSERT OR REPLACE INTO jobs (id, record) VALUES (?, ?)", (job["job_id"], json.dumps(job, ensure_ascii=False, separators=(",", ":"))))


def _bump(job: Dict[str, Any]) -> None:
    job["revision"] += 1
    job["updated_at"] = _iso()


def _refresh(job: Dict[str, Any]) -> bool:
    """Recover read-only leases; never automatically replay a possibly executed action."""
    now = _now()
    if dt.datetime.fromisoformat(job["expires_at"]) <= now and job["status"] not in FINAL_STATES:
        job["status"] = "expired"
        _bump(job)
        return True
    if job["status"] in {"running", "action_running", "verifying"}:
        lease = job.get("lease_expires_at")
        if not lease or dt.datetime.fromisoformat(lease) <= now:
            job["status"] = "action_uncertain" if job["status"] == "action_running" else "pending" if job["status"] == "running" else "verification_pending"
            job["lease_id"] = None
            job["lease_expires_at"] = None
            _bump(job)
            return True
    return False


def _validate_id(job_id: str) -> bool:
    return isinstance(job_id, str) and bool(JOB_ID.fullmatch(job_id))


def _session_allowed(session_id: Optional[str]) -> bool:
    if session_id is None:
        return True
    session = get_agent_session(session_id).get("session")
    return bool(session and session.get("status") == "active" and dt.datetime.fromisoformat(session["expires_at"]) > _now())


def _clean(value: Any, depth: int = 0) -> Any:
    if depth >= 4:
        return "<nested result omitted>"
    if isinstance(value, dict):
        return {str(key)[:60]: _clean(_redact(item, str(key)), depth + 1) for key, item in list(value.items())[:24]}
    if isinstance(value, list):
        return [_clean(item, depth + 1) for item in value[:12]]
    if isinstance(value, str):
        return _scrub(value[:500])
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:100]


def _compact_result(result: Dict[str, Any]) -> Dict[str, Any]:
    clean = _clean(result)
    encoded = json.dumps(clean, ensure_ascii=False, separators=(",", ":"))
    if len(encoded) <= MAX_RESULT_CHARS:
        return clean
    return {
        "status": clean.get("status", "unknown"),
        "overall_status": clean.get("overall_status"),
        "error": clean.get("error"),
        "fingerprint": hashlib.sha256(encoded.encode()).hexdigest()[:16],
        "truncated": True,
    }


def _run_check(check: str, target: Optional[str]) -> Dict[str, Any]:
    if check == "system_health":
        result = get_system_health()
        return {
            "status": result.get("status"),
            "cpu_percent": result.get("cpu", {}).get("usage_percent_total"),
            "memory_available_bytes": result.get("memory", {}).get("ram", {}).get("available_bytes"),
            "memory_used_percent": result.get("memory", {}).get("ram", {}).get("used_percent"),
            "root_disk_used_percent": result.get("disk", {}).get("used_percent"),
        }
    if check == "runtime_budget":
        return get_runtime_budget()
    if check == "workload_brief":
        return get_workload_brief(target or "", "health,events,logs", max_chars=3000)
    if check == "event_delta":
        return get_server_event_delta(60, 12, target)
    if check == "service_logs":
        return summarize_service_logs(target or "", lines_count=80, max_groups=8)
    if check == "service_status":
        result = check_service_status(target or "")
        return {key: result.get(key) for key in ("status", "service", "active_state", "is_running", "enabled_state", "error") if key in result}
    return {"status": "error", "error": "Check is not allowlisted."}


def _summary(job: Dict[str, Any]) -> Dict[str, Any]:
    return {key: job.get(key) for key in ("job_id", "title", "target", "status", "revision", "created_at", "updated_at", "expires_at", "next_check", "check_count", "last_session_id")}


def create_agent_job(title: str, checks: list[str], target: Optional[str] = None, session_id: Optional[str] = None, ttl_hours: int = 168) -> Dict[str, Any]:
    if not isinstance(title, str) or not 3 <= len(title.strip()) <= 160:
        return {"status": "error", "error": "title must contain 3-160 characters."}
    if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_CHECKS or any(not isinstance(item, str) or item not in CHECKS for item in checks):
        return {"status": "error", "error": f"checks must contain 1-{MAX_CHECKS} allowlisted check names.", "allowed_checks": sorted(CHECKS)}
    if target is not None and (not isinstance(target, str) or not 1 <= len(target.strip()) <= 128 or any(ord(char) < 32 for char in target)):
        return {"status": "error", "error": "target must contain 1-128 printable characters."}
    if any(item in TARGET_CHECKS for item in checks) and not target:
        return {"status": "error", "error": "A target is required for the selected checks."}
    if any(item == "service_status" for item in checks) and not SERVICE_NAME_REGEX.fullmatch(target or ""):
        return {"status": "error", "error": "service_status requires a valid systemd service name."}
    if not isinstance(ttl_hours, int) or isinstance(ttl_hours, bool) or not 1 <= ttl_hours <= 720:
        return {"status": "error", "error": "ttl_hours must be 1-720."}
    if not _session_allowed(session_id):
        return {"status": "not_found", "error": "An active agent session is required when session_id is supplied."}
    now = _now()
    job = {
        "job_id": f"job_{secrets.token_hex(8)}", "title": _scrub(title), "target": _scrub(target) if target else None,
        "checks": [{"name": name, "status": "pending", "attempts": 0, "result": None, "revision": 0} for name in checks],
        "check_count": len(checks), "next_check": 0, "status": "pending", "revision": 1,
        "created_at": _iso(now), "updated_at": _iso(now), "expires_at": _iso(now + dt.timedelta(hours=ttl_hours)),
        "lease_id": None, "lease_expires_at": None, "last_session_id": session_id, "action": None, "conclusion": None,
    }
    try:
        with _transaction() as connection:
            rows = connection.execute("SELECT id, record FROM jobs").fetchall()
            if len(rows) >= MAX_JOBS:
                existing = [json.loads(raw) for _, raw in rows]
                for item in existing:
                    if _refresh(item):
                        _save(connection, item)
                finished = sorted((item for item in existing if item.get("status") in FINAL_STATES), key=lambda item: item["updated_at"])
                if not finished:
                    return {"status": "capacity", "error": "Agent Jobs capacity reached; active jobs are never evicted."}
                connection.execute("DELETE FROM jobs WHERE id = ?", (finished[0]["job_id"],))
            _save(connection, job)
    except (OSError, sqlite3.Error) as exc:
        return {"status": "error", "error": f"Could not persist Agent Job: {exc}"}
    return {"status": "ok", "job": _summary(job), "checks": checks, "note": "Call advance_agent_job once per check. Optional background mode runs only that check, not an always-on worker."}


def get_agent_job(job_id: str, after_revision: int = 0) -> Dict[str, Any]:
    if not _validate_id(job_id) or not isinstance(after_revision, int) or after_revision < 0:
        return {"status": "error", "error": "Invalid job_id or after_revision."}
    try:
        with _transaction() as connection:
            job = _load(connection, job_id)
            if job and _refresh(job):
                _save(connection, job)
    except (OSError, sqlite3.Error):
        return {"status": "error", "error": "Could not read Agent Job state."}
    if not job:
        return {"status": "not_found", "error": "Agent Job was not found."}
    if after_revision >= job["revision"]:
        return {"status": "unchanged", "job_id": job_id, "revision": job["revision"]}
    return {"status": "ok", "job": _summary(job), "checks": [item for item in job["checks"] if item["revision"] > after_revision or after_revision == 0], "action": job["action"], "conclusion": job["conclusion"]}


def list_agent_jobs(include_finished: bool = False, limit: int = 25) -> Dict[str, Any]:
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        return {"status": "error", "error": "limit must be 1-100."}
    try:
        with _transaction() as connection:
            rows = connection.execute("SELECT record FROM jobs").fetchall()
            jobs = [json.loads(row[0]) for row in rows]
            for job in jobs:
                if _refresh(job):
                    _save(connection, job)
    except (OSError, sqlite3.Error):
        return {"status": "error", "error": "Could not list Agent Jobs."}
    jobs = [item for item in jobs if include_finished or item["status"] not in FINAL_STATES]
    jobs.sort(key=lambda item: item["updated_at"], reverse=True)
    return {"status": "ok", "job_count": min(len(jobs), limit), "jobs": [_summary(item) for item in jobs[:limit]]}


def advance_agent_job(job_id: str, session_id: Optional[str] = None, background: bool = False) -> Dict[str, Any]:
    """Execute one allowlisted read-only check. A crashed lease may be retried."""
    if not _validate_id(job_id) or not _session_allowed(session_id) or not isinstance(background, bool):
        return {"status": "error", "error": "Invalid job ID or inactive agent session."}
    if background and os.name == "nt":
        return {"status": "unavailable", "error": "Detached checks are supported on Linux only; call without background on this host."}
    try:
        with _transaction() as connection:
            job = _load(connection, job_id)
            if not job:
                return {"status": "not_found", "error": "Agent Job was not found."}
            if _refresh(job):
                _save(connection, job)
            if job["status"] not in {"pending", "needs_attention"}:
                return {"status": job["status"], "job": _summary(job), "error": "No read-only check is ready."}
            if job["next_check"] >= job["check_count"]:
                return {"status": "awaiting_agent", "job": _summary(job)}
            step = job["checks"][job["next_check"]]
            if step["attempts"] >= 3:
                return {"status": "needs_attention", "job": _summary(job), "error": "Check retry limit reached."}
            budget = get_runtime_budget()
            if budget["profile"] == "critical" and step["name"] not in {"runtime_budget", "system_health"}:
                return {"status": "resource_limited", "profile": "critical", "error": "Only lightweight checks are allowed below 256 MB available memory."}
            if background and budget["profile"] != "standard":
                return {"status": "resource_limited", "profile": budget["profile"], "error": "Detached checks require at least 512 MB available memory; use synchronous mode instead."}
            rows = connection.execute("SELECT record FROM jobs").fetchall()
            active = sum(1 for (raw,) in rows if (other := json.loads(raw)).get("status") in {"running", "verifying"} and other.get("lease_expires_at") and other["lease_expires_at"] > _iso())
            if active >= (1 if budget["profile"] != "standard" else 2):
                return {"status": "busy", "error": "Agent Jobs concurrency budget is full; retry later."}
            lease_id = secrets.token_hex(8)
            step["attempts"] += 1
            step["status"] = "running"
            job.update({"status": "running", "lease_id": lease_id, "lease_expires_at": _iso(_now() + dt.timedelta(seconds=LEASE_SECONDS)), "last_session_id": session_id or job["last_session_id"]})
            _bump(job)
            _save(connection, job)
    except (OSError, sqlite3.Error):
        return {"status": "error", "error": "Could not acquire Agent Job lease."}

    if background:
        try:
            process = subprocess.Popen(
                [sys.executable, "-m", "src.agent_jobs", "--complete-check", job_id, lease_id],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True, start_new_session=True,
            )
            threading.Thread(target=process.wait, name="guardian-job-reaper", daemon=True).start()
        except (OSError, ValueError):
            with _transaction() as connection:
                job = _load(connection, job_id)
                if job and job["status"] == "running" and job["lease_id"] == lease_id:
                    job["status"] = "pending"
                    job["lease_id"] = job["lease_expires_at"] = None
                    job["checks"][job["next_check"]]["status"] = "pending"
                    _bump(job)
                    _save(connection, job)
            return {"status": "error", "error": "Could not start a bounded detached check; job remains retryable."}
        return {"status": "running", "job": _summary(job), "note": "One detached read-only check started. Fetch progress by job ID; no polling daemon was installed."}
    return _complete_claimed_check(job_id, lease_id)


def _complete_claimed_check(job_id: str, lease_id: str) -> Dict[str, Any]:
    try:
        with _transaction() as connection:
            job = _load(connection, job_id)
            if not job or job["status"] != "running" or job["lease_id"] != lease_id:
                return {"status": "interrupted", "error": "Check lease is no longer active."}
            step = job["checks"][job["next_check"]]
            check, target = step["name"], job["target"]
    except (OSError, sqlite3.Error):
        return {"status": "error", "error": "Could not read claimed check."}
    try:
        result = _compact_result(_run_check(check, target))
    except Exception as exc:
        result = _compact_result({"status": "error", "error": f"Check failed: {type(exc).__name__}: {exc}"})
    try:
        with _transaction() as connection:
            job = _load(connection, job_id)
            if not job or job["status"] != "running" or job["lease_id"] != lease_id:
                return {"status": "interrupted", "error": "Job changed while the check was running; result was not committed."}
            step = job["checks"][job["next_check"]]
            step.update({"status": "completed" if result.get("status") in {"ok", "unchanged"} else "failed", "result": result, "finished_at": _iso()})
            job["lease_id"] = job["lease_expires_at"] = None
            if step["status"] == "completed":
                job["next_check"] += 1
                job["status"] = "awaiting_agent" if job["next_check"] == job["check_count"] else "pending"
            else:
                job["status"] = "needs_attention"
            _bump(job)
            step["revision"] = job["revision"]
            _save(connection, job)
            return {"status": "ok", "job": _summary(job), "check": step}
    except (OSError, sqlite3.Error):
        return {"status": "error", "error": "Check finished but Agent Job result could not be persisted; inspect the job before retrying."}


def _worker_main() -> int:
    if len(sys.argv) != 4 or sys.argv[1] != "--complete-check" or not _validate_id(sys.argv[2]) or not re.fullmatch(r"[0-9a-f]{16}", sys.argv[3]):
        return 2
    if hasattr(signal, "SIGALRM"):
        def timeout_check(_number, _frame):
            raise TimeoutError("Agent Job check exceeded 110 seconds.")
        signal.signal(signal.SIGALRM, timeout_check)
        signal.alarm(110)
    try:
        return 0 if _complete_claimed_check(sys.argv[2], sys.argv[3]).get("status") == "ok" else 1
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)


def cancel_agent_job(job_id: str, reason: str = "") -> Dict[str, Any]:
    if not _validate_id(job_id):
        return {"status": "error", "error": "Invalid job_id."}
    try:
        with _transaction() as connection:
            job = _load(connection, job_id)
            if not job:
                return {"status": "not_found", "error": "Agent Job was not found."}
            if _refresh(job):
                _save(connection, job)
            if job["status"] in FINAL_STATES:
                return {"status": job["status"], "job": _summary(job)}
            if job["status"] in {"action_running", "action_uncertain"}:
                return {"status": job["status"], "error": "Recovery may have run; inspect service and audit log before closing this job."}
            job["status"] = "cancelled"
            job["conclusion"] = _scrub(reason or "Cancelled by an agent.")
            job["lease_id"] = job["lease_expires_at"] = None
            _bump(job)
            _save(connection, job)
            return {"status": "ok", "job": _summary(job), "note": "An in-flight read-only check may finish, but its result will not revive this job."}
    except (OSError, sqlite3.Error):
        return {"status": "error", "error": "Could not cancel Agent Job."}


def finish_agent_job(job_id: str, conclusion: str) -> Dict[str, Any]:
    if not _validate_id(job_id) or not isinstance(conclusion, str) or not 3 <= len(conclusion.strip()) <= 1000:
        return {"status": "error", "error": "Valid job_id and 3-1000 character conclusion required."}
    try:
        with _transaction() as connection:
            job = _load(connection, job_id)
            if not job:
                return {"status": "not_found", "error": "Agent Job was not found."}
            if _refresh(job):
                _save(connection, job)
            if job["status"] != "awaiting_agent":
                return {"status": job["status"], "error": "Finish only after all checks or successful recovery verification."}
            job["status"] = "completed"
            job["conclusion"] = _scrub(conclusion)
            _bump(job)
            _save(connection, job)
            return {"status": "ok", "job": _summary(job)}
    except (OSError, sqlite3.Error):
        return {"status": "error", "error": "Could not finish Agent Job."}


def propose_agent_job_recovery(job_id: str, service_name: str, reason: str) -> Dict[str, Any]:
    """Record one restart proposal; this never restarts a service."""
    if not _validate_id(job_id) or not isinstance(service_name, str) or not SERVICE_NAME_REGEX.fullmatch(service_name):
        return {"status": "error", "error": "Valid job_id and systemd service name required."}
    if not isinstance(reason, str) or not 3 <= len(reason.strip()) <= 500:
        return {"status": "error", "error": "reason must contain 3-500 characters."}
    try:
        with _transaction() as connection:
            job = _load(connection, job_id)
            if not job:
                return {"status": "not_found", "error": "Agent Job was not found."}
            if _refresh(job):
                _save(connection, job)
            if job["status"] not in {"awaiting_agent", "needs_attention"}:
                return {"status": job["status"], "error": "Finish or inspect checks before proposing recovery."}
            if job["target"] != service_name or not any(step["name"] == "service_status" and step["status"] == "completed" for step in job["checks"]):
                return {"status": "error", "error": "A completed service_status check for this exact service is required before recovery."}
            if job["action"] is not None:
                return {"status": "error", "error": "This job already has a recovery proposal; create a new job for another action."}
            job["action"] = {"name": "restart_service", "target": service_name, "reason": _scrub(reason), "status": "proposed", "result": None}
            job["status"] = "awaiting_confirmation"
            _bump(job)
            _save(connection, job)
            return {"status": "ok", "job": _summary(job), "action": job["action"], "note": "Call execute_agent_job_recovery for the existing controlled-mode confirmation flow. No action ran yet."}
    except (OSError, sqlite3.Error):
        return {"status": "error", "error": "Could not persist recovery proposal."}


def execute_agent_job_recovery(job_id: str, confirmation_token: Optional[str] = None) -> Dict[str, Any]:
    """Run one proposed, allowlisted restart through the existing safety gate."""
    if not _validate_id(job_id):
        return {"status": "error", "error": "Invalid job_id."}
    try:
        with _transaction() as connection:
            job = _load(connection, job_id)
            if not job:
                return {"status": "not_found", "error": "Agent Job was not found."}
            if _refresh(job):
                _save(connection, job)
            if job["status"] != "awaiting_confirmation" or not job["action"]:
                return {"status": job["status"], "error": "No recovery action is awaiting confirmation."}
            rows = connection.execute("SELECT record FROM jobs").fetchall()
            if any((other := json.loads(raw)).get("status") == "action_running" and other.get("lease_expires_at") and other["lease_expires_at"] > _iso() for (raw,) in rows):
                return {"status": "busy", "error": "Another Agent Job recovery is in progress."}
            lease_id = secrets.token_hex(8)
            job["status"] = "action_running"
            job["lease_id"] = lease_id
            job["lease_expires_at"] = _iso(_now() + dt.timedelta(seconds=LEASE_SECONDS))
            _bump(job)
            _save(connection, job)
            target = job["action"]["target"]
    except (OSError, sqlite3.Error):
        return {"status": "error", "error": "Could not acquire recovery lease."}
    try:
        outcome = run_recovery_action("restart_service", target, confirmation_token)
    except Exception as exc:
        outcome = {"status": "uncertain", "error": f"Recovery returned an exception: {type(exc).__name__}: {exc}"}
    try:
        with _transaction() as connection:
            job = _load(connection, job_id)
            if not job or job["status"] != "action_running" or job["lease_id"] != lease_id:
                return {"status": "action_uncertain", "error": "Recovery state changed during execution. Inspect service and audit log; do not retry blindly."}
            job["lease_id"] = job["lease_expires_at"] = None
            if outcome.get("status") in {"confirmation_required", "forbidden"}:
                job["status"] = "awaiting_confirmation"
            elif outcome.get("status") == "ok" and outcome.get("success"):
                job["status"] = "verification_pending"
                job["action"]["status"] = "executed"
                job["action"]["result"] = _compact_result(outcome)
            else:
                job["status"] = "action_uncertain" if outcome.get("status") == "uncertain" else "needs_attention"
                job["action"]["status"] = "uncertain" if job["status"] == "action_uncertain" else "failed"
                job["action"]["result"] = _compact_result(outcome)
            _bump(job)
            _save(connection, job)
            return {"status": outcome.get("status", "error"), "job": _summary(job), "recovery": outcome if outcome.get("status") == "confirmation_required" else job["action"]["result"]}
    except (OSError, sqlite3.Error):
        return {"status": "action_uncertain", "error": "Recovery may have run, but its result could not be persisted. Inspect service and audit log; do not retry blindly."}


def verify_agent_job_recovery(job_id: str) -> Dict[str, Any]:
    """Read service status after a restart; no further mutation is performed."""
    if not _validate_id(job_id):
        return {"status": "error", "error": "Invalid job_id."}
    try:
        with _transaction() as connection:
            job = _load(connection, job_id)
            if not job:
                return {"status": "not_found", "error": "Agent Job was not found."}
            if _refresh(job):
                _save(connection, job)
            if job["status"] != "verification_pending":
                return {"status": job["status"], "error": "No executed recovery awaits verification."}
            lease_id = secrets.token_hex(8)
            job["status"] = "verifying"
            job["lease_id"] = lease_id
            job["lease_expires_at"] = _iso(_now() + dt.timedelta(seconds=LEASE_SECONDS))
            _bump(job)
            _save(connection, job)
            target = job["action"]["target"]
    except (OSError, sqlite3.Error):
        return {"status": "error", "error": "Could not acquire verification lease."}
    try:
        raw = check_service_status(target)
        result = _compact_result({key: raw.get(key) for key in ("status", "service", "active_state", "is_running", "enabled_state", "error") if key in raw})
    except Exception as exc:
        result = _compact_result({"status": "error", "error": f"Verification failed: {type(exc).__name__}: {exc}"})
    try:
        with _transaction() as connection:
            job = _load(connection, job_id)
            if not job or job["status"] != "verifying" or job["lease_id"] != lease_id:
                return {"status": "interrupted", "error": "Verification state changed; inspect job."}
            job["lease_id"] = job["lease_expires_at"] = None
            job["action"]["verification"] = result
            healthy = result.get("status") == "ok" and result.get("is_running") is True
            job["status"] = "awaiting_agent" if healthy else "needs_attention"
            _bump(job)
            _save(connection, job)
            return {"status": "ok" if healthy else "needs_attention", "job": _summary(job), "verification": result}
    except (OSError, sqlite3.Error):
        return {"status": "error", "error": "Could not persist verification result."}


if __name__ == "__main__":  # pragma: no cover - exercised by Linux integration tests
    raise SystemExit(_worker_main())
