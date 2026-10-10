"""Root-owned mission ledger, private assignments and untrusted agent reports.

No daemon, LLM or project command is started. Reports are reconciled by the
operator, never treated as proof of success or permission to write production.
"""
from __future__ import annotations

from contextlib import contextmanager
import datetime as dt
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import unicodedata

from src import gateway, mission_control as workspaces
from src.resource_policy import get_runtime_budget
from src.safe_io import atomic_replace, open_regular_fd, private_directory, read_bounded
from src.safety import _scrub_text

MISSION_ID = re.compile(r"mission_[0-9a-f]{24}\Z")
JOB_ID = re.compile(r"job_[0-9a-f]{16}\Z")
MAX_TASKS = 64
MAX_ACTIVE_PER_AGENT = 8
MAX_RECORD = 96000
CHECKS = {"python_syntax", "json_syntax", "toml_syntax"}
FINAL = {"done", "cancelled", "expired"}
OPERATOR_TOOLS = frozenset({"create_mission_task", "list_mission_tasks", "inspect_mission_task",
    "reassign_mission_task", "import_mission_task_review", "run_mission_task_check",
    "verify_mission_task", "finish_mission_task", "cancel_mission_task", "return_mission_task"})


class MissionConflict(ValueError):
    pass


def _safe_errors(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except MissionConflict:
            return {"status": "conflict", "error": "Mission changed. Refresh its details before acting; do not replay a production write."}
        except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            return {"status": "error", "error": "Mission request refused. Check the assignment, identity, scope, revision, review state and capacity. No production action is replayed."}
    return wrapped


def _text(value, limit):
    if (not isinstance(value, str) or not 1 <= len(value) <= limit
            or any(ord(c) < 32 and c not in "\n\t" or ord(c) == 127 or unicodedata.category(c) == "Cf" for c in value)):
        raise ValueError("Bounded plain text required.")
    return _scrub_text(value, limit)


def _revision(value):
    if type(value) is not int or not 1 <= value <= 1000000:
        raise ValueError("A current integer revision is required.")


def _identity(value):
    if not isinstance(value, str) or not MISSION_ID.fullmatch(value):
        raise ValueError("Invalid mission ID.")


def _directory():
    path = gateway.POLICY_BASE / "tasks"
    gateway._trusted_directory(gateway.POLICY_BASE, create=True, administrator=True)
    if not os.path.lexists(path):
        path.mkdir(mode=0o700)
    gateway._trusted_directory(path, administrator=True)
    return Path(private_directory(str(path)))


def _read(path, uid, private=True):
    fd = open_regular_fd(str(path))
    try:
        info = os.fstat(fd)
        if (info.st_uid != uid or info.st_nlink != 1 or info.st_size > MAX_RECORD
                or private and os.name == "posix" and info.st_mode & 0o077):
            raise PermissionError("Unsafe mission state file.")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_RECORD + 1)
        if len(raw) > MAX_RECORD:
            raise ValueError("Mission record exceeds budget.")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("Invalid mission record.")
        return value
    finally:
        os.close(fd)


def _write(path, value):
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    atomic_replace(str(path), raw, private=True, limit=MAX_RECORD)


def _task(mission_id):
    _identity(mission_id)
    item = _read(_directory() / (mission_id + ".json"), 0)
    if item["mission_id"] != mission_id or item["schema"] != 1:
        raise ValueError("Mission identity changed.")
    _revision(item["revision"])
    return item


def _policy(item):
    policy = workspaces._live_policy(item["agent_id"])
    user = gateway.pwd.getpwnam(policy["account"])
    if any(policy[key] != item[key] for key in ("uid", "key_fingerprint")) or user.pw_gid != item["gid"]:
        raise PermissionError("Assigned identity changed.")
    workspaces._project(policy, item["project_path"])
    return policy


def _public(item, detail=False):
    keys = ("mission_id", "agent_id", "title", "state", "revision", "created_at", "updated_at", "expires_at",
            "workspace_id", "review_id", "review_state", "review_digest", "reported_job_id")
    result = {k: item.get(k) for k in keys}
    if detail:
        result["project_path"] = item["project_path"]
        result.update({k: item.get(k) for k in ("goal", "acceptance_criteria", "required_checks", "agent_report", "report_error", "events", "checks", "verification")})
        result["note"] = "Agent reports and Job IDs are unverified claims. Only root snapshot checks and fresh production hashes are independent evidence; neither proves application correctness."
    return result


def _event(item, kind, summary):
    item["events"] = (item["events"] + [{"at": time.time(), "kind": kind, "summary": _text(summary, 512)[:160]}])[-32:]


def _feed_directory(policy, gid, create=False):
    base = gateway.POLICY_BASE / "assignments"
    gateway._trusted_directory(base, create=create, administrator=create)
    path = base / policy["agent_id"]
    if create and not os.path.lexists(path):
        path.mkdir(mode=0o700)
        os.chown(path, 0, gid)
        path.chmod(0o750)
    gateway._trusted_directory(path, administrator=create)
    info = path.stat(follow_symlinks=False)
    if info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o750:
        raise PermissionError("Assignment directory must be root-owned and private to this agent group.")
    return path


def _export(item):
    policy = gateway._read_policy(item["agent_id"])
    if policy["uid"] != item["uid"] or policy["key_fingerprint"] != item["key_fingerprint"]:
        raise PermissionError("Cannot export to a replacement identity.")
    directory = _feed_directory(policy, item["gid"], create=True)
    path = directory / (item["mission_id"] + ".json")
    feed = {**_public(item, detail=True), "uid": item["uid"], "key_fingerprint": item["key_fingerprint"],
            "epoch": item["epoch"], "last_report_hash": item.get("last_report_hash")}
    raw = json.dumps(feed, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    # Validate an existing target BEFORE replace can read or preserve metadata.
    if os.path.lexists(path):
        fd = open_regular_fd(str(path))
        try:
            info = os.fstat(fd)
            repairable = info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= MAX_RECORD
        finally:
            os.close(fd)
        if repairable:
            existing = _read(path, 0)
            if existing.get("mission_id") != item["mission_id"] or existing.get("agent_id") != item["agent_id"]:
                raise PermissionError("Refuse replacing another assignment.")
        else:
            _read_feed_path(path, policy, item["gid"])
    atomic_replace(str(path), raw, limit=MAX_RECORD)
    fd = open_regular_fd(str(path))
    try:
        os.fchown(fd, 0, item["gid"])
        os.fchmod(fd, 0o640)
        os.fsync(fd)
    finally:
        os.close(fd)


def _save(item):
    item["updated_at"] = time.time()
    _write(_directory() / (item["mission_id"] + ".json"), item)
    # Root ledger is authoritative. A failed export can be safely repaired by
    # Refresh; it never rolls back or repeats a production operation.
    try:
        _export(item)
    except (OSError, ValueError, KeyError):
        return False
    return True


def _read_feed_path(path, policy, gid):
    fd = open_regular_fd(str(path))
    try:
        info = os.fstat(fd)
        if (info.st_uid != 0 or info.st_gid != gid or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o640 or info.st_size > MAX_RECORD):
            raise PermissionError("Unsafe assignment file.")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_RECORD + 1)
        if len(raw) > MAX_RECORD:
            raise ValueError("Assignment exceeds budget.")
        item = json.loads(raw)
    finally:
        os.close(fd)
    if (item["agent_id"] != policy["agent_id"] or item["uid"] != policy["uid"]
            or item["key_fingerprint"] != policy["key_fingerprint"]):
        raise PermissionError("Assignment belongs to another identity.")
    _identity(item["mission_id"])
    if item["mission_id"] != path.stem:
        raise ValueError("Assignment filename/identity mismatch.")
    _revision(item["revision"])
    workspaces._project(policy, item["project_path"])
    return item


def _feed(policy, mission_id):
    _identity(mission_id)
    gid = gateway.pwd.getpwnam(policy["account"]).pw_gid
    return _read_feed_path(_feed_directory(policy, gid) / (mission_id + ".json"), policy, gid)


def _progress_directory(policy):
    return workspaces._workspace_directory(policy).with_name("vps-guardian-mission-progress")


@contextmanager
def _progress_lock(policy):
    directory = Path(private_directory(str(_progress_directory(policy))))
    with workspaces._thread_lock:
        fd = open_regular_fd(str(directory / ".lock"), os.O_RDWR | os.O_CREAT, private=True)
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield directory
        finally:
            os.close(fd)


def _report_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _refresh(item):
    before = json.dumps(item, sort_keys=True)
    if item["state"] not in FINAL:
        if time.time() >= item["expires_at"]:
            item["state"] = "expired"
        else:
            try:
                policy = _policy(item)
                item.pop("report_error", None)
                if item["review_id"]:
                    _, review = workspaces._review(item["review_id"])
                    item["review_state"] = review["state"]
                    item["state"] = {"pending": "needs_review", "approved": "ready_to_apply", "completed": "verifying"}.get(review["state"], "needs_attention")
                else:
                    path = _progress_directory(policy) / (item["mission_id"] + ".json")
                    if os.path.lexists(path):
                        report = _read(path, policy["uid"])
                        digest = _report_hash(report)
                        if (digest != item.get("last_report_hash") and report.get("mission_id") == item["mission_id"]
                                and report.get("epoch") == item["epoch"] and report.get("expected_revision") == item["revision"]):
                            phase = report.get("phase")
                            if phase not in {"working", "blocked", "needs_review"}:
                                raise ValueError("Invalid agent phase.")
                            summary = _text(report.get("summary"), 1200)
                            workspace_id = report.get("workspace_id")
                            job_id = report.get("job_id")
                            if job_id is not None and (not isinstance(job_id, str) or not JOB_ID.fullmatch(job_id)):
                                raise ValueError("Invalid reported Job ID.")
                            if phase == "needs_review":
                                source = workspaces._workspace(workspaces._workspace_directory(policy), workspace_id, policy)
                                if source["state"] != "submitted" or source["project_path"] != item["project_path"]:
                                    raise ValueError("Submitted workspace for the assigned project required.")
                            elif workspace_id is not None:
                                raise ValueError("Only submissions bind workspaces.")
                            item.update(state=phase, agent_report=summary, workspace_id=workspace_id,
                                        reported_job_id=job_id, last_report_hash=digest)
                            _event(item, "agent_report", summary[:512])
            except (OSError, ValueError, TypeError, KeyError, RecursionError):
                # Malformed/forged mailbox input never authorizes any action.
                # Preserve canonical state and surface a bounded operator note.
                item["report_error"] = "Agent report or live identity/scope is unavailable; inspect the assignment."
    if json.dumps(item, sort_keys=True) != before:
        item["revision"] += 1
        _save(item)
    else:
        try:
            _export(item)
        except (OSError, ValueError, KeyError):
            pass
    return item


def _current(mission_id, expected_revision, require_identity=True):
    _revision(expected_revision)
    item = _refresh(_task(mission_id))
    if item["revision"] != expected_revision:
        raise MissionConflict()
    if item["state"] in FINAL:
        raise ValueError("Mission is closed.")
    if require_identity:
        _policy(item)
    return item


def _reply(item):
    return {"status": "ok", "mission": _public(item, detail=True)}


def _commit(item, kind, summary):
    _event(item, kind, summary)
    item["revision"] += 1
    delivered = _save(item)
    return {**_reply(item), "assignment_exported": delivered}


@_safe_errors
@gateway._serialized_administration
def create_mission_task(agent_id: str, project_path: str, title: str, goal: str,
                        acceptance_criteria: list[str], required_checks: list[str]):
    policy = workspaces._live_policy(agent_id)
    project = workspaces._project(policy, project_path)
    title, goal = _text(title, 120), _text(goal, 2400)
    if not isinstance(acceptance_criteria, list) or not 1 <= len(acceptance_criteria) <= 8:
        raise ValueError("Provide one to eight acceptance criteria.")
    criteria = [_text(value, 300) for value in acceptance_criteria]
    if not isinstance(required_checks, list) or len(required_checks) > 3 or any(c not in CHECKS for c in required_checks):
        raise ValueError("Select supported static checks only.")
    paths = workspaces._paths(_directory(), MISSION_ID, MAX_TASKS)
    if len(paths) >= MAX_TASKS or sum(_task(p.stem)["agent_id"] == agent_id and _task(p.stem)["state"] not in FINAL for p in paths) >= MAX_ACTIVE_PER_AGENT:
        raise ValueError("Mission capacity reached.")
    now = time.time()
    item = {"schema": 1, "mission_id": "mission_" + secrets.token_hex(12), "agent_id": agent_id,
            "uid": policy["uid"], "gid": gateway.pwd.getpwnam(policy["account"]).pw_gid,
            "key_fingerprint": policy["key_fingerprint"], "epoch": secrets.token_hex(16),
            "project_path": str(project), "title": title, "goal": goal, "acceptance_criteria": criteria,
            "required_checks": sorted(set(required_checks)), "state": "queued", "revision": 1,
            "created_at": now, "updated_at": now,
            "expires_at": min(now + 7 * 86400, dt.datetime.fromisoformat(policy["expires_at"]).timestamp()),
            "workspace_id": None, "review_id": None, "review_state": None, "review_digest": None, "checks": None,
            "verification": None, "agent_report": None, "reported_job_id": None, "events": []}
    _event(item, "assigned", "Assigned to " + agent_id + "; production is unchanged.")
    return {**_reply(item), "assignment_exported": _save(item)}


@_safe_errors
@gateway._serialized_administration
def list_mission_tasks():
    items = [_refresh(_task(p.stem)) for p in workspaces._paths(_directory(), MISSION_ID, MAX_TASKS)]
    return {"status": "ok", "missions": [_public(item) for item in sorted(items, key=lambda i: i["updated_at"], reverse=True)]}


@_safe_errors
@gateway._serialized_administration
def inspect_mission_task(mission_id: str):
    return _reply(_refresh(_task(mission_id)))


@_safe_errors
def list_assigned_missions():
    policy = workspaces._worker_policy()
    gid = gateway.pwd.getpwnam(policy["account"]).pw_gid
    try:
        directory = _feed_directory(policy, gid)
    except FileNotFoundError:
        return {"status": "ok", "missions": []}
    items = [_read_feed_path(p, policy, gid) for p in workspaces._paths(directory, MISSION_ID, MAX_TASKS)]
    return {"status": "ok", "missions": [_public(i) for i in items if i["expires_at"] > time.time() and i["state"] not in FINAL],
            "note": "Assignments are explicit operator instructions, not an autonomous agent or production-write permission."}


@_safe_errors
def get_mission_brief(mission_id: str, after_revision: int = 0):
    if type(after_revision) is not int or not 0 <= after_revision <= 1000000:
        raise ValueError("Invalid cursor.")
    item = _feed(workspaces._worker_policy(), mission_id)
    if after_revision > item["revision"]:
        raise ValueError("Cursor is ahead of the assignment.")
    if after_revision == item["revision"]:
        return {"status": "ok", "mission_id": mission_id, "revision": item["revision"], "unchanged": True,
                "state": item["state"], "expires_at": item["expires_at"]}
    brief = _public(item, detail=True)
    brief.pop("events", None)
    for key in ("checks", "verification"):
        if brief.get(key):
            brief[key] = {field: brief[key].get(field) for field in ("digest", "passed", "complete", "at")}
    return {"status": "ok", "mission": brief, "unchanged": False,
            "note": "Reports are acknowledged only when the operator refreshes the board. Do not repeat production writes."}


@_safe_errors
def report_mission_progress(mission_id: str, expected_revision: int, phase: str, summary: str,
                            workspace_id: str | None = None, job_id: str | None = None):
    policy = workspaces._worker_policy()
    item = _feed(policy, mission_id)
    _revision(expected_revision)
    if expected_revision != item["revision"]:
        raise MissionConflict()
    if item["review_id"] or item["state"] in FINAL or item["expires_at"] <= time.time():
        raise ValueError("Assignment changed, expired or is already in operator review.")
    if phase not in {"working", "blocked", "needs_review"}:
        raise ValueError("Agents cannot approve, apply or declare independent success.")
    summary = _text(summary, 1200)
    if job_id is not None and (not isinstance(job_id, str) or not JOB_ID.fullmatch(job_id)):
        raise ValueError("Invalid reported Job ID.")
    if phase == "needs_review":
        with workspaces._workspace_lock(policy) as directory:
            source = workspaces._workspace(directory, workspace_id, policy)
            if source["state"] != "submitted" or source["project_path"] != item["project_path"]:
                raise ValueError("Submit a workspace for the assigned project first.")
    elif workspace_id is not None:
        raise ValueError("Only submissions bind a workspace.")
    report = {"mission_id": mission_id, "epoch": item["epoch"], "expected_revision": expected_revision,
              "phase": phase, "summary": summary, "workspace_id": workspace_id, "job_id": job_id}
    with _progress_lock(policy) as directory:
        paths = workspaces._paths(directory, MISSION_ID, MAX_TASKS)
        path = directory / (mission_id + ".json")
        if len(paths) >= MAX_TASKS and not os.path.lexists(path):
            raise ValueError("Report capacity reached.")
        _write(path, report)
    return {"status": "ok", "mission_id": mission_id, "report_hash": _report_hash(report),
            "acknowledged": False, "note": "Untrusted progress report saved. The operator must refresh to acknowledge it; production is unchanged."}


@_safe_errors
@gateway._serialized_administration
def reassign_mission_task(mission_id: str, expected_revision: int, agent_id: str):
    item = _current(mission_id, expected_revision, require_identity=False)
    if item["review_id"] or agent_id == item["agent_id"]:
        raise ValueError("Return any review before handoff; choose another worker.")
    policy = workspaces._live_policy(agent_id)
    workspaces._project(policy, item["project_path"])
    paths = workspaces._paths(_directory(), MISSION_ID, MAX_TASKS)
    if sum(_task(p.stem)["agent_id"] == agent_id and _task(p.stem)["state"] not in FINAL for p in paths) >= MAX_ACTIVE_PER_AGENT:
        raise ValueError("New worker is at capacity.")
    old = _feed_directory(gateway._read_policy(item["agent_id"]), item["gid"]) / (mission_id + ".json")
    _read_feed_path(old, gateway._read_policy(item["agent_id"]), item["gid"])
    old.unlink()  # Exact root-owned assignment only, not an account or source.
    item.update(agent_id=agent_id, uid=policy["uid"], gid=gateway.pwd.getpwnam(policy["account"]).pw_gid,
                key_fingerprint=policy["key_fingerprint"], epoch=secrets.token_hex(16), state="queued",
                workspace_id=None, last_report_hash=None, reported_job_id=None)
    item["expires_at"] = min(item["expires_at"], dt.datetime.fromisoformat(policy["expires_at"]).timestamp())
    return _commit(item, "handoff", "Reassigned to " + agent_id + "; private files and approval were not transferred.")


@_safe_errors
@gateway._serialized_administration
def import_mission_task_review(mission_id: str, expected_revision: int):
    item = _current(mission_id, expected_revision)
    if item["state"] != "needs_review" or item["review_id"] or not item["workspace_id"]:
        raise ValueError("A new submitted workspace is required.")
    result = workspaces._import_review(item["agent_id"], item["workspace_id"])
    review_id = result["review"]["review_id"]
    directory, review = workspaces._review(review_id)
    if review["state"] != "pending" or review.get("mission_id") not in (None, mission_id):
        raise ValueError("This workspace already has another or non-pending review.")
    review["mission_id"] = mission_id
    review["digest"] = workspaces._review_digest(review)
    workspaces._write(directory / (review_id + ".json"), review)
    item.update(review_id=review_id, review_state="pending", review_digest=review["digest"], checks=None, verification=None)
    return {**_commit(item, "review_imported", "Exact private operator snapshot imported; not approved or applied."),
            "review": workspaces._review_detail(review)}


def _assert_review_allowed(review, require_checks=False):
    item = _task(review["mission_id"])
    if (item["state"] in FINAL or time.time() >= item["expires_at"]
            or item["review_id"] != review["review_id"] or item["review_digest"] != review["digest"]
            or item["agent_id"] != review["agent_id"]):
        raise PermissionError("Mission closed or the linked review was withdrawn.")
    _policy(item)
    if require_checks and (not item["checks"] or item["checks"]["digest"] != review["digest"]
                           or not item["checks"]["complete"] or not item["checks"]["passed"]):
        raise PermissionError("Independent snapshot checks must pass before approval or apply.")


def _retain_linked_review(review):
    try:
        item = _task(review["mission_id"])
        return item["state"] not in FINAL and time.time() < item["expires_at"]
    except (OSError, ValueError, KeyError):
        # A missing/corrupt ledger is not permission to discard recovery data.
        return True


def _workspace_has_assignment(agent_id, workspace_id):
    # Called inside the operator's existing administration lock. Reconcile
    # submissions before allowing the legacy standalone import path.
    if not os.path.lexists(gateway.POLICY_BASE / "tasks"):
        return False
    for path in workspaces._paths(_directory(), MISSION_ID, MAX_TASKS):
        item = _task(path.stem)
        if item["agent_id"] == agent_id:
            item = _refresh(item)
            if item["workspace_id"] == workspace_id:
                return True
    return False


_PARSER = """import ast,json,resource,sys,warnings
warnings.simplefilter('ignore')
resource.setrlimit(resource.RLIMIT_AS,(134217728,134217728))
resource.setrlimit(resource.RLIMIT_CPU,(2,2))
resource.setrlimit(resource.RLIMIT_FSIZE,(0,0))
source=sys.stdin.buffer.read(512001)
try:
 if len(source)>512000: raise ValueError()
 text=source.decode('utf-8')
 if sys.argv[1]=='python_syntax': ast.parse(text)
 elif sys.argv[1]=='json_syntax': json.loads(text,parse_constant=lambda x: (_ for _ in ()).throw(ValueError()))
 else:
  import tomllib
  tomllib.loads(text)
 print(json.dumps({'passed':True}))
except (SyntaxError,ValueError,UnicodeError,RecursionError,MemoryError) as e:
 print(json.dumps({'passed':False,'error':type(e).__name__,'line':getattr(e,'lineno',None)}))
"""


def _parse(check, source):
    if not sys.platform.startswith("linux") or get_runtime_budget()["available_memory_bytes"] < 192 * 1024 * 1024:
        return {"passed": False, "error": "Static checks require Linux and 192 MiB available memory. No host execution fallback."}
    if check == "toml_syntax" and sys.version_info < (3, 11):
        return {"passed": False, "error": "TOML checks require Python 3.11+; no unbounded third-party parser fallback."}
    process = subprocess.Popen([sys.executable, "-I", "-S", "-c", _PARSER, check], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
                               env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    try:
        stdout, _ = process.communicate(source.encode("utf-8"), timeout=3)
        if process.returncode != 0 or len(stdout) > 2048:
            return {"passed": False, "error": "Parser exceeded its budget or failed."}
        value = json.loads(stdout)
        if type(value.get("passed")) is not bool:
            raise ValueError("Invalid parser reply.")
        return value
    except (subprocess.TimeoutExpired, ValueError):
        process.kill()
        process.communicate()
        return {"passed": False, "error": "Parser timed out or returned an invalid result."}
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)


def _check_plan(item, review):
    suffixes = {".py": "python_syntax", ".json": "json_syntax", ".toml": "toml_syntax"}
    return [(file, suffixes[Path(file["relative_path"]).suffix]) for file in review["files"]
            if file["candidate"] is not None and suffixes.get(Path(file["relative_path"]).suffix) in item["required_checks"]]


@_safe_errors
@gateway._serialized_administration
def run_mission_task_check(mission_id: str, expected_revision: int):
    item = _current(mission_id, expected_revision)
    if not item["review_id"]:
        raise ValueError("Import a snapshot first.")
    _, review = workspaces._review(item["review_id"])
    if review["state"] not in {"pending", "approved"}:
        raise ValueError("Only unapplied snapshots can be checked.")
    workspaces._review_live(review)
    checks = item["checks"]
    if not checks or checks["digest"] != review["digest"]:
        checks = {"digest": review["digest"], "results": [], "complete": False, "passed": False}
    plan = _check_plan(item, review)
    # One file per request; no long worker or unbounded operator-call lifetime.
    done = {result["relative_path"] for result in checks["results"] if result["passed"]}
    pending = [(file, check) for file, check in plan if file["relative_path"] not in done]
    if pending:
        file, check = pending[0]
        checks["results"] = [r for r in checks["results"] if r["relative_path"] != file["relative_path"]]
        checks["results"].append({"relative_path": file["relative_path"], "check": check, **_parse(check, file["candidate"])})
    checks["complete"] = len(checks["results"]) == len(plan)
    checks["passed"] = checks["complete"] and all(result["passed"] for result in checks["results"])
    checks["note"] = "Fixed static parsers only, not project test execution or a correctness proof. Files in unselected/unsupported formats are not checked."
    item["checks"] = checks
    return _commit(item, "snapshot_check", "Snapshot check recorded; " + ("all selected checks passed." if checks["passed"] else "more checks or corrections required."))


def _verify(item):
    policy = _policy(item)
    _, review = workspaces._review(item["review_id"])
    if review["state"] != "completed" or review["digest"] != item["review_digest"]:
        raise ValueError("A successfully applied bound snapshot is required.")
    results = []
    for file in review["files"]:
        try:
            if file["candidate"] is None:
                workspaces._absent(policy, item["project_path"], file["relative_path"])
                passed = True
            else:
                _, actual = workspaces._target(policy, item["project_path"], file["relative_path"])
                passed = workspaces._hash(actual) == workspaces._hash(file["candidate"])
        except (OSError, ValueError):
            passed = False
        results.append({"relative_path": file["relative_path"], "passed": passed})
    return {"digest": review["digest"], "at": time.time(), "passed": all(r["passed"] for r in results), "results": results,
            "note": "Exact live file/absence checks only. This does not verify service behavior, payments, tests or future health."}


@_safe_errors
@gateway._serialized_administration
def verify_mission_task(mission_id: str, expected_revision: int):
    item = _current(mission_id, expected_revision)
    item["verification"] = _verify(item)
    return _commit(item, "production_verification", "Live production hashes " + ("match the approved snapshot." if item["verification"]["passed"] else "do not match; inspect production."))


@_safe_errors
@gateway._serialized_administration
def finish_mission_task(mission_id: str, expected_revision: int):
    item = _current(mission_id, expected_revision)
    if not item["verification"] or not item["verification"]["passed"]:
        raise ValueError("Verify production before finishing.")
    fresh = _verify(item)
    if not fresh["passed"]:
        raise ValueError("Production changed since verification; completion refused.")
    item.update(state="done", verification=fresh)
    return _commit(item, "operator_completed", "Operator confirmed acceptance criteria and fresh production hashes. No agent may declare this independently.")


@_safe_errors
@gateway._serialized_administration
def cancel_mission_task(mission_id: str, expected_revision: int):
    item = _current(mission_id, expected_revision, require_identity=False)
    if item["review_id"]:
        _, review = workspaces._review(item["review_id"])
        if review["state"] in {"completed", "uncertain"}:
            raise ValueError("Production may have changed. Inspect and verify; cancellation is not rollback.")
    item["state"] = "cancelled"
    return _commit(item, "operator_cancelled", "Cancelled; future linked approval/apply is blocked. No production rollback or in-flight cancellation is claimed.")


@_safe_errors
@gateway._serialized_administration
def return_mission_task(mission_id: str, expected_revision: int):
    item = _current(mission_id, expected_revision)
    if not item["review_id"]:
        raise ValueError("A linked review is required.")
    directory, review = workspaces._review(item["review_id"])
    if review["state"] not in {"pending", "approved", "rejected", "superseded"}:
        raise ValueError("Applied or uncertain production work cannot be reset or replayed.")
    review["state"] = "superseded"
    workspaces._write(directory / (review["review_id"] + ".json"), review)
    item.update(review_id=None, review_state=None, review_digest=None, workspace_id=None, checks=None, verification=None,
                state="working", last_report_hash=None)
    return _commit(item, "revision_requested", "Review withdrawn. Prepare a new workspace; old approval cannot be reused.")
