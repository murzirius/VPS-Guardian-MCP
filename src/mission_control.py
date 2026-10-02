"""Bounded proposal workspaces and independent, root-operator review.

No code is executed. Agent-owned proposals are untrusted inputs: the operator
copies validated bytes into private root-owned records before approving them.
Only existing, root-protected text files are supported in this first version.
"""
from __future__ import annotations

from contextlib import contextmanager
import difflib
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import threading
import time

from src import gateway
from src.code_navigator import _allowed
from src.files import _redact_config_text
from src.resource_policy import get_runtime_budget
from src.safe_io import atomic_replace, open_regular_fd, private_directory, read_bounded

WORKSPACE_ID = re.compile(r"ws_[0-9a-f]{24}\Z")
REVIEW_ID = re.compile(r"review_[0-9a-f]{24}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MAX_FILES = 3
MAX_FILE_BYTES = 100_000
MAX_RECORD_BYTES = 1_900_000  # JSON escaping of three source/candidate pairs.
MAX_WORKSPACES = 8
MAX_REVIEWS = 32
MAX_DIFF = 48_000
TTL = 86400
_thread_lock = threading.RLock()
OPERATOR_TOOLS = frozenset({"list_mission_submissions", "import_mission_review", "list_mission_reviews",
                            "get_mission_review", "decide_mission_review", "apply_mission_review"})


def _safe_errors(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            return {"status": "error", "error": "Mission request refused. Check identity, expiry, scope, protected paths and byte/capacity limits. No operation is replayed automatically."}
    return wrapped


def _budget():
    budget = get_runtime_budget()
    if budget["available_memory_bytes"] < 96 * 1024 * 1024:
        raise ValueError("Not enough available memory for a workspace.")
    limits = budget["limits"]
    return min(MAX_FILES, limits["project_patch_files"]), min(MAX_FILE_BYTES, limits["project_read_bytes"]), min(300_000, limits["project_patch_bytes"])


def _worker_policy():
    policy = gateway._active_policy()
    if not policy or policy.get("profile") != "mission-worker":
        raise PermissionError("A dedicated Mission worker Gateway identity is required.")
    return policy


def _live_policy(agent_id):
    policy = gateway._read_policy(agent_id)
    import datetime as dt
    if (not policy["enabled"] or policy["profile"] != "mission-worker"
            or dt.datetime.fromisoformat(policy["expires_at"]) <= dt.datetime.now(dt.timezone.utc)):
        raise PermissionError("Agent was revoked or expired.")
    # Refuse Unix account reuse, including root or a mismatched home directory.
    user = gateway.pwd.getpwnam(policy["account"])
    if user.pw_uid != policy["uid"] or user.pw_dir != str(gateway.HOME_BASE / agent_id):
        raise PermissionError("Agent Unix identity changed.")
    return policy


def _workspace_directory(policy):
    return gateway.HOME_BASE / policy["agent_id"] / ".local" / "share" / "vps-guardian-missions"


@contextmanager
def _workspace_lock(policy):
    directory = Path(private_directory(str(_workspace_directory(policy))))
    with _thread_lock:
        fd = open_regular_fd(str(directory / ".lock"), os.O_RDWR | os.O_CREAT, private=True)
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield directory
        finally:
            os.close(fd)


def _paths(directory, pattern, maximum):
    result = []
    # Do not glob/sort an unbounded directory controlled by an agent.
    with os.scandir(directory) as entries:
        for index, entry in enumerate(entries):
            if index > maximum + 1:
                raise ValueError("Directory capacity exceeded.")
            if entry.name == ".lock":
                continue
            if not entry.name.endswith(".json") or not pattern.fullmatch(entry.name[:-5]):
                raise ValueError("Unexpected state file.")
            result.append(Path(entry.path))
    if len(result) > maximum:
        raise ValueError("State capacity exceeded.")
    return sorted(result)


def _read_json(path, *, uid):
    fd = open_regular_fd(str(path))
    try:
        info = os.fstat(fd)
        if info.st_uid != uid or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > MAX_RECORD_BYTES:
            raise PermissionError("Unsafe state file.")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_RECORD_BYTES + 1)
        if len(raw) > MAX_RECORD_BYTES:
            raise ValueError("State read budget exceeded.")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("Invalid state.")
        return value
    finally:
        os.close(fd)


def _write(path, value):
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    atomic_replace(str(path), raw, private=True, limit=MAX_RECORD_BYTES)


def _project(policy, value):
    if not isinstance(value, str) or len(value) > 1024 or not os.path.isabs(value):
        raise ValueError("Absolute project path required.")
    project = Path(value)
    if str(project) != str(project.resolve()) or not project.is_dir():
        raise ValueError("Canonical non-symlink project required.")
    if not any(str(project) == root or str(project).startswith(root + os.sep) for root in policy["project_roots"]):
        raise PermissionError("Outside this agent's roots.")
    protected = [gateway.POLICY_BASE, gateway.HOME_BASE, Path(__file__).resolve().parent]
    if sys.prefix != sys.base_prefix:
        protected.append(Path(sys.prefix).resolve())
    protected.extend(Path(p) for p in ("/etc", "/root", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/proc", "/sys", "/dev", "/run"))
    for root in protected:
        if project == root or root in project.parents or project in root.parents:
            raise PermissionError("Guardian, account and system control paths are excluded.")
    gateway._trusted_directory(project)
    return project


def _relative(relative):
    if (not isinstance(relative, str) or len(relative) > 512 or "\\" in relative
            or not _allowed(relative) or any(part in {".", ".."} for part in relative.split("/"))):
        raise ValueError("Choose a non-hidden, non-sensitive relative path.")
    return relative


def _target(policy, project, relative):
    relative = _relative(relative)
    path = _project(policy, str(project)) / relative
    gateway._trusted_directory(path.parent)
    # Each file and ancestor is root-owned and not group/world writable. The
    # worker may read it but cannot alter it or replace its parent directory.
    with os.fdopen(open_regular_fd(str(path)), "rb") as stream:
        info = os.fstat(stream.fileno())
        if info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_mode & 0o6000:
            raise PermissionError("Production file must be root-protected.")
        limit = _budget()[1]
        if info.st_size > limit:
            raise ValueError("File exceeds workspace budget.")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("File grew beyond budget.")
    return path, _text(raw.decode("utf-8"))


def _text(value):
    if (not isinstance(value, str) or len(value.encode("utf-8")) > _budget()[1]
            or value.count("\n") > 2000 or any(ord(c) < 32 and c not in "\n\r\t" or ord(c) == 127 for c in value)):
        raise ValueError("Bounded UTF-8 text required.")
    if _redact_config_text(value)[1]:
        raise ValueError("Files with recognized inline secrets require separate operator handling.")
    return value


def _hash(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _summary(item):
    result = {key: item[key] for key in ("workspace_id", "agent_id", "project_path", "title", "state", "created_at", "expires_at")}
    result["files"] = [{"relative_path": f["relative_path"], "baseline_sha256": f["baseline_sha256"],
                        "candidate_sha256": _hash(f["candidate"])} for f in item["files"]]
    if "review_id" in item:
        result.update(review_id=item["review_id"], digest=item["digest"], result=item.get("result"))
    return result


def _validate_workspace(value, policy, workspace_id, *, check_baseline=True):
    if value.get("workspace_id") != workspace_id or value.get("agent_id") != policy["agent_id"]:
        raise ValueError("Workspace identity mismatch.")
    if (not isinstance(value.get("title"), str) or not 1 <= len(value["title"]) <= 120
            or any(ord(c) < 32 for c in value["title"])):
        raise ValueError("Invalid title.")
    now = time.time()
    if (type(value.get("created_at")) not in (int, float) or type(value.get("expires_at")) not in (int, float)
            or not now - TTL <= value["created_at"] <= now
            or not now < value["expires_at"] <= value["created_at"] + TTL):
        raise ValueError("Workspace expired or invalid.")
    if value.get("state") not in {"draft", "submitted"}:
        raise ValueError("Invalid workspace state.")
    project = _project(policy, value["project_path"])
    files = value.get("files")
    count, _, byte_limit = _budget()
    if not isinstance(files, list) or not 1 <= len(files) <= count:
        raise ValueError("File count exceeded.")
    seen, total = set(), 0
    for file in files:
        relative = _relative(file["relative_path"])
        baseline = file.get("baseline_sha256")
        if relative in seen or not isinstance(baseline, str) or not DIGEST.fullmatch(baseline):
            raise ValueError("Invalid baseline or duplicate file.")
        # Reading an already copied candidate is not production authorization.
        # Stage/import/approval/apply still require a fresh, protected baseline.
        if check_baseline and baseline != _hash(_target(policy, project, relative)[1]):
            raise ValueError("Production changed or duplicate file.")
        seen.add(relative)
        _text(file["candidate"])
        total += len(file["candidate"].encode("utf-8"))
    if total > byte_limit:
        raise ValueError("Candidate byte budget exceeded.")
    return value


def _workspace(directory, workspace_id, policy, *, check_baseline=True):
    if not isinstance(workspace_id, str) or not WORKSPACE_ID.fullmatch(workspace_id):
        raise ValueError("Invalid workspace ID.")
    return _validate_workspace(_read_json(directory / (workspace_id + ".json"), uid=policy["uid"]), policy, workspace_id,
                               check_baseline=check_baseline)


@_safe_errors
def create_mission_workspace(project_path: str, relative_paths: list[str], title: str):
    policy = _worker_policy()
    project = _project(policy, project_path)
    if not isinstance(relative_paths, list) or not 1 <= len(relative_paths) <= _budget()[0]:
        raise ValueError("Select one to three files.")
    now = time.time()
    item = {"workspace_id": "ws_" + secrets.token_hex(12), "agent_id": policy["agent_id"], "project_path": str(project),
            "title": title, "state": "draft", "created_at": now, "expires_at": now + TTL, "files": []}
    for relative in relative_paths:
        _, source = _target(policy, project, relative)
        item["files"].append({"relative_path": relative, "baseline_sha256": _hash(source), "candidate": source})
    _validate_workspace(item, policy, item["workspace_id"])
    with _workspace_lock(policy) as directory:
        for path in _paths(directory, WORKSPACE_ID, MAX_WORKSPACES):
            saved = _read_json(path, uid=policy["uid"])
            if type(saved.get("expires_at")) in (int, float) and saved["expires_at"] <= now:
                path.unlink()
        if len(_paths(directory, WORKSPACE_ID, MAX_WORKSPACES)) >= MAX_WORKSPACES:
            raise ValueError("Workspace capacity reached.")
        _write(directory / (item["workspace_id"] + ".json"), item)
    return {"status": "ok", "workspace": _summary(item), "note": "Private candidate copy only. Production is unchanged."}


@_safe_errors
def read_mission_workspace(workspace_id: str, relative_path: str, byte_offset: int = 0, max_bytes: int = 12000):
    policy = _worker_policy()
    if type(byte_offset) is not int or not 0 <= byte_offset <= MAX_FILE_BYTES or type(max_bytes) is not int or not 100 <= max_bytes <= 24000:
        raise ValueError("Invalid read range.")
    with _workspace_lock(policy) as directory:
        item = _workspace(directory, workspace_id, policy, check_baseline=False)
        file = next((f for f in item["files"] if f["relative_path"] == relative_path), None)
        if file is None:
            raise ValueError("File is not in this workspace.")
        raw = file["candidate"].encode("utf-8")
        fragment = raw[byte_offset:byte_offset + max_bytes]
        # Interior UTF-8 boundaries must be selected explicitly by the caller.
        raw[byte_offset:].decode("utf-8")  # Reject a start in the middle of a character.
        content = fragment.decode("utf-8", errors="ignore")
        fragment = content.encode("utf-8")
        return {"status": "ok", "workspace": _summary(item), "live_baseline_checked": False, "relative_path": relative_path, "content": content,
                "next_byte_offset": byte_offset + len(fragment) if byte_offset + len(fragment) < len(raw) else None}


@_safe_errors
def stage_mission_file(workspace_id: str, relative_path: str, content: str, expected_sha256: str):
    policy = _worker_policy()
    _text(content)
    with _workspace_lock(policy) as directory:
        item = _workspace(directory, workspace_id, policy)
        if item["state"] != "draft":
            raise ValueError("Submitted workspace is frozen; create a new one.")
        file = next((f for f in item["files"] if f["relative_path"] == relative_path), None)
        if file is None or expected_sha256 != _hash(file["candidate"]):
            return {"status": "conflict", "error": "Candidate changed; read it again before editing."}
        file["candidate"] = content
        _validate_workspace(item, policy, workspace_id)
        _write(directory / (workspace_id + ".json"), item)
    return {"status": "ok", "workspace": _summary(item)}


@_safe_errors
def submit_mission_workspace(workspace_id: str):
    policy = _worker_policy()
    with _workspace_lock(policy) as directory:
        item = _workspace(directory, workspace_id, policy)
        item["state"] = "submitted"
        _write(directory / (workspace_id + ".json"), item)
    return {"status": "ok", "workspace": _summary(item), "note": "Awaiting independent operator review. This is not permission to apply."}


@_safe_errors
def list_mission_workspaces():
    policy = _worker_policy()
    with _workspace_lock(policy) as directory:
        result = [_summary(_workspace(directory, path.stem, policy, check_baseline=False)) for path in _paths(directory, WORKSPACE_ID, MAX_WORKSPACES)
                  if _read_json(path, uid=policy["uid"]).get("expires_at", 0) > time.time()]
    return {"status": "ok", "workspaces": result, "live_baseline_checked": False}


@_safe_errors
def stage_mission_line_edit(workspace_id: str, relative_path: str, start_line: int, end_line: int,
                            replacement: str, expected_sha256: str):
    policy = _worker_policy()
    if (type(start_line) is not int or type(end_line) is not int or not 1 <= start_line <= end_line
            or not isinstance(replacement, str) or len(replacement.encode("utf-8")) > 24000):
        raise ValueError("Invalid bounded line edit.")
    with _workspace_lock(policy) as directory:
        item = _workspace(directory, workspace_id, policy)
        file = next((f for f in item["files"] if f["relative_path"] == relative_path), None)
        if item["state"] != "draft" or file is None:
            raise ValueError("Editable workspace file required.")
        if expected_sha256 != _hash(file["candidate"]):
            return {"status": "conflict", "error": "Candidate changed; read it again before editing."}
        lines = file["candidate"].splitlines(keepends=True)
        if end_line > len(lines):
            raise ValueError("Line range is outside the candidate.")
        file["candidate"] = "".join(lines[:start_line - 1]) + replacement + "".join(lines[end_line:])
        _validate_workspace(item, policy, workspace_id)
        _write(directory / (workspace_id + ".json"), item)
    return {"status": "ok", "workspace": _summary(item)}


def _review_directory():
    directory = gateway.POLICY_BASE / "reviews"
    gateway._trusted_directory(gateway.POLICY_BASE, create=True, administrator=True)
    if not os.path.lexists(directory):
        directory.mkdir(mode=0o700)
    gateway._trusted_directory(directory, administrator=True)
    return Path(private_directory(str(directory)))


def _review_digest(item):
    bound = {key: item[key] for key in ("review_id", "workspace_id", "agent_id", "uid", "key_fingerprint", "project_roots",
                                      "project_path", "title", "created_at", "expires_at", "files")}
    return hashlib.sha256(json.dumps(bound, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _review(review_id):
    if not isinstance(review_id, str) or not REVIEW_ID.fullmatch(review_id):
        raise ValueError("Invalid review ID.")
    directory = _review_directory()
    item = _read_json(directory / (review_id + ".json"), uid=0)
    if item["review_id"] != review_id or item["digest"] != _review_digest(item):
        raise ValueError("Review digest changed.")
    if item["state"] == "applying":
        item["state"] = "uncertain"
        _write(directory / (review_id + ".json"), item)
    return directory, item


def _review_live(item):
    policy = _live_policy(item["agent_id"])
    if time.time() >= item["expires_at"] or any(policy[key] != item[key] for key in ("uid", "key_fingerprint", "project_roots")):
        raise ValueError("Review expired or identity/scope changed.")
    _validate_workspace({**item, "state": "submitted"}, policy, item["workspace_id"])
    return policy


def _review_detail(item):
    diffs = []
    for file in item["files"]:
        diff = "".join(difflib.unified_diff(file["original"].splitlines(keepends=True), file["candidate"].splitlines(keepends=True),
                                           fromfile=file["relative_path"], tofile=file["relative_path"]))
        diffs.append(diff)
    full = "\n".join(diffs)
    # JSON escaping worst case keeps a full detail under the panel's 256 KB cap.
    return {"status": "ok", "review": _summary(item), "diff": full[:MAX_DIFF], "diff_truncated": len(full) > MAX_DIFF,
            "note": "Source is shown only to the private operator connection. No code or checks are executed."}


@_safe_errors
@gateway._serialized_administration
def list_mission_submissions(agent_id: str):
    policy = _live_policy(agent_id)
    directory = _workspace_directory(policy)
    if not directory.exists():
        return {"status": "ok", "submissions": []}
    result = []
    for path in _paths(directory, WORKSPACE_ID, MAX_WORKSPACES):
        item = _read_json(path, uid=policy["uid"])
        if type(item.get("expires_at")) in (int, float) and item["expires_at"] <= time.time():
            continue
        _validate_workspace(item, policy, path.stem, check_baseline=False)
        if item["state"] == "submitted":
            result.append(_summary(item))
    return {"status": "ok", "submissions": result, "live_baseline_checked": False}


@_safe_errors
@gateway._serialized_administration
def import_mission_review(agent_id: str, workspace_id: str):
    policy = _live_policy(agent_id)
    item = _workspace(_workspace_directory(policy), workspace_id, policy)
    if item["state"] != "submitted":
        raise ValueError("Submit workspace before review.")
    directory = _review_directory()
    paths = _paths(directory, REVIEW_ID, MAX_REVIEWS)
    for path in paths:
        old = _read_json(path, uid=0)
        if old.get("agent_id") == agent_id and old.get("workspace_id") == workspace_id:
            # Never import a revised proposal over an already reviewed snapshot.
            _, previous = _review(path.stem)
            return _review_detail(previous)
    if len(paths) >= MAX_REVIEWS:
        raise ValueError("Review capacity reached. Expired reviews can be pruned by listing them.")
    # Drop untrusted fields; bind only validated candidate bytes and live source.
    source = item
    item = {key: source[key] for key in ("workspace_id", "agent_id", "project_path", "title", "created_at", "expires_at")}
    item.update(review_id="review_" + secrets.token_hex(12), state="pending", uid=policy["uid"],
                key_fingerprint=policy["key_fingerprint"], project_roots=list(policy["project_roots"]), files=[])
    for file in source["files"]:
        _, original = _target(policy, item["project_path"], file["relative_path"])
        item["files"].append({"relative_path": file["relative_path"], "baseline_sha256": _hash(original),
                              "original": original, "candidate": file["candidate"]})
    _review_live(item)
    item["digest"] = _review_digest(item)
    _write(directory / (item["review_id"] + ".json"), item)
    return _review_detail(item)


@_safe_errors
@gateway._serialized_administration
def list_mission_reviews():
    directory = _review_directory()
    result = []
    for path in _paths(directory, REVIEW_ID, MAX_REVIEWS):
        _, item = _review(path.stem)
        if item["expires_at"] <= time.time() and item["state"] not in {"uncertain"}:
            path.unlink()  # Root-protected exact expired record; never live work.
            continue
        result.append(_summary(item))
    return {"status": "ok", "reviews": result}


@_safe_errors
@gateway._serialized_administration
def get_mission_review(review_id: str):
    _, item = _review(review_id)
    return _review_detail(item)


@_safe_errors
@gateway._serialized_administration
def decide_mission_review(review_id: str, digest: str, decision: str):
    directory, item = _review(review_id)
    if item["state"] != "pending" or digest != item["digest"] or decision not in {"approve", "reject"}:
        raise ValueError("Review state or digest changed.")
    if decision == "approve":
        _review_live(item)
        if _review_detail(item)["diff_truncated"]:
            raise ValueError("Split this change: a truncated diff cannot be approved.")
    item["state"] = "approved" if decision == "approve" else "rejected"
    _write(directory / (review_id + ".json"), item)
    return _review_detail(item)


@_safe_errors
@gateway._serialized_administration
def apply_mission_review(review_id: str, digest: str):
    directory, item = _review(review_id)
    if item["state"] != "approved" or digest != item["digest"]:
        raise ValueError("Independent approval of this exact digest is required.")
    policy = _review_live(item)
    item["state"] = "applying"
    path = directory / (review_id + ".json")
    _write(path, item)  # Durable claim BEFORE the first external write.
    written = []
    try:
        for file in item["files"]:
            target, original = _target(policy, item["project_path"], file["relative_path"])
            if _hash(original) != file["baseline_sha256"]:
                raise ValueError("Production changed after review.")
            backup, _ = atomic_replace(str(target), file["candidate"].encode("utf-8"), backup=True,
                                       limit=MAX_FILE_BYTES, expected_sha256=file["baseline_sha256"])
            written.append({"relative_path": file["relative_path"], "backup": backup})
    except (OSError, ValueError):
        # A write may have succeeded before an fsync or metadata error. Do not
        # guess, retry, or claim an automatic all-or-nothing rollback.
        item["state"] = "uncertain"
    else:
        item["state"] = "completed"
    item["result"] = {"written": written, "automatic_replay": False, "atomic_across_files": False}
    _write(path, item)
    return _review_detail(item)
