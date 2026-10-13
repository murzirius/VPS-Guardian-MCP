"""Operator-only isolated checks of immutable Mission reviews.

Evidence includes every copied input and the immutable local image ID. Neither
project commands nor candidate imports ever run in the privileged helper.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from src import mission_control as workspaces, test_capsules as capsules
from src.files import _redact_config_text
from src.safe_io import open_regular_fd, private_directory

CHECKS = frozenset({"python_unittest", "npm_test", "node_syntax"})
RECIPE = "mission-capsule-v1"
_UNITTEST = """import sys,unittest
suite=unittest.defaultTestLoader.discover('tests')
if suite.countTestCases()==0:
 print('No unittest cases discovered; refusing an empty pass.',file=sys.stderr)
 sys.exit(2)
result=unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(0 if result.wasSuccessful() and result.testsRun>len(result.skipped) else 1)
"""


@contextmanager
def _lock():
    if not capsules._check_lock.acquire(blocking=False):
        raise ValueError("Another capsule is running; retry later.")
    fd = None
    try:
        directory = private_directory(capsules._state_dir())
        fd = open_regular_fd(os.path.join(directory, "test-capsule.lock"), os.O_RDWR | os.O_CREAT, private=True)
        if os.fstat(fd).st_nlink != 1:
            raise ValueError("Unsafe capsule lock.")
        capsules.fcntl.flock(fd, capsules.fcntl.LOCK_EX | capsules.fcntl.LOCK_NB)
        yield
    finally:
        if fd is not None:
            os.close(fd)
        capsules._check_lock.release()


def _image(check):
    image, error = capsules._preflight(check)
    if error:
        raise ValueError(error)
    docker = shutil.which("docker") or "docker"
    result = subprocess.run([docker, "image", "inspect", image, "--format", "{{.Id}}"],
                            capture_output=True, timeout=5, check=False)
    identity = result.stdout.decode("ascii", errors="replace").strip()
    if result.returncode or not re.fullmatch(r"sha256:[0-9a-f]{64}", identity):
        raise ValueError("Cannot pin a local capsule image ID; no image pull or host fallback.")
    return docker, identity


def _manifest(snapshot):
    entries = []
    for directory, dirs, files in os.walk(snapshot):
        dirs.sort()
        for name in sorted(files):
            path = Path(directory) / name
            with path.open("rb") as handle:
                raw = handle.read(capsules.MAX_SNAPSHOT_BYTES + 1)
            # Only eligible UTF-8 source/fixtures. Recognized inline secrets are
            # refused, not silently modified (which would test different code).
            text = raw.decode("utf-8")
            if _redact_config_text(text)[1]:
                raise ValueError("A capsule input contains a recognized inline secret. Use a secret-free test tree.")
            entries.append([path.relative_to(snapshot).as_posix(), hashlib.sha256(raw).hexdigest()])
    return hashlib.sha256(json.dumps(sorted(entries), separators=(",", ":")).encode()).hexdigest()


def _prepare(review, snapshot):
    policy = workspaces._live_policy(review["agent_id"])
    project = workspaces._project(policy, review["project_path"])
    summary = capsules._copy_snapshot(str(project), snapshot, protected=True)
    baseline = _manifest(snapshot)
    changed = []
    for file in review["files"]:
        relative = workspaces._relative(file["relative_path"])
        parts = relative.split("/")
        if any(not capsules._allowed_name(part, index < len(parts) - 1) for index, part in enumerate(parts)):
            raise ValueError("A reviewed file is excluded from capsule inputs.")
        workspaces._baseline(policy, str(project), file)
        target = Path(snapshot).joinpath(*parts)
        existed = file["baseline_sha256"] is not None
        if existed:
            if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != file["baseline_sha256"]:
                raise ValueError("Copied input differs from the reviewed baseline.")
        elif target.exists():
            raise ValueError("New reviewed file conflicts with the copied tree.")
        old_size = target.stat().st_size if existed else 0
        candidate = file["candidate"]
        summary["files"] += (0 if existed else 1) if candidate is not None else -1
        summary["bytes"] += (len(candidate.encode()) if candidate is not None else 0) - old_size
        if summary["files"] > capsules.MAX_SNAPSHOT_FILES or summary["bytes"] > capsules.MAX_SNAPSHOT_BYTES:
            raise ValueError("Candidate exceeds the capsule snapshot budget.")
        if candidate is None:
            target.unlink()  # Exact file in this new temporary copy only.
        else:
            capsules._snapshot_parent(snapshot, relative)
            target.write_bytes(candidate.encode("utf-8"))
            target.chmod(0o644)
            changed.append(relative)
    return {"baseline": baseline, "candidate": _manifest(snapshot), "summary": summary, "changed": changed}


def _inputs(review):
    with tempfile.TemporaryDirectory(prefix="vps-guardian-mission-inputs-") as snapshot:
        return _prepare(review, snapshot)


def validate(review, results):
    """Fail closed if inputs, runtime image or isolation recipe changed."""
    images = {result["check"]: _image(result["check"])[1] for result in results}
    inputs = _inputs(review)
    for result in results:
        image = images[result["check"]]
        evidence = result.get("evidence") or {}
        if evidence != {"recipe": RECIPE, "review_digest": review["digest"], "image_id": image,
                        "baseline": inputs["baseline"], "candidate": inputs["candidate"]}:
            raise ValueError("Capsule evidence is stale. Run tests again before approving or applying.")


def run(review, check):
    """One fixed check, one bounded copy, one unprivileged offline container."""
    if check not in CHECKS:
        raise ValueError("Unsupported Mission capsule check.")
    started = time.monotonic()
    executed = False
    try:
        docker, image = _image(check)
        with _lock(), tempfile.TemporaryDirectory(prefix="vps-guardian-mission-capsule-") as private:
            # The host's other accounts cannot traverse the private parent.
            # Docker binds only its child, accessible to the container user.
            os.chmod(private, 0o700)
            snapshot = str(Path(private) / "source")
            os.mkdir(snapshot, 0o755)
            inputs = _prepare(review, snapshot)
            if check == "python_unittest" and not any(p.name.startswith("test") and p.suffix == ".py" for p in Path(snapshot, "tests").rglob("*.py")):
                raise ValueError("No Python unittest files were copied; no tests were run.")
            if check == "npm_test":
                package = Path(snapshot, "package.json")
                script = json.loads(package.read_text()).get("scripts", {}).get("test") if package.is_file() else None
                if not isinstance(script, str) or not script.strip():
                    raise ValueError("No npm test script was copied; no tests were run.")
            command = ["python", "-B", "-c", _UNITTEST] if check == "python_unittest" else capsules._command(check, inputs["changed"])
            os.chmod(snapshot, 0o755)
            result = capsules._run_container(docker, image, snapshot, command)
            executed = True
            passed = (result.get("success") is True and result.get("status") == "ok"
                      and result.get("exit_code") == 0 and not result.get("cleanup_uncertain"))
            # Detect changes during the test as well as later at approval/apply.
            if passed and _inputs(review) != inputs:
                raise ValueError("Project inputs changed during testing. Run tests again.")
            evidence = {"recipe": RECIPE, "review_digest": review["digest"], "image_id": image,
                        "baseline": inputs["baseline"], "candidate": inputs["candidate"]}
            return {"check": check, "passed": passed, "status": "passed" if passed else "cleanup_uncertain" if result.get("cleanup_uncertain") else result["status"],
                    "evidence": evidence, "snapshot": inputs["summary"], "at": time.time(),
                    "duration_seconds": round(time.monotonic() - started, 2),
                    **{key: result[key] for key in ("exit_code", "output", "output_truncated", "error", "cleanup_uncertain") if key in result}}
    except (OSError, ValueError, UnicodeError, TypeError, subprocess.SubprocessError) as exc:
        return {"check": check, "passed": False, "status": "stale" if executed else "not_run", "at": time.time(),
                "error": capsules._scrub(str(exc))[:512]}
