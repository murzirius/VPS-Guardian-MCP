"""On-demand project environment diagnosis using bounded metadata, not project code."""

from __future__ import annotations

import email.parser
import hashlib
import json
import os
import platform
import posixpath
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, Optional

import psutil
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib

try:
    from src.project_workspace import _project_path, _project_file, _within
    from src.monitor import SERVICE_NAME_REGEX
except ImportError:  # pragma: no cover - direct script compatibility
    from project_workspace import _project_path, _project_file, _within
    from monitor import SERVICE_NAME_REGEX


MAX_FILE_BYTES = 128_000
MAX_TOTAL_BYTES = 2_000_000
MAX_ENTRIES = 1000
MAX_DEPENDENCIES = 100
MAX_ISSUES = 30
MAX_PLAN_PINS = 40
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,100}$")
NODE_NAME = re.compile(r"^(?:@[a-z0-9._-]{1,100}/)?[a-z0-9][a-z0-9._-]{0,100}$")
NODE_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?$")
PYTHON_VERSION = re.compile(r"^\d+\.\d+(?:\.\d+)?$")


class MetadataBudget:
    def __init__(self):
        self.bytes = 0
        self.entries = 0
        self.unsafe_entries = 0
        self.deadline = time.monotonic() + 5

    def read(self, root: str, relative: str, limit: int = MAX_FILE_BYTES) -> Optional[str]:
        if time.monotonic() > self.deadline:
            raise ValueError("Metadata scan timed out.")
        path, error = _project_file(root, relative)
        if error:
            raise ValueError("Metadata path is a symlink or escapes its authorized root.")
        if not os.path.exists(path):
            return None
        if os.name == "posix":
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                parts = os.path.relpath(path, root).split(os.sep)
                for part in parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    os.close(directory)
                    directory = child
                descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            finally:
                os.close(directory)
        else:
            descriptor = os.open(path, os.O_RDONLY)
        with os.fdopen(descriptor, "rb") as handle:
            import stat
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ValueError("Metadata must be a regular file.")
            raw = handle.read(min(limit, MAX_TOTAL_BYTES - self.bytes) + 1)
        if len(raw) > limit or self.bytes + len(raw) > MAX_TOTAL_BYTES:
            raise ValueError("Environment metadata exceeds its read budget.")
        self.bytes += len(raw)
        return raw.decode("utf-8")

    def listing(self, root: str, relative: str):
        path, error = _project_file(root, relative)
        if error:
            raise ValueError("Metadata directory is a symlink or escapes its authorized root.")
        if not os.path.isdir(path):
            return
        with os.scandir(path) as entries:
            for entry in entries:
                self.entries += 1
                if self.entries > MAX_ENTRIES or time.monotonic() > self.deadline:
                    raise ValueError("Environment metadata exceeds its directory-entry budget.")
                if entry.is_symlink():
                    self.unsafe_entries += 1
                    continue
                yield entry


def _issue(code: str, package: Optional[str] = None, **details) -> Dict[str, Any]:
    result = {"code": code, **{key: value[:300] if isinstance(value, str) else value for key, value in details.items()}}
    if package:
        result["package"] = package
    return result


def _node_version(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= 100 and bool(NODE_VERSION.fullmatch(value))


def _service_runtime(service_name: Optional[str]) -> Dict[str, Any]:
    if service_name is None:
        return {"status": "not_requested"}
    if not isinstance(service_name, str) or not SERVICE_NAME_REGEX.fullmatch(service_name) or service_name.startswith("-"):
        return {"status": "invalid", "error": "A valid systemd service name is required."}
    systemctl = shutil.which("systemctl")
    if not sys.platform.startswith("linux") or not systemctl:
        return {"status": "unavailable", "service": service_name}
    try:
        response = subprocess.run([systemctl, "show", "--property=MainPID", "--value", "--", service_name], capture_output=True, text=True, timeout=4, check=False)
        value = response.stdout.strip()
        if response.returncode or not re.fullmatch(r"[0-9]{1,10}", value):
            return {"status": "unavailable", "service": service_name}
        pid = int(value)
        if pid == 0:
            return {"status": "not_running", "service": service_name, "note": "No running MainPID; configured launch arguments were not read."}
        process = psutil.Process(pid)
        with open(f"/proc/{pid}/cmdline", "rb") as handle:
            launch = handle.read(4096).split(b"\0", 1)[0].decode("utf-8", errors="replace")
        executable = process.exe()
        cwd = process.cwd()
        # Never return argv, environment variables or an arbitrary argv[0] string.
        recognized = posixpath.isabs(launch) and bool(re.fullmatch(r"(?:python(?:\d+(?:\.\d+)?)?|node|gunicorn|uvicorn)", posixpath.basename(launch)))
        return {"status": "ok", "service": service_name, "pid": pid, "executable": executable, "launch_path": launch if recognized else None, "working_directory": cwd, "note": "MainPID only; wrappers, workers, containers and stopped units may need separate diagnosis."}
    except (OSError, psutil.Error, subprocess.SubprocessError):
        return {"status": "unavailable", "service": service_name, "error": "Cannot inspect the running service process."}


def _python_environment(project: str, environment_path: Optional[str], budget: MetadataBudget) -> Dict[str, Any]:
    candidates = []
    if environment_path is not None:
        root, error = _project_path(environment_path)
        if error:
            raise ValueError("environment_path must be an authorized existing directory.")
        candidates.append(root)
    else:
        for relative in (".venv", "venv"):
            candidate, error = _project_file(project, relative)
            if error:
                raise ValueError("Project virtual environment cannot be a symlink.")
            if os.path.isdir(candidate):
                candidates.append(candidate)
    environments = []
    for root in candidates[:2]:
        raw = budget.read(root, "pyvenv.cfg")
        if raw is None:
            continue
        values = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
        values = {key.strip().lower(): value.strip() for key, value in values.items()}
        version = values.get("version", "")
        environments.append({"path": root, "python_version": version if len(version) <= 32 and PYTHON_VERSION.fullmatch(version) else None, "version_source": "pyvenv.cfg; interpreter not executed", "system_site_packages": values.get("include-system-site-packages", "false").lower() == "true"})
    selected = environments[0] if len(environments) == 1 else None
    return {"candidates": environments, "selected": selected, "ambiguous": len(environments) > 1}


def _python_inventory(environment: Dict[str, Any], budget: MetadataBudget) -> tuple[dict, bool]:
    root = environment["path"]
    directories = ["Lib/site-packages"]
    complete = not environment["system_site_packages"]
    expected = ".".join((environment["python_version"] or "").split(".")[:2])
    for entry in budget.listing(root, "lib"):
        if re.fullmatch(r"python\d+\.\d+", entry.name) and entry.is_dir(follow_symlinks=False):
            if expected and entry.name != f"python{expected}":
                complete = False
                continue
            directories.append(f"lib/{entry.name}/site-packages")
    installed = {}
    if not expected and len(directories) > 2:
        complete = False
    sites_found = 0
    for relative in directories[:9]:
        site, error = _project_file(root, relative)
        if error:
            raise ValueError("Virtual environment metadata cannot contain directory symlinks.")
        if not os.path.isdir(site):
            continue
        sites_found += 1
        for entry in budget.listing(root, relative):
            if entry.name.endswith((".egg-info", ".pth")):
                complete = False
            if not entry.name.endswith(".dist-info"):
                continue
            if not entry.is_dir(follow_symlinks=False):
                complete = False
                continue
            raw = budget.read(root, f"{relative}/{entry.name}/METADATA")
            if raw is None:
                complete = False
                continue
            metadata = email.parser.Parser().parsestr(raw, headersonly=True)
            name, version = metadata.get("Name", ""), metadata.get("Version", "")
            if not NAME.fullmatch(name) or len(version) > 100:
                complete = False
                continue
            try:
                version = str(Version(version))
            except InvalidVersion:
                complete = False
                continue
            key = canonicalize_name(name)
            if key in installed:
                complete = False
                installed[key] = None
            else:
                installed[key] = version
    return installed, complete and sites_found > 0 and len(directories) <= 9 and budget.unsafe_entries == 0


def _python_requirements(project: str, budget: MetadataBudget) -> tuple[list, Optional[str], list]:
    requirements, issues = [], []
    requires_python = None
    raw = budget.read(project, "pyproject.toml")
    has_manifest = False
    if raw is not None:
        metadata = tomllib.loads(raw).get("project", {})
        has_manifest = "dependencies" in metadata or "dependencies" in metadata.get("dynamic", [])
        requires_python = metadata.get("requires-python")
        declared = metadata.get("dependencies", [])
        if not isinstance(declared, list) or any(not isinstance(item, str) for item in declared):
            raise ValueError("Invalid pyproject dependency metadata.")
        requirements.extend(declared)
        if "dependencies" in metadata.get("dynamic", []):
            issues.append(_issue("dynamic_dependencies_not_evaluated"))
    raw = budget.read(project, "requirements.txt")
    if raw is None and not has_manifest:
        issues.append(_issue("python_dependency_manifest_not_found"))
    if raw is not None:
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Includes, hashes, URL installs and custom indexes require explicit review.
            if line.startswith("-") or "\\" in line or " --" in line:
                issues.append(_issue("requirements_directive_not_evaluated"))
                continue
            requirements.append(re.split(r"\s+#", line, maxsplit=1)[0])
    if len(requirements) > MAX_DEPENDENCIES:
        raise ValueError("Project exceeds the 100-dependency diagnosis budget.")
    parsed = []
    for value in requirements:
        if len(value) > 2048:
            issues.append(_issue("requirement_not_evaluated"))
            continue
        try:
            requirement = Requirement(value)
            if not NAME.fullmatch(requirement.name) or len(str(requirement.specifier)) > 500 or len(str(requirement.marker or "")) > 500 or len(requirement.extras) > 20:
                issues.append(_issue("requirement_not_evaluated"))
                continue
            if requirement.url:
                issues.append(_issue("direct_url_not_evaluated", canonicalize_name(requirement.name)))
            else:
                parsed.append(requirement)
        except InvalidRequirement:
            issues.append(_issue("requirement_not_evaluated"))
    return parsed, requires_python, issues


def _python_diagnosis(project: str, environment_path: Optional[str], budget: MetadataBudget) -> Dict[str, Any]:
    environment = _python_environment(project, environment_path, budget)
    requirements, requires_python, issues = _python_requirements(project, budget)
    selected = environment["selected"]
    if not selected:
        issues.append(_issue("ambiguous_virtual_environment" if environment["ambiguous"] else "virtual_environment_not_found"))
        return {"environment": environment, "declared_dependencies": len(requirements), "inventory_complete": False, "issues": issues, "pins": []}
    installed, complete = _python_inventory(selected, budget)
    version = selected["python_version"]
    if not version:
        issues.append(_issue("python_version_unknown"))
    if requires_python:
        try:
            if version and Version(version) not in SpecifierSet(requires_python):
                issues.append(_issue("python_version_mismatch", required=str(SpecifierSet(requires_python)), installed=version))
        except (InvalidSpecifier, TypeError):
            issues.append(_issue("requires_python_not_evaluated"))
    pins = set()
    for requirement in requirements:
        name = canonicalize_name(requirement.name)
        if requirement.marker:
            marker = str(requirement.marker)
            unsupported = any(re.search(rf"\b{key}\b", marker) for key in ("implementation_name", "implementation_version", "platform_python_implementation"))
            if unsupported or (not version and re.search(r"\bpython_(?:full_)?version\b", marker)):
                issues.append(_issue("marker_not_evaluated", name))
                continue
            context = {"python_version": ".".join((version or "0.0").split(".")[:2]), "python_full_version": version or "0.0.0", "os_name": os.name, "sys_platform": sys.platform, "platform_system": platform.system(), "platform_machine": platform.machine(), "extra": ""}
            if not requirement.marker.evaluate(environment=context):
                continue
        if requirement.extras:
            issues.append(_issue("requested_extras_not_verified", name))
        current = installed.get(name)
        if current is None:
            issues.append(_issue("missing_dependency" if complete else "dependency_inventory_incomplete", name))
        elif not requirement.specifier.contains(current, prereleases=True):
            issues.append(_issue("dependency_version_mismatch", name, required=str(requirement.specifier), installed=current))
        else:
            pins.add(f"{name}=={current}")
    if not complete:
        issues.append(_issue("python_inventory_incomplete"))
    return {"environment": environment, "declared_dependencies": len(requirements), "installed_packages": len(installed), "inventory_complete": complete, "issues": issues, "pins": sorted(pins)}


def _node_diagnosis(project: str, budget: MetadataBudget, include_dev: bool) -> Dict[str, Any]:
    raw = budget.read(project, "package.json")
    if raw is None:
        return {}
    manifest = json.loads(raw)
    dependencies = dict(manifest.get("dependencies", {}))
    optional = manifest.get("optionalDependencies", {})
    dependencies.update(optional)
    if include_dev:
        dependencies.update(manifest.get("devDependencies", {}))
    if len(dependencies) > MAX_DEPENDENCIES:
        raise ValueError("Project exceeds the 100-dependency diagnosis budget.")
    lock_text = budget.read(project, "package-lock.json", limit=512_000)
    lock = json.loads(lock_text) if lock_text else {}
    lock_version = lock.get("lockfileVersion")
    lock_version = lock_version if type(lock_version) is int and 0 <= lock_version <= 100 else None
    packages = lock.get("packages", {}) if lock_version in (2, 3) else {}
    root_specs = packages.get("", {})
    declared_lock = dict(root_specs.get("dependencies", {}))
    declared_lock.update(root_specs.get("optionalDependencies", {}))
    if include_dev:
        declared_lock.update(root_specs.get("devDependencies", {}))
    issues, pins = [], []
    if not packages:
        issues.append(_issue("supported_npm_lockfile_not_found"))
    for name, wanted in dependencies.items():
        if not isinstance(name, str) or not NODE_NAME.fullmatch(name) or not isinstance(wanted, str):
            issues.append(_issue("npm_dependency_not_evaluated"))
            continue
        recorded = packages.get(f"node_modules/{name}", {})
        version = recorded.get("version", "")
        if recorded.get("link") or not _node_version(version):
            issues.append(_issue("npm_lock_dependency_not_evaluated", name))
        if packages and declared_lock.get(name) != wanted:
            issues.append(_issue("npm_manifest_lock_mismatch", name))
        package_text = budget.read(project, f"node_modules/{name}/package.json")
        if package_text is None:
            if name not in optional:
                issues.append(_issue("missing_dependency", name))
            continue
        package = json.loads(package_text)
        if package.get("name") != name:
            issues.append(_issue("npm_package_identity_mismatch", name))
            continue
        current = package.get("version", "")
        if not _node_version(current):
            issues.append(_issue("npm_installed_version_not_evaluated", name))
        elif _node_version(version) and current != version:
            issues.append(_issue("npm_lock_version_mismatch", name, installed=current, locked=version))
        elif _node_version(version):
            pins.append({"package": name, "version": version})
    engine = manifest.get("engines", {}).get("node")
    if not isinstance(engine, str) or not re.fullmatch(r"[0-9vVxX.*^~<>=| +\-]{1,100}", engine):
        engine = None
    return {"declared_dependencies": len(dependencies), "lockfile_version": lock_version, "declared_node_engine": engine, "runtime_version": None, "includes_dev": include_dev, "issues": issues, "pins": pins, "scope": "Direct dependencies; lockfile v2/v3 exact versions only. Node engine and transitive semver compatibility are not evaluated. No npm scripts are executed."}


def _report(project_path: str, service_name: Optional[str], environment_path: Optional[str], include_dev: bool) -> Dict[str, Any]:
    project, error = _project_path(project_path)
    if error:
        return error
    if not isinstance(include_dev, bool):
        return {"status": "error", "error": "include_dev must be boolean."}
    budget = MetadataBudget()
    try:
        markers = [_project_file(project, name)[0] for name in ("requirements.txt", "pyproject.toml", ".venv/pyvenv.cfg", "venv/pyvenv.cfg")]
        python = _python_diagnosis(project, environment_path, budget) if environment_path or any(path and os.path.isfile(path) for path in markers) else {}
        node = _node_diagnosis(project, budget, include_dev)
        runtime = _service_runtime(service_name)
        issues = [{**item, "ecosystem": "python"} for item in python.get("issues", [])] + [{**item, "ecosystem": "node"} for item in node.get("issues", [])]
        if not python and not node:
            issues.append(_issue("supported_project_metadata_not_found"))
        if runtime["status"] == "invalid":
            return {"status": "error", "error": runtime["error"]}
        selected = python.get("environment", {}).get("selected")
        launch = runtime.get("launch_path")
        if selected and launch and os.path.basename(launch).startswith("python") and not _within(os.path.abspath(launch), selected["path"]):
            issues.append(_issue("service_python_environment_mismatch", evidence="Running MainPID launch path is outside the selected virtual environment."))
        if selected and runtime["status"] == "ok" and not launch:
            issues.append(_issue("service_launch_not_resolved"))
        if runtime.get("working_directory") and os.path.realpath(runtime["working_directory"]) != project:
            issues.append(_issue("service_working_directory_differs", evidence="May be intentional; check the service entry point before changing it."))
        if service_name and runtime["status"] != "ok":
            issues.append(_issue("service_runtime_not_verified"))
        report = {"status": "ok", "project_path": project, "python": python, "node": node, "runtime": runtime, "issues": issues, "metadata_bytes": budget.bytes, "scope": "Metadata-only, direct dependencies. No imports, shell, installers, package-index queries or lifecycle scripts. Metadata is not proof of runtime importability."}
        report["fingerprint"] = hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:24]
        return report
    except (OSError, ValueError, TypeError, AttributeError, tomllib.TOMLDecodeError):
        return {"status": "incomplete", "error": "Malformed, unreadable, unsafe or over-budget environment metadata; no healthy diagnosis is inferred.", "metadata_bytes": budget.bytes}


def inspect_project_environment(project_path: str, service_name: Optional[str] = None, environment_path: Optional[str] = None) -> Dict[str, Any]:
    report = _report(project_path, service_name, environment_path, False)
    if report.get("status") != "ok":
        return report
    python = report["python"]
    return {key: report[key] for key in ("status", "project_path", "runtime", "fingerprint", "scope")} | {"python": {key: python.get(key) for key in ("environment", "installed_packages", "inventory_complete")}, "node": {key: report["node"].get(key) for key in ("declared_dependencies", "lockfile_version", "declared_node_engine", "runtime_version")}, "issue_count": len(report["issues"])}


def diagnose_project_dependencies(project_path: str, service_name: Optional[str] = None, environment_path: Optional[str] = None, include_dev: bool = False, after_fingerprint: Optional[str] = None) -> Dict[str, Any]:
    report = _report(project_path, service_name, environment_path, include_dev)
    if report.get("status") != "ok":
        return report
    if after_fingerprint == report["fingerprint"]:
        return {"status": "unchanged", "fingerprint": after_fingerprint}
    return {"status": "ok", "fingerprint": report["fingerprint"], "issues": report["issues"][:MAX_ISSUES], "issue_count": len(report["issues"]), "truncated": len(report["issues"]) > MAX_ISSUES, "runtime": report["runtime"], "scope": report["scope"], "next_step": "Use plan_environment_repair; do not install or restart based solely on this report."}


def plan_environment_repair(project_path: str, service_name: Optional[str] = None, environment_path: Optional[str] = None) -> Dict[str, Any]:
    report = _report(project_path, service_name, environment_path, False)
    if report.get("status") != "ok":
        return report
    codes = {issue["code"] for issue in report["issues"]}
    steps = []
    if "service_python_environment_mismatch" in codes:
        steps.append("Verify the service entry point and intended venv; preview a unit change before switching the interpreter. Restart requires separate authorization.")
    if codes & {"missing_dependency", "dependency_version_mismatch", "npm_lock_version_mismatch"}:
        steps.append("Prepare a separate test environment from reviewed dependencies/lockfiles; validate it in a capsule before replacing anything live.")
    if "npm_manifest_lock_mismatch" in codes:
        steps.append("Resolve manifest/lockfile drift in development and review the resulting lockfile; do not run an unreviewed production npm update.")
    if codes - {"service_python_environment_mismatch", "missing_dependency", "dependency_version_mismatch", "npm_lock_version_mismatch", "npm_manifest_lock_mismatch"}:
        steps.append("Resolve incomplete or ambiguous metadata first. Do not treat unknown dependencies or markers as missing packages.")
    selected = (report["python"].get("environment", {}).get("selected") or {}).get("path")
    return {"status": "ok", "fingerprint": report["fingerprint"], "selected_environment": selected, "issues": report["issues"][:10], "issue_count": len(report["issues"]), "steps": steps or ["No detected direct-dependency issue; runtime imports, transitive dependencies and application tests still require separate verification."], "executes_changes": False}


def plan_capsule_environment(project_path: str, environment_path: Optional[str] = None, include_dev: bool = False) -> Dict[str, Any]:
    report = _report(project_path, None, environment_path, include_dev)
    if report.get("status") != "ok":
        return report
    python = report["python"]
    version = (python.get("environment", {}).get("selected") or {}).get("python_version")
    python_pins, node_pins = python.get("pins", []), report["node"].get("pins", [])
    truncated = len(python_pins) > MAX_PLAN_PINS or len(node_pins) > MAX_PLAN_PINS
    return {"status": "blocked" if report["issues"] else "incomplete" if truncated else "ok", "fingerprint": report["fingerprint"], "issues": report["issues"][:MAX_ISSUES], "issue_count": len(report["issues"]), "pins_truncated": truncated, "python": {"version": version, "direct_dependency_pins": python_pins[:MAX_PLAN_PINS], "server_image_setting": "VPS_GUARDIAN_CAPSULE_PYTHON_IMAGE"}, "node": {"direct_lock_versions": node_pins[:MAX_PLAN_PINS], "lockfile": "package-lock.json" if report["node"] else None, "server_image_setting": "VPS_GUARDIAN_CAPSULE_NODE_IMAGE"}, "steps": ["Review a trusted local image with matching runtime and preinstalled dependencies.", "Build/download only in a separately authorized environment; installers may execute package build scripts.", "Point the relevant server image setting at the reviewed local image, reconnect MCP, then test the staged patch."], "limitations": "This prepares a metadata plan, not an image. Direct pins are not a complete reproducible transitive lock. Platform/wheel compatibility and installed image contents are not verified. No live venv or node_modules is mounted or copied."}
