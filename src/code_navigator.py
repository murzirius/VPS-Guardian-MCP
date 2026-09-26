"""Bounded, on-demand Python source navigation. Never imports project code."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import re
import threading
import time
import tokenize
from collections import deque
from typing import Any, Dict, Optional

try:
    from src.environment_doctor import MetadataBudget
    from src.project_workspace import _project_path, _project_file, IGNORED_DIRS
    from src.resource_policy import get_runtime_budget
except ImportError:  # pragma: no cover - direct script compatibility
    from environment_doctor import MetadataBudget
    from project_workspace import _project_path, _project_file, IGNORED_DIRS
    from resource_policy import get_runtime_budget


MAX_FILES = 150
MAX_FILE_BYTES = 128_000
MAX_TOTAL_BYTES = 2_000_000
MAX_NODES = 12_000
MAX_TOTAL_NODES = 80_000
MAX_FACTS = 8000
MAX_RESULTS = 50
MAX_PATH = 240
MAX_DEPTH = 8
MAX_DIAGNOSTICS = 20
MAX_CONTEXT_CHARS = 8000
MIN_MEMORY = 96 * 1024 * 1024
SENSITIVE = re.compile(r"(?i)(secret|credential|password|private[_-]?key|^id_(rsa|ed25519))")
SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,79}(?:\.[A-Za-z_][A-Za-z0-9_]{0,79}){0,5}$")
EXCLUDED = IGNORED_DIRS | {"logs", "backups", "vendor", "site-packages"}
_scan_lock = threading.Lock()
LIMITATIONS = ("Static Python candidates, not a runtime call graph or test coverage proof. "
               "Aliases may be shadowed; dynamic imports, reflection, monkey patches, instance types, "
               "generated code and non-Python sources are unresolved. Sources are never executed. "
               "Hidden/sensitive/dependency paths are excluded. No index daemon or disk cache.")


def _allowed(path: str) -> bool:
    parts = path.replace("\\", "/").split("/")
    return len(path) <= MAX_PATH and all(part and not part.startswith(".") and part not in EXCLUDED and not SENSITIVE.search(part) for part in parts)


def _module(path: str) -> str:
    parts = path[:-3].split("/")
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _safe_fragments(source: str, tree: ast.AST, deadline: float) -> list[str]:
    """Mask all literals/comments, including entire interpolated strings; keep line numbers."""
    lines = source.splitlines(keepends=True)
    spans = []
    for node in ast.walk(tree):
        if time.monotonic() > deadline:
            raise ValueError("snippet_deadline")
        if isinstance(node, (ast.Constant, ast.JoinedStr, getattr(ast, "TemplateStr", ast.JoinedStr))) and hasattr(node, "end_lineno"):
            start = len(lines[node.lineno - 1].encode("utf-8")[:node.col_offset].decode("utf-8"))
            end = len(lines[node.end_lineno - 1].encode("utf-8")[:node.end_col_offset].decode("utf-8"))
            spans.append((node.lineno, start, node.end_lineno, end))
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if time.monotonic() > deadline:
            raise ValueError("snippet_deadline")
        if token.type in (tokenize.COMMENT, tokenize.STRING, tokenize.NUMBER):
            spans.append((*token.start, *token.end))
    # Masking with '*' preserves all line/column positions, including overlaps.
    work = 0
    for first, start, last, end in spans:
        for number in range(first, last + 1):
            if time.monotonic() > deadline:
                raise ValueError("snippet_deadline")
            line = lines[number - 1]
            left = start if number == first else 0
            right = end if number == last else len(line.rstrip("\r\n"))
            work += max(0, right - left)
            if work > 1_000_000:
                raise ValueError("snippet_work_budget")
            lines[number - 1] = line[:left] + "*" * max(0, right - left) + line[right:]
    return [line.rstrip("\r\n")[:240] for line in lines]


def _expression(node: ast.AST) -> Optional[str]:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
        if len(parts) > 6:
            return None
    if isinstance(node, ast.Name):
        parts.append(node.id)
        value = ".".join(reversed(parts))
        return value if SYMBOL.fullmatch(value) else None
    return None


class Facts(ast.NodeVisitor):
    def __init__(self, path: str, snippets: list[str], deadline: float):
        self.path = path
        self.snippets = snippets
        self.deadline = deadline
        self.scope = []
        self.definitions = []
        self.imports = []
        self.references = []
        self.dynamic = False
        self.parents = []

    def visit(self, node):
        if time.monotonic() > self.deadline:
            raise ValueError("scan_deadline")
        if len(self.definitions) + len(self.imports) + len(self.references) > MAX_FACTS:
            raise ValueError("file_fact_budget")
        self.parents.append(node)
        try:
            return super().visit(node)
        finally:
            self.parents.pop()

    def _definition(self, node):
        name = ".".join([*self.scope, node.name])
        if SYMBOL.fullmatch(name):
            self.definitions.append({"name": name, "kind": "class" if isinstance(node, ast.ClassDef) else "function", "line": node.lineno, "end_line": node.end_lineno, "snippet": self.snippets[node.lineno - 1]})
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    visit_FunctionDef = _definition
    visit_AsyncFunctionDef = _definition
    visit_ClassDef = _definition

    def visit_Import(self, node):
        for alias in node.names:
            if SYMBOL.fullmatch(alias.name):
                self.imports.append({"module": alias.name, "symbol": None, "alias": alias.asname or alias.name.split(".")[0], "bound_module": alias.name if alias.asname else alias.name.split(".")[0], "line": node.lineno, "scope": ".".join(self.scope)})

    def visit_ImportFrom(self, node):
        package = self.path[:-3].split("/")[:-1]
        if node.level:
            if node.level > len(package):
                self.dynamic = True
                return
            package = package[:len(package) - node.level + 1]
            module = ".".join(package + ((node.module or "").split(".") if node.module else []))
        else:
            module = node.module or ""
        if module and not SYMBOL.fullmatch(module):
            self.dynamic = True
            return
        for alias in node.names:
            if alias.name == "*":
                self.dynamic = True
                self.imports.append({"module": module, "symbol": "*", "alias": None, "line": node.lineno, "scope": ".".join(self.scope)})
            elif SYMBOL.fullmatch(alias.name):
                self.imports.append({"module": module, "symbol": alias.name, "alias": alias.asname or alias.name, "bound_module": ".".join(filter(None, (module, alias.name))), "line": node.lineno, "scope": ".".join(self.scope)})

    def _reference(self, node):
        if not isinstance(node.ctx, ast.Load):
            return
        parent = self.parents[-2] if len(self.parents) > 1 else None
        if isinstance(parent, ast.Attribute) and parent.value is node:
            return
        expression = _expression(node)
        if expression:
            self.references.append({"expression": expression, "line": node.lineno, "kind": "call" if isinstance(parent, ast.Call) and parent.func is node else "reference", "scope": ".".join(self.scope), "snippet": self.snippets[node.lineno - 1]})
        self.generic_visit(node)

    visit_Name = _reference
    visit_Attribute = _reference

    def visit_Call(self, node):
        name = _expression(node.func)
        if name and (name in {"__import__", "eval", "exec", "getattr", "setattr"} or name.endswith(".import_module")):
            self.dynamic = True
        self.generic_visit(node)


def _scan(project: str, preferred: Optional[str] = None) -> Dict[str, Any]:
    resources = get_runtime_budget()
    if resources["available_memory_bytes"] < MIN_MEMORY:
        return {"status": "unavailable", "error": "At least 96 MiB of available memory is required; no scan started."}
    constrained = resources["profile"] != "standard"
    file_limit = 60 if constrained else MAX_FILES
    byte_limit = 750_000 if constrained else MAX_TOTAL_BYTES
    budget = MetadataBudget()
    files, diagnostics, excluded, nodes, facts = {}, [], 0, 0, 0
    failures = 0
    pending = [("", 0)]

    def problem(path, reason):
        nonlocal failures
        failures += 1
        if len(diagnostics) < MAX_DIAGNOSTICS:
            diagnostics.append({"relative_path": path[:MAX_PATH], "reason": reason})

    def parse_source(path):
        nonlocal nodes, facts
        try:
            source = budget.read(project, path, min(MAX_FILE_BYTES, byte_limit - budget.bytes))
            if source is None:
                problem(path, "source_disappeared")
                return
            sha = hashlib.sha256(source.encode("utf-8")).hexdigest()
            tree = ast.parse(source, filename="<project-source>")
            count = 0
            for _ in ast.walk(tree):
                count += 1
                if count > MAX_NODES or nodes + count > MAX_TOTAL_NODES or time.monotonic() > budget.deadline:
                    raise ValueError("ast_budget")
            nodes += count
            snippets = _safe_fragments(source, tree, budget.deadline)
            visitor = Facts(path, snippets, budget.deadline)
            visitor.visit(tree)
            count = len(visitor.definitions) + len(visitor.imports) + len(visitor.references)
            if facts + count > MAX_FACTS or len(visitor.imports) > 200:
                raise ValueError("fact_budget")
            facts += count
            files[path] = {"module": _module(path), "sha256": sha, "definitions": visitor.definitions, "imports": visitor.imports, "references": visitor.references, "dynamic": visitor.dynamic, "is_test": any(part in {"tests", "test"} for part in path.split("/")) or os.path.basename(path).startswith("test_") or path.endswith("_test.py")}
        except (OSError, ValueError, SyntaxError, RecursionError, tokenize.TokenError):
            problem(path, "unreadable_unsupported_or_over_budget")

    # Never let unrelated files exhaust the budget before the requested target.
    if preferred is not None:
        parse_source(preferred)

    while pending:
        relative, depth = pending.pop()
        try:
            # MetadataBudget streams entries and refuses symlinked directories/files.
            for entry in budget.listing(project, relative or "."):
                path = (relative + "/" if relative else "") + entry.name
                if not _allowed(path):
                    excluded += 1
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth >= MAX_DEPTH:
                        problem(path, "depth_limit")
                    else:
                        pending.append((path, depth + 1))
                    continue
                if not path.endswith(".py"):
                    continue
                if path == preferred:
                    continue
                if not entry.is_file(follow_symlinks=False):
                    problem(path, "non_regular_source")
                    continue
                if len(files) >= file_limit or budget.bytes >= byte_limit or nodes >= MAX_TOTAL_NODES or facts >= MAX_FACTS:
                    problem(path, "scan_budget")
                    pending.clear()
                    break
                parse_source(path)
        except (OSError, ValueError):
            problem(relative or ".", "directory_budget_or_unreadable")
            break
    if budget.unsafe_entries:
        problem(".", "symlinks_excluded")
    # Canonicalize fingerprint independently of filesystem iteration order.
    state = {"files": {path: item["sha256"] for path, item in sorted(files.items())}, "failure_count": failures, "excluded": excluded, "diagnostics": sorted(diagnostics, key=lambda item: (item["relative_path"], item["reason"])), "profile": resources["profile"]}
    fingerprint = hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()[:24]
    return {"status": "ok", "files": files, "fingerprint": fingerprint, "scan": {"python_files": len(files), "bytes_read": budget.bytes, "directory_entries": budget.entries, "complete_within_policy": failures == 0, "skipped_count": failures, "excluded_entries": excluded, "diagnostics": diagnostics, "diagnostics_truncated": failures > len(diagnostics), "resource_profile": resources["profile"]}}


def _load(project_path: str, relative_path: Optional[str] = None):
    project, error = _project_path(project_path)
    if error:
        return None, error
    if relative_path is not None:
        preferred, error = _project_file(project, relative_path)
        if error:
            return None, error
        relative_path = os.path.relpath(preferred, project).replace("\\", "/")
        if not _allowed(relative_path) or not relative_path.endswith(".py") or relative_path.count("/") > MAX_DEPTH:
            return None, {"status": "error", "error": "Target must be an allowed Python path within the depth budget."}
    if not _scan_lock.acquire(blocking=False):
        return None, {"status": "busy", "error": "Another Code Navigator scan is running in this MCP process."}
    try:
        result = _scan(project, relative_path)
        return project, result
    finally:
        _scan_lock.release()


def _modules(files: dict) -> dict:
    modules = {}
    for path, item in files.items():
        names = [item["module"]]
        if path.startswith("src/"):
            names.append(item["module"][4:])
        for name in names:
            if name:
                modules.setdefault(name, set()).add(path)
    return modules


def _resolve(module: str, modules: dict) -> tuple[list, str]:
    candidates = modules.get(module, set())
    if len(candidates) == 1:
        return sorted(candidates), "local_candidate"
    if candidates:
        return sorted(candidates), "ambiguous_local_module"
    return [], "external_or_unresolved"


def _edges(files: dict) -> list:
    modules = _modules(files)
    edges = []
    for path, item in sorted(files.items()):
        for imported in item["imports"]:
            targets, confidence = _resolve(imported["module"], modules)
            if imported["symbol"] and imported["symbol"] != "*":
                child, child_confidence = _resolve(".".join(filter(None, (imported["module"], imported["symbol"]))), modules)
                targets = sorted(set(targets + child))
                if child:
                    confidence = child_confidence
            edges.append({"source": path, "module": imported["module"], "symbol": imported["symbol"], "line": imported["line"], "targets": targets[:4], "confidence": confidence})
    return edges


def _base(index: dict) -> dict:
    return {"status": "ok", "fingerprint": index["fingerprint"], "scan": index["scan"], "limitations": LIMITATIONS}


def _target(project: str, index: dict, relative_path: str, symbol_name: Optional[str] = None):
    path, error = _project_file(project, relative_path)
    if error:
        return None, error
    relative = os.path.relpath(path, project).replace("\\", "/")
    if not _allowed(relative) or not relative.endswith(".py"):
        return None, {"status": "error", "error": "Target must be an allowed Python source path."}
    if relative not in index["files"]:
        return None, {"status": "incomplete", "error": "Target was not successfully scanned; reduce the project root or inspect scan diagnostics.", "scan": index["scan"]}
    if symbol_name is not None:
        if not isinstance(symbol_name, str) or not SYMBOL.fullmatch(symbol_name):
            return None, {"status": "error", "error": "symbol_name must be a bounded dotted Python identifier."}
        definitions = [item for item in index["files"][relative]["definitions"] if item["name"] == symbol_name]
        if len(definitions) != 1:
            return None, {"status": "ambiguous" if definitions else "not_found", "error": "Select one exact qualified function/class name using get_project_symbols."}
    return relative, None


def _references(index: dict, target: str, symbol_name: str) -> list:
    files = index["files"]
    modules = _modules(files)
    module_names = [name for name, paths in modules.items() if target in paths]
    identities = {f"{name}.{symbol_name}" for name in module_names}
    results = []
    short = symbol_name.split(".")[-1]
    for path, item in sorted(files.items()):
        aliases = {}
        for imported in item["imports"]:
            if imported.get("alias"):
                aliases.setdefault(imported["alias"], []).append(imported)
        for reference in item["references"]:
            expression = reference["expression"]
            head, _, tail = expression.partition(".")
            bindings = [imp for imp in aliases.get(head, []) if not imp["scope"] or reference["scope"] == imp["scope"] or reference["scope"].startswith(imp["scope"] + ".")]
            resolved = {imp["bound_module"] + ("." + tail if tail else "") for imp in bindings}
            if resolved & identities:
                ambiguous = any(len(paths) > 1 and target in paths and any(identity.startswith(name + ".") for identity in resolved & identities) for name, paths in modules.items())
                confidence = "ambiguous_import_candidate" if ambiguous else "import_alias_candidate"
            elif path == target and expression == symbol_name:
                confidence = "same_file_candidate"
            elif expression.split(".")[-1] == short:
                confidence = "name_only_candidate"
            else:
                continue
            results.append({"relative_path": path, **reference, "confidence": confidence, "is_test": item["is_test"]})
    return results


def _valid_limit(value) -> bool:
    return type(value) is int and 1 <= value <= MAX_RESULTS


def _query(index: dict, *args) -> str:
    return hashlib.sha256(json.dumps([index["fingerprint"], *args], separators=(",", ":")).encode()).hexdigest()[:24]


def get_project_import_map(project_path: str, relative_path: Optional[str] = None, max_results: int = 30, after_fingerprint: Optional[str] = None) -> Dict[str, Any]:
    """Map local Python imports; unresolved/external modules remain explicitly uncertain."""
    if not _valid_limit(max_results):
        return {"status": "error", "error": "max_results must be 1-50."}
    project, index = _load(project_path, relative_path)
    if index.get("status") != "ok":
        return index
    if relative_path is not None:
        relative_path, error = _target(project, index, relative_path)
        if error:
            return error
    fingerprint = _query(index, "imports", relative_path, max_results)
    if after_fingerprint == fingerprint:
        return {"status": "unchanged", "fingerprint": fingerprint}
    edges = _edges(index["files"])
    if relative_path is not None:
        edges = [edge for edge in edges if edge["source"] == relative_path or relative_path in edge["targets"]]
    return {**_base(index), "fingerprint": fingerprint, "imports": edges[:max_results], "total_imports": len(edges), "truncated": len(edges) > max_results, "dynamic_files": [path for path, item in sorted(index["files"].items()) if item["dynamic"]][:10]}


def find_project_references(project_path: str, relative_path: str, symbol_name: str, max_results: int = 30, after_fingerprint: Optional[str] = None) -> Dict[str, Any]:
    """Find Python symbol-use candidates with alias vs name-only confidence, not runtime certainty."""
    if not _valid_limit(max_results):
        return {"status": "error", "error": "max_results must be 1-50."}
    project, index = _load(project_path, relative_path)
    if index.get("status") != "ok":
        return index
    target, error = _target(project, index, relative_path, symbol_name)
    if error:
        return error
    fingerprint = _query(index, "references", target, symbol_name, max_results)
    if after_fingerprint == fingerprint:
        return {"status": "unchanged", "fingerprint": fingerprint}
    matches = _references(index, target, symbol_name)
    return {**_base(index), "fingerprint": fingerprint, "target": {"relative_path": target, "symbol": symbol_name}, "references": matches[:max_results], "total_matches": len(matches), "truncated": len(matches) > max_results}


def _impact(index: dict, target: str, symbol_name: Optional[str], max_results: int) -> dict:
    edges = _edges(index["files"])
    reverse = {}
    for edge in edges:
        for imported in edge["targets"]:
            reverse.setdefault(imported, set()).add(edge["source"])
    queue, distances = deque([(target, 0)]), {target: 0}
    while queue:
        path, distance = queue.popleft()
        if distance >= 3:
            continue
        for caller in sorted(reverse.get(path, set())):
            if caller not in distances:
                distances[caller] = distance + 1
                queue.append((caller, distance + 1))
    refs = _references(index, target, symbol_name) if symbol_name else []
    candidates = {}
    for path, distance in sorted(distances.items(), key=lambda pair: (pair[1], pair[0])):
        if path != target:
            candidates[path] = {"relative_path": path, "reason": "static_import_chain", "import_hops": distance, "is_test": index["files"][path]["is_test"]}
    for ref in refs:
        if ref["relative_path"] != target and ref["relative_path"] not in candidates:
            candidates[ref["relative_path"]] = {"relative_path": ref["relative_path"], "reason": ref["confidence"], "line": ref["line"], "is_test": ref["is_test"]}
    tests = [item for item in candidates.values() if item["is_test"]]
    if index["files"][target]["is_test"]:
        tests.insert(0, {"relative_path": target, "reason": "target_is_test", "is_test": True})
    return {"affected_candidates": list(candidates.values())[:max_results], "total_candidates": len(candidates), "related_tests": tests[:max_results], "total_test_candidates": len(tests), "truncated": len(candidates) > max_results or len(tests) > max_results, "import_hop_limit": 3, "test_note": "Candidates only. No tests run; zero candidates does not mean no tests or no impact."}


def assess_project_change(project_path: str, relative_path: str, symbol_name: Optional[str] = None, max_results: int = 20, after_fingerprint: Optional[str] = None) -> Dict[str, Any]:
    """Assess bounded reverse-import impact and test candidates for a file or exact Python symbol."""
    if not _valid_limit(max_results):
        return {"status": "error", "error": "max_results must be 1-50."}
    project, index = _load(project_path, relative_path)
    if index.get("status") != "ok":
        return index
    target, error = _target(project, index, relative_path, symbol_name)
    if error:
        return error
    fingerprint = _query(index, "impact", target, symbol_name, max_results)
    if after_fingerprint == fingerprint:
        return {"status": "unchanged", "fingerprint": fingerprint}
    return {**_base(index), "fingerprint": fingerprint, "target": {"relative_path": target, "symbol": symbol_name}, **_impact(index, target, symbol_name, max_results)}


def get_project_task_context(project_path: str, relative_path: str, symbol_name: str, max_chars: int = 6000, after_fingerprint: Optional[str] = None) -> Dict[str, Any]:
    """Bundle a Python definition, use-site fragments and related tests; literals/comments are masked."""
    if type(max_chars) is not int or not 2000 <= max_chars <= MAX_CONTEXT_CHARS:
        return {"status": "error", "error": "max_chars must be 2000-8000."}
    project, index = _load(project_path, relative_path)
    if index.get("status") != "ok":
        return index
    target, error = _target(project, index, relative_path, symbol_name)
    if error:
        return error
    fingerprint = _query(index, "context", target, symbol_name, max_chars)
    if after_fingerprint == fingerprint:
        return {"status": "unchanged", "fingerprint": fingerprint}
    definition = next(item for item in index["files"][target]["definitions"] if item["name"] == symbol_name)
    result = {**_base(index), "fingerprint": fingerprint, "target": {"relative_path": target, "sha256": index["files"][target]["sha256"], **definition}, "references": [], "related_tests": [], "truncated": False, "source_policy": "Literals and comments are masked, snippets are at most one source line. Read exact bodies separately with read_project_file_range.", "next_read": {"relative_path": target, "start_line": definition["line"], "max_lines": min(40, definition["end_line"] - definition["line"] + 1)}}
    matches = _references(index, target, symbol_name)
    tests = _impact(index, target, symbol_name, 10)["related_tests"]
    # Keep essential metadata even when detailed scan diagnostics take the budget.
    result["scan"] = {key: value for key, value in result["scan"].items() if key != "diagnostics"}
    for key, items in (("references", matches), ("related_tests", tests)):
        for item in items[:20]:
            result[key].append(item)
            if len(json.dumps(result, ensure_ascii=False, separators=(",", ":"))) > max_chars:
                result[key].pop()
                result["truncated"] = True
                break
        if len(items) > len(result[key]):
            result["truncated"] = True
    result["total_reference_candidates"] = len(matches)
    # Counts reserve a small margin; remove tail entries if needed.
    while len(json.dumps(result, ensure_ascii=False, separators=(",", ":"))) > max_chars and (result["references"] or result["related_tests"]):
        result["truncated"] = True
        (result["references"] or result["related_tests"]).pop()
    if len(json.dumps(result, ensure_ascii=False, separators=(",", ":"))) > max_chars:
        result["target"].pop("snippet", None)
        result["limitations"] = "Static candidates only; not runtime or coverage proof. Inspect full tool documentation for limitations."
        result["truncated"] = True
    return result
