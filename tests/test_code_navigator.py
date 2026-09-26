"""Static navigation tests: uncertainty, resource limits, path safety and token budgets."""

import ast
import asyncio
import json
import os
import tempfile
import time
import unittest
from unittest import mock

from src import code_navigator as nav


class TestCodeNavigator(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.project = os.path.join(self.temp.name, "project")
        os.mkdir(self.project)
        self.roots = mock.patch.dict(os.environ, {"VPS_GUARDIAN_PROJECT_ROOTS": self.temp.name})
        self.roots.start()
        self.resources = mock.patch.object(nav, "get_runtime_budget", return_value={"profile": "standard", "available_memory_bytes": 1024 ** 3})
        self.resource_mock = self.resources.start()
        self.write("app/__init__.py", "")
        self.write("app/payments.py", "TOKEN = 'very-private-token'\ndef charge(amount):\n    return amount\n\nclass Gateway:\n    def refund(self):\n        return charge(5)\n")
        self.write("app/bot.py", "from .payments import charge as pay\nimport app.payments as payments\ndef handle():\n    pay(10)\n    payments.charge(20)\n")
        self.write("tests/test_payments.py", "from app.bot import handle\ndef test_payment():\n    handle()\n")

    def tearDown(self):
        self.resources.stop()
        self.roots.stop()
        self.temp.cleanup()

    def write(self, path, source):
        target = os.path.join(self.project, *path.split("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(source)

    def test_local_relative_imports_and_reverse_edges(self):
        result = nav.get_project_import_map(self.project, "app/payments.py")
        links = [edge for edge in result["imports"] if edge["source"] == "app/bot.py"]
        self.assertEqual(len(links), 2)
        self.assertTrue(all("app/payments.py" in edge["targets"] for edge in links))
        self.assertTrue(result["scan"]["complete_within_policy"])

    def test_alias_and_name_only_references_are_distinct(self):
        self.write("other.py", "def charge(x):\n    return x\ncharge(1)\n")
        result = nav.find_project_references(self.project, "app/payments.py", "charge")
        by_expression = {(ref["relative_path"], ref["expression"]): ref["confidence"] for ref in result["references"]}
        self.assertEqual(by_expression[("app/bot.py", "pay")], "import_alias_candidate")
        self.assertEqual(by_expression[("app/bot.py", "payments.charge")], "import_alias_candidate")
        self.assertEqual(by_expression[("other.py", "charge")], "name_only_candidate")
        self.assertEqual(by_expression[("app/payments.py", "charge")], "same_file_candidate")
        self.assertIn("shadowed", result["limitations"])

    def test_nested_class_and_async_symbols(self):
        self.write("worker.py", "class Worker:\n    async def run(self):\n        pass\n")
        result = nav.find_project_references(self.project, "worker.py", "Worker.run")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(nav.find_project_references(self.project, "worker.py", "run")["status"], "not_found")

    def test_impact_and_transitive_test_candidates(self):
        result = nav.assess_project_change(self.project, "app/payments.py", "charge")
        tests = {item["relative_path"]: item for item in result["related_tests"]}
        self.assertEqual(tests["tests/test_payments.py"]["import_hops"], 2)
        self.assertIn("No tests run", result["test_note"])

    def test_source_is_not_executed(self):
        sentinel = os.path.join(self.project, "SHOULD_NOT_EXIST")
        self.write("danger.py", "raise RuntimeError('never import')\nopen('SHOULD_NOT_EXIST', 'w').write('x')\n")
        with mock.patch("subprocess.run", side_effect=AssertionError("no binaries")), mock.patch("builtins.eval", side_effect=AssertionError("no eval")):
            result = nav.assess_project_change(self.project, "app/payments.py")
        self.assertEqual(result["status"], "ok")
        self.assertFalse(os.path.exists(sentinel))

    def test_literals_comments_fstrings_unicode_are_masked(self):
        self.write("usage.py", "from app.payments import charge\n# private-comment\nlabel = 'юникод'; charge('private-inline')\ncharge(f'private-fstring {label}')\ncharge(987654321)\n")
        result = nav.get_project_task_context(self.project, "app/payments.py", "charge")
        text = json.dumps(result, ensure_ascii=False)
        for value in ("very-private-token", "private-comment", "private-inline", "private-fstring", "987654321", "юникод"):
            self.assertNotIn(value, text)
        self.assertIn("charge", text)
        self.assertEqual(result["next_read"]["start_line"], 2)

    def test_multiline_literals_are_masked(self):
        source = 'def x(token="""first-secret\nsecond-secret"""):\n    return token # comment-secret\n'
        fragments = nav._safe_fragments(source, ast.parse(source), time.monotonic() + 3)
        self.assertNotIn("secret", "\n".join(fragments))
        self.assertEqual(len(fragments), 3)

    def test_context_output_budget_and_many_callers(self):
        self.write("many.py", "from app.payments import charge\n" + "charge('private')\n" * 100)
        result = nav.get_project_task_context(self.project, "app/payments.py", "charge", max_chars=2000)
        self.assertLessEqual(len(json.dumps(result, ensure_ascii=False, separators=(",", ":"))), 2000)
        self.assertTrue(result["truncated"])
        self.assertGreater(result["total_reference_candidates"], len(result["references"]))

    def test_unchanged_fingerprint_includes_query_and_content(self):
        first = nav.get_project_import_map(self.project)
        self.assertEqual(nav.get_project_import_map(self.project, after_fingerprint=first["fingerprint"])["status"], "unchanged")
        self.assertEqual(nav.get_project_import_map(self.project, max_results=1, after_fingerprint=first["fingerprint"])["status"], "ok")
        self.write("app/bot.py", "import external_lib\n")
        self.assertEqual(nav.get_project_import_map(self.project, after_fingerprint=first["fingerprint"])["status"], "ok")

    def test_external_dynamic_and_wildcard_are_unresolved(self):
        self.write("dynamic.py", "import nonexistent\nfrom app.payments import *\nimport importlib\nimportlib.import_module('private-module')\n")
        result = nav.get_project_import_map(self.project)
        self.assertIn("dynamic.py", result["dynamic_files"])
        self.assertTrue(any(edge["confidence"] == "external_or_unresolved" for edge in result["imports"]))
        self.assertNotIn("private-module", json.dumps(result))

    def test_src_layout_module_alias_and_collision(self):
        self.write("src/lib.py", "def run():\n    pass\n")
        self.write("consumer.py", "from lib import run\nrun()\n")
        result = nav.find_project_references(self.project, "src/lib.py", "run")
        self.assertTrue(any(ref["expression"] == "run" and ref["confidence"] == "import_alias_candidate" for ref in result["references"]))
        self.write("lib.py", "def run():\n    pass\n")
        result = nav.get_project_import_map(self.project, "consumer.py")
        self.assertEqual(result["imports"][0]["confidence"], "ambiguous_local_module")
        result = nav.find_project_references(self.project, "src/lib.py", "run")
        self.assertTrue(any(ref["confidence"] == "ambiguous_import_candidate" for ref in result["references"]))

    def test_package_submodule_import(self):
        self.write("consumer.py", "from app import payments\npayments.charge(3)\n")
        result = nav.find_project_references(self.project, "app/payments.py", "charge")
        self.assertTrue(any(ref["expression"] == "payments.charge" and ref["confidence"] == "import_alias_candidate" for ref in result["references"]))

    def test_import_cycle_is_bounded(self):
        self.write("a.py", "import b\n")
        self.write("b.py", "import a\n")
        result = nav.assess_project_change(self.project, "a.py")
        self.assertEqual(result["total_candidates"], 1)

    def test_invalid_syntax_is_partial_not_clean(self):
        self.write("broken.py", "def invalid(:\n")
        result = nav.get_project_import_map(self.project)
        self.assertFalse(result["scan"]["complete_within_policy"])
        self.assertEqual(nav.assess_project_change(self.project, "broken.py")["status"], "incomplete")

    def test_duplicate_definition_requires_disambiguation(self):
        self.write("duplicate.py", "def run():\n    pass\ndef run():\n    pass\n")
        self.assertEqual(nav.find_project_references(self.project, "duplicate.py", "run")["status"], "ambiguous")

    def test_exclusions_and_forbidden_paths(self):
        for path in (".hidden.py", "credentials.py", "node_modules/a.py", ".venv/a.py"):
            self.write(path, "import private_module\n")
        result = nav.get_project_import_map(self.project)
        self.assertNotIn("private_module", json.dumps(result))
        self.assertEqual(nav.assess_project_change(self.project, "credentials.py")["status"], "error")
        self.assertEqual(nav.assess_project_change(self.project, "../outside.py")["status"], "error")
        self.assertEqual(nav.get_project_import_map(os.path.dirname(self.temp.name))["status"], "forbidden")

    def test_invalid_arguments(self):
        for limit in (0, 51, True, "5"):
            self.assertEqual(nav.get_project_import_map(self.project, max_results=limit)["status"], "error")
        self.assertEqual(nav.find_project_references(self.project, "app/payments.py", "../charge")["status"], "error")
        self.assertEqual(nav.get_project_task_context(self.project, "app/payments.py", "charge", 100)["status"], "error")

    def test_low_memory_and_concurrency_refuse_scan(self):
        self.resource_mock.return_value = {"profile": "critical", "available_memory_bytes": nav.MIN_MEMORY - 1}
        self.assertEqual(nav.get_project_import_map(self.project)["status"], "unavailable")
        with nav._scan_lock:
            self.assertEqual(nav.get_project_import_map(self.project)["status"], "busy")

    def test_file_and_node_limits_report_incomplete(self):
        self.write("huge.py", "#" + "x" * nav.MAX_FILE_BYTES)
        result = nav.get_project_import_map(self.project)
        self.assertFalse(result["scan"]["complete_within_policy"])
        with mock.patch.object(nav, "MAX_NODES", 2):
            self.assertFalse(nav.get_project_import_map(self.project)["scan"]["complete_within_policy"])
        with mock.patch.object(nav, "MAX_FILES", 1):
            self.assertFalse(nav.get_project_import_map(self.project)["scan"]["complete_within_policy"])
            target = nav.get_project_task_context(self.project, "app/payments.py", "charge")
            self.assertEqual(target["status"], "ok")
            self.assertFalse(target["scan"]["complete_within_policy"])

    def test_symlink_not_followed(self):
        outside = os.path.join(self.temp.name, "outside.py")
        with open(outside, "w", encoding="utf-8") as handle:
            handle.write("import private_module\n")
        try:
            os.symlink(outside, os.path.join(self.project, "linked.py"))
        except OSError:
            self.skipTest("Symlinks require privileges on this host")
        result = nav.get_project_import_map(self.project)
        self.assertNotIn("private_module", json.dumps(result))
        self.assertFalse(result["scan"]["complete_within_policy"])
        self.assertEqual(nav.assess_project_change(self.project, "linked.py")["status"], "forbidden")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_fifo_is_never_opened(self):
        os.mkfifo(os.path.join(self.project, "pipe.py"))
        result = nav.get_project_import_map(self.project)
        self.assertFalse(result["scan"]["complete_within_policy"])
        self.assertEqual(nav.assess_project_change(self.project, "pipe.py")["status"], "incomplete")

    def test_mcp_registration_returns_compact_structured_context(self):
        from src import server
        response = asyncio.run(server.mcp.call_tool("get_project_task_context", {"project_path": self.project, "relative_path": "app/payments.py", "symbol_name": "charge"}))
        self.assertEqual(json.loads(response.content[0].text), response.structuredContent)
        self.assertEqual(response.structuredContent["status"], "ok")
        self.assertNotIn("\n", response.content[0].text)

    def test_fingerprints_for_each_query_are_not_interchangeable(self):
        functions = [(nav.find_project_references, ("app/payments.py", "charge")), (nav.assess_project_change, ("app/payments.py", "charge")), (nav.get_project_task_context, ("app/payments.py", "charge"))]
        fingerprints = []
        for function, args in functions:
            result = function(self.project, *args)
            fingerprints.append(result["fingerprint"])
            self.assertEqual(function(self.project, *args, after_fingerprint=result["fingerprint"])["status"], "unchanged")
        self.assertEqual(len(set(fingerprints)), 3)

    def test_long_target_keeps_small_context_budget(self):
        path = "a" * 100 + "/" + "b" * 100 + ".py"
        names = ["c" * 79, "d" * 79, "e" * 79]
        self.write(path, f"class {names[0]}:\n    class {names[1]}:\n        def {names[2]}(self):\n            pass\n")
        result = nav.get_project_task_context(self.project, path, ".".join(names), max_chars=2000)
        self.assertEqual(result["status"], "ok")
        self.assertLessEqual(len(json.dumps(result, ensure_ascii=False, separators=(",", ":"))), 2000)

    def test_constrained_file_budget_and_deadline(self):
        self.resource_mock.return_value = {"profile": "constrained", "available_memory_bytes": 128 * 1024 ** 2}
        for number in range(65):
            self.write(f"module_{number}.py", "value = 1\n")
        result = nav.get_project_import_map(self.project)
        self.assertLessEqual(result["scan"]["python_files"], 60)
        self.assertFalse(result["scan"]["complete_within_policy"])
        with mock.patch.object(nav.time, "monotonic", side_effect=[0] + [10] * 1000):
            self.assertFalse(nav.get_project_import_map(self.project)["scan"]["complete_within_policy"])

    @unittest.skipUnless(hasattr(ast, "TemplateStr"), "Template strings require Python 3.14")
    def test_template_string_values_are_masked(self):
        source = 'def x(value=t"private-template {1}"):\n    pass\n'
        self.assertNotIn("private-template", "\n".join(nav._safe_fragments(source, ast.parse(source), time.monotonic() + 3)))


if __name__ == "__main__":
    unittest.main()
