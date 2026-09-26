"""Environment Doctor reads bounded metadata and never executes project binaries."""

import json
import os
import tempfile
import unittest
from unittest import mock

from src import environment_doctor as doctor


class TestEnvironmentDoctor(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"VPS_GUARDIAN_PROJECT_ROOTS": self.temp.name})
        self.env.start()
        self.project = os.path.join(self.temp.name, "bot")
        os.mkdir(self.project)
        self.write("requirements.txt", "requests>=2,<3\n")
        self.write(".venv/pyvenv.cfg", "version = 3.12.4\ninclude-system-site-packages = false\n")
        self.package("requests", "2.32.0")

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def write(self, path, text):
        target = os.path.join(self.project, *path.split("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as file:
            file.write(text)

    def package(self, name, version):
        self.write(f".venv/lib/python3.12/site-packages/{name}-{version}.dist-info/METADATA", f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")

    def node(self, installed="1.2.3", locked="1.2.3"):
        self.write("package.json", json.dumps({"dependencies": {"@example/worker": "^1.2.0"}}))
        self.write("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {"": {"dependencies": {"@example/worker": "^1.2.0"}}, "node_modules/@example/worker": {"version": locked}}}))
        if installed:
            self.write("node_modules/@example/worker/package.json", json.dumps({"name": "@example/worker", "version": installed}))

    def codes(self, report):
        return {item["code"] for item in report.get("issues", [])}

    def test_metadata_only_inspection_and_delta(self):
        self.write("setup.py", "raise RuntimeError('NEVER EXECUTE')\n")
        self.write(".venv/bin/python", "NEVER EXECUTE")
        with mock.patch.object(doctor.subprocess, "run", side_effect=AssertionError("project binaries may not run")):
            result = doctor.diagnose_project_dependencies(self.project)
            self.assertEqual(result["issues"], [])
            self.assertEqual(doctor.diagnose_project_dependencies(self.project, after_fingerprint=result["fingerprint"])["status"], "unchanged")
            inspected = doctor.inspect_project_environment(self.project)
        self.assertEqual(inspected["python"]["installed_packages"], 1)
        self.assertEqual(inspected["python"]["environment"]["selected"]["python_version"], "3.12.4")

    def test_missing_and_incompatible_dependencies(self):
        self.write("requirements.txt", "requests>=3\nmissing-package==1.0\n")
        report = doctor.diagnose_project_dependencies(self.project)
        self.assertIn("dependency_version_mismatch", self.codes(report))
        self.assertIn("missing_dependency", self.codes(report))
        self.assertTrue(doctor.plan_environment_repair(self.project)["steps"])

    def test_python_requires_version_and_markers(self):
        self.write("requirements.txt", "skipped; python_version < '3.0'\nunknown; implementation_name == 'pypy'\n")
        self.write("pyproject.toml", "[project]\nrequires-python='>=3.13'\n")
        report = doctor.diagnose_project_dependencies(self.project)
        self.assertIn("python_version_mismatch", self.codes(report))
        self.assertIn("marker_not_evaluated", self.codes(report))
        self.assertNotIn("missing_dependency", self.codes(report))

    def test_inherited_or_legacy_environment_is_not_complete(self):
        self.write(".venv/pyvenv.cfg", "version=3.12.4\ninclude-system-site-packages=true\n")
        self.write("requirements.txt", "external-package==1\n")
        report = doctor.diagnose_project_dependencies(self.project)
        self.assertIn("dependency_inventory_incomplete", self.codes(report))
        self.assertNotIn("missing_dependency", self.codes(report))

    def test_ambiguous_venv_requires_explicit_choice(self):
        self.write("venv/pyvenv.cfg", "version=3.12.4\n")
        self.assertIn("ambiguous_virtual_environment", self.codes(doctor.diagnose_project_dependencies(self.project)))
        report = doctor.diagnose_project_dependencies(self.project, environment_path=os.path.join(self.project, ".venv"))
        self.assertEqual(report["issues"], [])

    def test_service_launch_mismatch_uses_evidence_not_mutation(self):
        runtime = {"status": "ok", "launch_path": "/usr/bin/python3", "working_directory": self.project}
        with mock.patch.object(doctor, "_service_runtime", return_value=runtime):
            report = doctor.diagnose_project_dependencies(self.project, "bot.service")
            plan = doctor.plan_environment_repair(self.project, "bot.service")
        self.assertIn("service_python_environment_mismatch", self.codes(report))
        self.assertFalse(plan["executes_changes"])

    def test_stopped_service_does_not_claim_a_launch_path(self):
        with mock.patch.object(doctor, "_service_runtime", return_value={"status": "not_running"}):
            report = doctor.diagnose_project_dependencies(self.project, "bot.service")
        self.assertIn("service_runtime_not_verified", self.codes(report))
        self.assertNotIn("service_python_environment_mismatch", self.codes(report))

    def test_runtime_never_returns_arguments_or_credentials(self):
        process = mock.Mock()
        process.exe.return_value = "/usr/bin/python3.12"
        process.cwd.return_value = self.project
        opened = mock.mock_open(read_data=b"/home/bot/.venv/bin/python\0main.py\0--token=private-secret\0")
        with mock.patch.object(doctor.sys, "platform", "linux"), mock.patch.object(doctor.shutil, "which", return_value="/usr/bin/systemctl"), mock.patch.object(doctor.subprocess, "run", return_value=mock.Mock(stdout="123\n", returncode=0)), mock.patch.object(doctor.psutil, "Process", return_value=process), mock.patch("builtins.open", opened):
            runtime = doctor._service_runtime("bot.service")
        self.assertEqual(runtime["launch_path"], "/home/bot/.venv/bin/python")
        self.assertNotIn("private-secret", json.dumps(runtime))
        self.assertNotIn("main.py", json.dumps(runtime))

    def test_invalid_service_never_reaches_systemctl(self):
        with mock.patch.object(doctor.subprocess, "run") as run:
            for name in ("-evil", "bot;shutdown", "", 42):
                self.assertEqual(doctor._service_runtime(name)["status"], "invalid")
        run.assert_not_called()

    def test_node_scoped_package_and_lock_drift(self):
        self.node(installed="2.0.0")
        report = doctor.diagnose_project_dependencies(self.project)
        self.assertIn("npm_lock_version_mismatch", self.codes(report))
        self.node()
        self.assertEqual(doctor.diagnose_project_dependencies(self.project)["issues"], [])

    def test_node_package_identity_is_not_inferred_from_directory(self):
        self.node()
        self.write("node_modules/@example/worker/package.json", json.dumps({"name": "different-package", "version": "1.2.3"}))
        self.assertIn("npm_package_identity_mismatch", self.codes(doctor.diagnose_project_dependencies(self.project)))

    def test_extras_and_unknown_versions_do_not_produce_ready_plan(self):
        self.write("requirements.txt", "requests[security]>=2\n")
        self.assertIn("requested_extras_not_verified", self.codes(doctor.diagnose_project_dependencies(self.project)))
        self.assertEqual(doctor.plan_capsule_environment(self.project)["status"], "blocked")
        self.write(".venv/pyvenv.cfg", "version=unknown\n")
        self.write("requirements.txt", "requests; python_version > '3.10'\n")
        self.assertIn("marker_not_evaluated", self.codes(doctor.diagnose_project_dependencies(self.project)))

    def test_optional_and_dev_node_dependencies(self):
        self.node()
        with open(os.path.join(self.project, "package.json"), encoding="utf-8") as file:
            manifest = json.load(file)
        manifest["devDependencies"] = {"dev-only": "^1"}
        self.write("package.json", json.dumps(manifest))
        default = doctor.diagnose_project_dependencies(self.project)
        self.assertEqual(default["issues"], [])
        self.assertIn("missing_dependency", self.codes(doctor.diagnose_project_dependencies(self.project, include_dev=True)))

    def test_capsule_plan_does_not_install_or_claim_image_ready(self):
        self.node()
        with mock.patch.object(doctor.subprocess, "run", side_effect=AssertionError("no installers")):
            plan = doctor.plan_capsule_environment(self.project)
        self.assertEqual(plan["status"], "ok")
        self.assertEqual(plan["python"]["direct_dependency_pins"], ["requests==2.32.0"])
        self.assertIn("not an image", plan["limitations"])
        self.write("requirements.txt", "not-installed\n")
        self.assertEqual(doctor.plan_capsule_environment(self.project)["status"], "blocked")

    def test_url_credentials_and_raw_metadata_never_leave_server(self):
        self.write("requirements.txt", "private-package @ https://user:secret-password@example.invalid/package.whl\n--extra-index-url https://other-secret@example.invalid\n")
        for result in (doctor.diagnose_project_dependencies(self.project), doctor.plan_capsule_environment(self.project)):
            encoded = json.dumps(result)
            self.assertNotIn("secret-password", encoded)
            self.assertNotIn("other-secret", encoded)
            self.assertIn("not_evaluated", encoded)

    def test_malformed_and_oversized_metadata_fail_closed(self):
        self.write("pyproject.toml", "[invalid TOML")
        self.assertEqual(doctor.diagnose_project_dependencies(self.project)["status"], "incomplete")
        os.remove(os.path.join(self.project, "pyproject.toml"))
        self.write("requirements.txt", "x" * (doctor.MAX_FILE_BYTES + 1))
        self.assertEqual(doctor.diagnose_project_dependencies(self.project)["status"], "incomplete")

    def test_forbidden_project_and_unsafe_package_names(self):
        self.assertEqual(doctor.inspect_project_environment(os.path.dirname(self.temp.name))["status"], "forbidden")
        self.write("package.json", json.dumps({"dependencies": {"../../outside": "*"}}))
        self.assertIn("npm_dependency_not_evaluated", self.codes(doctor.diagnose_project_dependencies(self.project)))

    def test_metadata_symlink_refused(self):
        target = os.path.join(self.project, "requirements.txt")
        outside = os.path.join(self.temp.name, "outside.txt")
        with open(outside, "w", encoding="utf-8") as file:
            file.write("private-package @ https://secret@example.invalid\n")
        os.remove(target)
        try:
            os.symlink(outside, target)
        except OSError:
            self.skipTest("Symlinks require privileges on this host")
        self.assertEqual(doctor.diagnose_project_dependencies(self.project)["status"], "incomplete")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO files require POSIX")
    def test_metadata_fifo_is_rejected_without_blocking(self):
        target = os.path.join(self.project, "requirements.txt")
        os.remove(target)
        os.mkfifo(target)
        self.assertEqual(doctor.diagnose_project_dependencies(self.project)["status"], "incomplete")

    def test_duplicate_metadata_and_pth_never_claim_complete_inventory(self):
        self.package("requests", "1.0")
        self.write(".venv/lib/python3.12/site-packages/external.pth", "/outside/environment\n")
        result = doctor.diagnose_project_dependencies(self.project)
        self.assertIn("python_inventory_incomplete", self.codes(result))
        self.assertNotIn("dependency_version_mismatch", self.codes(result))

    def test_tool_only_pyproject_and_unknown_interpreter_are_not_ready(self):
        os.remove(os.path.join(self.project, "requirements.txt"))
        self.write("pyproject.toml", "[tool.ruff]\nline-length = 120\n")
        self.write(".venv/pyvenv.cfg", "include-system-site-packages = false\n")
        plan = doctor.plan_capsule_environment(self.project)
        self.assertEqual(plan["status"], "blocked")
        self.assertIn("python_dependency_manifest_not_found", self.codes(plan))
        self.assertIn("python_version_unknown", self.codes(plan))

    def test_untrusted_version_metadata_is_not_echoed(self):
        self.node()
        self.write("package-lock.json", json.dumps({"lockfileVersion": {"secret": "private-token"}}))
        self.write(".venv/pyvenv.cfg", "version = " + "1" * 10000 + ".12\n")
        result = doctor.inspect_project_environment(self.project)
        self.assertNotIn("private-token", json.dumps(result))
        self.assertIsNone(result["node"]["lockfile_version"])
        self.assertIsNone(result["python"]["environment"]["selected"]["python_version"])


if __name__ == "__main__":
    unittest.main()
