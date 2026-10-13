"""Real Docker check only on a disposable GitHub-hosted CI runner, never a VPS."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src import mission_capsules as capsules


@unittest.skipUnless(os.environ.get("VPS_GUARDIAN_CAPSULE_INTEGRATION") == "1"
                     and os.environ.get("GITHUB_ACTIONS") == "true" and os.name == "posix",
                     "Real Docker checks require an explicitly enabled disposable CI runner")
class TestMissionDocker(unittest.TestCase):
    def test_real_offline_unprivileged_candidate_and_stale_context(self):
        self.assertEqual(os.geteuid(), 0)
        base = Path("/var/lib/guardian-gateway-ci")
        self.assertTrue(base.is_dir())
        with tempfile.TemporaryDirectory(dir=base) as private:
            project = Path(private) / "project"
            project.mkdir(mode=0o755)
            tests = project / "tests"
            tests.mkdir(mode=0o755)
            original = "VALUE = 'production'\n"
            candidate = "VALUE = 'candidate'\n"
            (project / "main.py").write_text(original)
            (project / ".env").write_text("DO_NOT_COPY=production_secret\n")
            (tests / "test_isolation.py").write_text("""import os,pathlib,socket,unittest
import main
class Isolation(unittest.TestCase):
 def test_candidate_and_boundary(self):
  self.assertEqual(main.VALUE,'candidate')
  self.assertEqual(os.geteuid(),65534)
  self.assertNotIn('GUARDIAN_CI_PRIVATE_VALUE',os.environ)
  self.assertFalse(pathlib.Path('/workspace/.env').exists())
  self.assertFalse(pathlib.Path('/var/run/docker.sock').exists())
  with self.assertRaises(OSError): pathlib.Path('/workspace/mutated').write_text('no')
  with self.assertRaises(OSError):
   s=socket.socket(); s.settimeout(1)
   try: s.connect(('192.0.2.1',80))
   finally: s.close()
""")
            for path in project.rglob("*"):
                path.chmod(0o755 if path.is_dir() else 0o644)
            policy = {"agent_id": "docker-ci", "project_roots": [str(project)]}
            review = {"agent_id": policy["agent_id"], "project_path": str(project), "digest": "a" * 64,
                      "files": [{"relative_path": "main.py", "baseline_sha256": hashlib.sha256(original.encode()).hexdigest(), "candidate": candidate}]}
            with patch("src.mission_control._live_policy", return_value=policy), patch.dict(os.environ, {"GUARDIAN_CI_PRIVATE_VALUE": "not-forwarded"}):
                result = capsules.run(review, "python_unittest")
                self.assertTrue(result["passed"], result)
                self.assertTrue(result["evidence"]["image_id"].startswith("sha256:"))
                self.assertEqual((project / "main.py").read_text(), original)
                capsules.validate(review, [result])
                (tests / "test_isolation.py").write_text("# new context\n")
                with self.assertRaises(ValueError):
                    capsules.validate(review, [result])
                (project / "main.py").chmod(0o666)
                refused = capsules.run(review, "python_unittest")
                self.assertFalse(refused["passed"])
                self.assertEqual(refused["status"], "not_run")


if __name__ == "__main__":
    unittest.main()
