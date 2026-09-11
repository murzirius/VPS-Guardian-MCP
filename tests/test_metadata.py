"""Release metadata consistency tests."""

from __future__ import annotations

import json
import pathlib
import re
import unittest

from src import __version__


ROOT = pathlib.Path(__file__).resolve().parents[1]


class TestReleaseMetadata(unittest.TestCase):
    def test_python_and_npm_versions_match(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE)
        self.assertIsNotNone(match)
        package_version = json.loads(
            (ROOT / "package.json").read_text(encoding="utf-8")
        )["version"]
        self.assertEqual(__version__, match.group(1))
        self.assertEqual(__version__, package_version)

    def test_documented_tool_count_matches_registry(self):
        server = (ROOT / "src" / "server.py").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        actual_count = server.count("@mcp.tool()")
        documented_match = re.search(r"Tools Reference \((\d+) Active Tools\)", readme)
        self.assertIsNotNone(documented_match)
        self.assertEqual(actual_count, int(documented_match.group(1)))


if __name__ == "__main__":
    unittest.main()
