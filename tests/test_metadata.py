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

    def test_readme_links_to_external_tool_catalog(self):
        server = (ROOT / "src" / "server.py").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertGreater(server.count("@guardian_tool()"), 0)
        self.assertIn(
            "https://thomas-studios.com/projects/vps-guardian-mcp#tools",
            readme,
        )

    def test_registry_metadata_matches_package_metadata(self):
        registry = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))

        self.assertEqual(registry["name"], package["mcpName"])
        self.assertEqual(registry["version"], __version__)
        self.assertEqual(package["version"], __version__)
        self.assertEqual(
            {item["identifier"] for item in registry["packages"]},
            {"@murzirius/vps-guardian-mcp", "vps-guardian-mcp"},
        )

    def test_panel_entrypoint_and_asset_package_data(self):
        from importlib import resources
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('vps-guardian-panel = "src.local_panel:main"', pyproject)
        self.assertIn('"panel_assets/*.html"', pyproject)
        for name in ("index.html", "app.js", "style.css"):
            self.assertGreater(len(resources.files("src").joinpath("panel_assets", name).read_bytes()), 0)


if __name__ == "__main__":
    unittest.main()
