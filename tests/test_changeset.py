"""Tests for bounded reversible ChangeSets."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from src import changeset


class TestChangeSets(unittest.TestCase):
    def setUp(self):
        changeset._sets.clear()

    def test_empty_changeset_cannot_be_previewed(self):
        created = changeset.begin_change_set("Update web config")
        result = changeset.preview_change_set(created["change_set"]["change_set_id"])
        self.assertEqual(result["status"], "error")

    def test_stage_rejects_non_nginx_path(self):
        created = changeset.begin_change_set("Update web config")
        result = changeset.stage_file_change(created["change_set"]["change_set_id"], "/var/www/index.html", "hello")
        self.assertEqual(result["status"], "forbidden")

    @patch("src.changeset.is_path_permitted", return_value=(True, "/etc/nginx/sites-enabled/site.conf"))
    @patch("src.changeset.os.path.isfile", return_value=False)
    @patch("src.changeset.os.path.islink", return_value=False)
    @patch("src.changeset.os.path.isdir", return_value=True)
    def test_stage_has_bounded_metadata(self, _dir, _link, _file, _permitted):
        created = changeset.begin_change_set("Update web config")
        result = changeset.stage_file_change(created["change_set"]["change_set_id"], "/etc/nginx/sites-enabled/site.conf", "server {}")
        self.assertEqual(result["status"], "ok")
        self.assertNotIn("content", result["file"])


if __name__ == "__main__":
    unittest.main()
