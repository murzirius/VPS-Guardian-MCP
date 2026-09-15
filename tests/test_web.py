"""Tests for safe HTTP and web-deployment diagnostics."""

from __future__ import annotations

import unittest

from src import web


class TestWebDiagnostics(unittest.TestCase):
    def test_endpoint_rejects_non_http_url_without_network(self):
        result = web.check_http_endpoint("file:///etc/passwd")
        self.assertEqual(result["status"], "error")
        self.assertIn("http", result["error"].lower())

    def test_endpoint_rejects_loopback_ssrf_target(self):
        result = web.check_http_endpoint("http://127.0.0.1:8080/health")
        self.assertEqual(result["status"], "error")
        self.assertIn("non-public", result["error"])

    def test_batch_limits_endpoint_count(self):
        result = web.check_http_endpoints([{"url": "https://example.com"}] * 21)
        self.assertEqual(result["status"], "error")
        self.assertIn("20", result["error"])

    def test_deployment_status_rejects_unsafe_path_shape(self):
        result = web.get_web_deployment_status("example.com", "not-a-path")
        self.assertEqual(result["status"], "error")
        self.assertIn("path", result["error"])


if __name__ == "__main__":
    unittest.main()
