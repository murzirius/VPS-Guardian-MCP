"""Tests for workload-level topology and safe diagnosis helpers."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from src import topology


class TestTopology(unittest.TestCase):
    def _topology_mocks(self):
        return {
            "src.topology.list_virtual_hosts": {"status": "ok", "virtual_hosts": [{"config_file": "/etc/nginx/sites-enabled/app", "domains": ["app.example.com"], "listen_ports": ["443 ssl"], "has_ssl": True, "proxy_pass_targets": ["http://api:8080"]}]},
            "src.topology.list_docker_containers": {"status": "ok", "containers": [{"id": "abc", "name": "api", "image": "example/api:1", "status": "running", "ports": ["127.0.0.1:8080->8080/tcp"], "health": "healthy", "exit_code": 0, "oom_killed": False}]},
            "src.topology.get_open_ports": {"status": "ok", "ports": [{"protocol": "tcp", "ip": "127.0.0.1", "port": 8080, "pid": 12, "process_name": "docker-proxy"}]},
            "src.topology.get_database_health": {"status": "ok", "databases": [{"engine": "postgresql", "status": "ok", "latency_ms": 1.2}]},
            "src.topology.list_compose_projects": {"status": "ok", "projects": [{"compose_file": "/var/www/app/compose.yml", "project_directory": "/var/www/app"}]},
            "src.topology.inspect_compose_project": {"status": "ok", "services": [{"name": "api", "image": "example/api:1", "ports": ["8080:8080"], "depends_on": ["db"], "has_healthcheck": True, "restart": "always"}]},
        }

    @patch("src.topology.inspect_compose_project")
    @patch("src.topology.list_compose_projects")
    @patch("src.topology.get_database_health")
    @patch("src.topology.get_open_ports")
    @patch("src.topology.list_docker_containers")
    @patch("src.topology.list_virtual_hosts")
    def test_topology_links_proxy_to_known_component_without_secrets(self, vhosts, containers, ports, databases, projects, inspect):
        values = self._topology_mocks()
        vhosts.return_value = values["src.topology.list_virtual_hosts"]
        containers.return_value = values["src.topology.list_docker_containers"]
        ports.return_value = values["src.topology.get_open_ports"]
        databases.return_value = values["src.topology.get_database_health"]
        projects.return_value = values["src.topology.list_compose_projects"]
        inspect.return_value = values["src.topology.inspect_compose_project"]

        result = topology.get_vps_topology()

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["relationships"][0]["matched_component_names"], ["api"])
        self.assertNotIn("environment", str(result["containers"]))

    @patch("src.topology.get_vps_topology")
    def test_find_workload_matches_domain_and_deduplicates(self, get_map):
        get_map.return_value = {
            "status": "ok", "collection_errors": {},
            "websites": [{"domains": ["app.example.com"], "config_file": "/etc/nginx/app", "proxy_pass_targets": ["http://api:8080"]}],
            "compose_projects": [{"compose_file": "/var/www/app/compose.yml", "project_directory": "/var/www/app", "services": [{"name": "api", "image": "example/api", "ports": ["8080:8080"]}]}],
            "containers": [{"name": "api", "image": "example/api", "ports": ["8080:8080"], "status": "running"}],
            "open_ports": [{"protocol": "tcp", "port": 8080, "process_name": "docker-proxy"}], "databases": [],
        }
        result = topology.find_workload("app.example.com")
        self.assertEqual(result["match_count"], 1)
        self.assertEqual(result["matches"][0]["kind"], "website")

    def test_rejects_control_characters_in_query(self):
        self.assertEqual(topology.find_workload("api\nmalformed")["status"], "error")


class TestWorkloadBaselines(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(dir=os.getcwd())
        self.env = patch.dict(os.environ, {"VPS_GUARDIAN_WORKLOAD_BASELINE_DIR": self.tempdir.name})
        self.env.start()
        topology._last_baseline_dir = None

    def tearDown(self):
        topology._last_baseline_dir = None
        self.env.stop()
        self.tempdir.cleanup()

    @patch("src.topology.get_workload_health")
    def test_create_and_compare_workload_baseline(self, health):
        initial = {"status": "ok", "matched_components": [{"kind": "container", "identity": "api", "component": {"status": "running", "health": "healthy", "image": "api:1", "ports": ["8080:8080"]}}], "ssl_certificates": []}
        changed = {"status": "ok", "matched_components": [{"kind": "container", "identity": "api", "component": {"status": "running", "health": "unhealthy", "image": "api:2", "ports": ["8080:8080"]}}], "ssl_certificates": []}
        health.side_effect = [initial, changed]

        baseline = topology.create_workload_baseline("api", "healthy")
        comparison = topology.compare_workload_baseline(baseline["baseline_id"])

        self.assertEqual(baseline["status"], "ok")
        self.assertTrue(comparison["changed"])
        self.assertEqual(comparison["changes"][0]["category"], "workload_components")

    def test_rejects_path_traversal_baseline_id(self):
        result = topology.compare_workload_baseline("../secrets")
        self.assertEqual(result["status"], "error")


class TestRepairPlan(unittest.TestCase):
    @patch("src.topology.diagnose_workload")
    def test_plan_never_executes_actions(self, diagnose):
        diagnose.return_value = {"status": "ok", "evidence": [], "oom_events": {"total_oom_events": 0}, "health": {"matched_components": []}}
        result = topology.prepare_repair_plan("api")
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["executed"])
        self.assertIn("create_workload_baseline", {step["tool"] for step in result["plan"]})


if __name__ == "__main__":
    unittest.main()
