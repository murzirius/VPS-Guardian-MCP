"""Unit tests for deep Docker management features in src.docker_manager."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from src.docker_manager import (
    clean_docker_garbage,
    docker_container_action,
    inspect_docker_container,
)


class TestDockerDeep(unittest.TestCase):
    """Test suite for Docker container lifecycle, inspection, and garbage pruning."""

    def test_docker_container_action_invalid_name(self):
        """Verify rejection of potentially hazardous container names."""
        res = docker_container_action("my_container; rm -rf /", "start")
        self.assertEqual(res["status"], "error")
        self.assertIn("Invalid container name", res["error"])

    def test_docker_container_action_invalid_action(self):
        """Verify rejection of unsupported lifecycle actions."""
        res = docker_container_action("web-app", "destroy")
        self.assertEqual(res["status"], "error")
        self.assertIn("Invalid action", res["error"])

    def test_docker_container_action_lifecycle_success(self):
        """Verify container actions invoke corresponding docker-py SDK methods."""
        mock_container = MagicMock()
        mock_container.name = "web-prod"
        mock_container.short_id = "abc1234"
        mock_container.status = "exited"

        def fake_start():
            mock_container.status = "running"

        mock_container.start.side_effect = fake_start

        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container

        with patch("src.docker_manager._get_docker_client", return_value=(mock_client, None)):
            res = docker_container_action("web-prod", "start")
            self.assertEqual(res["status"], "ok")
            self.assertEqual(res["action"], "start")
            self.assertEqual(res["previous_status"], "exited")
            self.assertEqual(res["current_status"], "running")
            mock_container.start.assert_called_once()

    def test_inspect_docker_container_masks_sensitive_env(self):
        """Verify environment variables containing sensitive keywords are masked."""
        mock_container = MagicMock()
        mock_container.id = "abcdef1234567890"
        mock_container.short_id = "abcdef1"
        mock_container.name = "db-service"
        mock_container.image = "postgres:15-alpine"
        mock_container.status = "running"
        mock_container.attrs = {
            "Created": "2026-09-10T12:00:00Z",
            "State": {"Status": "running", "Running": True, "ExitCode": 0},
            "Config": {
                "Image": "postgres:15-alpine",
                "Env": [
                    "POSTGRES_DB=production",
                    "POSTGRES_PASSWORD=super_secret_master_pw",
                    "API_KEY=key_abcdef12345",
                    "NORMAL_VAR=hello_world",
                ],
            },
            "HostConfig": {"RestartPolicy": {"Name": "always"}, "Memory": 1073741824},
            "NetworkSettings": {"Ports": {}, "Networks": {}},
            "Mounts": [],
        }

        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container

        with patch("src.docker_manager._get_docker_client", return_value=(mock_client, None)):
            res = inspect_docker_container("db-service")
            self.assertEqual(res["status"], "ok")
            env = res["environment_variables"]
            self.assertIn("POSTGRES_DB=production", env)
            self.assertIn("NORMAL_VAR=hello_world", env)
            self.assertIn("POSTGRES_PASSWORD=***MASKED***", env)
            self.assertIn("API_KEY=***MASKED***", env)

    def test_clean_docker_garbage_invalid_type(self):
        """Verify rejection of invalid prune type."""
        res = clean_docker_garbage("everything")
        self.assertEqual(res["status"], "error")
        self.assertIn("Invalid prune_type", res["error"])

    def test_clean_docker_garbage_prune_all(self):
        """Verify clean_docker_garbage invokes pruning APIs and aggregates space reclaimed."""
        mock_client = MagicMock()
        mock_client.containers.prune.return_value = {
            "ContainersDeleted": ["c1", "c2"],
            "SpaceReclaimed": 52428800,  # 50 MB
        }
        mock_client.images.prune.return_value = {
            "ImagesDeleted": [{"Deleted": "sha256:img1"}],
            "SpaceReclaimed": 104857600,  # 100 MB
        }
        mock_client.volumes.prune.return_value = {
            "VolumesDeleted": ["vol1"],
            "SpaceReclaimed": 209715200,  # 200 MB
        }
        mock_client.networks.prune.return_value = {
            "NetworksDeleted": ["net1"],
        }

        with patch("src.docker_manager._get_docker_client", return_value=(mock_client, None)):
            res = clean_docker_garbage(prune_type="all")
            self.assertEqual(res["status"], "ok")
            self.assertEqual(res["prune_type"], "all")
            self.assertEqual(res["containers_deleted_count"], 2)
            self.assertEqual(res["images_deleted_count"], 1)
            self.assertEqual(res["volumes_deleted_count"], 1)
            self.assertEqual(res["networks_deleted_count"], 1)
            self.assertEqual(res["total_space_reclaimed_bytes"], 367001600)  # 350 MB
            self.assertIn("350.00 MB", res["total_space_reclaimed"])


if __name__ == "__main__":
    unittest.main()
