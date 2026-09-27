"""Test-only MCP peer; never opens a network connection or runs server commands."""
import os
from pathlib import Path
import sys
from mcp.server.fastmcp import FastMCP

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src import access_policy, safety

if os.environ.get("PANEL_TEST_POLICY_DIR"):
    access_policy.policy_directory = lambda: os.environ["PANEL_TEST_POLICY_DIR"]
    safety.record_audit_event = lambda *args, **kwargs: None

mcp = FastMCP("panel-test")


@mcp.tool()
def get_safety_status() -> dict:
    mode = os.environ.get("PANEL_TEST_MODE", "read-only")
    return {"status": "ok", "safety_mode": mode, "state_changes_enabled": mode != "read-only" or os.environ.get("PANEL_TEST_CHANGES") == "1",
            "access_policy_supported": bool(os.environ.get("PANEL_TEST_POLICY_DIR"))}


@mcp.tool()
def get_system_health() -> dict:
    if os.environ.get("PANEL_TEST_POLICY_DIR") and (denied := access_policy.access_denial("get_system_health")):
        return denied
    return {"status": "ok", "system": {"hostname": "fixture-vps", "os": "Linux"},
            "cpu": {"status": "ok", "usage_percent_total": 12.5, "logical_cores": 2},
            "memory": {"ram": {"used_percent": 42, "used": "420 MB", "total": "1 GB"},
                       "swap": {"used": "0 B", "total": "0 B"}},
            "disk": {"status": "ok", "used_percent": 25, "used": "5 GB", "total": "20 GB"},
            "uptime": {"uptime_human": "3d 2h 1m"}}


@mcp.tool()
def get_failed_systemd_units() -> dict:
    if os.environ.get("PANEL_TEST_POLICY_DIR") and (denied := access_policy.access_denial("get_failed_systemd_units")):
        return denied
    return {"status": "ok", "failed_units": []}


@mcp.tool()
def get_access_policy() -> dict:
    return access_policy.get_access_policy()


@mcp.tool()
def save_access_policy(policy: dict, expected_revision: str) -> dict:
    return access_policy.save_access_policy(policy, expected_revision)


if __name__ == "__main__":
    mcp.run()
