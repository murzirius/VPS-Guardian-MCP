"""Test-only MCP peer; never opens a network connection or runs server commands."""
import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("panel-test")


@mcp.tool()
def get_safety_status() -> dict:
    mode = os.environ.get("PANEL_TEST_MODE", "read-only")
    return {"status": "ok", "safety_mode": mode, "state_changes_enabled": mode != "read-only" or os.environ.get("PANEL_TEST_CHANGES") == "1"}


@mcp.tool()
def get_system_health() -> dict:
    return {"status": "ok", "system": {"hostname": "fixture-vps", "os": "Linux"},
            "cpu": {"status": "ok", "usage_percent_total": 12.5, "logical_cores": 2},
            "memory": {"ram": {"used_percent": 42, "used": "420 MB", "total": "1 GB"},
                       "swap": {"used": "0 B", "total": "0 B"}},
            "disk": {"status": "ok", "used_percent": 25, "used": "5 GB", "total": "20 GB"},
            "uptime": {"uptime_human": "3d 2h 1m"}}


@mcp.tool()
def get_failed_systemd_units() -> dict:
    return {"status": "ok", "failed_units": []}


if __name__ == "__main__":
    mcp.run()
