"""CI report for the size of common agent-facing responses and tool catalogs."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from unittest import mock

from src import agent_efficiency


def catalog_size(profile: str) -> tuple[int, int]:
    environment = dict(os.environ, VPS_GUARDIAN_TOOL_PROFILE=profile)
    code = "from src import server; import json; print(json.dumps([{'name': t.name, 'description': t.description} for t in server.mcp._tool_manager.list_tools()], separators=(',', ':')))"
    result = subprocess.run([sys.executable, "-c", code], env=environment, capture_output=True, text=True, timeout=20, check=True)
    tools = json.loads(result.stdout)
    return len(tools), len(result.stdout.encode("utf-8"))


def main() -> None:
    full_count, full_bytes = catalog_size("full")
    core_count, core_bytes = catalog_size("core")
    components = [{"kind": "container", "identity": f"worker-{number}", "component": {"image": "example/large-image:latest", "ports": [8080, 8081]}} for number in range(30)]
    health = {"status": "ok", "overall_status": "ok", "found": len(components), "matched_components": components, "host_pressure": {"cpu_percent": 20, "ram_used_percent": 50}, "collection_errors": {}}
    with mock.patch.object(agent_efficiency, "get_workload_health", return_value=health):
        brief = agent_efficiency.get_workload_brief("worker", max_chars=4000)
    full_payload_bytes = len(json.dumps(health, ensure_ascii=False, indent=2).encode("utf-8"))
    brief_payload_bytes = len(json.dumps(brief, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    print(json.dumps({"full_tools": full_count, "core_tools": core_count, "full_catalog_bytes": full_bytes, "core_catalog_bytes": core_bytes, "full_workload_bytes": full_payload_bytes, "brief_workload_bytes": brief_payload_bytes}, indent=2))
    if not (core_count < full_count and core_bytes < full_bytes and brief_payload_bytes <= 4000 and brief_payload_bytes < full_payload_bytes):
        raise SystemExit("Response size budget regressed.")


if __name__ == "__main__":
    main()
