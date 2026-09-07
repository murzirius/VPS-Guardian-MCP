# VPS-Guardian-MCP 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP%202024--11--05-green.svg)](https://modelcontextprotocol.io/)
[![Author: murzirius](https://img.shields.io/badge/Author-murzirius-purple.svg)](https://github.com/murzirius)
[![Tools Count](https://img.shields.io/badge/Tools-9%20Active-brightgreen.svg)](#-tools-reference)

A secure, open-source [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server designed for remote Linux VPS observability, Docker management, system diagnostics, and isolated emergency recovery.

It provides AI agents (Google Antigravity, Claude Desktop, Cursor) with structured, programmatic tools to inspect server health and resolve infrastructure issues without raw shell access or unconstrained root privileges.

---

## 📊 Project Overview & Statistics

| Metric | Details |
| :--- | :--- |
| **Version** | `0.1.0` |
| **Active MCP Tools** | **9 tools** |
| **Architecture** | Python 3.10+, FastMCP, Stdio JSON-RPC Transport |
| **Supported Platforms** | Linux (Ubuntu, Debian, CentOS, AlmaLinux, Arch Linux) |
| **Security Standards** | 100% Shell-less execution (`shell=False`), strict regex whitelisting, atomic operations |
| **Compatible Clients** | Google Antigravity, Anthropic Claude Desktop, Cursor IDE, Zed, any MCP client |

---

## ✨ Core Features

### 1. 🖥️ System & Resource Monitoring (`src/monitor.py`)
- **`get_system_health`**: Collects a comprehensive system snapshot including per-core CPU utilization, RAM and Swap metrics, root filesystem capacity, Disk I/O counters (read/write operations and throughput), Network I/O metrics, and humanized uptime.
- **`get_top_processes`**: Identifies top resource-consuming processes ranked by CPU or memory usage, detailing PID, user, memory RSS, status, and command line summaries.
- **`check_service_status`**: Queries systemd service state (`active`, `enabled`, recent unit logs) for critical services like Nginx, MySQL, PostgreSQL, and UFW.
- **`get_failed_systemd_units`**: Performs rapid system audits to discover degraded or failed systemd units (`systemctl --failed`).
- **`read_service_logs`**: Extracts service logs with pure Python-level keyword/regex filtering (`grep_filter`), eliminating command injection vectors.

### 2. 🐳 Docker Management (`src/docker_manager.py`)
- **`list_docker_containers`**: Inspects container inventory, reporting status, image tags, port forwards, bind mounts/volumes, health checks, and exit codes.
- **`get_docker_container_logs`**: Safely retrieves stdout and stderr streams for any container with bounded line limits.
- **`get_docker_stats`**: Streams live resource telemetry (CPU %, memory usage and limits, network RX/TX, block I/O) equivalent to `docker stats`.

### 3. 🔧 Isolated Recovery (`src/recover.py`)
- **`execute_recovery`**: Enforces strict whitelist-only recovery actions (`clean_docker_cache`, `restart_nginx`), rejecting any unauthorized commands with explicit access errors.

---

## 🤖 Guidelines for AI Agents

When interacting with a host via VPS-Guardian-MCP, AI agents must adhere to the following operational standards:

1. **Invoke Native MCP Tools Exclusively**: Never simulate or guess server states. Always call the corresponding tool (`get_system_health`, `list_docker_containers`, etc.) to obtain verified ground-truth telemetry.
2. **Follow the Principle of Least Privilege**: Use read-only diagnostic tools first before suggesting or applying changes.
3. **Handle Errors Structurally**: Diagnostic outputs and system exceptions are returned as structured JSON payloads. Check the `status` field (`"ok"`, `"error"`, `"unavailable"`, `"forbidden"`) to decide subsequent actions.
4. **Require Confirmation for State-Changing Operations**: Any recovery or modification action (`execute_recovery`) must be explicitly confirmed with the operator prior to execution.

---

## 📁 Repository Structure

```text
VPS-Guardian-MCP/
├── src/
│   ├── __init__.py          # Package initialization
│   ├── server.py            # FastMCP server and tool registry (9 tools)
│   ├── monitor.py           # CPU, RAM, Disk I/O, Network, Services, Logs
│   ├── docker_manager.py    # Container inventory, logs, and live telemetry
│   └── recover.py           # Whitelisted recovery and emergency actions
├── pyproject.toml           # Package configuration and dependencies
├── LICENSE                  # MIT License (2026, murzirius)
├── .gitignore               # Ignored environments, builds, and caches
└── README.md                # Documentation and technical reference
```

---

## 🚀 Installation & Server Setup

### 1. Install on the VPS

Clone the repository and install dependencies in an isolated virtual environment:

```bash
git clone https://github.com/murzirius/VPS-Guardian-MCP.git /opt/vps-guardian-mcp
cd /opt/vps-guardian-mcp

python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 2. Configure Permissions (Unprivileged Operation)

To allow the service user to monitor Docker and system logs without requiring root privileges:

```bash
# Add user to the docker socket group
sudo usermod -aG docker $USER

# Add user to systemd journal reader group
sudo usermod -aG systemd-journal $USER
```

---

## ⚙️ Client Configuration

Configure your MCP client (Antigravity `mcp_config.json` or Claude Desktop `claude_desktop_config.json`) to establish a clean stdio connection via SSH:

```json
{
  "mcpServers": {
    "vps-guardian": {
      "command": "ssh",
      "args": [
        "-q",
        "-i",
        "C:/Users/<Username>/.ssh/id_ed25519",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "root@<YOUR_VPS_IP>",
        "/opt/vps-guardian-mcp/.venv/bin/vps-guardian-mcp"
      ]
    }
  }
}
```

---

## 🛠️ Tools Reference

| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `get_system_health` | *none* | Complete system snapshot (per-core CPU, RAM, Swap, Disk I/O, Network I/O, Uptime) |
| `get_top_processes` | `sort_by` (*"cpu"* / *"memory"*), `limit` (*int*) | Top resource-consuming processes with memory and command details |
| `check_service_status` | `service_name` (*string*) | Detailed systemd unit operational status and recent unit logs |
| `get_failed_systemd_units`| *none* | Discovers degraded or failed systemd units across the operating system |
| `read_service_logs` | `service_name` (*string*), `lines_count` (*int*), `grep_filter` (*string*) | Retrieves service logs with safe, pure-Python keyword filtering |
| `list_docker_containers` | `all` (*bool*, default: *true*) | Lists all Docker containers with port forwards, volumes, and health state |
| `get_docker_container_logs` | `container_name` (*string*), `lines_count` (*int*) | Fetches stdout/stderr logs from a specific container |
| `get_docker_stats` | *none* | Live telemetry for running containers (CPU %, RAM, Network and Block I/O) |
| `execute_recovery` | `action_name` (*string*) | Executes whitelisted recovery operations (`clean_docker_cache`, `restart_nginx`) |

---

## 🔒 Security Architecture

1. **No Shell Invocations**: Subprocess executions consistently use explicit argument arrays (`shell=False`) to prevent command injection.
2. **Strict Parameter Validation**: Service identifiers, container names, and filters are validated against restrictive regex patterns.
3. **Immutable Whitelists**: Execution actions are governed by fixed lookup tables.
4. **Graceful Permission Degradation**: Missing capabilities (e.g. unprivileged Docker socket or lack of sudo) return descriptive diagnostic payloads rather than crashing the protocol stream.

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

Copyright (c) 2026 murzirius.
