# VPS-Guardian-MCP 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP%202024--11--05-green.svg)](https://modelcontextprotocol.io/)
[![Author: murzirius](https://img.shields.io/badge/Author-murzirius-purple.svg)](https://github.com/murzirius)
[![Tools Count](https://img.shields.io/badge/Tools-9%20Active-brightgreen.svg)](#-available-mcp-tools)

A secure, open-source [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server written in Python. It empowers AI agents (Antigravity, Claude Desktop, Cursor) to safely monitor Linux VPS health, manage Docker containers, inspect systemd logs, and perform isolated recovery operations without raw shell or root risks.

---

## 📊 Project Statistics & Status

| Metric | Status / Value |
| :--- | :--- |
| **Current Version** | `0.1.0` (Milestone 2 Completed) |
| **Active MCP Tools** | **9 tools** (System, Processes, Services, Logs, Docker, Recovery) |
| **Supported OS** | Linux (Ubuntu, Debian, CentOS, AlmaLinux, Arch) |
| **Client Support** | Google Antigravity, Claude Desktop, Cursor, Zed, Any MCP Client |
| **Security Standard** | 100% Shell-less execution (`shell=False`), strict regex input whitelisting |
| **Transport** | Stdio (Local & SSH tunnel-ready) |

---

## ✨ Features by Category

### 1. 🖥️ System & Resource Monitoring (`src/monitor.py`)
- **`get_system_health`**: Complete system snapshot (per-core CPU %, RAM/Swap bytes and %, root disk usage, Disk I/O read/write, Network I/O, humanized uptime).
- **`get_top_processes`**: Live ranking of top resource-consuming processes sorted by CPU or Memory (PID, user, RSS memory, command).
- **`check_service_status`**: Real-time status of systemd units (`nginx`, `mysql`, `postgresql`, `ufw`).
- **`get_failed_systemd_units`**: Rapid audit of degraded or failed system services (`systemctl --failed`).
- **`read_service_logs`**: Safe service log retrieval with pure Python-level keyword/regex filtering (`grep_filter`), immune to command injection.

### 2. 🐳 Docker Management (`src/docker_manager.py`) [NEW in Chunk 2]
- **`list_docker_containers`**: Detailed container inspection with port bindings, volumes/mounts, health status, and exit codes.
- **`get_docker_container_logs`**: Safe tailing of container stdout/stderr logs.
- **`get_docker_stats`**: Real-time resource metrics for running containers (CPU %, Memory used/limit/%, Network I/O, Block I/O).

### 3. 🔧 Isolated Recovery (`src/recover.py`)
- **`execute_recovery`**: Strict whitelist-only execution (`clean_docker_cache`, `restart_nginx`). Rejects unauthorized actions.

---

## 🤖 Guidelines for AI Agents (Правила для ИИ-агентов)

> [!IMPORTANT]
> **Для всех взаимодействующих ИИ-агентов:**
> 1. **Используйте ТОЛЬКО нативные вызовы MCP-инструментов**: Всегда вызывайте системные инструменты через `call_mcp_tool` (или стандартный JSON-RPC диспетчер).
> 2. **Никаких выдуманных данных**: Запрещено гадать или имитировать состояние сервера. Если инструмент вернул ошибку прав или статус службы, сообщайте пользователю точный JSON-ответ.
> 3. **Принцип наименьших привилегий**: Для диагностики используйте инструменты чтения (`get_system_health`, `get_top_processes`, `list_docker_containers`). Реанимационные действия (`execute_recovery`) применяйте строго с подтверждения пользователя.

---

## 📁 Project Architecture

```text
vps-guardian-mcp/
├── src/
│   ├── __init__.py          # Package initialization
│   ├── server.py            # FastMCP server & 9 registered tools
│   ├── monitor.py           # CPU, RAM, Disk I/O, Network, Services, Logs
│   ├── docker_manager.py    # Container inspection, logs, and live stats
│   └── recover.py           # Whitelisted recovery & emergency actions
├── pyproject.toml           # Package metadata, pinned dependencies (<2.0.0)
├── LICENSE                  # MIT License (2026, murzirius)
├── .gitignore               # Ignored environments and caches
└── README.md                # Documentation and project stats
```

---

## 🚀 Installation & VPS Setup

### 1. Clone & Install on your VPS

```bash
git clone https://github.com/murzirius/VPS-Guardian-MCP.git /opt/vps-guardian-mcp
cd /opt/vps-guardian-mcp

python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 2. Permissions (No Root Required)

```bash
# Allow reading Docker without root
sudo usermod -aG docker $USER

# Allow reading system logs
sudo usermod -aG systemd-journal $USER
```

---

## ⚙️ Antigravity & Claude Desktop Configuration

Add `VPS-Guardian-MCP` to your `~/.gemini/config/mcp_config.json` (for Antigravity) or `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vps-guardian": {
      "command": "ssh",
      "args": [
        "-q",
        "-i",
        "C:/Users/Михаил/.ssh/id_ed25519",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "root@65.75.200.108",
        "/opt/vps-guardian-mcp/.venv/bin/vps-guardian-mcp"
      ]
    }
  }
}
```

---

## 🛠️ Complete Tools Reference

| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `get_system_health` | none | Full CPU (per core), RAM, Disk I/O, Network I/O, Uptime |
| `get_top_processes` | `sort_by` ('cpu'/'memory'), `limit` (int) | Top resource-consuming processes |
| `check_service_status` | `service_name` (str) | Systemd unit status (`active`, `enabled`, logs) |
| `get_failed_systemd_units`| none | List all degraded or failed systemd units |
| `read_service_logs` | `service_name` (str), `lines_count` (int), `grep_filter` (str) | Safe service logs with Python keyword filtering |
| `list_docker_containers` | `all` (bool, default True) | List containers with ports, volumes, and health |
| `get_docker_container_logs` | `container_name` (str), `lines_count` (int) | Tail stdout/stderr for a container |
| `get_docker_stats` | none | Live CPU %, Memory %, Network & Block I/O per container |
| `execute_recovery` | `action_name` (str) | Whitelisted actions: `clean_docker_cache`, `restart_nginx` |

---

## 📄 License

MIT License - Copyright (c) 2026 murzirius. See [LICENSE](LICENSE) for details.
