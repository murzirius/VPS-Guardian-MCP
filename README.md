# VPS-Guardian-MCP 🛡️

A secure, open-source [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server written in Python. It empowers AI agents (Claude Desktop, Antigravity, Cursor, etc.) to safely monitor Linux VPS health metrics, inspect Docker container states, retrieve service logs, and execute isolated recovery commands without giving full shell or root access.

---

## ✨ Features

- **📊 Comprehensive System Monitoring (`get_system_health`)**:
  - Real-time CPU load (%), physical & logical core count, and system load averages.
  - RAM & Swap usage (used/free/available both in human-readable and raw bytes).
  - Root disk filesystem capacity and utilization.
  - Docker container health check: detects exited, dead, restarting, or unhealthy containers.

- **📜 Safe Service Log Inspection (`read_service_logs`)**:
  - Reads the last $N$ lines of logs for systemd units and Nginx.
  - Supports container-specific logs (`docker:<container_name>`).
  - **Injection Prevention**: Input validation with strict regex patterns and non-shell execution (`shell=False`).

- **🔧 Isolated Emergency Recovery (`execute_recovery`)**:
  - Strict whitelist-only execution policy.
  - `clean_docker_cache`: Cleans stopped containers, unused networks, and dangling images.
  - `restart_nginx`: Restarts the Nginx web server service via systemctl or Docker.
  - Rejects any unauthorized action with a `forbidden` status.

- **🛡️ Robust Error Handling & Permissions**:
  - All operations wrapped in safe exception boundaries.
  - Clear, informative diagnostic messages for permission issues (e.g. missing access to `/var/run/docker.sock` or sudo privileges) without crashing the MCP connection.

---

## 📁 Project Structure

```text
vps-guardian-mcp/
├── src/
│   ├── __init__.py        # Package initialization
│   ├── server.py          # FastMCP server & tool definitions
│   ├── monitor.py         # System & Docker metrics collector
│   └── recover.py         # Whitelisted recovery & log inspection
├── pyproject.toml         # Package definition and dependencies
├── LICENSE                # MIT License
├── .gitignore             # Git exclusion rules
└── README.md              # Documentation
```

---

## 🚀 Installation & Setup

### 1. Requirements
- Python 3.10+
- Linux VPS (Ubuntu/Debian/CentOS/Fedora) with systemd and Docker (optional)

### 2. Install dependencies

Create a virtual environment and install the package:

```bash
git clone https://github.com/murzirius/VPS-Guardian-MCP.git
cd vps-guardian-mcp

python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 3. Grant Required VPS Permissions (Optional but Recommended)

To allow the server to inspect Docker and restart Nginx without full root:

```bash
# Allow Docker socket access without sudo
sudo usermod -aG docker $USER

# Allow reading systemd logs
sudo usermod -aG systemd-journal $USER

# Allow passwordless Nginx restart via sudoers (optional for restart_nginx)
echo "$USER ALL=(ALL) NOPASSWD: /bin/systemctl restart nginx" | sudo tee /etc/sudoers.d/vps-guardian-nginx
sudo chmod 0440 /etc/sudoers.d/vps-guardian-nginx
```

---

## ⚙️ MCP Client Configuration

Add `VPS-Guardian-MCP` to your client configuration file (e.g. `claude_desktop_config.json` or Antigravity MCP settings):

```json
{
  "mcpServers": {
    "vps-guardian": {
      "command": "/path/to/vps-guardian-mcp/.venv/bin/python",
      "args": [
        "-m",
        "src.server"
      ]
    }
  }
}
```

Or when running via `uvx` / `pipx`:

```json
{
  "mcpServers": {
    "vps-guardian": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/vps-guardian-mcp",
        "run",
        "vps-guardian-mcp"
      ]
    }
  }
}
```

---

## 🛠️ Available MCP Tools

### 1. `get_system_health`
Retrieves CPU, RAM, root disk usage, and unhealthy/failed Docker containers.

**Example Agent Output:**
```json
{
  "system": { "os": "Linux", "platform": "Linux-5.15.0-generic-x86_64", "architecture": "x86_64" },
  "cpu": { "status": "ok", "cpu_usage_percent": 18.4, "logical_cores": 4 },
  "memory": {
    "status": "ok",
    "ram": { "total": "15.62 GB", "used": "4.20 GB", "available": "11.42 GB", "used_percent": 26.9 }
  },
  "disk": {
    "status": "ok",
    "mount_point": "/",
    "total": "98.24 GB",
    "free": "64.12 GB",
    "used_percent": 34.7
  },
  "docker": {
    "status": "connected",
    "total_containers": 5,
    "running_containers": 4,
    "failed_containers": [
      {
        "id": "a1b2c3d4e5f6",
        "name": "payment-api",
        "status": "exited",
        "exit_code": 137,
        "error": "OOMKilled"
      }
    ]
  }
}
```

### 2. `read_service_logs`
Fetches the last $N$ lines of logs for Nginx, systemd services, or Docker containers.

**Parameters:**
- `service_name` (string, required): e.g. `"nginx"`, `"docker:payment-api"`, or `"systemd:redis"`.
- `lines_count` (integer, optional, default: 50): clamped between 1 and 1000.

### 3. `execute_recovery`
Executes an isolated, predefined recovery operation.

**Parameters:**
- `action_name` (string, required):
  - `"clean_docker_cache"`: Runs Docker prune for containers, images, and networks.
  - `"restart_nginx"`: Safely restarts Nginx via systemctl or Docker.

---

## 🔒 Security Principles

1. **No Arbitrary Command Execution**: We deliberately avoid exposing a raw terminal or generic `exec` tool.
2. **Strict Whitelisting**: Actions are hard-coded in an immutable lookup table.
3. **No Shell Invocations**: All subprocess executions use explicit list arguments (`shell=False`), preventing shell meta-character evaluation and command injections.
4. **Least Privilege**: Designed to run as an unprivileged user with narrowly scoped group memberships (`docker`, `systemd-journal`).

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
