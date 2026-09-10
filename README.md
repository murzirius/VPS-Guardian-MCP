# VPS-Guardian-MCP 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP%202024--11--05-green.svg)](https://modelcontextprotocol.io/)
[![Author: murzirius](https://img.shields.io/badge/Author-murzirius-purple.svg)](https://github.com/murzirius)
[![Release](https://img.shields.io/github/v/tag/murzirius/VPS-Guardian-MCP?color=blue&label=version)](https://github.com/murzirius/VPS-Guardian-MCP/tags)
[![Stars](https://img.shields.io/github/stars/murzirius/VPS-Guardian-MCP?style=flat&color=yellow)](https://github.com/murzirius/VPS-Guardian-MCP/stargazers)
[![Tools Count](https://img.shields.io/badge/Tools-37%20Active-brightgreen.svg)](#-tools-reference)
[![Updates](https://img.shields.io/badge/Changelog-UPDATES.md-informational.svg)](UPDATES.md)

A secure, open-source [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server designed for remote Linux VPS observability, Docker management, configuration editing with automated backups, network security audits, storage diagnostics, scheduled task inspection, OS patch auditing, kernel crash investigations, outbound network latency benchmarks, database health checks, and isolated emergency recovery.

It provides next-generation AI developer tools (Google Antigravity 2.0, Claude Code, Cursor, OpenAI Codex, Windsurf) with structured, programmatic capabilities to inspect server health and resolve infrastructure issues without raw shell access or unconstrained root privileges.

---

## 📊 Project Overview & Statistics

| Metric | Details |
| :--- | :--- |
| **Version** | `0.9.0` (See [UPDATES.md](UPDATES.md)) |
| **Active MCP Tools** | **37 tools** |
| **MCP Resources** | `vps://system-overview`, `vps://security-dashboard`, `vps://docker-overview` |
| **MCP Prompts** | `triage_server_incident`, `emergency_disk_cleanup`, `security_and_update_audit`, `troubleshoot_application_crash` |
| **Release Status** | [v0.9.0 on GitHub](https://github.com/murzirius/VPS-Guardian-MCP/releases) / Open Source (MIT) |
| **Architecture** | Python 3.10+, FastMCP, Stdio JSON-RPC Transport |
| **Supported Platforms** | Linux (Ubuntu, Debian, CentOS, AlmaLinux, Arch Linux) |
| **Security Standards** | 100% Shell-less execution (`shell=False`), directory whitelisting, atomic file swaps |
| **Compatible Modern Clients** | Google Antigravity 2.0, Claude Code, Cursor IDE, OpenAI Codex / ChatGPT, Windsurf |

---

## ✨ Core Features

### 1. 🖥️ System & Resource Monitoring (`src/monitor.py` & `src/proc_deep.py`)
- **`get_system_health`**: Collects a comprehensive system snapshot including per-core CPU utilization, RAM and Swap metrics, root filesystem capacity, Disk I/O counters (read/write operations and throughput), Network I/O metrics, and humanized uptime.
- **`get_top_processes`**: Identifies top resource-consuming processes ranked by CPU or memory usage, detailing PID, user, memory RSS, status, and command line summaries using two-pass selective inspection.
- **`get_process_details`**: Exhaustive runtime profiling of a specific PID including parent/children hierarchy, CPU percentage, user/system times, thread counts, RSS/VMS/shared memory maps, open file descriptor counts (`num_fds`), open files sample, active network sockets, I/O counters, and sanitized environment variables.
- **`detect_zombie_processes`**: Scans the process table for defunct/zombie processes, identifies their non-reaping parent processes (PPID, command line), and provides diagnostic instructions for clearing stalled processes.
- **`check_system_limits`**: Audits Linux kernel and system limits: system-wide file descriptors (`/proc/sys/fs/file-nr` vs `fs.file-max`) and process NOFILE limits, process/thread capacity (`/proc/sys/kernel/pid_max` and NPROC), virtual memory parameters (`vm.swappiness`, `vm.vfs_cache_pressure`, `vm.max_map_count`), and socket backlog limits (`somaxconn`, `tcp_max_syn_backlog`), flagging warnings when utilization exceeds 80%.
- **`check_service_status`**: Queries systemd service state (`active`, `enabled`, recent unit logs) for critical services like Nginx, MySQL, PostgreSQL, and UFW.
- **`get_failed_systemd_units`**: Performs rapid system audits to discover degraded or failed systemd units (`systemctl --failed`).
- **`read_service_logs`**: Extracts service logs with pure Python-level keyword/regex filtering (`grep_filter`), eliminating command injection vectors.

### 2. 🐳 Docker Management & Control (`src/docker_manager.py`)
- **`list_docker_containers`**: Inspects container inventory, reporting status, image tags, port forwards, bind mounts/volumes, health checks, and exit codes.
- **`get_docker_container_logs`**: Safely retrieves stdout and stderr streams for any container with bounded line limits.
- **`get_docker_stats`**: Streams live resource telemetry (CPU %, memory usage and limits, network RX/TX, block I/O) equivalent to `docker stats`.
- **`docker_container_action`**: Safely executes container lifecycle operations (`start`, `stop`, `restart`, `pause`, `unpause`) with input validation (`CONTAINER_NAME_REGEX`) and configurable shutdown grace timeouts.
- **`inspect_docker_container`**: Detailed architectural introspection of any container, returning network addresses, port mappings, mounted volumes/binds, healthcheck history, restart policies, resource limits, and environment variables with automated credential masking.
- **`clean_docker_garbage`**: Reclaims disk space by safely pruning dangling images, stopped containers, unused volumes, and orphan networks (`prune_type`: `'containers'`, `'images'`, `'volumes'`, `'networks'`, `'all'`).

### 3. 🌐 Network Security & Firewall Diagnostics (`src/network.py`)
- **`get_open_ports`**: Discovers all open and listening network ports (TCP and UDP, IPv4 and IPv6) with corresponding bound processes and PIDs.
- **`get_ufw_status`**: Audits Uncomplicated Firewall (UFW) active status, default incoming/outgoing policies, and detailed rule configurations.

### 4. 📁 File & Configuration Management (`src/files.py`)
- **`view_file_content`**: Safely reads configuration files within authorized administrative paths (`/etc/nginx/`, `/etc/mysql/`, `/etc/postgresql/`, `/etc/docker/`, `/etc/caddy/`, `/var/www/`) with context-protective size bounds.
- **`write_file_content`**: Atomically updates configuration files via temporary file staging, preserving original permissions and automatically generating timestamped backup copies (`.bak.<timestamp>`).
- **`list_directory`**: Explores directory structures up to configurable depth limits within permitted paths.

### 5. 🌍 Web Server & SSL Diagnostics (`src/web.py`)
- **`test_nginx_config`**: Validates Nginx syntax non-disruptively (`nginx -t`) before reloading configuration files.
- **`check_ssl_certificates`**: Scans Certbot and Let's Encrypt certificates, verifying domain bindings and alerting if renewal is required (<14 days).
- **`list_virtual_hosts`**: Parses virtual host declarations from `/etc/nginx/sites-enabled/` and `conf.d/` (server names, listening ports, SSL, and reverse proxy targets).

### 6. 🔒 Security Auditing & Intrusion Detection (`src/security.py`)
- **`check_failed_logins`**: Analyzes recent failed SSH authentications to surface brute-force attackers and repeat offending IP addresses.
- **`get_fail2ban_status`**: Audits Fail2ban service status, active protection jails, and banned IP registries.
- **`audit_ssh_config`**: Analyzes `/etc/ssh/sshd_config` against hardening guidelines (password auth, root login, port configurations) with a security score (0-100).

### 7. 💾 Storage & Disk Usage Diagnostics (`src/storage.py`)
- **`analyze_disk_usage`**: Recursively audits directories for high disk usage without following symlinks or descending into pseudo-filesystems (`/proc`, `/sys`, `/dev`, `/run`). Identifies the largest space consumers and files with humanized size formatting.

### 8. ⏰ Scheduler & Automation Auditing (`src/scheduler.py`)
- **`list_cron_jobs`**: Scans `/etc/crontab`, modular `/etc/cron.d/`, standard cron intervals (`daily`, `hourly`, `weekly`, `monthly`), and user crontabs with human-friendly schedule translations.
- **`list_systemd_timers`**: Audits active and pending systemd timers, reporting triggers, countdowns, and target service activations.

### 9. 🔄 System Updates & Self-Version Verification (`src/updates.py`)
- **`check_system_updates`**: Audits available operating system packages, flags unpatched security CVE updates, and detects kernel reboot requirements (`/var/run/reboot-required`). Generates prominent alerts for AI agents.
- **`check_guardian_updates`**: Verifies local installation against the upstream GitHub repository to alert operators when a newer version or commit is available.

### 10. 💥 Kernel Diagnostics & OOM Crash Analysis (`src/crash.py`)
- **`check_oom_events`**: Parses kernel logs to surface Out-Of-Memory (OOM) Killer terminations, identifying terminated processes, PIDs, and consumed RSS memory.
- **`check_kernel_errors`**: Scans kernel journal for storage I/O errors, filesystem warnings (EXT4/Btrfs), hardware degradation, and application segfaults.

### 11. 🚀 Outbound Network Connectivity & DNS Benchmarking (`src/net_diag.py`)
- **`test_network_connectivity`**: Performs 100% pure Python socket benchmarking of DNS resolution latency, TCP handshake time, and TLS handshake latency without shell `ping`.
- **`check_dns_health`**: Audits system DNS resolver health, configured nameservers in `/etc/resolv.conf`, and latency against core public endpoints.

### 12. 🗄️ Database & Cache Health (`src/database.py`)
- **`get_database_health`**: Non-invasively audits active local database engines: Redis (pure socket PING and RSS memory), PostgreSQL (`pg_isready`), MySQL/MariaDB (`mysqladmin` ping), and SQLite database file integrity.

### 13. 🔧 Emergency Recovery & Backups (`src/recover.py`)
- **`execute_recovery`**: Executes strictly whitelisted administrative recovery operations:
  - `restart_service`: Restarts target systemd services with strict identifier validation.
  - `clean_docker_cache`: Performs a deep prune of dangling/unused images, stopped containers, networks, and build caches.
  - `clean_system_logs`: Vacuums systemd journal logs older than 3 days and prunes rotated log archives in `/var/log`.
  - `kill_process`: Terminates stuck runaway processes by PID while enforcing protections for PID 1, init, and core system daemons.
  - `vacuum_systemd_journal`: Safely prunes systemd journal logs to a target size threshold (e.g. `200M`).
  - `clean_package_cache`: Cleans APT archive cache and purges obsolete packages (`apt-get clean && apt-get autoremove`).
  - `apply_security_updates`: Safely applies pending operating system security patches non-interactively.
  - `update_guardian`: Automatically updates VPS-Guardian-MCP from GitHub and refreshes the virtual environment.
- **`create_backup`**: Creates standalone `.tar.gz` compressed archives of authorized directories inside an isolated backup repository (`/var/backups/vps-guardian/`).

---

## 🤖 Guidelines for AI Agents

When interacting with a host via VPS-Guardian-MCP, AI agents must adhere to the following operational standards:

1. **Invoke Native MCP Tools Exclusively**: Never simulate or guess server states. Always call the corresponding tool (`get_system_health`, `test_nginx_config`, `check_oom_events`, etc.) to obtain verified ground-truth telemetry.
2. **Follow the Principle of Least Privilege**: Use read-only diagnostic tools first before suggesting or applying changes.
3. **Diagnose Mysterious Crashes Methodically**: When an application or container terminates without obvious error logs, always run `check_oom_events` and `check_kernel_errors` to identify memory exhaustion or segfaults before restarting.
4. **Verify Configurations Before Reloading**: When modifying web server configurations, always execute `test_nginx_config` prior to invoking `execute_recovery(action_name='restart_service', target='nginx')`.
5. **Handle Errors Structurally**: Diagnostic outputs and system exceptions are returned as structured JSON payloads. Check the `status` field (`"ok"`, `"error"`, `"unavailable"`, `"forbidden"`) to decide subsequent actions.
6. **Promptly Surface Critical Alerts**: When `check_system_updates` or `vps://system-overview` flags pending security patches or reboot requirements, prioritize alerting the operator and proposing remediation.
7. **Require Confirmation for State-Changing Operations**: Any recovery or file modification action (`execute_recovery`, `write_file_content`, `create_backup`) must be explicitly confirmed with the operator prior to execution.

---

## 📁 Repository Structure

```text
VPS-Guardian-MCP/
├── src/
│   ├── __init__.py          # Package version (v0.8.1)
│   ├── server.py            # FastMCP server, resources, prompts, and tool registry (31 tools)
│   ├── monitor.py           # CPU, RAM, Disk I/O, Network, Services, Logs
│   ├── docker_manager.py    # Container inventory, logs, and live telemetry
│   ├── network.py           # Listening ports, bound processes, and UFW rules
│   ├── files.py             # Whitelisted config viewer, atomic writer, directory inspector
│   ├── web.py               # Nginx syntax verification, SSL checks, virtual host listing
│   ├── security.py          # Failed logins, Fail2ban status, SSH configuration audit
│   ├── storage.py           # Disk usage analyzer and space hog finder
│   ├── scheduler.py         # Cron schedules and systemd timers inspection
│   ├── updates.py           # OS security patch auditor and guardian self-version checker
│   ├── crash.py             # OOM-killer events and kernel error diagnostics
│   ├── net_diag.py          # Outbound network benchmarks and DNS latency checks
│   ├── database.py          # Redis, PostgreSQL, MySQL, and SQLite health audits
│   └── recover.py           # Service restarts, cache/log pruners, process killer, tar.gz backups
├── pyproject.toml           # Package configuration and dependencies
├── LICENSE                  # MIT License (2026, murzirius)
├── .gitignore               # Ignored environments, builds, and caches
├── UPDATES.md               # Project changelog and release history
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

To allow the service user to monitor Docker, network connections, and system logs without requiring root privileges:

```bash
# Add user to the docker socket group
sudo usermod -aG docker $USER

# Add user to systemd journal reader group
sudo usermod -aG systemd-journal $USER
```

---

## ⚙️ Modern Client Configuration

VPS-Guardian-MCP can be launched effortlessly via **`npx`** (recommended — handles SSH keepalive, timeouts, and stdio pipes automatically) or via direct **OpenSSH stdio**.

### ⚡ Quickstart via NPX (Cursor, Claude Code, Antigravity, Windsurf)

Run instantly without cloning, manual SSH parameter setup, or token registration via GitHub shorthand:

```json
{
  "mcpServers": {
    "vps-guardian": {
      "command": "npx",
      "args": [
        "-y",
        "github:murzirius/VPS-Guardian-MCP",
        "--host", "<YOUR_VPS_IP>",
        "-i", "~/.ssh/id_ed25519"
      ]
    }
  }
}
```

Or for **Claude Code** CLI terminal:

```bash
claude mcp add vps-guardian -- npx -y github:murzirius/VPS-Guardian-MCP --host <YOUR_VPS_IP> -i ~/.ssh/id_ed25519
```

---

### 🔧 Direct OpenSSH Stdio Configuration

### 1. 🚀 Google Antigravity 2.0 / Antigravity IDE
Add to your global or workspace configuration in `~/.gemini/config/mcp_config.json`:

```json
{
  "mcpServers": {
    "vps-guardian": {
      "command": "ssh",
      "args": [
        "-q",
        "-i", "C:/Users/<Username>/.ssh/id_ed25519",
        "-o", "LogLevel=ERROR",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4",
        "-o", "TCPKeepAlive=yes",
        "-o", "ConnectTimeout=10",
        "root@<YOUR_VPS_IP>",
        "/opt/vps-guardian-mcp/.venv/bin/vps-guardian-mcp"
      ]
    }
  }
}
```

### 2. ⚡ Anthropic Claude Code (CLI Agent)
Add the server with a single terminal command:

```bash
claude mcp add vps-guardian -- ssh -q -i ~/.ssh/id_ed25519 -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o TCPKeepAlive=yes root@<YOUR_VPS_IP> /opt/vps-guardian-mcp/.venv/bin/vps-guardian-mcp
```

### 3. 💻 Cursor IDE
Add to your project or user configuration in `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "vps-guardian": {
      "command": "ssh",
      "args": [
        "-q",
        "-i", "~/.ssh/id_ed25519",
        "-o", "LogLevel=ERROR",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4",
        "-o", "TCPKeepAlive=yes",
        "root@<YOUR_VPS_IP>",
        "/opt/vps-guardian-mcp/.venv/bin/vps-guardian-mcp"
      ]
    }
  }
}
```

### 4. 🧠 OpenAI Codex / ChatGPT Desktop
Configure in your local MCP configuration file:

```json
{
  "mcpServers": {
    "vps-guardian": {
      "command": "ssh",
      "args": [
        "-q",
        "-i", "~/.ssh/id_ed25519",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4",
        "root@<YOUR_VPS_IP>",
        "/opt/vps-guardian-mcp/.venv/bin/vps-guardian-mcp"
      ]
    }
  }
}
```

### 5. 🌊 Codeium Windsurf
Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "vps-guardian": {
      "command": "ssh",
      "args": [
        "-q",
        "-i", "~/.ssh/id_ed25519",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4",
        "root@<YOUR_VPS_IP>",
        "/opt/vps-guardian-mcp/.venv/bin/vps-guardian-mcp"
      ]
    }
  }
}
```

---

## 🛠️ Tools Reference (37 Active Tools)

| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `get_system_health` | *none* | Complete system snapshot (per-core CPU, RAM, Swap, Disk I/O, Network I/O, Uptime) |
| `get_top_processes` | `sort_by` (*"cpu"* / *"memory"*), `limit` (*int*) | Top resource-consuming processes with memory and command details (low CPU two-pass) |
| `get_process_details` | `pid` (*int*) | In-depth diagnostics for a specific PID (threads, memory maps, open files, sockets, I/O) |
| `detect_zombie_processes` | *none* | Scans system process table for defunct/zombie processes and identifies non-reaping parents |
| `check_system_limits` | *none* | Audits system limits (file descriptors `/proc/sys/fs/file-nr`, max PIDs, virtual memory, sockets) |
| `check_service_status` | `service_name` (*string*) | Detailed systemd unit operational status and recent unit logs |
| `get_failed_systemd_units`| *none* | Discovers degraded or failed systemd units across the operating system |
| `read_service_logs` | `service_name` (*string*), `lines_count` (*int*), `grep_filter` (*string*) | Retrieves service logs with safe, pure-Python keyword filtering |
| `list_docker_containers` | `all` (*bool*, default: *true*) | Lists all Docker containers with port forwards, volumes, and health state |
| `get_docker_container_logs` | `container_name` (*string*), `lines_count` (*int*) | Fetches stdout/stderr logs from a specific container |
| `get_docker_stats` | *none* | Live telemetry for running containers (CPU %, RAM, Network and Block I/O) |
| `docker_container_action` | `container_name` (*string*), `action` (*string*), `timeout` (*int*) | Safely executes container lifecycle operations (`start`, `stop`, `restart`, `pause`, `unpause`) |
| `inspect_docker_container` | `container_name` (*string*) | Deep container introspection (network, ports, mounts, restart policy, masked env vars) |
| `clean_docker_garbage` | `prune_type` (*string*, default: *"all"*) | Prunes dangling images, stopped containers, unused volumes, and networks to reclaim disk space |
| `get_open_ports` | *none* | Discovers all listening ports (TCP/UDP, IPv4/IPv6) with process names and PIDs |
| `get_ufw_status` | *none* | Audits UFW firewall state, default traffic policies, and active rules |
| `view_file_content` | `file_path` (*string*), `max_bytes` (*int*) | Reads authorized configuration files with size bounding |
| `write_file_content` | `file_path` (*string*), `content` (*string*), `backup` (*bool*) | Atomically updates config files with automated `.bak` backups |
| `list_directory` | `dir_path` (*string*), `max_depth` (*int*) | Lists directory contents within authorized paths |
| `test_nginx_config` | *none* | Validates Nginx configuration syntax (`nginx -t`) non-disruptively |
| `check_ssl_certificates` | *none* | Audits SSL/TLS certificates and alerts on expirations within 14 days |
| `list_virtual_hosts` | *none* | Inspects active Nginx virtual hosts, listening ports, SSL, and proxies |
| `check_failed_logins` | `limit` (*int*, default: *20*) | Surfaces recent failed SSH logins and top offending attacker IPs |
| `get_fail2ban_status` | *none* | Queries Fail2ban operational status, active jails, and banned IPs |
| `audit_ssh_config` | *none* | Audits `/etc/ssh/sshd_config` security settings with scoring (0-100) |
| `analyze_disk_usage` | `target_path` (*string*), `max_depth` (*int*), `min_size_mb` (*int*), `top_n` (*int*) | Identifies largest directories and files consuming disk space |
| `list_cron_jobs` | *none* | Audits scheduled cron jobs across system, drop-ins, and user crontabs |
| `list_systemd_timers` | *none* | Audits systemd timers with next trigger, elapsed, and active units |
| `check_system_updates` | *none* | Audits available OS package upgrades, security CVE patches, and reboot status |
| `check_guardian_updates` | *none* | Compares current VPS-Guardian version/commit with upstream GitHub release |
| `check_oom_events` | `limit` (*int*, default: *10*) | Audits kernel logs for Linux Out-Of-Memory (OOM) Killer terminations |
| `check_kernel_errors` | `limit` (*int*, default: *20*) | Inspects kernel errors for hardware, storage I/O, and segfault events |
| `test_network_connectivity` | `target_host` (*string*), `port` (*int*), `timeout_seconds` (*float*) | Benchmarks DNS, TCP handshake, and TLS latency via pure Python sockets |
| `check_dns_health` | `domains` (*list[string]*, optional) | Audits system DNS resolver health, nameservers, and query latencies |
| `get_database_health` | *none* | Audits local database services (Redis, PostgreSQL, MySQL/MariaDB, SQLite) |
| `execute_recovery` | `action_name` (*string*), `target` (*string*, optional) | Executes whitelisted operations (`restart_service`, `clean_docker_cache`, `clean_system_logs`, `kill_process`, `vacuum_systemd_journal`, `clean_package_cache`, `apply_security_updates`, `update_guardian`) |
| `create_backup` | `backup_type` (*string*), `source_path` (*string*) | Generates isolated `.tar.gz` archives in `/var/backups/vps-guardian/` |

---

## 📡 MCP Resources & Prompts

### Resources
- **`vps://system-overview`**: Continuous live JSON system snapshot including per-core CPU, RAM, swap, disk I/O, network telemetry, and ambient operating system patch warnings.
- **`vps://security-dashboard`**: Unified security telemetry consolidating UFW firewall status, Fail2ban jails, recent failed authentication attempts, and open listening ports.
- **`vps://docker-overview`**: Live multi-container overview aggregating Docker daemon status, container inventories, health metrics, and disk space reclamation opportunities.

### Prompts
- **`triage_server_incident`**: Systematic runbook guiding the AI step-by-step through incident investigation (CPU/RAM, failed systemd units, journal errors, authentication logs).
- **`emergency_disk_cleanup`**: Guided procedure for identifying disk space saturation (>90%) and safely applying bounded log vacuums, container caches, and APT cleanup.
- **`security_and_update_audit`**: Comprehensive security auditing routine assessing CVE patches, SSH daemon settings, brute-force activity, and cron task integrity.
- **`troubleshoot_application_crash`**: Incident diagnosis runbook investigating Out-Of-Memory terminations, kernel hardware/storage errors, and database reachability.


---

## 🔒 Security Architecture

1. **No Shell Invocations**: Subprocess executions consistently use explicit argument arrays (`shell=False`) to prevent command injection.
2. **Strict Parameter Validation**: Service identifiers, container names, and filters are validated against restrictive regex patterns.
3. **Directory Path Whitelisting**: File and backup operations are strictly locked down to `/etc/nginx/`, `/etc/mysql/`, `/etc/postgresql/`, `/etc/docker/`, `/etc/caddy/`, and `/var/www/`. Path traversal (`../`) is blocked at canonical resolution.
4. **Atomic File Modifications**: File writing stages changes via temporary files before atomic replacement to prevent file corruption.
5. **Process Safety Controls**: The process killer rejects requests targeting PID 1, init, sshd, or vital core operating system processes.
6. **Immutable Whitelists**: Execution actions are governed by fixed lookup tables.
7. **Graceful Permission Degradation**: Missing capabilities return descriptive diagnostic payloads rather than crashing the protocol stream.

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

Copyright (c) 2026 murzirius.
