# VPS-Guardian-MCP 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![CI](https://github.com/murzirius/VPS-Guardian-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/murzirius/VPS-Guardian-MCP/actions/workflows/ci.yml)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP%202024--11--05-green.svg)](https://modelcontextprotocol.io/)
[![Author: murzirius](https://img.shields.io/badge/Author-murzirius-purple.svg)](https://github.com/murzirius)
[![Release](https://img.shields.io/github/v/tag/murzirius/VPS-Guardian-MCP?color=blue&label=version)](https://github.com/murzirius/VPS-Guardian-MCP/tags)
[![Stars](https://img.shields.io/github/stars/murzirius/VPS-Guardian-MCP?style=flat&color=yellow)](https://github.com/murzirius/VPS-Guardian-MCP/stargazers)
[![Tools Count](https://img.shields.io/badge/Tools-51%20Active-brightgreen.svg)](#-tools-reference)
[![Updates](https://img.shields.io/badge/Changelog-UPDATES.md-informational.svg)](UPDATES.md)

A secure, open-source [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server designed for remote Linux VPS observability, Docker management, configuration editing with automated backups, network security audits, storage diagnostics, scheduled task inspection, OS patch auditing, kernel crash investigations, outbound network latency benchmarks, database health checks, and isolated emergency recovery.

It gives AI agents (Google Antigravity 2.0, Claude Code, Cursor, OpenAI Codex, and Windsurf) **named, structured VPS capabilities** instead of an unrestricted “run this shell command and paste the output” workflow. The agent calls tools such as `get_system_health`, `inspect_compose_project`, or `plan_config_deployment`; the server validates inputs, limits writable paths, and enforces confirmations for changes.

---

## 🚀 Connect an AI Agent to Your VPS

Use this section first. It covers the normal setup, the Codex Desktop form, alternative SSH arrangements, verification, and upgrades. The detailed tool catalogue is further down.

### What you need

- A Linux VPS reachable via SSH.
- An SSH key that can log in to the VPS. Password-based SSH is intentionally not supported by the `npx` runner.
- Node.js 16+ on the computer running the AI client; Python 3.10+ on the VPS.
- A trusted VPS: the runner accepts its SSH host key on first connection. Verify the server fingerprint by another channel when that matters for your environment.

### 1. Install the MCP server on the VPS

Run once on the VPS. `/opt/vps-guardian-mcp` is the default path used by the client examples.

```bash
git clone https://github.com/murzirius/VPS-Guardian-MCP.git /opt/vps-guardian-mcp
cd /opt/vps-guardian-mcp
python3 -m venv .venv
.venv/bin/pip install -e .
```

If the MCP process will not run as `root`, grant only the capabilities it needs:

```bash
sudo usermod -aG docker <MCP_USER>
sudo usermod -aG systemd-journal <MCP_USER>
```

Log out and back in after changing group membership. The server still degrades safely when Docker or journal permissions are unavailable.

### 2. Choose a safety mode

| Situation | Mode | Result |
| :--- | :--- | :--- |
| The agent should only inspect and diagnose a VPS | `read-only` | Default. Any write, restart, cleanup, backup, or update is blocked. |
| The agent may administer the VPS, but you must approve every change | `controlled` | Recommended. The first mutation returns an exact, single-use confirmation token valid for 5 minutes. |
| A tightly isolated, separately protected automation environment | `unrestricted` | Changes run immediately. Avoid for a personal workstation or a general-purpose agent. |

For most users, start with `read-only`, verify the connection, then choose `controlled` when you need assisted repairs.

### 3. Recommended connection: `npx` over SSH

The local `npx` runner keeps MCP's stdio transport clean and opens SSH to the binary installed on the VPS. Pin a release tag so an unexpected upstream change never alters the agent's available behavior.

```json
{
  "mcpServers": {
    "vps-guardian": {
      "command": "npx",
      "args": [
        "-y",
        "github:murzirius/VPS-Guardian-MCP#v0.16.0",
        "--host", "<VPS_IP_OR_HOSTNAME>",
        "--user", "root",
        "--key", "~/.ssh/id_ed25519",
        "--mode", "controlled"
      ]
    }
  }
}
```

Every item in `args` is a separate argument. Do not combine `--host` with its value or put the full command in one field.

### 4. OpenAI Codex / ChatGPT Desktop: fill in the form

Open **Settings → MCP servers → Add server**, then choose **STDIO**. Enter the following values. The official Codex guidance confirms that a Desktop MCP server is saved and then restarted, and that `command`, `args`, `env`, and `cwd` are supported for STDIO servers. [OpenAI Docs](https://learn.chatgpt.com/es-419/docs/extend/mcp)

| Field | Value |
| :--- | :--- |
| Name | `vps-guardian` |
| Command | `npx` |
| Arguments | Add **one row per line** in the exact order below |
| Environment variables | Leave empty |
| Working directory | Leave the default value |

Arguments, one per row:

```text
-y
github:murzirius/VPS-Guardian-MCP#v0.16.0
--host
<VPS_IP_OR_HOSTNAME>
--user
root
--key
C:\Users\<WindowsUser>\.ssh\id_ed25519
--mode
controlled
```

Save the server, restart Codex Desktop, and use `/mcp` to confirm that `vps-guardian` is connected. Codex Desktop, the Codex CLI, and the IDE extension share the same MCP configuration on a host. [OpenAI Docs](https://learn.chatgpt.com/es-419/docs/extend/mcp)

### 5. Other common client situations

#### Cursor, Windsurf, Antigravity, or another JSON-configured client

Use the JSON from step 3 in that client's MCP server configuration. Keep the arguments as an array of separate strings.

#### Claude Code

```bash
claude mcp add vps-guardian -- npx -y github:murzirius/VPS-Guardian-MCP#v0.16.0 --host <VPS_IP_OR_HOSTNAME> --user root --key ~/.ssh/id_ed25519 --mode controlled
```

#### The SSH user is not `root`

Replace the value after `--user`, for example `--user deploy`. Ensure that account can read the required logs and Docker socket when you expect those tools to work. Do not give passwordless `sudo` merely to make the MCP work; use the minimum permissions needed.

#### SSH uses a non-standard port

Add two more arguments after the key path:

```text
--port
2222
```

#### The private key is elsewhere or has a Windows path

Set the value after `--key` to its absolute path, for example `C:\Users\<WindowsUser>\.ssh\vps_ed25519`. The key is read on the AI client's computer, never uploaded to the VPS.

#### The MCP server is installed outside `/opt/vps-guardian-mcp`

Add:

```text
--remote-path
/srv/vps-guardian/.venv/bin/vps-guardian-mcp
```

#### You prefer direct OpenSSH instead of `npx`

Use this only when the client can launch `ssh` directly. It bypasses the convenience runner but exposes the same MCP server:

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
        "root@<VPS_IP_OR_HOSTNAME>",
        "env", "VPS_GUARDIAN_MODE=controlled",
        "/opt/vps-guardian-mcp/.venv/bin/vps-guardian-mcp"
      ]
    }
  }
}
```

### 6. Verify the connection

Ask the agent: **“Check the CPU and RAM load on my server.”** A working connection produces a structured response from `get_system_health`, rather than an SSH command for you to run.

If the server fails to start:

| Symptom | Check |
| :--- | :--- |
| `npx` is not recognized | Install Node.js 16+ on the AI client's computer, then restart the client. |
| `Permission denied (publickey)` | Test the same key and user locally with `ssh -i <key> <user>@<host>`. |
| Remote binary not found | Complete step 1 or pass the actual binary location using `--remote-path`. |
| Docker or system logs are unavailable | Check the non-root account's `docker` and `systemd-journal` group membership, then start a new SSH session. |
| MCP is saved but tools are absent in Codex | Restart Codex Desktop and inspect `/mcp`. |

### 7. Upgrade safely

Update **both ends** to the same release:

1. On the VPS, fetch the new tag, inspect any local modifications first, then check out the new release and reinstall:

   ```bash
   cd /opt/vps-guardian-mcp
   git status
   git fetch --tags
   git checkout vX.Y.Z
   .venv/bin/pip install -e .
   ```

2. In the client MCP configuration, replace `#v0.14.1` with `#vX.Y.Z`, save, and restart the client. If you pinned a release, do not use `#main` unless you intentionally want unreleased changes.

The running agent process is recreated when the MCP client reconnects, so no separate daemon restart is needed for the default SSH setup.

---

## 📊 Project Overview & Statistics

| Metric | Details |
| :--- | :--- |
| **Version** | `0.16.0` (See [UPDATES.md](UPDATES.md)) |
| **Active MCP Tools** | **60 tools** |
| **MCP Resources** | `vps://system-overview`, `vps://security-dashboard`, `vps://docker-overview` |
| **MCP Prompts** | `triage_server_incident`, `emergency_disk_cleanup`, `security_and_update_audit`, `troubleshoot_application_crash` |
| **Release Status** | [v0.16.0 on GitHub](https://github.com/murzirius/VPS-Guardian-MCP/releases) / Open Source (MIT) |
| **Architecture** | Python 3.10+, FastMCP, Stdio JSON-RPC Transport |
| **Supported Platforms** | Linux with APT, DNF/YUM, Pacman, or Zypper; UFW, firewalld, or nftables; systemd, OpenRC, or SysVinit |
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
- **`set_web_file_mode`**: Token-confirmed, intentionally limited `0644` or `0640` permissions for an existing regular static file under `/var/www/`; it never changes file content or accepts arbitrary chmod modes.
- **`list_directory`**: Explores directory structures up to configurable depth limits within permitted paths.

### 5. 🌍 Web Server & SSL Diagnostics (`src/web.py`)
- **`test_nginx_config`**: Validates Nginx syntax non-disruptively (`nginx -t`) before reloading configuration files.
- **`check_http_endpoint`**: Checks a public URL's response code, TLS, redirects, latency, and optionally a required text fragment without returning page contents.
- **`check_http_endpoints`**: Checks up to 20 public endpoints in one compact deployment-health report.
- **`get_web_deployment_status`**: Correlates a public HTTPS response with its local Nginx virtual host and matching TLS certificate.
- **`check_ssl_certificates`**: Scans Certbot and Let's Encrypt certificates, verifying domain bindings and alerting if renewal is required (<14 days).
- **`list_virtual_hosts`**: Parses virtual host declarations from `/etc/nginx/sites-enabled/` and `conf.d/` (server names, listening ports, SSL, and reverse proxy targets).

### Agent Sessions & Live Server Events (`src/agent_runtime.py`)
- **Agent Sessions**: Expiring shared task context with bounded, secret-redacted findings, handoffs, outcomes, and short-lived workload locks.
- **Live Server Events**: A compact timeline joining VPS-Guardian audit events with important journal entries; event watches provide a resumable cursor for a workload.

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

### 14. 🛡️ Server-Enforced Safety & Audit (`src/safety.py`)
- **`get_safety_status`**: Reports the active execution mode, confirmation policy, token lifetime, and audit destination.
- **`get_audit_events`**: Returns recent redacted JSONL audit events for state-changing operations.
- State-changing tools use short-lived, single-use confirmation tokens bound to their exact parameters.
- The default `read-only` mode blocks all state changes at the server boundary.

### 15. 🚨 Unified Incident Triage (`src/incident.py`)
- **`generate_incident_report`**: Aggregates system pressure, failed services, Docker health, OOM events, kernel errors, databases, security posture, and pending updates into one severity-ranked report.

### 16. 🔁 Transactional Configuration Deployment (`src/deploy.py`)
- **`plan_config_deployment`**: Stages an Nginx config or Caddyfile candidate outside the live path, runs its native validator, produces a bounded unified diff, and issues a short-lived deployment plan.
- **`deploy_config_change`**: Atomically writes the validated plan, creates a backup, reloads the matching service, verifies it is active, and restores the prior configuration if reload or health validation fails.
- Plans are bound to the current file hash; a concurrent file change is rejected instead of overwritten.

### 17. 📸 State Baselines & Drift Detection (`src/snapshot.py`)
- **`create_system_snapshot`**: Saves a baseline of ports, failed units, cron/timers, Docker inventory, and optional configuration hashes without storing config or cron-command content.
- **`list_system_snapshots`**: Lists retained baseline metadata.
- **`compare_system_snapshots`**: Prioritizes changes between two snapshots: failed units, new exposed ports, scheduled-task drift, Docker changes, and config hash changes.

### 18. 🧩 Docker Compose Awareness (`src/compose.py`)
- **`list_compose_projects`** and **`inspect_compose_project`**: Discover authorized Compose projects and expose safe topology (services, images, ports, dependencies, healthchecks) without environment values.
- **`compose_project_action`**: Token-confirmed `up`, `restart`, or `stop` for a project or an explicit subset of services.

### 19. 🌍 Cross-Distro Capability Adapters (`src/platform.py`)
- **`get_platform_capabilities`**: Detects package manager, firewall, init system, and Compose availability.
- **`get_package_updates`**: Read-only update inventory for APT, DNF/YUM, Pacman, and Zypper.
- **`get_firewall_status`**: Normalized status for UFW, firewalld, or nftables; guarded service restart now supports systemd, OpenRC, and SysVinit.

### 20. 🧭 Agent Workload Topology (`src/topology.py`)
- **`get_vps_topology`**: Builds a bounded map of websites, reverse proxies, Compose projects, containers, listening ports, and databases. It excludes configuration contents, environment values, and credentials.
- **`find_workload`** and **`get_workload_health`**: Find an application by domain, container, service, port, or path fragment, then show its component health, matching SSL state, and host pressure.
- **`diagnose_workload`** and **`prepare_repair_plan`**: Gather focused, bounded evidence and create a non-executing repair plan using the existing guarded actions.
- **`get_change_impact`**: Shows affected components before a proposed restart, stop, configuration deployment, or update; it never performs that action.
- **`create_workload_baseline`** and **`compare_workload_baseline`**: Save and compare secret-free known-good state for a single workload.

---

## 🤖 Guidelines for AI Agents

When interacting with a host via VPS-Guardian-MCP, AI agents must adhere to the following operational standards:

1. **Invoke Native MCP Tools Exclusively**: Never simulate or guess server states. Always call the corresponding tool (`get_system_health`, `test_nginx_config`, `check_oom_events`, etc.) to obtain verified ground-truth telemetry.
2. **Follow the Principle of Least Privilege**: Use read-only diagnostic tools first before suggesting or applying changes.
3. **Diagnose Mysterious Crashes Methodically**: When an application or container terminates without obvious error logs, always run `check_oom_events` and `check_kernel_errors` to identify memory exhaustion or segfaults before restarting.
4. **Deploy Web Configurations Transactionally**: For supported Nginx configs and Caddyfiles, use `plan_config_deployment` first, then `deploy_config_change`; it validates, backs up, reloads, checks service health, and rolls back automatically on failure.
5. **Establish and Review Baselines**: Create a snapshot after a known-good deployment, then compare it before remediation. Treat critical or warning drift as evidence to investigate, not authorization to change a host.
6. **Inspect Compose Before Acting**: Inspect a Compose project and limit `compose_project_action` to only the services that need intervention.
7. **Find Before Diagnosing**: For an application request, start with `get_vps_topology` or `find_workload`, then use `get_workload_health` and `diagnose_workload` rather than guessing its container or service name.
8. **Plan Before Repairing**: Use `get_change_impact` and `prepare_repair_plan` as evidence. Neither authorizes a change or bypasses the server-side safety gate.
9. **Handle Errors Structurally**: Diagnostic outputs and system exceptions are returned as structured JSON payloads. Check the `status` field (`"ok"`, `"error"`, `"unavailable"`, `"forbidden"`) to decide subsequent actions.
10. **Promptly Surface Critical Alerts**: When `check_system_updates` or `vps://system-overview` flags pending security patches or reboot requirements, prioritize alerting the operator and proposing remediation.
11. **Use Server-Issued Confirmation Tokens**: In `controlled` mode, call a state-changing tool once without a token, show its impact plan to the operator, then repeat the exact call with the returned `confirmation_token`.

---

## 📁 Repository Structure

```text
VPS-Guardian-MCP/
├── src/
│   ├── __init__.py          # Package version (v0.16.0)
│   ├── server.py            # FastMCP server, resources, prompts, and tool registry (51 tools)
│   ├── safety.py            # Confirmation tokens, execution modes, and audit log
│   ├── incident.py          # Unified severity-ranked incident report
│   ├── deploy.py            # Validated config deployment, reload health check, and rollback
│   ├── snapshot.py          # Privacy-preserving state baseline and drift comparison
│   ├── compose.py           # Guarded Compose project discovery and lifecycle actions
│   ├── platform.py          # Cross-distro package, firewall, and service capability adapters
│   ├── topology.py          # Workload discovery, diagnosis, impact, and baselines
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

## 🔧 Direct OpenSSH Appendix

The `npx` configuration above is the recommended, version-pinned route. Use these examples only when a client cannot run the local `npx` wrapper. Add `env VPS_GUARDIAN_MODE=controlled` before the remote binary when you need controlled changes; otherwise the server starts in `read-only` mode.

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

## 🛠️ Tools Reference (73 Active Tools)

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
| `docker_container_action` | `container_name`, `action`, `timeout`, `confirmation_token` (*optional*) | Token-confirmed container lifecycle operation |
| `inspect_docker_container` | `container_name` (*string*) | Deep container introspection (network, ports, mounts, restart policy, masked env vars) |
| `clean_docker_garbage` | `prune_type`, `confirmation_token` (*optional*) | Token-confirmed pruning of unused Docker resources |
| `list_compose_projects` | `root_path`, `max_depth` | Finds authorized conventional Compose project files |
| `inspect_compose_project` | `compose_file` | Shows safe Compose topology without environment values |
| `compose_project_action` | `compose_file`, `action`, `services`, `confirmation_token` (*optional*) | Token-confirmed Compose `up`, `restart`, or `stop` |
| `get_vps_topology` | *none* | Safe map of websites, proxies, Compose, containers, ports, and databases |
| `find_workload` | `query` (*string*) | Finds workloads by domain, component name, port, image, or path fragment |
| `get_workload_health` | `target` (*string*) | Workload status, matching SSL metadata, container stats, and host pressure |
| `diagnose_workload` | `target`, `log_lines` (*int*) | Focused, bounded logs plus OOM, kernel, and health evidence |
| `get_change_impact` | `target`, `action` | Read-only affected-component report before a prospective change |
| `prepare_repair_plan` | `target` (*string*) | Evidence-backed repair plan; never executes a mutation |
| `create_workload_baseline` | `target`, `label` (*optional*) | Persists a secret-free known-good workload state |
| `compare_workload_baseline` | `baseline_id` (*string*) | Compares one workload baseline with current discovered state |
| `start_agent_session` | `title`, `target`, `ttl_minutes` | Creates expiring shared context for agents working on the VPS |
| `get_agent_session` | `session_id` | Reads objective, findings, handoff, and expiry state |
| `list_agent_sessions` | `include_closed` | Lists active or historical agent sessions |
| `record_session_finding` | `session_id`, `summary`, `kind` | Adds bounded secret-redacted context to a session |
| `handoff_agent_session` | `session_id`, `next_agent`, `summary` | Transfers concise context to another agent |
| `close_agent_session` | `session_id`, `outcome` | Closes a task with recorded outcome |
| `lock_workload` | `session_id`, `target`, `ttl_minutes` | Short-lived workload reservation to prevent conflicts |
| `get_recent_server_events` | `since_minutes`, `limit`, `target` | Joins Guardian audit and notable journal events into one timeline |
| `open_event_watch` | `target`, `session_id`, `ttl_minutes` | Opens an expiring workload event cursor |
| `get_event_watch` | `watch_id`, `limit` | Retrieves events since an event watch was opened |
| `get_open_ports` | *none* | Discovers all listening ports (TCP/UDP, IPv4/IPv6) with process names and PIDs |
| `get_ufw_status` | *none* | Audits UFW firewall state, default traffic policies, and active rules |
| `get_platform_capabilities` | *none* | Detects cross-distro management backends |
| `get_package_updates` | *none* | Lists updates via the detected package manager |
| `get_firewall_status` | *none* | Normalized UFW, firewalld, or nftables status |
| `view_file_content` | `file_path` (*string*), `max_bytes` (*int*) | Reads authorized configuration files with size bounding |
| `write_file_content` | `file_path`, `content`, `backup`, `confirmation_token` (*optional*) | Token-confirmed atomic config update with backup |
| `set_web_file_mode` | `file_path`, `mode`, `confirmation_token` (*optional*) | Token-confirmed 0644/0640 permissions for a static file under `/var/www` |
| `list_directory` | `dir_path` (*string*), `max_depth` (*int*) | Lists directory contents within authorized paths |
| `plan_config_deployment` | `file_path`, `content`, `service_name` (*optional*) | Validates and diffs an Nginx config/Caddyfile candidate without changing the live config |
| `deploy_config_change` | `deployment_id`, `confirmation_token` (*optional*) | Atomically deploys a plan, reloads it, checks health, and rolls back on failure |
| `create_system_snapshot` | `label` (*optional*), `include_config_hashes` (*bool*) | Saves a privacy-preserving VPS state baseline |
| `list_system_snapshots` | `limit` (*int*) | Lists stored baseline metadata |
| `compare_system_snapshots` | `baseline_id`, `current_id` | Prioritizes infrastructure drift between two snapshots |
| `test_nginx_config` | *none* | Validates Nginx configuration syntax (`nginx -t`) non-disruptively |
| `check_http_endpoint` | `url`, `expected_status`, `expected_text`, `timeout_seconds` | Checks one public endpoint's status, TLS, redirects, latency, and optional text |
| `check_http_endpoints` | `endpoints` | Checks up to 20 public endpoints in one deployment-health report |
| `get_web_deployment_status` | `domain`, `path`, `expected_status`, `expected_text` | Correlates public HTTPS, local Nginx vhost, and matching TLS certificate |
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
| `generate_incident_report` | `include_updates`, `include_security`, `include_network` (*bool*) | Produces one severity-ranked, read-only triage report |
| `get_safety_status` | *none* | Reports execution mode, confirmation policy, token TTL, and audit path |
| `get_audit_events` | `limit` (*int*, default: *50*) | Reads recent redacted state-change audit events |
| `execute_recovery` | `action_name`, `target`, `confirmation_token` (*optional*) | Executes a token-confirmed whitelisted recovery operation |
| `create_backup` | `backup_type`, `source_path`, `confirmation_token` (*optional*) | Creates a token-confirmed isolated `.tar.gz` backup |

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
8. **Server-Side Safety Modes**: Read-only is the default; controlled mode requires exact, short-lived, single-use confirmation tokens.
9. **Redacted Audit Trail**: Every completed state-changing operation writes a JSONL audit event without file contents, credentials, or confirmation tokens.

---

## 📄 License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

Copyright (c) 2026 murzirius.
