# Changelog & Project Updates

All notable updates and enhancements to **VPS-Guardian-MCP** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.6.0] - 2026-09-08

### Added
- **Web Server & SSL Diagnostics Suite (`src/web.py`)**:
  - `test_nginx_config`: Validates Nginx configuration syntax (`nginx -t`) non-disruptively before reloading.
  - `check_ssl_certificates`: Scans Certbot and Let's Encrypt certificates, reporting domains, expiration dates, and alerts for renewals due within 14 days.
  - `list_virtual_hosts`: Parses Nginx virtual host definitions from `/etc/nginx/sites-enabled/` and `conf.d/` (server names, ports, SSL, and reverse proxy targets).
- **Security Auditing & Intrusion Detection (`src/security.py`)**:
  - `check_failed_logins`: Audits SSH failure events from journal logs to identify brute-force attackers and recurring malicious IP addresses.
  - `get_fail2ban_status`: Queries Fail2ban jail states and active banned IP registries.
  - `audit_ssh_config`: Evaluates `/etc/ssh/sshd_config` against hardening guidelines (disabling password auth, root login policies, and non-standard ports) with security scoring.
- **MCP Resources & Prompt Templates**:
  - Added MCP Resource `vps://system-overview` for live ambient system telemetry.
  - Added MCP Prompt `triage_server_incident` providing AI agents with a structured runbook for server incident diagnosis.
- Expanded tool inventory from 15 to **21 active MCP tools**.

---

## [0.5.0] - 2026-09-07

### Added
- **Emergency Recovery & Backup Engine (`src/recover.py`)**:
  - Expanded `execute_recovery` with fine-grained whitelisted action handlers:
    * `restart_service`: Restarts permitted systemd units (`systemctl restart <target>`).
    * `clean_docker_cache`: Deep prune of unused containers, networks, images, and volumes.
    * `clean_system_logs`: Systemd journal log vacuuming (`--vacuum-time=3d`) and rotation cleanup for `/var/log/*.gz`.
    * `kill_process`: Safe termination of runaway processes by PID with core daemon protection (PID 1, sshd, init).
    * `restart_nginx`: Backward-compatible alias for `restart_service` targeting Nginx.
  - `create_backup`: Safe, shell-less `.tar.gz` archive generation of authorized directory trees into `/var/backups/vps-guardian/`.
- Registered `create_backup` in `src/server.py` and updated `execute_recovery` with target parameter support, bringing total tool inventory to **15 active MCP tools**.

---

## [0.4.0] - 2026-09-07

### Added
- **File & Configuration Management Suite (`src/files.py`)**:
  - `view_file_content`: Bounded text extraction for system configuration files in whitelisted administrative paths (`/etc/nginx/`, `/etc/mysql/`, `/etc/postgresql/`, `/etc/docker/`, `/etc/caddy/`, `/var/www/`).
  - `write_file_content`: Atomic configuration file updating via temporary file swap and automated timestamped `.bak.<timestamp>` backup generation.
  - `list_directory`: Safe directory tree exploration up to configurable depth limits inside authorized paths.
  - Security validation preventing directory traversal (`../`), relative path escapes, and unauthorized symlink attacks.
- Registered file tools in `src/server.py` bringing total tool inventory to **14 active MCP tools**.

---

## [0.3.0] - 2026-09-07

### Added
- **Network Security & Port Discovery (`src/network.py`)**:
  - `get_open_ports`: Discovers all open and listening network ports (TCP/UDP, IPv4/IPv6) and resolves bound process names and PIDs using `psutil` and fallback Linux `ss` utility.
  - `get_ufw_status`: Queries Uncomplicated Firewall (UFW) state, default routing/traffic policies, and parsed table of active firewall rules.
- Registered network tools in `src/server.py` bringing total tool inventory to **11 active MCP tools**.
- Added `UPDATES.md` changelog to track development history and feature rollouts.

---

## [0.2.0] - 2026-09-07

### Added
- **Docker Management Suite (`src/docker_manager.py`)**:
  - `list_docker_containers`: Detailed container inspection including container IDs, names, images, statuses, port mappings, and volume/bind-mount paths.
  - `get_docker_container_logs`: Safe extraction of stdout and stderr streams for specific containers with bounded line limits.
  - `get_docker_stats`: Real-time container resource monitoring (CPU percentage, memory usage and limit, network I/O, and block I/O).
- Added comprehensive AI Agent Guidelines to `README.md` enforcing strict reliance on native MCP tool calls over bash simulation.
- Expanded FastMCP server registry from 6 to 9 tools.

---

## [0.1.1] - 2026-09-07

### Added
- **Extended System Observability (`src/monitor.py`)**:
  - Per-core CPU load percentages, Swap memory metrics, Disk I/O counters, Network I/O metrics, and human-formatted uptime.
  - `get_top_processes`: Resource-consuming process rankings sorted by CPU or memory with PID, user, memory RSS, and command line.
  - `check_service_status`: Safe systemd unit health inspection (`systemctl is-active`, `status`).
  - `get_failed_systemd_units`: System-wide discovery of degraded or failed units (`systemctl --failed`).
  - `read_service_logs`: Service log extraction with pure Python keyword filtering (`grep_filter`).

### Fixed
- Pinned `mcp<2.0.0,>=1.0.0` in `pyproject.toml` for FastMCP compatibility.
- Fixed CLI entrypoint path mapping to `src.server:main`.

---

## [0.1.0] - 2026-09-07

### Added
- Initial project MVP release of **VPS-Guardian-MCP**.
- FastMCP server architecture over stdio JSON-RPC.
- Core tools: `get_system_health`, `read_service_logs`, `execute_recovery`.
- Security controls: Strict argument validation regex, `shell=False` execution, and whitelisted recovery commands (`clean_docker_cache`, `restart_nginx`).
- Standard MIT License (2026, murzirius) and `.gitignore`.
