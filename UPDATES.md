# Changelog & Project Updates

All notable updates and enhancements to **VPS-Guardian-MCP** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.10.0] - 2026-09-11

### Added
- **Server-Enforced Safety Gate (`src/safety.py`)**:
  - Added `read-only` (default), `controlled`, and `unrestricted` execution modes.
  - Added short-lived, single-use confirmation tokens bound to the exact tool and parameters.
  - Protected file writes, Docker lifecycle/prune actions, recovery operations, and backup creation.
  - Added redacted JSONL audit logging plus `get_safety_status` and `get_audit_events` tools.
- **Unified Incident Report (`src/incident.py`)**:
  - Added `generate_incident_report`, combining system pressure, failed units, Docker health,
    OOM and kernel events, database status, updates, SSH posture, and optional open ports.
  - Findings are ordered by `critical`, `warning`, and `info` severity.
- **Continuous Integration**:
  - Added GitHub Actions coverage for Python 3.10 through 3.14.
  - Added syntax/undefined-name linting, dependency checks, coverage reporting, and metadata tests.
- Total tool inventory increased from 37 to **40 active MCP tools**.

### Changed
- State-changing operations now default to disabled. Set `VPS_GUARDIAN_MODE=controlled`
  to enable the recommended two-step confirmation flow.
- Synchronized Python, npm, documentation, and runner versions at `0.10.0`.

### Fixed
- Added the missing `tempfile` import used by the Windows/fallback backup destination.

---

## [0.9.0] - 2026-09-10

### Added
- **Docker Lifecycle Management & Storage Reclamation (`src/docker_manager.py`)**:
  - `docker_container_action`: Safely executes container lifecycle operations (`start`, `stop`, `restart`, `pause`, `unpause`) with strict input sanitation (`CONTAINER_NAME_REGEX`) and configurable shutdown grace timeouts.
  - `inspect_docker_container`: Detailed architectural introspection of any container, returning network addresses, port mappings, mounted volumes/binds, healthcheck history, restart policies, resource limits, and environment variables with automated masking of sensitive credentials.
  - `clean_docker_garbage`: Reclaims disk space by safely pruning dangling images, stopped containers, unused volumes, and orphan networks (`prune_type`: `'containers'`, `'images'`, `'volumes'`, `'networks'`, `'all'`).
  - Added MCP Resource `vps://docker-overview`: Continuous live summary of Docker daemon status, container inventories, health metrics, and disk reclamation opportunities.
- **Deep Process Profiling & Linux Kernel Limits (`src/proc_deep.py`)**:
  - `get_process_details`: Exhaustive runtime profiling of a specific PID including parent/children hierarchy, CPU percentage, user/system times, thread counts, RSS/VMS/shared memory maps, open file descriptor counts (`num_fds`), open files sample, active network sockets (`local -> remote`, `LISTEN`/`ESTABLISHED`), I/O counters, and sanitized environment variables.
  - `detect_zombie_processes`: Scans the system process table for defunct/zombie processes, identifies their non-reaping parent processes (PPID, command line, status), and provides diagnostic instructions for resolving uncollected child processes.
  - `check_system_limits`: Audits system-wide file descriptor allocations (`/proc/sys/fs/file-nr` vs `fs.file-max`) and process NOFILE limits, process/thread capacity (`/proc/sys/kernel/pid_max` and NPROC), virtual memory parameters (`vm.swappiness`, `vm.vfs_cache_pressure`, `vm.max_map_count`), and socket backlog limits (`somaxconn`, `tcp_max_syn_backlog`), flagging warnings when utilization exceeds 80%.
- **Test Suite**:
  - Added test suites in `tests/test_proc_deep.py` and `tests/test_docker_deep.py` compatible with standard `unittest` and `pytest`.
- Total tool inventory increased from 31 to **37 active MCP tools**.

---

## [0.8.1] - 2026-09-08

### Changed & Optimized
- **Ultra-Low CPU Architecture for Process Inspection (`src/monitor.py`)**:
  - Implemented two-pass selective process inspection in `get_top_processes`. Expensive metadata resolution (`cmdline`, `username`, `memory_info`, and `status`) is deferred and resolved exclusively for the top N candidates, reducing `/proc` syscall overhead and CPU spikes by over 85%.
  - Added single-pass instant execution for memory sorting (`sort_by="memory"`), completely bypassing CPU priming loops and sleep delays.
  - Implemented in-memory UID-to-Username caching to eliminate redundant `/etc/passwd` filesystem reads.
  - Optimized CPU percentage sampling interval from 500ms down to 80ms in `get_system_health`, achieving 6x faster telemetry responses with negligible processor load.
- **In-Memory TTL Caching for Expensive System Audits (`src/updates.py`)**:
  - Added 5-minute TTL caching to `check_system_updates` to avoid repetitive `apt list --upgradable` package repository parsing that previously triggered noticeable CPU/IO load.
  - Added 5-minute TTL caching to `check_guardian_updates` to eliminate redundant remote network and git queries.
  - Provided `force_refresh: bool = False` parameter on both tools to enable on-demand fresh audits when required.

---

## [0.8.0] - 2026-09-08

### Added
- **Kernel Diagnostics & OOM Crash Analysis (`src/crash.py`)**:
  - `check_oom_events`: Audits kernel journal for Linux Out-Of-Memory (OOM) Killer invocations, identifying terminated processes, PIDs, and consumed RSS memory.
  - `check_kernel_errors`: Inspects kernel logs for storage I/O errors, filesystem warnings (EXT4/Btrfs), hardware notices, and application segfaults.
- **Outbound Network Connectivity & DNS Benchmarking (`src/net_diag.py`)**:
  - `test_network_connectivity`: 100% pure Python socket benchmarking of DNS resolution latency, TCP handshake time, and TLS handshake latency without shell `ping`.
  - `check_dns_health`: Tests system DNS resolver health, configured nameservers in `/etc/resolv.conf`, and query responsiveness against essential public endpoints.
- **Database & Cache Health Inspector (`src/database.py`)**:
  - `get_database_health`: Non-invasive discovery and health status checks for Redis (pure socket PING/PONG and RSS memory), PostgreSQL (`pg_isready` and Unix sockets), MySQL/MariaDB (`mysqladmin` ping), and SQLite database files.
- **Security Dashboard Resource & Troubleshooting Prompt**:
  - Added MCP Resource `vps://security-dashboard` aggregating firewall rules, Fail2ban jails, failed SSH authentications, and open listening ports.
  - Added MCP Prompt `troubleshoot_application_crash`: Step-by-step diagnostic runbook for investigating mystery container, daemon, and OOM terminations.
- Expanded total tool inventory from 26 to **31 active MCP tools**.

---

## [0.7.0] - 2026-09-08

### Added
- **Storage & Disk Usage Diagnostics (`src/storage.py`)**:
  - `analyze_disk_usage`: Bounded, recursive directory scan identifying largest disk space consumers and runaway files without shell commands or pseudo-filesystem traversals (`/proc`, `/sys`, `/dev`, `/run`).
- **Scheduler & Automation Inspection (`src/scheduler.py`)**:
  - `list_cron_jobs`: Audits `/etc/crontab`, `/etc/cron.d/*`, periodic cron scripts (`cron.daily`, `cron.hourly`, etc.), and user crontabs, returning human-friendly schedule explanations.
  - `list_systemd_timers`: Audits active and pending systemd timers (`systemctl list-timers`), reporting countdowns, trigger frequencies, and activated units.
- **Operating System & Server Updates (`src/updates.py`)**:
  - `check_system_updates`: Audits available APT packages, flags security CVE patches, and checks kernel restart requirements (`/var/run/reboot-required`). Generates prominent warnings for AI agents.
  - `check_guardian_updates`: Queries remote GitHub repository to verify VPS-Guardian-MCP version currency and generates actionable self-update instructions.
- **Enhanced Emergency Recovery Actions (`src/recover.py`)**:
  - Added `vacuum_systemd_journal`: Safely prunes systemd journal logs to a target size limit (default: 200M).
  - Added `clean_package_cache`: Cleans APT archive caches and removes obsolete packages (`apt-get clean && apt-get autoremove`).
  - Added `apply_security_updates`: Non-interactively applies pending operating system security patches.
  - Added `update_guardian`: Self-updates VPS-Guardian-MCP from GitHub and refreshes the virtual environment.
- **Ambient Awareness & Diagnostic Prompts**:
  - Enhanced MCP Resource `vps://system-overview` to continuously inject update alerts and kernel reboot flags into the AI agent's ambient context.
  - Added MCP Prompt `emergency_disk_cleanup`: Guided runbook for diagnosing and relieving >90% disk space saturation.
  - Added MCP Prompt `security_and_update_audit`: Comprehensive hardening routine auditing CVEs, SSH configuration, firewall rules, and intrusion logs.
- Expanded total tool inventory from 21 to **26 active MCP tools**.

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
