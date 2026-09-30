# VPS Guardian MCP

[![CI](https://github.com/murzirius/VPS-Guardian-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/murzirius/VPS-Guardian-MCP/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@murzirius/vps-guardian-mcp?label=npm)](https://www.npmjs.com/package/@murzirius/vps-guardian-mcp)
[![PyPI](https://img.shields.io/pypi/v/vps-guardian-mcp?label=PyPI)](https://pypi.org/project/vps-guardian-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

VPS Guardian is a secure [Model Context Protocol](https://modelcontextprotocol.io/) server for AI agents that work with Linux VPSs. It replaces an unrestricted “run this command and paste the result” loop with named, structured and safety-checked operations.

An agent can inspect a workload, collect bounded diagnostics, preview the impact of a change, and request an exact confirmation for a mutation. The server never exposes a general-purpose shell tool.

**Explore the project:** [capabilities](https://thomas-studios.com/projects/vps-guardian-mcp#capabilities) · [agent workflows](https://thomas-studios.com/projects/vps-guardian-mcp#agent-workflows) · [security model](https://thomas-studios.com/projects/vps-guardian-mcp#security) · [tool catalogue](https://thomas-studios.com/projects/vps-guardian-mcp#tools) · [release notes](UPDATES.md)

<!-- mcp-name: io.github.murzirius/vps-guardian-mcp -->

## Quick start

VPS Guardian has two parts:

- The Python MCP server runs on the VPS.
- The small npm launcher runs on the computer where Codex, Claude, Cursor or another AI client is installed. It opens an SSH stdio connection and never uploads the private key.

### What you need

- A Linux VPS reachable via SSH.
- An SSH key for that VPS.
- Python 3.10+ on the VPS and Node.js 16+ on the AI client's computer.
- A verified SSH host key. Password-based SSH is intentionally unsupported by the launcher.

### Optional: local MCP access panel

The English-language panel runs **on your computer, not on the VPS or this project's website**. Its main screen manages agent permissions: pause/resume MCP calls, cap the safety mode, allow individual tools and set project roots. A collapsed server overview provides optional read-only monitoring. The npm package remains the MCP launcher; the panel comes with the Python package.

With [uv](https://docs.astral.sh/uv/) installed on your computer:

```bash
uvx --from vps-guardian-mcp==0.33.0 vps-guardian-panel
```

Without uv, install in a local virtual environment. Windows PowerShell:

```powershell
py -m venv .guardian-panel
.\.guardian-panel\Scripts\python.exe -m pip install vps-guardian-mcp==0.33.0
.\.guardian-panel\Scripts\python.exe -m src.local_panel
```

Linux/macOS:

```bash
python3 -m venv .guardian-panel
.guardian-panel/bin/pip install vps-guardian-mcp==0.33.0
.guardian-panel/bin/vps-guardian-panel
```

The browser opens automatically. Enter the VPS address, SSH user, port and **path** to your local key, not its contents. Leave the key field empty to use ssh-agent; load encrypted keys into the agent beforehand. Advanced settings accept the Guardian executable path on the VPS and an optional local known_hosts file. Access management requires Guardian **0.30.0+ on the VPS**; Projects and Limits require **0.31.0+**, Operations requires **0.32.0+**, with the adjacent `vps-guardian-access` executable from the same installation. Older compatible installations can show monitoring only, with an upgrade warning. No server-side web service is installed.

To upgrade an existing pip installation on the VPS:

```bash
/opt/vps-guardian-mcp/.venv/bin/pip install --upgrade vps-guardian-mcp==0.33.0
```

Upgrade any other Guardian environments used by your agents, then reconnect **all agents once** so they start the policy-aware server. Subsequent permission changes affect new calls in those sessions without a restart. In-flight operations are not cancelled, and cached client tool lists may still show disabled tools; calls to those tools are rejected.

Use **Apply permissions** to save a shared per-SSH-user policy on the VPS at `~/.local/share/vps-guardian-access/policy.json`. Connection settings stay in local RAM, but the access policy persists across panel/server restarts. **Reload policy** fetches the current server values; concurrent edits are rejected rather than overwriting another operator's changes. No policy means the existing launch settings remain in force. Invalid or unsafe stored policies fail closed and pause normal MCP access; `get_safety_status` remains available for recovery. Unsafe file ownership, permissions or symlinks require manual repair by the operator.

- **Allow agent access:** pause/resume normal MCP tool and resource entry points. The separate operator helper remains reachable over SSH so you can restore access.
- **Maximum safety mode:** the effective mode is the stricter of the agent's launch mode and this cap. Setting `controlled` cannot elevate a client launched as `read-only`. Confirmation tokens are the existing same-caller mechanism, **not independent human approval**.
- **Allowed tools:** allow all installed/future tools, or uncheck that option and choose an explicit allowlist. New tools are denied by default in an explicit allowlist. `get_safety_status` cannot be disabled. Read-only mode can still create bookkeeping records; use tool permissions when you also need to block those entry points.
- **Project roots:** inherit each process's `VPS_GUARDIAN_PROJECT_ROOTS`, or replace it with up to 16 absolute VPS directory paths, one per line. An empty custom list blocks project workspaces. Filesystem roots and symlink roots are rejected. This controls project tools, not the separate fixed configuration-file directory whitelist.

The operator helper is **not registered as an ordinary agent tool**. Tools and the three read resources enforce access restrictions on the server. Policies apply to upgraded Guardian processes under the **same SSH user**, not to individually authenticated agent identities. An agent with independent root SSH access, the same account's shell, or permission to change Guardian's code can bypass this MCP boundary. For stronger separation use a restricted dedicated OS account; do not treat the panel as a sandbox or independent approval service.

#### Agent Gateway (opt-in, Linux)

The **Gateway** section creates a distinct, password-locked Unix account and accepts only that agent's **Ed25519 public key**. The root-owned `authorized_keys` file forces `vps-guardian-gateway serve <agent-id>` and disables SSH forwarding and PTY access for that key. Guardian checks a root-owned policy under `/etc/vps-guardian/gateway/` on every tool call, including expiration and revocation. The panel runs locally as before; Gateway adds **no web listener or always-on daemon** on the VPS.

Use **Guardian 0.33.0+ on both devices**, with a separate **administrator SSH account** capable of running the operator helper as root. The VPS package and its Python interpreter must be root-owned, protected against group/other writes and readable/executable by the new accounts. A venv under `/root` will not work: use a protected installation such as `/opt/vps-guardian-mcp/.venv`. Open **Gateway**, enter a short agent name, paste its `.pub` key, choose existing project directories, a duration (1–168 hours) and one of two presets:

- **Observer:** read-only diagnostics and project reading.
- **Project editor:** project search, staged patch/check/apply tools in `controlled` mode. The agent can modify only files the dedicated Unix account can modify. Controlled-mode tokens are generated in that same agent session; **they are not independent human approval**.

After creation, configure that agent's MCP client with the returned `vg_<name>` SSH username and its **own private key**, using the normal npm launcher. The client-supplied remote command and `--mode` cannot override the SSH forced command or the root-owned cap. Keep your administrator key out of the agent's environment. Project roots and tool allowlists narrow the MCP surface, but Linux file permissions are the hard boundary: grant the dedicated account only the required file permissions, never sudo, broad privileged groups or access to the Docker socket. Check that the selected directories are actually readable/writable by the account; Gateway does not change project ownership or ACLs.

For example, an enrolled `deploy-bot` uses `--user vg_deploy_bot --key <AGENT_PRIVATE_KEY>` alongside the normal `--host` option. Only the preset's 6 or 14 tools are advertised at connection time; their permissions are rechecked live. At most 32 accounts can be enrolled, including expired/revoked records; this initial release has no automatic deletion or reactivation. Gateway accounts have **separate** Access/Limits/history/state from the administrator account. The root user's Access pause/roots/limits do not automatically apply to them; use Gateway revocation for a Gateway agent. Private account-local audit files are not a tamper-proof central audit log.

**SSH compatibility:** the server must permit public-key login for locked accounts (normally `UsePAM yes` on Debian/Ubuntu) and use the account's `.ssh/authorized_keys`. Custom `AllowUsers`, `DenyUsers`, `AuthorizedKeysCommand`, trusted SSH CAs or `ForceCommand` settings can block or override this setup; an administrator must review them. Do not add alternative unrestricted keys/certificates for these accounts. Gateway does not rewrite or restart sshd.

**Revoke** immediately blocks new normal MCP calls and removes that account's key for new SSH logins. It does not cancel an already-running operation or delete the Unix account and its private work/history; inspect those separately if needed. Expiration similarly denies later tool calls and future Gateway starts. `get_safety_status` remains available for recovery metadata. If an agent also possesses another independent SSH credential, Gateway cannot constrain that credential. This initial Gateway does **not** include independent human approvals, a public HTTP endpoint or general shell access.

#### Projects and live Limits

The **Access**, **Projects** and **Limits** sections require the current Python package on your computer. Projects and Limits additionally require **Guardian 0.31.0+ on the VPS**. A 0.30.0 server can still manage Access, but cannot enforce these new limits. Upgrade every server environment used by your agents and reconnect once; changing saved limits afterwards does not require another restart.

In **Projects**, click **Find projects** for a bounded metadata scan inside the current roots (at most 1,000 entries, 100 directories, 50 projects and a cooperative two-second deadline). Select a project or enter an absolute VPS path and click **Inspect metadata**. The panel shows top-level file/directory metadata, OS readability and policy decisions for common project tools, without reading source, invoking Git or executing project code. Links and sensitive/hidden names are excluded. Missing projects can be outside the roots, lack recognized markers or exceed the scan budget. When roots are inherited, the helper's launch defaults may differ from an agent's environment; use explicit managed roots for a shared boundary.

**Use as the only project root** only prepares a draft in Access. Review and click **Apply permissions** to replace the current roots with that single project. Browsing alone never grants or changes agent access. Policy allowance is not a guarantee that an agent's launch mode, roots or OS permissions permit an operation.

In **Limits**, choose **Auto**, **Small VPS**, **Standard** or **Custom**, then **Apply limits**. Values persist in the same private operator directory as `limits.json`, separately from `policy.json`. Revision checks reject concurrent edits. Auto and Standard currently request the same normal budgets; both retain automatic host guards. Small VPS requests smaller reads/searches, one-file patches and no Test Capsules. Custom accepts only the displayed integer ranges; it cannot disable guards or exceed hard ceilings. **Reload live limits** fetches a fresh server snapshot; it asks before discarding a local draft.

The table distinguishes **Requested** values from **Effective on VPS** values. Orange effective values have been reduced by host protection. The applied settings, not an unsaved draft, determine effective limits. Available memory below 512 MiB or one logical CPU reduces several budgets; below 384 MiB capsules are disabled; below 256 MiB additional critical-load restrictions apply. These are cooperative per-operation budgets, **not a global CPU/RAM quota or OS sandbox**. They do not cancel already running work. Every upgraded process under the same SSH user reads shared settings for subsequent operations. Invalid/unsafe limits use conservative Small VPS defaults and show an error; unsafe ownership/permissions or links may need manual repair.

Editable budgets cover project-file reads (up to 300,000 bytes when host guards permit), MCP tool/resource JSON, HTTP diagnostic bodies, directory entries, journal lines, code-search file/input budgets, project-patch file/staged-text budgets, configuration ChangeSet file/text budgets, Agent Job check concurrency (0 disables checks) and Test Capsules (0 disables, 1 permits). Existing stricter operation-specific bounds still apply. Capsule RAM/CPU/timeout/output bounds remain fixed, not editable. Resource response limits apply to each JSON document; MCP transport encoding and text/structured duplication add overhead. Large fields are omitted with `response_truncated` and `omitted_fields`, retaining small status/IDs/tokens where possible. **A mutation has already returned: do not repeat it just to obtain omitted output.** Request a narrower read or status instead.

Cached project patches recheck current roots and resource limits before preview, staging, testing and applying. A revoked or over-budget candidate must be replaced with an allowed, smaller patch. Configuration ChangeSets also recheck live limits before applying.

#### Shared Operations and reconnects

**Operations** requires Guardian **0.32.1+ on the VPS and on your computer**. The English panel shows the latest 25 project patches/ChangeSets and up to 25 Agent Jobs, with search, state filters, file fingerprints and a bounded event timeline. Click a record to inspect metadata. Refresh is manual or every 30 seconds while the tab is open; it uses the separate short-lived operator helper, including while agent access is paused. This view **does not execute, approve, cancel or retry changes**. There is no additional always-on VPS worker.

Agents use `list_operations(limit=10)` and `get_operation(operation_id="...")` to retrieve the same metadata. `next_before` is an opaque cursor for older draft/history pages; pass it back as `before`. Job lists are separately bounded latest snapshots, not part of that cursor. Normal MCP tool permissions still apply; the human operator's helper is separate. History is per SSH user, not per individual agent or current project root: everyone granted these history tools under that account can see operation metadata.

Staged project patches and configuration ChangeSets now persist in private SQLite storage at `~/.local/share/vps-guardian-access/operations/`. A draft survives MCP/panel reconnects for **24 hours**, with the existing 24-patch/32-ChangeSet active caps. Active drafts are never silently evicted; storage-full errors require completing an allowed draft or waiting for expiry. Payloads are bounded to 9 MB each and 32 MB total; the SQLite database is capped at 48 MiB. Completed/expired source payloads are removed and their metadata retained for at most **30 days / 200 records**. Retention is enforced on requests, not by a background cleanup daemon. Active candidate/original source can contain secrets: files use private permissions, **not encryption**, and must be protected with the SSH account and disk backups. Panel/history replies never include source, raw command output or confirmation tokens. Secret redaction is best-effort; avoid secrets in titles and paths.

After reconnecting, preview the same staged ID again to obtain a **new session-local confirmation token**, then apply with the existing tool. Current mode, roots, budgets and live-file fingerprints are rechecked; persistence does not grant access or approve a write. A claimed apply/check has a 120-second lease. If it outlives that lease without a stored outcome, history marks it **uncertain**, drops the candidate and never replays it. Inspect live files/services before preparing a replacement. This history is not a transactional filesystem journal or an automatic rollback guarantee.

New Agent Jobs use the same fixed private operation directory, independently of `VPS_GUARDIAN_STATE_DIR`; their existing leases, job TTL and 100-record cap remain. Their database is capped at 8 MiB. **Upgrade note:** previous releases kept jobs in the old state directory and drafts only in RAM. Old job databases remain untouched and are not automatically imported into shared storage; finish important old jobs before upgrading. Old in-memory drafts cannot be recovered after the old process exits. Upgrade all server environments used by agents and reconnect once.

SSH host-key verification is mandatory. Verify the fingerprint independently and connect once with ordinary SSH before using the panel. The dashboard does not accept unknown keys or use custom SSH config/aliases, ProxyCommand or jump hosts: enter a directly reachable IP/hostname. A changed host key must be investigated, not bypassed.

Connection settings and snapshots stay in memory; the panel never uploads or reads private-key contents. One MCP connection samples metrics every 30 seconds; manual refresh is limited to once per 10 seconds. Unavailable metrics are shown as unavailable, not zero. No failed systemd units is **not** a guarantee all applications are healthy. If the connection fails, retained metrics are marked stale.

Keep the printed local link private: its fragment is a per-launch **operator** access token. The token stays in tab memory and is removed from the address bar; after reloading, reopen the full printed link. `Ctrl+C` in the launch terminal stops the panel and its connection. `--no-browser` only prints the link; `--port 8765` selects a loopback port. Do not reverse-proxy or expose the panel publicly. Loopback/token checks do not protect against malware running as your local user.

### 1. Install the server on the VPS

Run once on the VPS. This installs the published, pinned release:

```bash
sudo mkdir -p /opt/vps-guardian-mcp
sudo chown "$USER" /opt/vps-guardian-mcp
python3 -m venv /opt/vps-guardian-mcp/.venv
/opt/vps-guardian-mcp/.venv/bin/pip install --upgrade pip
/opt/vps-guardian-mcp/.venv/bin/pip install vps-guardian-mcp==0.33.0
```

For development from source instead:

```bash
git clone --branch v0.31.0 https://github.com/murzirius/VPS-Guardian-MCP.git /opt/vps-guardian-mcp
cd /opt/vps-guardian-mcp
python3 -m venv .venv
.venv/bin/pip install -e .
```

If the server runs as a non-root user, grant only the required read access. Docker and journal features gracefully report as unavailable when that access is absent.

```bash
sudo usermod -aG docker <MCP_USER>
sudo usermod -aG systemd-journal <MCP_USER>
```

Log out and back in after changing groups.

### 2. Choose a safety mode

| Mode | Use it when | Result |
| --- | --- | --- |
| `read-only` | Inspecting or diagnosing | Default. Guarded server mutations are blocked; bookkeeping tools may still save records. |
| `controlled` | Assisted administration | Recommended. Each exact change needs a short-lived, single-use confirmation token. |
| `unrestricted` | A separately protected automation environment | Changes run immediately. Avoid on a general-purpose agent. |

Start with `read-only`; use `controlled` once the connection is verified.

### 3. Connect an AI client over SSH

First verify the VPS fingerprint independently and make a normal SSH connection once. That stores the host key in `~/.ssh/known_hosts` (or `%USERPROFILE%\.ssh\known_hosts` on Windows). The launcher requires host-key verification by default.

Use this configuration for JSON-based MCP clients:

```json
{
  "mcpServers": {
    "vps-guardian": {
      "command": "npx",
      "args": [
        "-y",
        "@murzirius/vps-guardian-mcp@0.33.0",
        "--host", "<VPS_IP_OR_HOSTNAME>",
        "--user", "root",
        "--key", "~/.ssh/id_ed25519",
        "--mode", "controlled",
        "--tool-profile", "core"
      ]
    }
  }
}
```

Every item in `args` is a separate argument. Do not join `--host` with its value or paste the entire command into one form field.

### 4. Codex / ChatGPT Desktop

Open **Settings → MCP servers → Add server**, choose **STDIO**, then enter:

| Field | Value |
| --- | --- |
| Name | `vps-guardian` |
| Command | `npx` |
| Environment variables | Leave empty |
| Working directory | Leave empty/default |

Add these arguments as separate rows, in order:

```text
-y
@murzirius/vps-guardian-mcp@0.33.0
--host
<VPS_IP_OR_HOSTNAME>
--user
root
--key
C:\Users\<WindowsUser>\.ssh\id_ed25519
--mode
controlled
--tool-profile
core
```

Save, restart the client, then use `/mcp` to confirm that `vps-guardian` is connected.

### 5. Common situations

**Claude Code**

```bash
claude mcp add vps-guardian -- npx -y @murzirius/vps-guardian-mcp@0.33.0 --host <VPS_IP_OR_HOSTNAME> --user root --key ~/.ssh/id_ed25519 --mode controlled --tool-profile core
```

**A non-root SSH user** — replace `root` after `--user`. Do not add passwordless `sudo` just for the MCP; grant the minimum group permissions needed.

**A non-standard port** — add separate arguments:

```text
--port
2222
```

**A different server location** — add:

```text
--remote-path
/srv/vps-guardian/.venv/bin/vps-guardian-mcp
```

**Host key verification failed** — do not disable verification. Check the VPS fingerprint through a trusted channel and correct `known_hosts`. Use `--known-hosts <path>` for a dedicated file. `--accept-new-host-key` is only for an intentional first-time bootstrap.

### 6. Verify and upgrade

Ask the agent: **“Check CPU and RAM load on my server.”** A correct setup returns structured VPS data rather than a shell command for you to run.

To upgrade the VPS server, install the matching version and restart the client connection:

```bash
/opt/vps-guardian-mcp/.venv/bin/pip install --upgrade vps-guardian-mcp==X.Y.Z
```

Then replace `@0.25.1` with `@X.Y.Z` in the client configuration. For source installations, fetch the tag, inspect local changes, check out the tag, and reinstall with `.venv/bin/pip install -e .`.

## What it can do

VPS Guardian is built around a few workflows instead of a long, unstructured command list:

- **Observe:** system pressure, processes, services, Docker, databases, ports, TLS, logs and updates.
- **Understand a workload:** discover a site or Compose project, map its dependencies and health, then collect focused diagnostic evidence.
- **Coordinate agents:** sessions, handoffs, leased work queues, durable Agent Jobs, runbooks, checkpoints, workload locks, maintenance windows and resumable server-event watches.
- **Change safely:** preview impact, stage configuration changes, validate, back up, health-check and roll back when a deployment fails.
- **Recover deliberately:** create baselines, compare drift, produce repair plans, verify isolated backups and require exact confirmation for changes.
- **Work with code:** read a large file by line range, find Python symbols, stage a line edit, inspect a bounded Git diff and check a staged change in a temporary Docker capsule.
- **Understand an environment:** inspect project venv metadata, compare direct dependencies and npm lock versions, and identify a running systemd service's launch path without executing project code.
- **Navigate Python code:** map local imports, find symbol-use candidates, inspect likely change impact and gather short task context with related test candidates.

For smaller agent context, `--tool-profile core` exposes the everyday tools (including Agent Jobs); omit the flag or choose `full` for the complete catalogue. The launcher passes this profile to the server over SSH. Both profiles support compact JSON tool results, while new workload and log summaries return short answers by default. The profile takes effect when the MCP connection starts.

For a large project file, ask the agent to use `get_project_symbols`, then `read_project_file_range` around the relevant lines. A single range call returns at most 100 KB and includes a SHA-256 fingerprint. A subsequent `stage_project_line_edit` sends only changed lines and still uses the existing preview, confirmation, conflict check and backup flow. `get_workload_brief`, `summarize_service_logs` and `get_server_event_delta` provide compact operational context without background polling.

**Agent Jobs:** Create a job with 1-8 allowlisted checks, such as `service_status` and `service_logs` for target `bot.service`. Call `advance_agent_job` once per check. The job, bounded results, and progress survive MCP reconnects; `get_agent_job(after_revision=...)` returns only new results, and another authorized MCP client can continue by job ID. On Linux, `advance_agent_job(background=true)` starts just one detached read-only check that can finish after disconnection; it requires at least 512 MB available memory. After checking the exact service, an agent may propose one `restart_service` recovery. `execute_agent_job_recovery` uses the existing read-only/controlled/unrestricted safety mode; in controlled mode review its one-time confirmation and call again with the token. Then call `verify_agent_job_recovery` and record the conclusion. A possibly executed restart is **never retried automatically** after a disconnect. Jobs do not run an AI model, always-on worker, arbitrary shell commands, or automatic rollback on the VPS; a service restart cannot be undone. Existing reversible change tools retain their own backup and rollback rules.

**Test Capsules:** After `begin_project_patch` and `stage_project_line_edit` (or `stage_project_file_change`), call `get_test_capsule_status`, then `test_project_patch(patch_id, check="auto")`. In `controlled` mode, confirm this code-executing check with its own one-time token. `auto` syntax-checks staged Python or JavaScript files; `python_unittest` and `npm_test` explicitly run project tests. If it passes, call `preview_project_patch` to inspect the diff and obtain the *separate* apply confirmation, then `promote_tested_project_patch` with that token. A failed or edited candidate cannot be promoted through this tool. The existing `apply_project_patch` remains available for projects without Docker and does not claim a capsule test.

Capsules require a **local Linux Docker daemon**, an already-downloaded image (`python:3.12-alpine` or `node:20-alpine` by default) and at least 384 MiB available RAM. An operator may choose an already-local image with project dependencies via `VPS_GUARDIAN_CAPSULE_PYTHON_IMAGE` or `VPS_GUARDIAN_CAPSULE_NODE_IMAGE`. Guardian never pulls images or installs dependencies automatically. It copies at most 250 files / 8 MiB, omits common credential files and dependency directories, and allows one check at a time for 30 seconds. The container gets no network, host environment or live-project mount; CPU, RAM, processes and temporary storage are capped. Tests needing network, writable source files or missing dependencies will fail. **Source files may still contain hard-coded secrets**, so remove those before testing; Docker isolation reduces risk but is not a guarantee against malicious code or kernel vulnerabilities.

**Environment Doctor:** Ask the agent to call `inspect_project_environment(project_path, service_name="bot.service")`, then `diagnose_project_dependencies` for a focused problem report. It reads `pyvenv.cfg`, Python `.dist-info/METADATA`, static `pyproject.toml`/`requirements.txt` declarations, and direct npm dependencies against a v2/v3 `package-lock.json`. If both `.venv` and `venv` exist, supply an explicit authorized `environment_path`. `include_dev=true` includes npm development dependencies. Reuse `after_fingerprint` to receive only an `unchanged` reply when the relevant report has not changed. A dependency name is a distribution name, not necessarily its Python import name.

`plan_environment_repair` explains the next steps without installing packages or restarting anything. `plan_capsule_environment` prepares bounded direct dependency pins and runtime metadata for a reviewed local Capsule image; **it does not build or download that image, verify its contents, or produce a complete transitive lockfile**. Python versions come from venv metadata; running service evidence is limited to a Linux systemd MainPID. Stopped units, wrappers, containers, system Python without an authorized venv, inherited/legacy/editable packages, dynamic declarations, requirement directives, URLs, extras and unsupported npm locks may need separate review. Metadata is not proof that an import works, and Node runtime/engine compatibility is not probed. Reads are capped at 2 MB per report, 1,000 directory entries and 100 direct declarations per ecosystem; incomplete scans never report a clean result. No project interpreter, installer, npm script, package index or background worker is started.

**Code Navigator:** Start with `get_project_import_map(project_path, relative_path="app/payments.py")`, or use `get_project_task_context(project_path, relative_path="app/payments.py", symbol_name="charge")` to get a definition, short use-site fragments and related test candidates in one bounded answer. `find_project_references` distinguishes import-alias candidates from weaker name-only matches. `assess_project_change` follows reverse imports for up to three hops; test files are selected by import relationships and naming conventions, not measured coverage. For a class method use its exact qualified name, such as `Gateway.refund`; `get_project_symbols` helps choose it. All four tools accept `after_fingerprint` for compact unchanged replies; changing query arguments changes the fingerprint. No scan results are cached, so an unchanged reply saves output tokens but still requires a fresh scan.

No setup is needed beyond configured project roots. Navigator supports UTF-8 Python sources and bounded ASCII symbol names, including relative imports and common `src/` layouts. Snippets are limited to one line; literals (including f-strings/template strings) and comments are masked. File, module and identifier names remain visible; use existing range reads for exact source bodies. This is **not a runtime call graph, complete dependency analysis or proof that tests cover a change**: alias shadowing, ambiguous modules, dynamic imports/reflection, instance types and non-Python/generated sources remain uncertain. Hidden, sensitive and dependency paths are excluded. Unreadable files, unsafe paths, syntax errors and exhausted budgets are reported as partial scans.

Scans are on demand, with no background indexer or disk cache: at most 150 Python files (60 on constrained hosts), 128 KB per file, 2 MB total (750 KB constrained), 1,000 directory entries, eight directory levels and a five-second cooperative scan deadline. AST nodes and extracted facts are capped; files with more than 200 import aliases are skipped. Below 96 MiB available memory, no scan starts. Only one scan per MCP process runs at a time. Separate MCP processes do not share this lock. Reference/import reports return at most 50 entries; task context defaults to 6,000 characters and can be capped between 2,000 and 8,000.

Examples of native MCP tools:

| Request | Example tool | Result |
| --- | --- | --- |
| “Why is the API slow?” | `diagnose_workload` | Bounded health, logs, OOM and kernel evidence. |
| “What will a restart affect?” | `get_change_impact` | A read-only dependency and impact report. |
| “Hand this incident to another agent.” | `handoff_agent_session` | Secret-redacted context and outcome tracking. |
| “Split this audit between agents.” | `create_agent_task` | Prioritized work with dependencies and expiring ownership. |
| “Check this service, then let another agent continue.” | `create_agent_job` | Durable, bounded checks with delta results and gated recovery. |
| “Deploy this Nginx change safely.” | `plan_config_deployment` | Validated diff, backup, confirmation and rollback path. |

See the [complete capability guide](https://thomas-studios.com/projects/vps-guardian-mcp#capabilities) and [full tool catalogue](https://thomas-studios.com/projects/vps-guardian-mcp#tools) on the project site.

## Security model

- No arbitrary command-execution MCP tool.
- Server-side allow-lists for files, paths, services and mutation types.
- `controlled` mode uses parameter-bound, single-use confirmation tokens. This is **not independent human approval**: the caller receives the token and can repeat the operation. Client approval or a separately enforced operator policy is required for that guarantee. An agent with unrestricted SSH access can bypass MCP restrictions.
- Common secret patterns are redacted from file reads, sessions, audit data and diagnostic output. Redaction is best-effort, not a guarantee against every hard-coded credential or sensitive identifier.
- Reads, logs, directory scans and stored state are bounded for small VPSs.

On Linux, hardened project/config reads refuse symlink components and special files. Atomic writes pin the parent directory, refuse unsafe backup paths, use private unique backups and preserve normal ownership/permissions without setuid/setgid bits. Existing private state directories must be owned by the service user with `0700`, state/audit files with `0600`; unsafe paths fail closed rather than being silently chmodded. Audit files stop accepting writes at 4 MiB each (primary/fallback), and reads inspect at most a 256 KiB tail; an operator must archive/reset full logs. The fallback audit filename is scoped to the effective UID. Python syntax checks use bounded source snapshots with an isolated interpreter, skip oversized files and never claim full success for incomplete scans. These protections do not make root execution or a shared SSH key an isolation boundary.


Details: [security model](https://thomas-studios.com/projects/vps-guardian-mcp#security) · [agent operating guide](https://thomas-studios.com/projects/vps-guardian-mcp#agent-workflows)

## Packages and releases

- npm: [`@murzirius/vps-guardian-mcp`](https://www.npmjs.com/package/@murzirius/vps-guardian-mcp)
- PyPI: [`vps-guardian-mcp`](https://pypi.org/project/vps-guardian-mcp/)
- MCP Registry: [`io.github.murzirius/vps-guardian-mcp`](https://registry.modelcontextprotocol.io/)
- GitHub Packages mirrors each npm release; npmjs is recommended for normal installation.

## Development

```bash
python -m unittest discover -s tests -v
npm test
```

Please report security issues privately rather than publishing exploit details in a public issue.

## License

[MIT](LICENSE) © 2026 murzirius.
