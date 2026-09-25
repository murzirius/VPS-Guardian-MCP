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

### 1. Install the server on the VPS

Run once on the VPS. This installs the published, pinned release:

```bash
sudo mkdir -p /opt/vps-guardian-mcp
sudo chown "$USER" /opt/vps-guardian-mcp
python3 -m venv /opt/vps-guardian-mcp/.venv
/opt/vps-guardian-mcp/.venv/bin/pip install --upgrade pip
/opt/vps-guardian-mcp/.venv/bin/pip install vps-guardian-mcp==0.26.0
```

For development from source instead:

```bash
git clone --branch v0.26.0 https://github.com/murzirius/VPS-Guardian-MCP.git /opt/vps-guardian-mcp
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
| `read-only` | Inspecting or diagnosing | Default. Every mutation is blocked. |
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
        "@murzirius/vps-guardian-mcp@0.26.0",
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
@murzirius/vps-guardian-mcp@0.26.0
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
claude mcp add vps-guardian -- npx -y @murzirius/vps-guardian-mcp@0.26.0 --host <VPS_IP_OR_HOSTNAME> --user root --key ~/.ssh/id_ed25519 --mode controlled --tool-profile core
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

For smaller agent context, `--tool-profile core` exposes the everyday tools (including Agent Jobs); omit the flag or choose `full` for the complete catalogue. The launcher passes this profile to the server over SSH. Both profiles support compact JSON tool results, while new workload and log summaries return short answers by default. The profile takes effect when the MCP connection starts.

For a large project file, ask the agent to use `get_project_symbols`, then `read_project_file_range` around the relevant lines. A single range call returns at most 100 KB and includes a SHA-256 fingerprint. A subsequent `stage_project_line_edit` sends only changed lines and still uses the existing preview, confirmation, conflict check and backup flow. `get_workload_brief`, `summarize_service_logs` and `get_server_event_delta` provide compact operational context without background polling.

**Agent Jobs:** Create a job with 1-8 allowlisted checks, such as `service_status` and `service_logs` for target `bot.service`. Call `advance_agent_job` once per check. The job, bounded results, and progress survive MCP reconnects; `get_agent_job(after_revision=...)` returns only new results, and another authorized MCP client can continue by job ID. On Linux, `advance_agent_job(background=true)` starts just one detached read-only check that can finish after disconnection; it requires at least 512 MB available memory. After checking the exact service, an agent may propose one `restart_service` recovery. `execute_agent_job_recovery` uses the existing read-only/controlled/unrestricted safety mode; in controlled mode review its one-time confirmation and call again with the token. Then call `verify_agent_job_recovery` and record the conclusion. A possibly executed restart is **never retried automatically** after a disconnect. Jobs do not run an AI model, always-on worker, arbitrary shell commands, or automatic rollback on the VPS; a service restart cannot be undone. Existing reversible change tools retain their own backup and rollback rules.

**Test Capsules:** After `begin_project_patch` and `stage_project_line_edit` (or `stage_project_file_change`), call `get_test_capsule_status`, then `test_project_patch(patch_id, check="auto")`. In `controlled` mode, confirm this code-executing check with its own one-time token. `auto` syntax-checks staged Python or JavaScript files; `python_unittest` and `npm_test` explicitly run project tests. If it passes, call `preview_project_patch` to inspect the diff and obtain the *separate* apply confirmation, then `promote_tested_project_patch` with that token. A failed or edited candidate cannot be promoted through this tool. The existing `apply_project_patch` remains available for projects without Docker and does not claim a capsule test.

Capsules require a **local Linux Docker daemon**, an already-downloaded image (`python:3.12-alpine` or `node:20-alpine` by default) and at least 384 MiB available RAM. An operator may choose an already-local image with project dependencies via `VPS_GUARDIAN_CAPSULE_PYTHON_IMAGE` or `VPS_GUARDIAN_CAPSULE_NODE_IMAGE`. Guardian never pulls images or installs dependencies automatically. It copies at most 250 files / 8 MiB, omits common credential files and dependency directories, and allows one check at a time for 30 seconds. The container gets no network, host environment or live-project mount; CPU, RAM, processes and temporary storage are capped. Tests needing network, writable source files or missing dependencies will fail. **Source files may still contain hard-coded secrets**, so remove those before testing; Docker isolation reduces risk but is not a guarantee against malicious code or kernel vulnerabilities.

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
- `controlled` mode uses parameter-bound, single-use confirmation tokens.
- Secret values are redacted from file reads, sessions, audit data and diagnostic output.
- Reads, logs, directory scans and stored state are bounded for small VPSs.

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
