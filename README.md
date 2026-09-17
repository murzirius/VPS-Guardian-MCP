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
/opt/vps-guardian-mcp/.venv/bin/pip install vps-guardian-mcp==0.21.0
```

For development from source instead:

```bash
git clone --branch v0.21.0 https://github.com/murzirius/VPS-Guardian-MCP.git /opt/vps-guardian-mcp
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
        "@murzirius/vps-guardian-mcp@0.21.0",
        "--host", "<VPS_IP_OR_HOSTNAME>",
        "--user", "root",
        "--key", "~/.ssh/id_ed25519",
        "--mode", "controlled"
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
@murzirius/vps-guardian-mcp@0.21.0
--host
<VPS_IP_OR_HOSTNAME>
--user
root
--key
C:\Users\<WindowsUser>\.ssh\id_ed25519
--mode
controlled
```

Save, restart the client, then use `/mcp` to confirm that `vps-guardian` is connected.

### 5. Common situations

**Claude Code**

```bash
claude mcp add vps-guardian -- npx -y @murzirius/vps-guardian-mcp@0.21.0 --host <VPS_IP_OR_HOSTNAME> --user root --key ~/.ssh/id_ed25519 --mode controlled
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

Then replace `@0.20.1` with `@X.Y.Z` in the client configuration. For source installations, fetch the tag, inspect local changes, check out the tag, and reinstall with `.venv/bin/pip install -e .`.

## What it can do

VPS Guardian is built around a few workflows instead of a long, unstructured command list:

- **Observe:** system pressure, processes, services, Docker, databases, ports, TLS, logs and updates.
- **Understand a workload:** discover a site or Compose project, map its dependencies and health, then collect focused diagnostic evidence.
- **Coordinate agents:** secret-redacted sessions, handoffs, short-lived workload locks, maintenance windows and resumable server-event watches.
- **Change safely:** preview impact, stage configuration changes, validate, back up, health-check and roll back when a deployment fails.
- **Recover deliberately:** create baselines, compare drift, produce repair plans, verify isolated backups and require exact confirmation for changes.

Examples of native MCP tools:

| Request | Example tool | Result |
| --- | --- | --- |
| “Why is the API slow?” | `diagnose_workload` | Bounded health, logs, OOM and kernel evidence. |
| “What will a restart affect?” | `get_change_impact` | A read-only dependency and impact report. |
| “Hand this incident to another agent.” | `handoff_agent_session` | Secret-redacted context and outcome tracking. |
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
