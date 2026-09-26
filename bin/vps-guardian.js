#!/usr/bin/env node

/**
 * VPS-Guardian-MCP: Node.js runner and OpenSSH tunnel proxy for MCP clients.
 *
 * Enables running VPS-Guardian-MCP directly via `npx -y vps-guardian-mcp` across
 * Google Antigravity 2.0, Claude Code, Cursor IDE, OpenAI Codex, and Windsurf.
 */

const { spawn } = require("child_process");
const path = require("path");
const net = require("net");

function printHelp() {
  process.stderr.write(`
VPS-Guardian-MCP Runner (npx wrapper)

USAGE:
  npx -y @murzirius/vps-guardian-mcp --host <IP_OR_HOSTNAME> [OPTIONS]
  npx -y @murzirius/vps-guardian-mcp [user@]<host> [OPTIONS]

OPTIONS:
  -H, --host <host>          VPS IP address or hostname (Required)
  -u, --user <username>      SSH user (Default: root)
  -i, --key <identity_file>  Path to private SSH key (e.g. ~/.ssh/id_ed25519)
  -p, --port <port>          SSH port (Default: 22)
  --known-hosts <path>       Known-hosts file to verify the VPS host key
  --accept-new-host-key      Accept a new host key once (bootstrap only; less secure)
  --remote-path <path>       Path to binary on VPS (Default: /opt/vps-guardian-mcp/.venv/bin/vps-guardian-mcp)
  --mode <mode>              Safety mode: read-only, controlled, unrestricted (Default: read-only)
  --tool-profile <profile>   Tool catalog: core or full (Default: full)
  -h, --help                 Show this help message
  -v, --version              Show version

EXAMPLES:
  # In MCP configuration (Cursor, Claude Code, Antigravity):
  {
    "mcpServers": {
      "vps-guardian": {
        "command": "npx",
        "args": ["-y", "@murzirius/vps-guardian-mcp", "--host", "<VPS_IP_OR_HOSTNAME>", "--mode", "controlled", "--tool-profile", "core", "-i", "~/.ssh/id_ed25519"]
      }
    }
  }

  # In Claude Code CLI:
  claude mcp add vps-guardian -- npx -y @murzirius/vps-guardian-mcp --host <VPS_IP_OR_HOSTNAME> --mode controlled --tool-profile core -i ~/.ssh/id_ed25519
\n`);
}

function parseArgs(args = process.argv.slice(2)) {
  let host = "";
  let user = "root";
  let key = "";
  let port = 22;
  let knownHosts = "";
  let acceptNewHostKey = false;
  let remotePath = "/opt/vps-guardian-mcp/.venv/bin/vps-guardian-mcp";
  let mode = "read-only";
  let toolProfile = "full";

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === "-h" || arg === "--help") {
      printHelp();
      process.exit(0);
    }

    if (arg === "-v" || arg === "--version") {
      try {
        const pkg = require("../package.json");
        process.stderr.write(`vps-guardian-mcp v${pkg.version}\n`);
      } catch {
        process.stderr.write("vps-guardian-mcp v0.25.1\n");
      }
      process.exit(0);
    }

    if ((arg === "-H" || arg === "--host") && i + 1 < args.length) {
      host = args[++i];
    } else if ((arg === "-u" || arg === "--user") && i + 1 < args.length) {
      user = args[++i];
    } else if ((arg === "-i" || arg === "--key" || arg === "--identity") && i + 1 < args.length) {
      key = args[++i];
    } else if ((arg === "-p" || arg === "--port") && i + 1 < args.length) {
      const value = args[++i];
      if (!/^[0-9]+$/.test(value)) throw new Error("--port must be an integer from 1 to 65535.");
      port = Number(value);
    } else if (arg === "--known-hosts" && i + 1 < args.length) {
      knownHosts = args[++i];
    } else if (arg === "--accept-new-host-key") {
      acceptNewHostKey = true;
    } else if (arg === "--remote-path" && i + 1 < args.length) {
      remotePath = args[++i];
    } else if (arg === "--mode" && i + 1 < args.length) {
      mode = args[++i].toLowerCase();
    } else if (arg === "--tool-profile" && i + 1 < args.length) {
      toolProfile = args[++i].toLowerCase();
    } else if (!arg.startsWith("-") && !host) {
      // Positional host argument: root@1.2.3.4 or 1.2.3.4
      if (arg.includes("@")) {
        const parts = arg.split("@");
        user = parts[0];
        host = parts[1];
      } else {
        host = arg;
      }
    } else {
      throw new Error(`Unknown argument or missing value: ${arg}`);
    }
  }

  const validModes = new Set(["read-only", "controlled", "unrestricted"]);
  if (!validModes.has(mode)) {
    throw new Error(`Invalid --mode '${mode}'.`);
  }

  if (!new Set(["core", "full"]).has(toolProfile)) {
    throw new Error(`Invalid --tool-profile '${toolProfile}'.`);
  }

  const plainHost = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (!host || host.length > 253 || (!net.isIP(plainHost) && !/^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(host))) {
    throw new Error("--host must be an IP address or a hostname without shell characters.");
  }
  if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(user)) throw new Error("Invalid SSH username.");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("--port must be an integer from 1 to 65535.");
  if (!remotePath.startsWith("/") || remotePath.length > 1024 || /[\x00-\x1f\x7f]/.test(remotePath)) {
    throw new Error("--remote-path must be an absolute POSIX path without control characters.");
  }

  return { host, user, key, port, knownHosts, acceptNewHostKey, remotePath, mode, toolProfile };
}

function shellQuote(value) {
  return "'" + value.replace(/'/g, "'\\''") + "'";
}

function main() {
  const { host, user, key, port, knownHosts, acceptNewHostKey, remotePath, mode, toolProfile } = parseArgs();

  if (!host) {
    process.stderr.write("Error: Missing required argument '--host <IP>'.\n");
    printHelp();
    process.exit(1);
  }

  const sshArgs = [
    "-q",
    "-o", "LogLevel=ERROR",
    "-o", `StrictHostKeyChecking=${acceptNewHostKey ? "accept-new" : "yes"}`,
    "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=4",
    "-o", "TCPKeepAlive=yes",
    "-o", "ConnectTimeout=10",
  ];

  if (key) {
    // Resolve ~ if used on Windows / POSIX
    let expandedKey = key;
    if (expandedKey.startsWith("~")) {
      const home = process.env.HOME || process.env.USERPROFILE || "";
      expandedKey = path.join(home, expandedKey.slice(1));
    }
    sshArgs.push("-i", expandedKey);
  }

  if (knownHosts) {
    let expandedKnownHosts = knownHosts;
    if (expandedKnownHosts.startsWith("~")) {
      const home = process.env.HOME || process.env.USERPROFILE || "";
      expandedKnownHosts = path.join(home, expandedKnownHosts.slice(1));
    }
    sshArgs.push("-o", `UserKnownHostsFile=${expandedKnownHosts}`);
  }

  if (port && port !== 22) {
    sshArgs.push("-p", String(port));
  }

  sshArgs.push(`${user}@${host}`);
  // OpenSSH joins the remote command into shell text, even though local spawn
  // uses an argv array. Quote the executable rather than trusting that array.
  sshArgs.push(`env VPS_GUARDIAN_MODE=${mode} VPS_GUARDIAN_TOOL_PROFILE=${toolProfile} ${shellQuote(remotePath)}`);

  // Spawn SSH with direct stdio inheritance for seamless JSON-RPC MCP streaming
  const child = spawn("ssh", sshArgs, {
    stdio: ["inherit", "inherit", "inherit"],
    windowsHide: true,
  });

  child.on("error", (err) => {
    process.stderr.write(`[vps-guardian-mcp] Failed to launch SSH process: ${err.message}\n`);
    process.exit(1);
  });

  child.on("exit", (code, signal) => {
    if (signal) {
      process.exit(128 + 15);
    }
    process.exit(code ?? 0);
  });

  process.on("SIGINT", () => {
    if (child && !child.killed) child.kill("SIGINT");
  });

  process.on("SIGTERM", () => {
    if (child && !child.killed) child.kill("SIGTERM");
  });
}

module.exports = { parseArgs, shellQuote, main };
if (require.main === module) {
  try { main(); }
  catch (error) {
    process.stderr.write(`[vps-guardian-mcp] ${error.message}\n`);
    process.exitCode = 1;
  }
}
