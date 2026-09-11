#!/usr/bin/env node

/**
 * VPS-Guardian-MCP: Node.js runner and OpenSSH tunnel proxy for MCP clients.
 *
 * Enables running VPS-Guardian-MCP directly via `npx -y vps-guardian-mcp` across
 * Google Antigravity 2.0, Claude Code, Cursor IDE, OpenAI Codex, and Windsurf.
 */

const { spawn } = require("child_process");
const path = require("path");

function printHelp() {
  process.stderr.write(`
VPS-Guardian-MCP Runner (npx wrapper)

USAGE:
  npx -y vps-guardian-mcp --host <IP_OR_HOSTNAME> [OPTIONS]
  npx -y vps-guardian-mcp [user@]<host> [OPTIONS]

OPTIONS:
  -H, --host <host>          VPS IP address or hostname (Required)
  -u, --user <username>      SSH user (Default: root)
  -i, --key <identity_file>  Path to private SSH key (e.g. ~/.ssh/id_ed25519)
  -p, --port <port>          SSH port (Default: 22)
  --remote-path <path>       Path to binary on VPS (Default: /opt/vps-guardian-mcp/.venv/bin/vps-guardian-mcp)
  --mode <mode>              Safety mode: read-only, controlled, unrestricted (Default: read-only)
  -h, --help                 Show this help message
  -v, --version              Show version

EXAMPLES:
  # In MCP configuration (Cursor, Claude Code, Antigravity):
  {
    "mcpServers": {
      "vps-guardian": {
        "command": "npx",
        "args": ["-y", "vps-guardian-mcp", "--host", "65.75.200.108", "--mode", "controlled", "-i", "~/.ssh/id_ed25519"]
      }
    }
  }

  # In Claude Code CLI:
  claude mcp add vps-guardian -- npx -y vps-guardian-mcp --host 65.75.200.108 --mode controlled -i ~/.ssh/id_ed25519
\n`);
}

function parseArgs() {
  const args = process.argv.slice(2);
  let host = "";
  let user = "root";
  let key = "";
  let port = 22;
  let remotePath = "/opt/vps-guardian-mcp/.venv/bin/vps-guardian-mcp";
  let mode = "read-only";

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
        process.stderr.write("vps-guardian-mcp v0.11.0\n");
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
      port = parseInt(args[++i], 10) || 22;
    } else if (arg === "--remote-path" && i + 1 < args.length) {
      remotePath = args[++i];
    } else if (arg === "--mode" && i + 1 < args.length) {
      mode = args[++i].toLowerCase();
    } else if (!arg.startsWith("-") && !host) {
      // Positional host argument: root@1.2.3.4 or 1.2.3.4
      if (arg.includes("@")) {
        const parts = arg.split("@");
        user = parts[0];
        host = parts[1];
      } else {
        host = arg;
      }
    }
  }

  const validModes = new Set(["read-only", "controlled", "unrestricted"]);
  if (!validModes.has(mode)) {
    process.stderr.write(`Error: Invalid --mode '${mode}'.\n`);
    process.exit(1);
  }

  return { host, user, key, port, remotePath, mode };
}

function main() {
  const { host, user, key, port, remotePath, mode } = parseArgs();

  if (!host) {
    process.stderr.write("Error: Missing required argument '--host <IP>'.\n");
    printHelp();
    process.exit(1);
  }

  const sshArgs = [
    "-q",
    "-o", "LogLevel=ERROR",
    "-o", "StrictHostKeyChecking=accept-new",
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

  if (port && port !== 22) {
    sshArgs.push("-p", String(port));
  }

  sshArgs.push(`${user}@${host}`);
  sshArgs.push("env", `VPS_GUARDIAN_MODE=${mode}`, remotePath);

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

main();
