[中文](README.zh.md) | **English**

---

# Remote Signer

A secure, policy-driven signing service for EVM chains. Controls **what** gets signed through a rule engine, not just **who** can sign.

## Components

| Component | Description |
|-----------|-------------|
| **Server** | Daemon exposing a REST API (`:8548`), with Ed25519 auth, SQLite or PostgreSQL, and a rule engine |
| **CLI** | `remote-signer` binary — unified entrypoint for `server start`, `tui`, `validate`, `api-key`, `evm sign/broadcast/simulate`, rule management |
| **TUI** | Terminal UI (`remote-signer tui`) for interactive monitoring and management |
| **Web UI** | React dashboard served by the daemon at `http://127.0.0.1:8548` |
| **Desktop** | Electron shell (`.dmg`/`.exe`/`.AppImage`) wrapping the daemon + Web UI |
| **Chrome Extension** | EIP-1193 provider injection (`window.ethereum`) for dApp connectivity |
| **MCP Server** | `remote-signer-mcp` (npm) — exposes all operations as MCP tools for AI agents (Claude Code, Cursor, etc.) |
| **JS/TS SDK** | `remote-signer-client` (npm) — full TypeScript client with Ed25519 auth, polling, batch signing |
| **Go SDK** | `pkg/client` — resource-based Go client (`client.EVM.Sign.Execute`, `client.Templates.Get`, etc.) |
| **Rust SDK** | `pkg/rs-client` — native Rust client with Ed25519 authentication |

### Solidity Expression Rules

The `evm_solidity_expression` rule type requires **forge** (Foundry) to compile and evaluate Solidity expressions at sign-time. If forge is unavailable, the server starts without Solidity support, and all Solidity rule operations (create, update, instantiate, preset apply) return HTTP 503.

**Install forge:**

```bash
# Recommended: foundryup (macOS, Linux, WSL)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Homebrew (macOS / Linux)
brew install foundry

# Verify
forge --version
```

The Docker image includes forge automatically via multi-stage build — no host installation needed.

## Quick Start

### One-Command Single-Instance (SQLite, no Docker, no config)

```bash
curl -sSLf -o remote-signer \
  "https://github.com/ivanzzeth/remote-signer/releases/latest/download/remote-signer-$(uname -s | tr A-Z a-z)-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" \
  && chmod +x remote-signer

./remote-signer
```

First launch creates `~/.remote-signer/` with a default config (SQLite, `:8548`, no TLS) and generates an admin Ed25519 keypair. The private key path is printed once to stderr.

### Interactive Setup

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ivanzzeth/remote-signer/main/scripts/setup.sh)
```

### Manual Clone

```bash
git clone https://github.com/ivanzzeth/remote-signer.git && cd remote-signer && ./scripts/setup.sh
```

### Docker (personal, drop-in for native daemon)

```bash
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose -f docker-compose.local.yml up -d
```

Pulls `ghcr.io/ivanzzeth/remote-signer:latest` (multi-arch: `linux/amd64`, `linux/arm64`), bind-mounts your existing `~/.remote-signer` into the container, and adds restart-on-crash. Same SQLite DB, admin keystore, signers, and API keys as the native daemon — switch back and forth without migration.

For production multi-instance behind PostgreSQL, see [`docker-compose.yml`](docker-compose.yml) and [Deployment Guide](docs/deployment.md). For all release-engineering and version conventions, see [GIT.md](GIT.md).

### Desktop app

Each release ships `.dmg` (macOS), `.exe` (Windows), and `.AppImage` (Linux) installers built around an Electron shell that wraps the daemon. Download from the latest [Releases](https://github.com/ivanzzeth/remote-signer/releases) page.

The Electron shell is just a browser window pointed at the daemon's local HTTP server (`http://127.0.0.1:8548`), so while the desktop app is running you can open the same UI in any regular browser on the same machine — same React app, same session, same state. Useful when you want the daemon's lifecycle handled by the desktop launcher (auto-start, restart-on-crash) but prefer your normal browser for the UI.

### TypeScript / JavaScript SDK

```bash
npm install remote-signer-client
```

Same version cadence as the daemon — `remote-signer-client@0.3.9` matches daemon `v0.3.9`. See [Integration Guide](INTEGRATION.md) for usage.

## Chrome Extension

Remote Signer ships with a Chrome browser extension that injects an EIP-1193 `window.ethereum` provider into every page, allowing dApps to use your remote-signer service for signing.

### Installation

1. Build the extension:
   ```bash
   cd extension && npm ci --no-audit --no-fund && node build.mjs
   ```
2. Open Chrome → `chrome://extensions`
3. Enable **Developer mode** (toggle in top-right)
4. Click **Load unpacked** and point to the `extension/` directory
5. The **Remote Signer** icon appears in your toolbar

### Usage

1. Click the extension icon to open the popup
2. Go to **Settings** and enter:
   - **Remote Signer URL** (default `http://127.0.0.1:8548`)
   - **API Key ID** and **Private Key** from your remote-signer config
3. Click **Test Connection** to verify connectivity
4. Visit any dApp — it will auto-detect the Remote Signer provider

For management tasks (rules, signers, budgets), click **Open Management** in the popup to access the full web dashboard.

### Architecture

The extension follows a three-layer isolation pattern (identical to MetaMask):

```
dApp page (MAIN world)  ←postMessage→  content-script (ISOLATED)  ←chrome.runtime→  background (service worker)  ←fetch→  remote-signer API
```

- `inpage.js` — injects `window.ethereum` with EIP-1193 + EIP-6963, zero network I/O
- `content-script.js` — pure bidirectional relay between MAIN world and service worker
- `background.js` — EIP1193Provider + RemoteSignerClient, handles all signing and RPC
- No proxy needed — background worker signs requests directly with Ed25519

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full system design.

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Core concepts, relationships, data flow (Signer, Wallet, API Key, Rule, Template, Preset, Budget, Audit) |
| [SECURITY.md](SECURITY.md) | Threat model, security boundaries, key management, breach impact analysis |
| [Configuration Reference](docs/configuration.md) | Full `config.yaml` reference |
| [Deployment Guide](docs/deployment.md) | Docker, Kubernetes, HA, monitoring, backup |
| [Rules, Templates & Presets](docs/rules-templates-and-presets.md) | Concepts: rule templates, instances, presets |
| [Rule Syntax Reference](docs/rule-syntax.md) | All rule types with examples |
| [Integration Guide](INTEGRATION.md) | Go/TS/Rust SDKs, MCP server |
| [TLS / mTLS Guide](docs/tls.md) | Certificate trust model, generation, production practices |
| [TUI Guide](docs/tui.md) | Remote Signer TUI guide (`remote-signer tui`): build, run, key bindings, real-time request monitoring |
| [SDK/CLI Matrix](docs/sdk-cli-matrix.md) | Go SDK surface mapped to CLI commands, coverage gaps, and operator tools |
| [Testing Guide](docs/testing.md) | Unit tests, E2E, rule validation |
| [GIT.md](GIT.md) | Release flow, version conventions, NPM_TOKEN setup, Docker compose modes |

## License

MIT License
