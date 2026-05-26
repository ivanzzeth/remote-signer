---
name: remote-signer
description: >
  Comprehensive guide to the remote-signer service: installation, CLI usage, MCP server integration,
  signing flows (transaction, typed data, personal message, hash), AI agent pre-flight checklist,
  Ed25519 authentication, RBAC roles and permissions, TLS/mTLS setup, IP whitelist,
  and security configuration. Use when the user mentions remote-signer deployment,
  signing operations, API key management, security hardening, or integration setup.
---

# Remote Signer

[remote-signer](https://github.com/ivanzzeth/remote-signer) is a self-hosted, policy-driven signing service for EVM chains. It controls **what** gets signed through a rule engine, not just **who** can sign.

## When to Activate

- **Installing remote-signer** → guide through install method selection and configuration
- **User asks to sign anything** (transaction, typed data, message, hash) → run pre-flight checklist first
- Setting up or configuring a remote-signer deployment
- Managing API keys and RBAC permissions
- Configuring TLS/mTLS or IP whitelist
- Integrating via CLI, MCP, or SDKs
- Troubleshooting authentication or authorization issues

---

## 1. Installation

### AI Agent: Installation Guide

When a user asks to install remote-signer, walk through these questions to determine the right approach:

**Step 1 — Understand the environment:**

| Question | Options |
|----------|---------|
| What OS / platform? | macOS, Linux, Windows |
| Running locally or on a server? | Local dev, VPS, homelab, K8s |
| Do you have Go installed? | `go version` |
| Do you have Docker installed? | `docker --version` |

**Step 2 — Recommend the install method based on answers:**

| User Profile | Recommend | Reason |
|-------------|-----------|--------|
| Local dev, no Docker | Download binary | Single file, no deps |
| Local dev, has Docker | Docker (personal) | Isolated, same as native |
| Go developer | `go install` | Fits Go toolchain |
| Server / CI | Download binary + env var bootstrap | Minimal deps, automatable |
| Production multi-instance | Docker + PostgreSQL | HA, see deployment guide |
| Desktop user (non-CLI) | Desktop App | .dmg / .exe / .AppImage |

**Step 3 — Ask about configuration preferences:**

After installation, help the user through first setup:

> "Where would you like to store your config? Default is `~/.remote-signer/`."
>
> "Do you need TLS? (Recommended if not localhost-only.)"
>
> "Would you like me to help set up API keys now, or just start the server?"

### Install Methods

```bash
curl -sSLf -o remote-signer \
  "https://github.com/ivanzzeth/remote-signer/releases/latest/download/remote-signer-$(uname -s | tr A-Z a-z)-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" \
  && chmod +x remote-signer

# Verify
./remote-signer version
```

### Via Go

```bash
go install github.com/ivanzzeth/remote-signer/cmd/...@latest
```

### Via Setup Script

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ivanzzeth/remote-signer/main/scripts/setup.sh)
```

### From Source

```bash
git clone https://github.com/ivanzzeth/remote-signer.git && cd remote-signer && make build
```

### Docker (personal)

```bash
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose -f docker-compose.local.yml up -d
```

Pulls `ghcr.io/ivanzzeth/remote-signer:latest`, bind-mounts `~/.remote-signer` into the container. Same SQLite DB, admin keystore, signers, and API keys as the native daemon.

### Desktop App

Each release ships `.dmg` (macOS), `.exe` (Windows), and `.AppImage` (Linux) from the [Releases](https://github.com/ivanzzeth/remote-signer/releases) page.

---

## 2. AI Agent Signing Workflow

When a user asks to perform a signing operation (transaction, typed data, personal message, or hash), follow this checklist **before** calling any signing tool.

### Pre-Flight Checklist

#### 2.1 Check: remote-signer binary installed

```bash
which remote-signer || test -x ./remote-signer || \
  test -x ~/.local/bin/remote-signer
```

If not found, guide the user through [Installation](#1-installation) first.

#### 2.2 Check: server is running

```bash
curl -fsS "http://127.0.0.1:8548/health" 2>/dev/null || \
  curl -fsS --cacert certs/ca.crt "https://127.0.0.1:8548/health" 2>/dev/null
```

If the server is not running:
```bash
./remote-signer &
# or: ./remote-signer server start
```

Wait for it to be ready (the `/health` endpoint returns 200).

#### 2.3 Check: MCP environment variables (do NOT inspect values)

Verify these env vars **exist** — do NOT read or display their values:

```bash
# Check existence only — NEVER print values
test -n "$REMOTE_SIGNER_API_KEY_ID" || echo "REMOTE_SIGNER_API_KEY_ID is not set"
test -n "$REMOTE_SIGNER_PRIVATE_KEY" -o -n "$REMOTE_SIGNER_PRIVATE_KEY_FILE" || \
  echo "Neither REMOTE_SIGNER_PRIVATE_KEY nor REMOTE_SIGNER_PRIVATE_KEY_FILE is set"
```

If env vars are missing, the MCP server can't authenticate. The user needs to configure them in their MCP settings (see [Section 4 — MCP Server Integration](#4-mcp-server-integration)).

#### 2.4 Check: at least one signer exists and is usable

```bash
# Via MCP tool: evm_list_signers
# Via CLI:
./remote-signer evm signer list --url http://localhost:8548 \
  --api-key-id "$REMOTE_SIGNER_API_KEY_ID" \
  --api-key-file ~/.remote-signer/apikeys/admin.key.priv
```

If no signers exist, create one:
```bash
./remote-signer evm signer create --password "<password>" \
  --url http://localhost:8548 \
  --api-key-id admin --api-key-file ~/.remote-signer/apikeys/admin.key.priv
```

If the signer is locked, unlock it:
```bash
./remote-signer evm signer unlock 0x<signer-address> --password "<password>"
```

#### 2.5 Understand what you're signing

Before signing, clarify with the user:

| Question | Why |
|----------|-----|
| Which chain? | Chain ID determines the network (1=mainnet, 137=polygon, etc.) |
| Which signer address? | Which key to sign with |
| What type of signature? | `transaction`, `typed_data` (EIP-712), `personal` (eth_sign), or `hash` |
| What are we signing? | The actual payload — review it for safety |

### Signing Paths

Once pre-flight checks pass, there are two paths:

**Path A: MCP tools (AI agent has direct access)**
```
evm_sign_transaction / evm_sign_typed_data / evm_sign_personal_message / evm_sign_hash
  → If rule matched: signed immediately
  → If no rule match + manual approval enabled: request enters "authorizing"
    → evm_list_requests (status=authorizing) to find the request ID
    → evm_approve_request to approve it
```

**Path B: CLI (guide the user to run commands)**
```
./remote-signer evm sign tx --chain-id 137 --signer 0x... --to 0x... --value 0 --gas 21000
./remote-signer evm sign typed-data --chain-id 1 --signer 0x... --typed-data-file payload.json
./remote-signer evm sign personal --chain-id 1 --signer 0x... --message "Hello"
```

### Signing Flow Diagram

```
Pre-flight checks (install, server, env vars, signer)
  │
  ▼
Determine sign type (tx / typed_data / personal / hash)
  │
  ▼
Call sign tool (MCP or CLI)
  │
  ├─ Auto-approved (whitelist rule matched) → signature returned
  │
  ├─ Auto-blocked (blocklist rule matched) → rejected
  │
  └─ No rule match
       ├─ manual_approval_enabled=true → "authorizing" → wait for approval
       └─ manual_approval_enabled=false → rejected
```

---

## 3. Architecture Overview

```
Client → Ed25519 Auth → Middleware Pipeline → Handler → SignService
                                                            │
                              ChainAdapter ◄── SignService ─┤
                              Rule Engine  ◄── SignService ─┤
                              Budget Check ◄── SignService ─┤
                              Signer ──signs──► Signature ──┤
                              Audit Log ◄───── Every step ──┘
```

**Components:**
| Component | Description |
|-----------|-------------|
| Server | Daemon on `:8548`, REST API, SQLite or PostgreSQL |
| CLI | `remote-signer` — `server start`, `tui`, `validate`, `api-key`, `evm` |
| TUI | Terminal UI for interactive monitoring |
| Web UI | React dashboard served at `http://127.0.0.1:8548` |
| MCP Server | `remote-signer-mcp` (npm) — AI agent tools |
| JS/TS SDK | `remote-signer-client` (npm) |
| Go SDK | `pkg/client` |
| Rust SDK | `pkg/rs-client` |

---

## 4. CLI Usage

### First Launch

```bash
./remote-signer
# → Creates ~/.remote-signer/ with SQLite config
# → Generates Ed25519 admin keypair
# → Prints private key path ONCE to stderr
```

### Key Commands

```bash
# Server
./remote-signer                          # Start daemon
./remote-signer tui                      # Terminal UI
./remote-signer validate rules/          # Offline rule validation (needs forge)

# API Key management (requires admin auth)
./remote-signer api-key keygen --out ./my-key
./remote-signer api-key create --id my-key --name "My Key" --role dev \
  --public-key <hex> --url http://localhost:8548 \
  --api-key-id admin --api-key-file ~/.remote-signer/apikeys/admin.key.priv
./remote-signer api-key list
./remote-signer api-key delete my-key

# EVM operations
./remote-signer evm request list [--status authorizing]
./remote-signer evm request approve <request-id>
./remote-signer evm request reject <request-id>
./remote-signer evm simulate tx --chain-id 1 --from 0x... --to 0x...
./remote-signer evm broadcast <signed-tx-hex> --chain-id 1

# Presets
./remote-signer preset list
./remote-signer preset create-from polymarket_safe_polygon --write --config config.yaml \
  --set allowed_safe_addresses=0xYourSafe
```

### Bootstrap (first-time admin setup)

Three converging paths to create the admin API key:

| Path | Mechanism | Best for |
|------|-----------|----------|
| Env var | `REMOTE_SIGNER_KEYSTORE_PASSWORD` | CI / Kubernetes / systemd |
| Web UI | `/api/v1/bootstrap/admin` | Desktop / Electron / Docker |
| CLI | `remote-signer api-key bootstrap` | SSH / headless / `docker exec` |

---

## 5. MCP Server Integration

`remote-signer-mcp` exposes all operations as MCP tools for AI agents (Claude Code, Cursor, etc.).

### Quick Start

```bash
npx -y remote-signer-mcp
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `REMOTE_SIGNER_URL` | No | Base URL (default: `http://localhost:8548`) |
| `REMOTE_SIGNER_API_KEY_ID` | Yes | API key ID |
| `REMOTE_SIGNER_PRIVATE_KEY` | One of | Ed25519 private key in hex |
| `REMOTE_SIGNER_PRIVATE_KEY_FILE` | One of | Path to PEM file |
| `REMOTE_SIGNER_CA_FILE` | No | CA certificate for TLS |
| `REMOTE_SIGNER_CLIENT_CERT_FILE` | No | Client cert for mTLS |
| `REMOTE_SIGNER_CLIENT_KEY_FILE` | No | Client key for mTLS |

### Configuration (Claude Code / Cursor)

```json
{
  "mcpServers": {
    "remote-signer": {
      "command": "npx",
      "args": ["-y", "remote-signer-mcp"],
      "env": {
        "REMOTE_SIGNER_URL": "http://localhost:8548",
        "REMOTE_SIGNER_API_KEY_ID": "admin",
        "REMOTE_SIGNER_PRIVATE_KEY_FILE": "/path/to/admin_private.pem"
      }
    }
  }
}
```

### Available MCP Tools

The MCP server exposes all remote-signer API operations:

- **Signer management**: `evm_list_signers`, `evm_create_signer`, `evm_unlock_signer`, `evm_lock_signer`, `evm_approve_signer`, `evm_delete_signer`, `evm_transfer_signer_ownership`, `evm_grant_signer_access`, `evm_revoke_signer_access`, `evm_list_signer_access`
- **Signing**: `evm_sign_transaction`, `evm_sign_typed_data`, `evm_sign_personal_message`, `evm_sign_hash`, `evm_sign_batch`
- **Simulation**: `evm_simulate_tx`, `evm_simulate_batch`, `evm_get_request_simulation`
- **Broadcast**: `evm_broadcast_tx`
- **Rules**: `evm_list_rules`, `evm_get_rule`, `evm_create_rule`, `evm_update_rule`, `evm_delete_rule`, `evm_toggle_rule`, `evm_approve_rule`, `evm_reject_rule`, `evm_list_rule_budgets`
- **Budgets**: `list_budgets`, `create_budget`, `get_budget`, `update_budget`, `delete_budget`, `reset_budget`
- **Templates**: `list_templates`, `get_template`, `create_template`, `update_template`, `delete_template`, `instantiate_template`, `revoke_template_instance`
- **Presets**: `list_presets`, `get_preset`, `apply_preset`
- **Requests**: `evm_list_requests`, `evm_get_request`, `evm_approve_request`, `evm_preview_rule`
- **Transactions**: `list_transactions`, `get_transaction`
- **Wallets**: `list_wallets`, `get_wallet`, `create_wallet`, `update_wallet`, `delete_wallet`, `list_wallet_members`, `add_wallet_member`, `remove_wallet_member`
- **HD Wallets**: `evm_list_hd_wallets`, `evm_create_hd_wallet`, `evm_import_hd_wallet`, `evm_derive_address`, `evm_list_derived_addresses`
- **API Keys**: `list_api_keys`, `get_api_key`, `create_api_key`, `update_api_key`, `delete_api_key`, `list_api_key_names`
- **ACLs**: `get_ip_whitelist`
- **Audit**: `list_audit_logs`, `list_audit_by_request`
- **Guard**: `evm_guard_resume`
- **System**: `get_metrics`

---

## 6. Authentication & RBAC

### Ed25519 Request Signing

Every API request (except `/health` and `/metrics`) must be signed:

```
Signature payload: {timestamp}|{nonce}|{method}|{path}|{sha256(body)}
Signed with: API key's Ed25519 private key
Headers:
  X-API-Key-ID: <key-id>
  X-Timestamp: <unix-ms>
  X-Nonce: <random>
  X-Signature: <base64-signature>
```

- **Replay protection**: max request age (default 60s) + per-key nonce uniqueness
- **Rate limiting**: IP-level (pre-auth, 200 req/min) + per-key (configurable)

### RBAC Roles

| Capability | `role: admin` | `role: dev` | `role: agent` | `role: strategy` |
|------------|:---:|:---:|:---:|:---:|
| Submit sign requests | Yes | Yes | Yes | Yes |
| View own request status | Yes | Yes | Yes | Yes |
| View all request status | Yes | No | No | No |
| Approve/reject requests (signer owner) | Yes | No | No | No |
| Manage rules (CRUD) | Yes | No | No | No |
| Read rules/budgets | Yes | No | Yes | No |
| Create signers (keystore/HD) | Yes | No | No | No |
| Manage API keys | Yes | No | No | No |
| View audit logs | Yes | No | No | No |
| Manage templates | Yes | No | No | No |

### Scoping Fields

API keys can be further restricted:

| Field | Effect |
|-------|--------|
| `allowed_signers: []` | Can use all signers |
| `allowed_signers: [addr]` | Only listed signers |
| `allowed_hd_wallets: []` | `dev`: no HD wallet access. `admin`: all |
| `allowed_hd_wallets: [addr]` | Only listed HD wallets |
| `allowed_chain_types: []` | All chain types |
| `allowed_chain_types: ["evm"]` | EVM only |
| Per-key `rate_limit` | Override default rate limit |

### Signer Ownership Model

- The API key that **creates** a signer becomes its **owner**
- Only the owner can approve/reject pending requests for that signer
- The owner can grant/revoke access to other API keys
- The owner can transfer ownership to another API key (clears access list)

```bash
# Grant access
./remote-signer evm signer grant-access 0xSignerAddr --api-key-id agent-key

# Revoke access
./remote-signer evm signer revoke-access 0xSignerAddr agent-key

# Transfer ownership
./remote-signer evm signer transfer-ownership 0xSignerAddr --new-owner-id new-admin
```

---

## 7. TLS / mTLS

### Configuration

```yaml
server:
  port: 8548
  tls:
    enabled: true
    cert_file: "./certs/server.crt"
    key_file: "./certs/server.key"
    ca_file: "./certs/ca.crt"          # CA for verifying client certs
    client_auth: false                 # true = require client certs (mTLS)
```

### Generate Certificates

```bash
./scripts/gen-certs.sh
# Creates certs/ca.crt, certs/server.crt, certs/server.key,
#          certs/client.crt, certs/client.key
```

Force overwrite: `CERTS_FORCE=1 ./scripts/gen-certs.sh`

### Health Check by TLS Mode

**Plain HTTP:**
```bash
curl -fsS "http://127.0.0.1:8548/health"
```

**HTTPS (private CA, no mTLS):**
```bash
curl --cacert certs/ca.crt -fsS "https://127.0.0.1:8548/health"
```

**HTTPS + mTLS:**
```bash
curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key \
  -fsS "https://127.0.0.1:8548/health"
```

### MCP/TLS

```json
{
  "env": {
    "REMOTE_SIGNER_URL": "https://127.0.0.1:8548",
    "REMOTE_SIGNER_CA_FILE": "./certs/ca.crt",
    "REMOTE_SIGNER_CLIENT_CERT_FILE": "./certs/client.crt",
    "REMOTE_SIGNER_CLIENT_KEY_FILE": "./certs/client.key"
  }
}
```

---

## 8. IP Whitelist

```yaml
security:
  ip_whitelist:
    enabled: true
    allowed_ips:
      - "127.0.0.1"
      - "::1"
      - "10.0.0.0/8"
    trust_proxy: true                     # Trust X-Forwarded-For
    trusted_proxies: ["10.0.0.1"]         # Required when trust_proxy=true
```

- Without `trusted_proxies`, proxy headers are **ignored** (fail-closed)
- Only requests from `allowed_ips` (or trusted proxy with valid forwarded IP) are accepted

---

## 9. Security Configuration

### Recommended Production Baseline

```yaml
security:
  max_request_age: "30s"              # Replay window
  rate_limit_default: 100             # Per-key req/min
  ip_rate_limit: 200                  # Pre-auth req/min
  nonce_required: true                # Replay protection
  manual_approval_enabled: false      # true = unmatched → pending approval
  rules_api_readonly: true            # Block API rule mutations
  api_keys_api_readonly: true         # Block API key CRUD
  signers_api_readonly: false         # Allow runtime signer creation

  approval_guard:
    enabled: true
    window: "1h"
    rejection_threshold_pct: 50
    min_samples: 10
    resume_after: "2h"
```

### Key Management

| Method | Production Ready |
|--------|:---:|
| Encrypted keystore (JSON) | Yes |
| HD Wallet (BIP-39, encrypted) | Yes |
| Plaintext key (env var) | No (test only) |
| HSM | Planned |

**Memory hardening:** `mlockall`, `PR_SET_DUMPABLE=0`, password zeroization, container `mem_swappiness: 0`

### Sandboxing

- **JS rules**: 20ms timeout, 32MB memory, 13+ blocked globals (eval, Function, fetch, Reflect, Proxy)
- **Solidity rules**: 24 blocked patterns (vm.ffi, vm.readFile, etc.), 30s timeout

---

## 10. SDK Integration

### TypeScript/JavaScript

```bash
npm install remote-signer-client
```

```typescript
import { RemoteSignerClient } from '@remote-signer/client';

const client = new RemoteSignerClient({
  baseURL: 'http://localhost:8548',
  apiKeyID: 'my-key',
  privateKey: 'ed25519-private-key-hex',
});

const resp = await client.sign({
  chain_id: '1',
  signer_address: '0x...',
  sign_type: 'transaction',
  payload: { transaction: { to: '0x...', value: '0x0', gas: 21000 } }
});
```

### Go

```go
import "github.com/ivanzzeth/remote-signer/pkg/client"

client := client.New(client.Config{
    BaseURL:       "http://127.0.0.1:8548",
    APIKeyID:      "my-key",
    PrivateKeyHex: "...",
})
resp, err := client.EVM.Sign.Execute(ctx, req)
```

### Rust

```toml
[dependencies]
remote-signer-client = { path = "../remote-signer/pkg/rs-client" }
```

```rust
let client = Client::new(Config {
    base_url: "http://127.0.0.1:8548".into(),
    api_key_id: "my-key".into(),
    private_key_hex: Some("0x...".into()),
    ..Default::default()
})?;
let resp = client.evm.sign.execute(&req)?;
```

---

## References

- [ARCHITECTURE.md](ARCHITECTURE.md) — Core concepts and data flow
- [SECURITY.md](SECURITY.md) — Threat model and defense-in-depth
- [docs/configuration.md](docs/configuration.md) — Full config.yaml reference
- [docs/deployment.md](docs/deployment.md) — Docker, Kubernetes, HA
- [docs/tls.md](docs/tls.md) — TLS certificate trust model
- [INTEGRATION.md](INTEGRATION.md) — Go/TS/Rust SDKs, MCP server
