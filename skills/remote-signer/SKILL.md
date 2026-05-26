---
name: remote-signer
description: >
  Comprehensive guide to the remote-signer service: CLI usage, MCP server integration,
  signing flows (transaction, typed data, personal message, hash), Ed25519 authentication,
  RBAC roles and permissions, TLS/mTLS setup, IP whitelist, and security configuration.
  Use when the user mentions remote-signer deployment, signing operations,
  API key management, security hardening, or integration setup.
---

# Remote Signer

[remote-signer](https://github.com/ivanzzeth/remote-signer) is a self-hosted, policy-driven signing service for EVM chains. It controls **what** gets signed through a rule engine, not just **who** can sign.

## When to Activate

- Setting up or configuring a remote-signer deployment
- Managing API keys and RBAC permissions
- Configuring TLS/mTLS or IP whitelist
- Integrating via CLI, MCP, or SDKs
- Troubleshooting authentication or authorization issues

---

## 1. Architecture Overview

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

## 2. CLI Usage

### Installation

```bash
# Download binary
curl -sSLf -o remote-signer \
  "https://github.com/ivanzzeth/remote-signer/releases/latest/download/remote-signer-$(uname -s | tr A-Z a-z)-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" \
  && chmod +x remote-signer

# Or via Go
go install github.com/ivanzzeth/remote-signer/cmd/...@latest
```

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

## 3. MCP Server Integration

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
- Signer management: `evm_list_signers`, `evm_create_signer`, `evm_unlock_signer`, `evm_lock_signer`
- Signing: `evm_sign_transaction`, `evm_sign_typed_data`, `evm_sign_personal_message`, `evm_sign_hash`
- Simulation: `evm_simulate_tx`, `evm_simulate_batch`
- Rules: `evm_list_rules`, `evm_create_rule`, `evm_update_rule`, `evm_delete_rule`, `evm_toggle_rule`
- Templates: `list_templates`, `create_template`, `instantiate_template`, `delete_template`
- Presets: `list_presets`, `apply_preset`, `get_preset_vars`
- Requests: `evm_list_requests`, `evm_get_request`, `evm_approve_request`
- Budgets: `evm_list_rule_budgets`
- API Keys: `list_api_keys`, `create_api_key`, `delete_api_key`
- Audit: `list_audit_logs`

---

## 4. Authentication & RBAC

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

## 5. TLS / mTLS

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

## 6. IP Whitelist

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

## 7. Security Configuration

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

## 8. SDK Integration

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
