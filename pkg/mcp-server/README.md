# remote-signer-mcp

MCP (Model Context Protocol) server for the [remote-signer](https://github.com/ivanzzeth/remote-signer) service. Uses [remote-signer-client](https://www.npmjs.com/package/remote-signer-client) from npm.

## Run with npx (no install)

```bash
npx -y remote-signer-mcp
```

## Environment variables

Sensitive values can be set **by path** (recommended) or by raw value.

| Variable | Required | Description |
|----------|----------|-------------|
| `REMOTE_SIGNER_URL` | No | Base URL (default: http://localhost:8548) |
| `REMOTE_SIGNER_API_KEY_ID` | Yes | API key ID (e.g. `admin`) |
| `REMOTE_SIGNER_PRIVATE_KEY` | One of | Ed25519 private key in **hex** |
| `REMOTE_SIGNER_PRIVATE_KEY_FILE` | One of | **Path** to PEM file (e.g. `data/admin_private.pem`) |

**TLS / mTLS** (optional, for HTTPS backends):

| Variable | Description |
|----------|-------------|
| `REMOTE_SIGNER_CA_FILE` | Path to CA certificate (PEM) for server verification |
| `REMOTE_SIGNER_CLIENT_CERT_FILE` | Path to client certificate (PEM) for mTLS |
| `REMOTE_SIGNER_CLIENT_KEY_FILE` | Path to client private key (PEM) for mTLS |
| `REMOTE_SIGNER_TLS_INSECURE_SKIP_VERIFY` | Set to `1` or `true` to skip server cert verification (insecure, testing only) |

## Cursor / MCP config

**Path-based (recommended):** no secrets in config, only paths.

```json
{
  "mcpServers": {
    "remote-signer": {
      "command": "npx",
      "args": ["-y", "remote-signer-mcp"],
      "env": {
        "REMOTE_SIGNER_URL": "https://your-server.example.com",
        "REMOTE_SIGNER_API_KEY_ID": "admin",
        "REMOTE_SIGNER_PRIVATE_KEY_FILE": "/abs/path/to/data/admin_private.pem",
        "REMOTE_SIGNER_CA_FILE": "/path/to/ca.pem",
        "REMOTE_SIGNER_CLIENT_CERT_FILE": "/path/to/client.pem",
        "REMOTE_SIGNER_CLIENT_KEY_FILE": "/path/to/client-key.pem"
      }
    }
  }
}
```

**Local HTTP (no TLS):**

```json
{
  "mcpServers": {
    "remote-signer": {
      "command": "npx",
      "args": ["-y", "remote-signer-mcp"],
      "env": {
        "REMOTE_SIGNER_URL": "http://localhost:8548",
        "REMOTE_SIGNER_API_KEY_ID": "admin",
        "REMOTE_SIGNER_PRIVATE_KEY_FILE": "projects/personal/ivanzzeth/remote-signer/data/admin_private.pem"
      }
    }
  }
}
```

Paths in `env` are resolved from the process working directory (often the workspace root when Cursor starts the MCP server).

## Available Tools

The MCP server exposes the following tools for AI agents:

### Signing & Transactions
- **evm_sign_transaction** — Sign a transaction (may require manual approval from signer owner if no whitelist rule matches)
- **evm_sign_personal_message** — Sign a personal message
- **evm_sign_typed_data** — Sign EIP-712 typed data
- **evm_sign_hash** — Sign a pre-hashed value
- **evm_simulate_tx** — Simulate a single transaction (predict balance changes, gas usage, approval detection)
- **evm_simulate_batch** — Simulate multiple transactions in sequence
- **evm_broadcast_tx** — Broadcast a signed transaction to the network

### Request Management
- **evm_list_requests** — List signing requests (defaults to "authorizing" status)
- **evm_get_request** — Get details of a specific request
- **evm_approve_request** — Approve a pending request (signer owner only)

### Signer Management
- **evm_create_signer** — Create a new signer (keystore)
- **evm_list_signers** — List all signers
- **evm_create_hd_wallet** — Create an HD wallet
- **evm_import_hd_wallet** — Import an HD wallet from mnemonic
- **evm_derive_address** — Derive addresses from HD wallet
- **evm_list_derived_addresses** — List derived addresses
- **evm_list_hd_wallets** — List HD wallets

### Rules & Templates
- **evm_create_rule** — Create an authorization rule
- **evm_get_rule** — Get rule details
- **evm_list_rules** — List rules
- **evm_delete_rule** — Delete a rule
- **evm_update_rule** — Update a rule
- **evm_toggle_rule** — Enable/disable a rule
- **evm_preview_rule** — Preview auto-generated rule for a request
- **evm_list_rule_budgets** — List rule budget usage

### Operations
- **evm_guard_resume** — Resume approval guard after it trips
- **get_metrics** — Get Prometheus metrics

### Templates
- **create_template** / **get_template** / **list_templates** / **update_template** / **delete_template** — Template CRUD
- **instantiate_template** / **revoke_template_instance** — Template instance management

### Audit
- **list_audit_logs** — Query audit log records

Published: **remote-signer-mcp@0.0.5**

## Install and run locally

```bash
npm install
npm run build
REMOTE_SIGNER_API_KEY_ID=admin REMOTE_SIGNER_PRIVATE_KEY_FILE=./data/admin_private.pem node build/index.js
```

## Local development / test without publishing

When testing HTTPS or TLS fixes before publishing:

1. **Use the local client in the MCP:** from `pkg/mcp-server` run `npm install file:../js-client`, then `npm run build`.
2. **Verify HTTPS client:** from the agents repo root, with the same `env` as in `.cursor/mcp.json` (including `REMOTE_SIGNER_URL=https://...` and cert paths), run:
   ```bash
   node projects/personal/ivanzzeth/remote-signer/pkg/mcp-server/scripts/test-https.mjs
   ```
   You should see `OK: { "rules": [...] }` or a connection error if the backend is down — not "Client sent an HTTP request to an HTTPS server".
3. **Cover all MCP tools:** run the full self-test (all tools over HTTPS):
   ```bash
   node projects/personal/ivanzzeth/remote-signer/pkg/mcp-server/scripts/test-all-tools.mjs
   ```
   You should see `passed: 16, failed: 0`.
4. **Run the MCP from the repo:** in `.cursor/mcp.json` point `remote-signer` at the local build instead of npx, e.g. `"command": "node"`, `"args": ["projects/personal/ivanzzeth/remote-signer/pkg/mcp-server/build/index.js"]`, and keep the same `env`. Restart Cursor MCP and trigger a tool (e.g. list rules) to confirm.

Publish a new version only after local tests are stable.

## License

MIT
