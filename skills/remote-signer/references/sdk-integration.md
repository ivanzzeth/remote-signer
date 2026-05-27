# SDK Integration

## MCP Server

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

## TypeScript/JavaScript

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

## Go

```go
import "github.com/ivanzzeth/remote-signer/pkg/client"

client := client.New(client.Config{
    BaseURL:       "http://127.0.0.1:8548",
    APIKeyID:      "my-key",
    PrivateKeyHex: "...",
})
resp, err := client.EVM.Sign.Execute(ctx, req)
```

## Rust

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
