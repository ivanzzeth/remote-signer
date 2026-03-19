# Remote Signer Integration Guide

This document provides a comprehensive guide for integrating the remote-signer service using the JavaScript client library and MetaMask Snap.

## Table of Contents

1. [JavaScript Client Library](#javascript-client-library)
2. [MetaMask Snap Integration](#metamask-snap-integration)
3. [Authentication Setup](#authentication-setup)
4. [Usage Examples](#usage-examples)
5. [Error Handling](#error-handling)
6. [Best Practices](#best-practices)

## JavaScript Client Library

### Installation

```bash
npm install @remote-signer/client
```

### Basic Setup

```typescript
import { RemoteSignerClient } from '@remote-signer/client';

const client = new RemoteSignerClient({
  baseURL: 'http://localhost:8548',
  apiKeyID: 'my-api-key',
  privateKey: 'your-ed25519-private-key-hex', // 64 hex characters
});
```

### Key Features

- **Ed25519 Authentication**: Secure request signing with replay protection
- **Automatic Polling**: Waits for manual approval when needed
- **Type Safety**: Full TypeScript support
- **Error Handling**: Comprehensive error types

## MetaMask Snap Integration

### Installation

The MetaMask Snap can be installed in two ways:

1. **From dApp**: Prompt users to install the snap
2. **From MetaMask Snaps Directory**: Users can install directly

### Setup in dApp

```typescript
// Install snap
const snapId = 'npm:remote-signer-snap';
const result = await window.ethereum.request({
  method: 'wallet_requestSnaps',
  params: {
    [snapId]: {}
  }
});

// Configure snap
await window.ethereum.request({
  method: 'wallet_invokeSnap',
  params: {
    snapId,
    request: {
      method: 'configure',
      params: {
        baseURL: 'http://localhost:8548',
        apiKeyID: 'my-api-key',
        privateKey: 'your-ed25519-private-key-hex'
      }
    }
  }
});
```

## Authentication Setup

### 1. Generate Ed25519 Key Pair

```bash
# Generate private key
openssl genpkey -algorithm ed25519 -out private_key.pem

# Extract private key in hex format
openssl pkey -in private_key.pem -text | grep 'priv:' -A 3 | tail -n +2 | tr -d ':\n '

# Extract public key in hex format
openssl pkey -in private_key.pem -pubout -out public_key.pem
openssl pkey -pubin -in public_key.pem -text | grep 'pub:' -A 3 | tail -n +2 | tr -d ':\n '
```

### 2. Register API Key

Add the public key to your `config.yaml`:

```yaml
api_keys:
  - id: "my-api-key"
    name: "My Application"
    public_key: "your-public-key-hex"  # 64 hex characters
    enabled: true
    rate_limit: 100
```

### 3. Use Private Key in Client

```typescript
const client = new RemoteSignerClient({
  baseURL: 'http://localhost:8548',
  apiKeyID: 'my-api-key',
  privateKey: 'your-private-key-hex', // Keep this secret!
});
```

## Usage Examples

### Sign Personal Message

```typescript
const response = await client.sign({
  chain_id: '1',
  signer_address: '0x...',
  sign_type: 'personal',
  payload: {
    message: 'Hello, World!'
  }
});
```

### Sign Transaction

```typescript
const response = await client.sign({
  chain_id: '1',
  signer_address: '0x...',
  sign_type: 'transaction',
  payload: {
    transaction: {
      to: '0x...',
      value: '1000000000000000000', // 1 ETH
      gas: 21000,
      gasPrice: '20000000000',
      txType: 'legacy'
    }
  }
});
```

### Sign EIP-712 Typed Data

```typescript
const response = await client.sign({
  chain_id: '1',
  signer_address: '0x...',
  sign_type: 'typed_data',
  payload: {
    typed_data: {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' }
        ],
        Message: [
          { name: 'content', type: 'string' }
        ]
      },
      primaryType: 'Message',
      domain: {
        name: 'Example',
        version: '1',
        chainId: '1'
      },
      message: {
        content: 'Hello'
      }
    }
  }
});
```

### Check Request Status

```typescript
const status = await client.getRequest('req_abc123');
console.log('Status:', status.status);
```

### List Requests

```typescript
const response = await client.listRequests({
  status: 'completed',
  limit: 10
});
```

## Error Handling

### Error Types

```typescript
import { APIError, SignError, TimeoutError } from '@remote-signer/client';

try {
  await client.sign(request);
} catch (error) {
  if (error instanceof APIError) {
    // HTTP error (401, 404, 500, etc.)
    console.error('API Error:', error.statusCode, error.message);
  } else if (error instanceof SignError) {
    // Signing error (rejected, failed, etc.)
    console.error('Sign Error:', error.requestID, error.status);
  } else if (error instanceof TimeoutError) {
    // Timeout waiting for approval
    console.error('Timeout waiting for approval');
  } else {
    // Unknown error
    console.error('Unknown error:', error);
  }
}
```

### Common Error Scenarios

1. **Unauthorized (401)**: Invalid API key or signature
2. **Not Found (404)**: Request ID doesn't exist
3. **Rate Limited (429)**: Too many requests
4. **Pending Approval**: Request requires manual approval
5. **Rejected**: Request was rejected by admin

## Best Practices

### 1. Security

- **Never commit private keys**: Store them in environment variables or secure storage
- **Nonce protection**: Nonce-based replay protection is always enabled
- **Validate responses**: Always check response status before using signatures
- **Use HTTPS**: Always use HTTPS in production

### 2. Error Handling

- **Handle all error types**: Use try-catch blocks and check error types
- **Retry logic**: Implement retry for transient errors
- **User feedback**: Show clear error messages to users

### 3. Performance

- **Polling intervals**: Adjust `pollInterval` based on your needs
- **Timeouts**: Set appropriate `pollTimeout` values
- **Connection pooling**: Reuse client instances when possible

### 4. MetaMask Snap

- **User confirmation**: Always show confirmation dialogs for sensitive operations
- **State management**: Store configuration securely in snap state
- **Error messages**: Provide clear error messages in dialogs

## Troubleshooting

### Connection Issues

1. **Check baseURL**: Ensure the URL is correct and accessible
2. **Check API key**: Verify the API key ID and public key match
3. **Check private key**: Ensure the private key format is correct (64 hex characters)

### Authentication Failures

1. **Verify signature format**: Check that the signature is base64 encoded
2. **Check timestamp**: Ensure system clock is synchronized
3. **Check nonce**: If using nonce, ensure it's unique for each request

### Signing Failures

1. **Check signer address**: Ensure the signer is configured on the server
2. **Check rules**: Verify that rules allow the requested operation
3. **Check request format**: Ensure the payload matches the sign type

## Rust SDK

The Rust SDK (`pkg/rs-client/`) provides a native Rust client for the remote-signer service with Ed25519 authentication.

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
remote-signer-client = { path = "../remote-signer/pkg/rs-client" }
```

### Basic Usage

```rust
use remote_signer_client::{Client, Config};
use remote_signer_client::evm::{SignRequest, SIGN_TYPE_PERSONAL};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(Config {
        base_url: "http://127.0.0.1:8548".to_string(),
        api_key_id: "my-key".to_string(),
        private_key_hex: Some("0x...".to_string()),
        ..Default::default()
    })?;

    let req = SignRequest {
        chain_id: "1".to_string(),
        signer_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
        sign_type: SIGN_TYPE_PERSONAL.to_string(),
        payload: serde_json::json!({"message": "hello"}),
    };

    let resp = client.evm.sign.execute(&req)?;
    println!("status={} sig={:?}", resp.status, resp.signature);

    Ok(())
}
```

### Authentication

Requests are signed with Ed25519. The message format matches the server middleware:

```
{timestamp_ms}|{nonce}|{method}|{path_with_query}|{sha256(body)}
```

Headers sent automatically: `X-API-Key-ID`, `X-Timestamp`, `X-Nonce`, `X-Signature` (base64).

For more details, see [Rust SDK README](./pkg/rs-client/README.md).

---

## MCP Server (AI Agent Integration)

The MCP server (`pkg/mcp-server/`) exposes remote-signer operations as [Model Context Protocol](https://modelcontextprotocol.io/) tools, enabling AI agents (Claude Code, Cursor, etc.) to manage signers, rules, templates, and signing requests programmatically.

- **Package**: `remote-signer-mcp` (npm, v0.0.5)
- **Protocol**: MCP over stdio
- **Auth**: Same Ed25519 authentication as other SDKs
- **TLS/mTLS**: Supported via environment variables

### Quick Start (no install)

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

Optional TLS variables: `REMOTE_SIGNER_CA_FILE`, `REMOTE_SIGNER_CLIENT_CERT_FILE`, `REMOTE_SIGNER_CLIENT_KEY_FILE`.

### Cursor / Claude Code Configuration

Add to your MCP config (`.cursor/mcp.json` or `.mcp.json`):

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

Once configured, AI agents can create signers, manage rules, sign transactions, and approve requests through natural language. For more details, see [MCP Server README](./pkg/mcp-server/README.md).

---

## CLI Commands

The `remote-signer-cli` provides command-line access to all server operations. Requires auth flags: `--url`, `--api-key-id`, `--api-key-file`.

### Request Management

```bash
# List signing requests (defaults to "authorizing" status)
remote-signer-cli evm request list [--status authorizing]

# Get request details
remote-signer-cli evm request get <request-id>

# Approve a pending request (signer owner only)
remote-signer-cli evm request approve <request-id>

# Reject a pending request (signer owner only)
remote-signer-cli evm request reject <request-id>

# Preview auto-generated rule for a request
remote-signer-cli evm request preview-rule <request-id>
```

### Transaction Operations

```bash
# Broadcast a signed transaction
remote-signer-cli evm broadcast <signed-tx-hex> --chain-id <id> [--wait]

# Simulate a single transaction
remote-signer-cli evm simulate tx --chain-id 1 --from 0x... --to 0x... --data 0x...

# Simulate a batch of transactions (JSON format)
remote-signer-cli evm simulate batch --chain-id 1 --from 0x... \
  --tx '{"to":"0x...","value":"0x0","data":"0x..."}' \
  --tx '{"to":"0x...","value":"0x0","data":"0x..."}'
```

### Guard Management

```bash
# Resume approval guard after it trips
remote-signer-cli evm guard resume
```

### Transaction Signing Notes

- **Nonce**: When omitted or set to -1, the server auto-fetches from chain via `eth_getTransactionCount`.
- **Gas params**: `gasPrice`, `gasTipCap`, `gasFeeCap`, and `value` accept both decimal (`"20000000000"`) and hex (`"0x4a817c800"`) formats.
- **Input validation**: All API handlers validate Ethereum addresses (0x + 40 hex chars), chain_id (positive decimal), hex calldata, and hex values.

---

## Batch Signing

```typescript
// Sign multiple transactions atomically
const result = await client.evm.sign.executeBatch({
  requests: [
    {
      chain_id: '1',
      signer_address: '0x...',
      sign_type: 'transaction',
      payload: { transaction: { to: '0x...', value: '0x0', data: '0x095ea7b3...' } }
    },
    {
      chain_id: '1',
      signer_address: '0x...',
      sign_type: 'transaction',
      payload: { transaction: { to: '0x...', value: '0x0', data: '0xf2c42696...' } }
    }
  ]
});
```

## Simulation

```typescript
// Simulate a single transaction
const simResult = await client.evm.simulate({
  chainId: '1',
  from: '0x...',
  to: '0x...',
  value: '0x0',
  data: '0x...'
});

// Simulate a batch
const batchResult = await client.evm.simulateBatch({
  chainId: '1',
  from: '0x...',
  transactions: [
    { to: '0x...', value: '0x0', data: '0x...' },
    { to: '0x...', value: '0x0', data: '0x...' }
  ]
});

// Check simulation engine status
const status = await client.evm.simulate.status();
```

## Signer Access Control

```typescript
// Grant signer access to another API key
await client.evm.signers.grantAccess('0xSignerAddress', { api_key_id: 'agent-key' });

// Revoke signer access
await client.evm.signers.revokeAccess('0xSignerAddress', 'agent-key');

// List who has access to a signer
const access = await client.evm.signers.listAccess('0xSignerAddress');

// Transfer signer ownership
await client.evm.signers.transferOwnership('0xSignerAddress', { new_owner_id: 'new-admin' });
```

## Request Approval (Owner Only)

Only the signer's **owner API key** can approve or reject pending requests:

```typescript
// Approve a pending request (must be signer owner)
await client.approveRequest('request-id', { approved: true });

// Reject a pending request
await client.approveRequest('request-id', { approved: false });
```

---

## Additional Resources

- [API Documentation](docs/api.md)
- [Architecture Overview](docs/architecture.md)
- [JavaScript Client README](./pkg/js-client/README.md)
- [Rust SDK README](./pkg/rs-client/README.md)
- [MCP Server README](./pkg/mcp-server/README.md)
