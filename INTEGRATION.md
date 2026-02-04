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
  useNonce: true // Recommended for production
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
- **Use nonce**: Enable `useNonce: true` for replay protection
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

## Additional Resources

- [API Documentation](../docs/API.md)
- [Architecture Overview](../docs/ARCHITECTURE.md)
- [JavaScript Client README](./pkg/js-client/README.md)
- [MetaMask Snap README](./app/metamask-snap/README.md)
