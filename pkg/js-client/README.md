# Remote Signer JavaScript Client

JavaScript/TypeScript client library for the remote-signer service. This library provides a convenient interface for interacting with the remote-signer API, including Ed25519 authentication, request signing, and polling for approval.

## Installation

```bash
npm install @remote-signer/client
```

## Quick Start

```typescript
import { RemoteSignerClient } from '@remote-signer/client';

const client = new RemoteSignerClient({
  baseURL: 'http://localhost:8548',
  apiKeyID: 'your-api-key-id',
  privateKey: 'your-ed25519-private-key-hex',
});

// Check server health
const health = await client.health();
console.log('Server status:', health.status);

// Sign a personal message
const response = await client.sign({
  chain_id: '1',
  signer_address: '0x...',
  sign_type: 'personal',
  payload: {
    message: 'Hello, World!',
  },
}, true); // waitForApproval = true

console.log('Signature:', response.signature);
```

## Features

- **Ed25519 Authentication**: Secure request signing with replay protection
- **Multiple Sign Types**: Support for personal messages, transactions, EIP-712, hash signing, etc.
- **Automatic Polling**: Wait for manual approval with configurable polling
- **TypeScript Support**: Full type definitions included
- **Error Handling**: Comprehensive error types and handling

## API Reference

### Constructor

```typescript
new RemoteSignerClient(config: ClientConfig)
```

**Config Options:**
- `baseURL` (string, required): Base URL of the remote-signer service
- `apiKeyID` (string, required): API key identifier
- `privateKey` (string | Uint8Array, required): Ed25519 private key (hex string or bytes)
- `pollInterval` (number, optional): Polling interval in milliseconds (default: 2000)
- `pollTimeout` (number, optional): Polling timeout in milliseconds (default: 300000)
- `useNonce` (boolean, optional): Use nonce for replay protection (default: true)

### Methods

#### `health(): Promise<HealthResponse>`

Check server health status.

```typescript
const health = await client.health();
// { status: 'healthy', version: '1.0.0' }
```

#### `sign(request: SignRequest, waitForApproval?: boolean): Promise<SignResponse>`

Submit a signing request.

```typescript
const response = await client.sign({
  chain_id: '1',
  signer_address: '0x...',
  sign_type: 'personal',
  payload: {
    message: 'Hello, World!',
  },
}, true); // waitForApproval
```

**Sign Types:**
- `personal`: Personal message (adds Ethereum prefix)
- `eip191`: EIP-191 formatted message
- `typed_data`: EIP-712 typed data
- `transaction`: Ethereum transaction
- `hash`: Pre-hashed 32-byte value
- `raw_message`: Raw bytes

#### `getRequest(requestID: string): Promise<RequestStatusResponse>`

Get the status of a signing request.

```typescript
const request = await client.getRequest('request-id');
```

#### `listRequests(filter?: ListRequestsFilter): Promise<ListRequestsResponse>`

List signing requests with optional filters.

```typescript
const requests = await client.listRequests({
  status: 'completed',
  signer_address: '0x...',
  limit: 10,
});
```

#### `approveRequest(requestID: string, approveRequest: ApproveRequest): Promise<ApproveResponse>`

Approve or reject a pending request (admin only).

```typescript
const response = await client.approveRequest('request-id', {
  approved: true,
});
```

## Error Handling

The client throws specific error types:

- `APIError`: API request errors (4xx, 5xx)
- `SignError`: Signing request errors (rejected, failed)
- `TimeoutError`: Polling timeout errors
- `RemoteSignerError`: General client errors

```typescript
import { APIError, SignError, TimeoutError } from '@remote-signer/client';

try {
  await client.sign(request, true);
} catch (error) {
  if (error instanceof SignError) {
    console.error('Signing failed:', error.message);
    console.error('Request ID:', error.requestID);
    console.error('Status:', error.status);
  } else if (error instanceof TimeoutError) {
    console.error('Request timed out');
  } else if (error instanceof APIError) {
    console.error('API error:', error.statusCode, error.message);
  }
}
```

## Examples

See [examples/basic-usage.ts](examples/basic-usage.ts) for more examples.

## Development

### Building

```bash
npm run build
```

### Testing

#### Unit Tests

```bash
npm run test:unit
```

#### E2E Tests

E2E tests require a running remote-signer server. See [tests/README.md](tests/README.md) for details.

**Quick start:**

```bash
# Option 1: Use external server
export E2E_EXTERNAL_SERVER=true
export E2E_BASE_URL=http://localhost:8548
export E2E_API_KEY_ID=your-api-key-id
export E2E_PRIVATE_KEY=your-private-key-hex
npm run test:e2e

# Option 2: Start test server automatically
./scripts/start-test-server.sh &
sleep 5
npm run test:e2e
```

### Linting

```bash
npm run lint
```

## License

MIT
