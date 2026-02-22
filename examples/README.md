# Client SDK Examples

## Go Client

```bash
cd examples/go

# Set environment variables
export REMOTE_SIGNER_URL=https://localhost:8549
export REMOTE_SIGNER_API_KEY_ID=dev-key-1
export REMOTE_SIGNER_PRIVATE_KEY=<your-ed25519-private-key-hex>

# Run with mTLS (self-signed CA)
go run main.go \
  --ca-cert ../../certs/ca.crt \
  --client-cert ../../certs/client.crt \
  --client-key ../../certs/client.key

# Run without TLS (plain HTTP)
REMOTE_SIGNER_URL=http://localhost:8548 go run main.go
```

## JavaScript/TypeScript Client

```bash
cd examples/js

# Install dependencies
npm install

# Set environment variables
export REMOTE_SIGNER_URL=https://localhost:8549
export REMOTE_SIGNER_API_KEY_ID=dev-key-1
export REMOTE_SIGNER_PRIVATE_KEY=<your-ed25519-private-key-hex>

# Run with mTLS (self-signed CA)
npx ts-node example.ts \
  --ca-cert ../../certs/ca.crt \
  --client-cert ../../certs/client.crt \
  --client-key ../../certs/client.key

# Run without TLS (plain HTTP)
REMOTE_SIGNER_URL=http://localhost:8548 npx ts-node example.ts
```

## Prerequisites

1. A running remote-signer instance (see main README for setup)
2. An Ed25519 API key pair configured on the server
3. TLS certificates if using HTTPS/mTLS (run `./scripts/deploy.sh gen-certs`)
