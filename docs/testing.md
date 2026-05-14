# Testing Guide

## Unit Tests

```bash
go test ./...
```

On resource-constrained machines:

```bash
GOMAXPROCS=1 go test -p 1 ./...
```

## E2E Tests

E2E tests verify the complete signing workflow against a running server.

### Internal Test Server (Default)

```bash
go test -tags=e2e ./e2e/...
```

For a closer match to pre-commit runs:

```bash
GOMAXPROCS=1 E2E_API_PORT=18548 go test -p 1 -tags=e2e ./e2e/... -count=1 -timeout 10m -skip 'TestSimulate_'
```

### External Server

```bash
export E2E_EXTERNAL_SERVER=true
export E2E_BASE_URL=http://localhost:8548
export E2E_API_KEY_ID=your-admin-api-key-id
export E2E_PRIVATE_KEY=your-ed25519-private-key-hex
go test -tags=e2e ./e2e/...
```

### E2E Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `E2E_EXTERNAL_SERVER` | No | `false` | Set `true` for external server |
| `E2E_BASE_URL` | No | `http://localhost:8548` | Server URL |
| `E2E_API_KEY_ID` | Yes* | -- | Admin API key ID (*required for external) |
| `E2E_PRIVATE_KEY` | Yes* | -- | Admin Ed25519 private key (hex) |
| `E2E_SIGNER_ADDRESS` | No | `0xf39Fd6e...` | Signer address for tests |
| `E2E_CHAIN_ID` | No | `1` | Chain ID for tests |
| `E2E_NONADMIN_API_KEY_ID` | No | -- | Non-admin key ID (permission tests) |
| `E2E_NONADMIN_PRIVATE_KEY` | No | -- | Non-admin private key |

## Rule Validation

```bash
remote-signer validate -config config.yaml
```

## Coverage Targets

| Component | Target |
|-----------|--------|
| Overall | 85% |
| `internal/chain/evm` | 85% |
| Rule evaluation (JS) | < 10ms |
| Rule evaluation (Solidity) | 100ms — 2s |
