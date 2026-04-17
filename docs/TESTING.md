# Testing Guide

## Unit Tests

```bash
go test ./...
```

On resource-constrained machines:

```bash
GOMAXPROCS=1 go test -p 1 ./...
```

## Git hooks (`scripts/install-hooks.sh`)

Install or refresh hooks after cloning or when hook scripts change:

```bash
./scripts/install-hooks.sh
```

### Pre-commit and E2E

The **pre-commit** hook runs security scans and, when E2E is enabled for your commit, starts an ephemeral server on **`E2E_API_PORT=18548`** (to avoid colliding with a dev server on `8548`).

#### When E2E runs (default: auto)

| Situation | Behavior |
|-----------|----------|
| **`REMOTE_SIGNER_PRE_COMMIT_E2E=auto` (default)** | If **every** staged path matches a **doc / ops-only** allowlist (`*.md`, `docs/*`, `.github/*`, common image extensions, `.gitignore`, `.secrets.baseline`, …), **E2E is skipped**. **Any other** staged file runs E2E. |
| **Force E2E** | `REMOTE_SIGNER_FORCE_PRE_COMMIT_E2E=1` or `REMOTE_SIGNER_PRE_COMMIT_E2E=force` |
| **Skip E2E** | `REMOTE_SIGNER_SKIP_PRE_COMMIT_E2E=1` or `REMOTE_SIGNER_PRE_COMMIT_E2E=skip` (escape hatch; prefer fixing the environment) |

When E2E runs, the hook uses `GOMAXPROCS=1`, `go test -p 1`, a **10m** timeout, and `-skip 'TestSimulate_'` (external RPC gateway; too slow for local hooks).

**Pre-push** still runs `go test ./...` (see the `pre-push` hook in the same installer script). Remote CI may add additional jobs; local hooks are an extra safety net, not a substitute for full pipeline coverage.

## E2E Tests

E2E tests verify the complete signing workflow against a running server.

### Internal Test Server (Default)

The simplest way — automatically starts an in-memory test server:

```bash
go test -tags=e2e ./e2e/...
```

For a closer match to what **pre-commit** runs when E2E is enabled:

```bash
GOMAXPROCS=1 E2E_API_PORT=18548 go test -p 1 -tags=e2e ./e2e/... -count=1 -timeout 10m -skip 'TestSimulate_'
```

### External Server

For testing against your own running server:

1. **If Docker was previously used:** stop it first to free port 8548: `./scripts/deploy.sh down`
2. Start your server with the signer and API keys configured
2. Set environment variables and run:

```bash
export E2E_EXTERNAL_SERVER=true
export E2E_BASE_URL=http://localhost:8548
export E2E_API_KEY_ID=your-admin-api-key-id
export E2E_PRIVATE_KEY=your-ed25519-private-key-hex  # 128 hex chars (64 bytes)

# Optional
export E2E_SIGNER_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
export E2E_CHAIN_ID=1
export E2E_NONADMIN_API_KEY_ID=your-nonadmin-api-key-id
export E2E_NONADMIN_PRIVATE_KEY=nonadmin-ed25519-private-key-hex

go test -tags=e2e ./e2e/...
```

### E2E Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `E2E_EXTERNAL_SERVER` | No | `false` | Set `true` to use external server |
| `E2E_BASE_URL` | No | `http://localhost:8548` | Server URL |
| `E2E_API_KEY_ID` | Yes* | -- | Admin API key ID (*required for external) |
| `E2E_PRIVATE_KEY` | Yes* | -- | Admin Ed25519 private key (hex) |
| `E2E_SIGNER_ADDRESS` | No | `0xf39Fd6e...` | Signer address for tests |
| `E2E_CHAIN_ID` | No | `1` | Chain ID for tests |
| `E2E_NONADMIN_API_KEY_ID` | No | -- | Non-admin key ID (permission tests) |
| `E2E_NONADMIN_PRIVATE_KEY` | No | -- | Non-admin private key |

When using external server mode, ensure your server has:
- The API key configured with matching public key
- A signer configured for the test signer address
- Appropriate whitelist rules to allow sign requests

## Rule Validation

Validate rules without starting the server:

```bash
remote-signer-cli validate -config config.yaml
```

## Coverage Targets

| Component | Target |
|-----------|--------|
| Overall | 85% |
| `internal/chain/evm` | 85% |
| Rule evaluation (JS) | < 10ms |
| Rule evaluation (Solidity) | 100ms -- 2s |

See [PERFORMANCE.md](PERFORMANCE.md) for benchmark details.
