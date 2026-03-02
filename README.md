# Remote Signer

A secure, policy-driven signing service for EVM chains. Controls **what** gets signed through a rule engine, not just **who** can sign.

## Features

- **Policy-Driven Signing** -- Whitelist/blocklist rules with Solidity expressions, JS rules, address lists, value limits
- **Multi-Chain Extensible** -- EVM today, Solana/Cosmos/Bitcoin ready architecture
- **Manual Approval Workflow** -- Slack, Pushover, and webhook notifications for pending approvals
- **Ed25519 API Authentication** -- Secure request signing with nonce + timestamp replay protection
- **Dynamic Signer Management** -- Create keystores and HD wallets at runtime via API or TUI
- **Terminal UI (TUI)** -- Manage rules, approve requests, create signers from the terminal

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         API Layer                                │
│  /api/v1/evm/sign    /api/v1/solana/sign    /api/v1/.../sign   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                       Core Layer                                 │
│   SignService  │  RuleEngine  │  StateMachine  │  AuditLogger   │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                     Chain Adapter Layer                           │
│      EVM Adapter (ethsig)  │  Solana / Cosmos / ... (future)    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                      Storage Layer                               │
│              GORM + PostgreSQL / SQLite                           │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### One-Line Install (recommended)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ivanzzeth/remote-signer/main/scripts/setup.sh)
```

This auto-clones the repo (if needed), installs dependencies, and runs the guided setup.

### Or Manual Clone

```bash
git clone https://github.com/ivanzzeth/remote-signer.git
cd remote-signer
./scripts/setup.sh
```

### Prerequisites

- openssl
- Docker (recommended) or Go 1.24+ (for local mode)

### What the Setup Wizard Does

The interactive setup walks through 5 steps:
1. **Deployment mode** -- Docker + PostgreSQL (recommended) or Local + SQLite (dev only)
2. **API keys** -- Generates `admin` and `dev` Ed25519 key pairs
3. **TLS** -- HTTP, TLS, or mTLS (Docker defaults to mTLS)
4. **Configuration** -- Writes a ready-to-run config file with auto-generated secrets
5. **Next steps** -- Start command, health check, how to add signers

After setup:

```bash
# Start (Docker mode, recommended)
./scripts/deploy.sh run

# Or start (Local mode)
./scripts/deploy.sh local-run

# Health check (HTTP)
curl http://localhost:8548/health

# Health check (mTLS)
curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key https://localhost:8548/health
```

### Manual Setup

If you prefer manual control, see [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the full config reference and use `config.example.yaml` as a starting point.

### Adding Signers

The server starts without signers. Add them after startup:

- **TUI**: `go build -o remote-signer-tui ./cmd/tui` then connect with the `admin` key. Use the Signers tab to create keystores or HD wallets.
- **API**: `POST /api/v1/evm/signers` (admin only). See [docs/API.md](docs/API.md).
- **Config**: Edit `chains.evm.signers.private_keys` in your config file. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md#chains-evm).

## Supported Sign Types

| Type | Description |
|------|-------------|
| `hash` | Sign pre-hashed data (32 bytes) |
| `raw_message` | Sign raw bytes |
| `eip191` | Sign EIP-191 formatted message |
| `personal` | Sign personal message (`\x19Ethereum Signed Message:\n`) |
| `typed_data` | Sign EIP-712 typed data |
| `transaction` | Sign transaction (Legacy/EIP-2930/EIP-1559) |

## Documentation

### Getting Started

| Document | Description |
|----------|-------------|
| [Use Cases](docs/USE_CASES.md) | Treasury, bot, DeFi scenarios |
| [Architecture](docs/ARCHITECTURE.md) | System design, layers, adapters |

### Configure

| Document | Description |
|----------|-------------|
| [Configuration Reference](docs/CONFIGURATION.md) | Full `config.yaml` reference |
| [Rule Syntax Reference](docs/RULE_SYNTAX.md) | All rule types: address list, value limit, Solidity, JS, message pattern |
| [JS Rules (evm_js)](docs/architecture/js-rules-v5.md) | In-process JavaScript rules via Sobek |
| [config.example.yaml](config.example.yaml) | Annotated configuration template |

### Integrate

| Document | Description |
|----------|-------------|
| [API Reference](docs/API.md) | Complete endpoint docs: authentication, signing, rules, audit |
| [Integration Guide](INTEGRATION.md) | JS/TS client library, MetaMask Snap |

### Deploy & Operate

| Document | Description |
|----------|-------------|
| [Deployment Guide](docs/DEPLOYMENT.md) | Docker, Kubernetes, HA, monitoring, backup |
| [TLS / mTLS Guide](docs/TLS.md) | Certificate trust model, generation, production best practices |
| [TUI Guide](docs/TUI.md) | Terminal UI: build, run, key bindings |

### Security

| Document | Description |
|----------|-------------|
| [Security Overview](docs/SECURITY.md) | Defense-in-depth: 8 layers from network to application |
| [Security Review](docs/SECURITY_REVIEW.md) | Findings, priorities, implementation status |

### Development

| Document | Description |
|----------|-------------|
| [Components](docs/COMPONENTS.md) | Core interfaces, data types, services |
| [Request Flow](docs/FLOW.md) | 8-step signing flow with state machine |
| [Testing Guide](docs/TESTING.md) | Unit tests, E2E, rule validation, coverage |

## Roadmap

- [x] EIP-712 Typed Data Validation
- [x] Terminal UI (TUI)
- [x] Go Client SDK
- [x] JS/TS Client SDK
- [ ] Solidity Rule Coverage Enforcement
- [ ] Solana Chain Support
- [ ] Cosmos Chain Support
- [ ] Bitcoin Chain Support
- [ ] Web UI Dashboard
- [ ] Audit Log Export (S3, Elasticsearch)

## License

MIT License
