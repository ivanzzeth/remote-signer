# Remote Signer

A modular, stateless, secure signing service with multi-chain extensibility. Built on top of `ethsig` for EVM chains, with architecture ready for Solana/Cosmos/Bitcoin.

## Features

- **Multi-Chain Support**: Extensible architecture supporting EVM chains, with future support for Solana, Cosmos, Bitcoin
- **Whitelist-Based Authorization**: Rule engine with whitelist logic (any rule match = allow)
- **Manual Approval Workflow**: Notifications via Slack and Pushover for pending approvals
- **Ed25519 API Authentication**: Secure request signing with replay protection
- **Auto Rule Generation**: Automatically create rules from approved transactions
- **PostgreSQL Storage**: GORM with auto-migration for backward-compatible schema changes

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
│                     Chain Adapter Layer                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ EVM Adapter │  │Solana Adapter│  │Cosmos Adapter│  (future)   │
│  │  (ethsig)   │  │  (future)   │  │  (future)   │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                      Storage Layer                               │
│              GORM + PostgreSQL (auto-migration)                  │
└─────────────────────────────────────────────────────────────────┘
```

## Request Status Flow

```
pending → authorizing  (on validation pass)
pending → rejected     (on validation fail)

authorizing → signing  (on rule match OR manual approval)
authorizing → rejected (on manual rejection)

signing → completed    (on sign success)
signing → failed       (on sign error)
```

## Supported Sign Types (EVM)

| Type | Description |
|------|-------------|
| hash | Sign pre-hashed data (32 bytes) |
| raw_message | Sign raw bytes |
| eip191 | Sign EIP-191 formatted message |
| personal | Sign personal message (`\x19Ethereum Signed Message:\n`) |
| typed_data | Sign EIP-712 typed data |
| transaction | Sign transaction (Legacy/EIP-2930/EIP-1559) |

## Quick Start

### Prerequisites

- Go 1.24+
- PostgreSQL 14+

### Installation

```bash
# Clone the repository
git clone https://github.com/ivanzzeth/remote-signer.git
cd remote-signer

# Build
go build -o remote-signer ./cmd/remote-signer
```

### Configuration

```bash
# Copy example config
cp configs/config.example.yaml config.yaml

# Edit configuration
vim config.yaml
```

### Environment Variables

Set sensitive values via environment variables:

```bash
# EVM signer private key (hex, without 0x prefix)
export EVM_SIGNER_KEY_1="your_private_key_hex"

# Notification tokens (optional)
export SLACK_BOT_TOKEN="xoxb-..."
export PUSHOVER_APP_TOKEN="..."
```

### Run

```bash
./remote-signer -config config.yaml
```

## API Authentication

All API requests must be signed using Ed25519. The client signs:

```
{timestamp}|{method}|{path}|{sha256(body)}
```

Required headers:
- `X-API-Key-ID`: API key identifier
- `X-Timestamp`: Unix timestamp in milliseconds
- `X-Signature`: Base64-encoded Ed25519 signature

## API Endpoints

See [docs/API.md](docs/API.md) for detailed API documentation.

### Quick Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/v1/evm/sign` | Submit sign request |
| GET | `/api/v1/evm/requests` | List sign requests |
| GET | `/api/v1/evm/requests/{id}` | Get sign request |
| POST | `/api/v1/evm/requests/{id}/approve` | Approve/reject request |

## Project Structure

```
remote-signer/
├── cmd/remote-signer/      # Application entry point
├── internal/
│   ├── api/                # HTTP handlers, router, server
│   ├── chain/              # Chain adapters (EVM, future chains)
│   ├── config/             # Configuration loading
│   ├── core/               # Core business logic
│   │   ├── auth/           # Ed25519 authentication
│   │   ├── rule/           # Rule engine
│   │   ├── service/        # Sign and approval services
│   │   ├── statemachine/   # Request state machine
│   │   └── types/          # Core data types
│   ├── logger/             # Logging utilities
│   ├── notify/             # Notification (Slack, Pushover)
│   └── storage/            # Database repositories
├── configs/                # Configuration examples
└── docs/                   # Documentation
```

## Adding New Chain Support

To add support for a new chain (e.g., Solana):

1. Create chain package: `internal/chain/solana/`
2. Define types: `internal/chain/solana/types.go`
3. Implement `ChainAdapter` interface: `internal/chain/solana/adapter.go`
4. Implement signer registry: `internal/chain/solana/signer.go`
5. Implement rule evaluators: `internal/chain/solana/rule_evaluator.go`
6. Add API handlers: `internal/api/handler/solana/`
7. Register adapter in `main.go`

## License

MIT License
