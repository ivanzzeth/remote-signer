# Remote Signer

A modular, stateless, secure signing service with multi-chain extensibility. Built on top of `ethsig` for EVM chains, with architecture ready for Solana/Cosmos/Bitcoin.

## Features

- **Multi-Chain Support**: Extensible architecture supporting EVM chains, with future support for Solana, Cosmos, Bitcoin
- **Whitelist-Based Authorization**: Rule engine with whitelist logic (any rule match = allow)
- **Manual Approval Workflow**: Notifications via Slack and Pushover for pending approvals
- **Ed25519 API Authentication**: Secure request signing with replay protection
- **Auto Rule Generation**: Automatically create rules from approved transactions
- **PostgreSQL Storage**: GORM with auto-migration for backward-compatible schema changes

## Documentation

For detailed configuration and API usage, refer to the following resources:

| Resource | Description |
|----------|-------------|
| [docs/API.md](docs/API.md) | **Complete API reference** - Authentication, endpoints, workflows, rule types, and examples |
| [configs/config.example.yaml](configs/config.example.yaml) | **Configuration template** - Full example with all options and rule definitions |

**Quick Navigation:**
- **Getting Started**: See [Quick Start](#quick-start) below
- **API Authentication**: See [docs/API.md#authentication](docs/API.md#authentication)
- **Rule Configuration**: See [docs/API.md#rules-configuration](docs/API.md#rules-configuration)
- **Solidity Expression Rules**: See [docs/API.md#rule-type-evm_solidity_expression](docs/API.md#rule-type-evm_solidity_expression)
- **EIP-712 Typed Data Validation**: See [docs/API.md#eip-712-typed-data-signing](docs/API.md#eip-712-typed-data-signing)
- **ERC-20/721/1155 Examples**: See [docs/API.md#mainstream-eip-standard-examples](docs/API.md#mainstream-eip-standard-examples)

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

## Rule Types

### Standard Rules

| Type | Description |
|------|-------------|
| evm_address_whitelist | Whitelist specific recipient addresses |
| evm_contract_method | Allow specific contract method calls |
| evm_value_limit | Limit transaction value |

### Solidity Expression Rules

For complex validation logic, use `evm_solidity_expression` rules that allow writing validation using native Solidity syntax. Two modes are supported:

#### Mode 1: Expression Mode (require statements)

Write `require()` statements with available context variables:
- `to` (address) - Transaction recipient
- `value` (uint256) - Transaction value in wei
- `selector` (bytes4) - Method selector
- `data` (bytes) - Full calldata
- `chainId` (uint256) - Chain ID
- `signer` (address) - Signing address

```solidity
require(value <= 1 ether, "exceeds 1 ETH limit");
require(to != address(0), "cannot send to zero address");
```

#### Mode 2: Function Mode (automatic selector matching)

Define functions that match transaction selectors. When a transaction's selector matches a defined function, it's automatically called with decoded parameters:

```solidity
// When tx selector is 0xa9059cbb (transfer), this function is called
function transfer(address to, uint256 amount) external {
    require(amount <= 10000e6, "exceeds 10k USDC limit");
    require(to != address(0), "invalid recipient");
}

// When tx selector is 0x095ea7b3 (approve), this function is called
function approve(address spender, uint256 amount) external {
    require(spender != address(0), "cannot approve zero address");
}
```

Context variables available in Function mode as state variables:
- `txTo`, `txValue`, `txSelector`, `txData`, `txChainId`, `txSigner`

See [docs/API.md](docs/API.md) for detailed documentation.

## Quick Start

### Prerequisites

- Go 1.24+
- PostgreSQL 14+
- Foundry (optional, for Solidity expression rules)

### Installing Foundry (Optional)

Foundry is required only if you want to use `evm_solidity_expression` rules:

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Verify installation
forge --version
```

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

#### Configuration File Structure

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: false
    cert_file: "/etc/signer/tls/cert.pem"
    key_file: "/etc/signer/tls/key.pem"

database:
  dsn: "postgres://user:password@localhost:5432/remote_signer?sslmode=disable"

chains:
  evm:
    enabled: true
    signers:
      private_keys:
        - address: "0x1234567890abcdef1234567890abcdef12345678"
          key_env: "EVM_SIGNER_KEY_1"  # env var containing private key
      # keystores:
      #   - address: "0x..."
      #     path: "/etc/signer/keystores/"
      #     password_env: "EVM_KEYSTORE_PASSWORD_1"

    # Foundry configuration (for Solidity expression rules)
    foundry:
      enabled: true           # Enable Solidity expression rules
      forge_path: ""          # Path to forge binary (empty = auto-detect from PATH)
      cache_dir: "/var/cache/remote-signer/forge"  # Cache for compiled scripts
      timeout: "30s"          # Max execution time per rule evaluation

notify:
  slack:
    enabled: false
    bot_token: "${SLACK_BOT_TOKEN}"
  pushover:
    enabled: false
    app_token: "${PUSHOVER_APP_TOKEN}"

notify_channels:
  slack: ["C1234567890"]      # Slack channel IDs
  pushover: ["user_key"]      # Pushover user keys

security:
  max_request_age: "5m"       # Prevents replay attacks
  rate_limit_default: 100     # Requests per minute

logger:
  level: "info"               # debug, info, warn, error
  pretty: true                # Pretty print for development
```

#### Foundry Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable Solidity expression rules |
| `forge_path` | string | `""` | Path to forge binary. Empty = auto-detect from PATH |
| `cache_dir` | string | `/tmp/...` | Cache directory for compiled Solidity scripts |
| `timeout` | duration | `30s` | Maximum execution time per rule evaluation |

#### Rules Configuration

Rules can be defined in config file or via API. See `configs/config.example.yaml` for complete examples.

```yaml
rules:
  # Address whitelist
  - name: "Allow treasury"
    type: "evm_address_whitelist"
    mode: "whitelist"
    enabled: true
    config:
      addresses:
        - "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"

  # Value limit
  - name: "Max 10 ETH"
    type: "evm_value_limit"
    mode: "whitelist"
    enabled: true
    config:
      max_value: "10000000000000000000"  # 10 ETH in wei

  # Solidity expression (requires Foundry)
  - name: "Custom validation"
    type: "evm_solidity_expression"
    mode: "whitelist"
    enabled: true
    config:
      expression: |
        require(value <= 1 ether, "exceeds limit");
      description: "Max 1 ETH transfer"
      test_cases:  # Required - all must pass
        - name: "pass 0.5 ETH"
          input: { value: "500000000000000000" }
          expect_pass: true
        - name: "reject 2 ETH"
          input: { value: "2000000000000000000" }
          expect_pass: false
          expect_reason: "exceeds limit"
```

**Rule Types:**

| Type | Description |
|------|-------------|
| `evm_address_whitelist` | Whitelist recipient addresses |
| `evm_contract_method` | Allow specific contract methods |
| `evm_value_limit` | Limit transaction value |
| `evm_solidity_expression` | Custom Solidity validation (requires Foundry) |

**Rule Modes:**
- `whitelist`: Any match = auto-approve
- `blocklist`: Any match = block (checked first)

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

## Roadmap

### Planned Features

- [x] **EIP-712 Typed Data Validation**: Parameter-level validation for EIP-712 signed messages (Permit, Seaport orders, Permit2, etc.) using `typed_data_expression` and `typed_data_functions` modes
- [ ] **Solidity Rule Coverage Enforcement**: Integrate `forge coverage` to enforce minimum branch coverage threshold for `evm_solidity_expression` rules. Rules with insufficient test coverage would be rejected.
- [ ] **Solana Chain Support**: Add Solana signing adapter
- [ ] **Cosmos Chain Support**: Add Cosmos/Tendermint signing adapter
- [ ] **Bitcoin Chain Support**: Add Bitcoin signing adapter
- [ ] **Web UI**: Admin dashboard for rule management and approval workflow
- [ ] **Audit Log Export**: Export audit logs to external systems (S3, Elasticsearch)

## License

MIT License
