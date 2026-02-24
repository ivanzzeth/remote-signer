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
| [config.example.yaml](config.example.yaml) | **Configuration template** - Full example with all options, API keys, and rule definitions |

**Quick Navigation:**
- **Getting Started**: See [Quick Start](#quick-start) below
- **Client SDKs**: See [Client SDKs](#client-sdks) for Go and JS/TS client usage with TLS
- **TLS Configuration**: See [TLS Configuration](#tls-configuration) for HTTPS setup and certificate generation
- **TUI Management Interface**: See [TUI (Terminal User Interface)](#tui-terminal-user-interface)
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
| evm_address_list | Allow/block recipient addresses (mode: whitelist or blocklist) |
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
- PostgreSQL 14+ (or SQLite for development)
- Foundry (optional, for Solidity expression rules)

**Fastest path (SQLite, no PostgreSQL):** Clone, `go build -o remote-signer ./cmd/remote-signer`, copy `config.example.yaml` to `config.yaml`, set `database.dsn` to `file:./data/remote-signer.db?_journal_mode=WAL&_busy_timeout=5000`, then follow [Step 1](#step-1-generate-api-key-ed25519)–[Step 4](#step-4-run). Use `./remote-signer` (default config is `config.yaml`).

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

### Step 1: Generate API Key (Ed25519)

Before configuring, generate an Ed25519 key pair for API authentication:

```bash
# Generate Ed25519 key pair
openssl genpkey -algorithm ed25519 -out data/api_private.pem
openssl pkey -in data/api_private.pem -pubout -out data/api_public.pem

# Extract base64 keys (easier to use)
# Private key (keep secret! for client/TUI to sign requests):
openssl pkey -in data/api_private.pem -outform DER | base64
# Example output: MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/Vpguoq...

# Public key (for config file):
openssl pkey -in data/api_public.pem -pubin -outform DER | base64
# Example output: MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQH...
```

Both **hex** and **base64** formats are supported. Save the keys - you'll need them in the next steps.

### Step 2: Generate EVM Signer Key

Generate or prepare the private key for signing EVM transactions:

```bash
# Option A: Generate a new key (for testing)
openssl rand -hex 32 > data/evm_signer_key.txt

# Option B: Use an existing private key (hex, without 0x prefix)
# Get the address for this key using cast or ethers

# Set environment variable
export EVM_SIGNER_KEY_1=$(cat data/evm_signer_key.txt)
```

### Step 3: Configuration

Now you have all keys ready. Create the config file:

```bash
# Copy example config
cp config.example.yaml config.yaml

# Edit configuration
vim config.yaml
```

#### Configuration File Structure

```yaml
server:
  host: "0.0.0.0"
  port: 8548
  tls:
    enabled: false
    cert_file: "/etc/signer/tls/cert.pem"
    key_file: "/etc/signer/tls/key.pem"

database:
  # PostgreSQL (production)
  dsn: "postgres://user:password@localhost:5432/remote_signer?sslmode=disable"
  # SQLite (development)
  # dsn: "file:./remote-signer.db?_journal_mode=WAL&_busy_timeout=5000"

chains:
  evm:
    enabled: true
    signers:
      private_keys:
        - address: "0x..."              # Address derived from EVM_SIGNER_KEY_1
          key_env: "EVM_SIGNER_KEY_1"   # env var set in Step 2
          enabled: true
      # keystores:
      #   - address: "0x..."
      #     path: "data/keystores/"
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

# API Keys - use the public key generated in Step 1
api_keys:
  - id: "my-app-key"                    # Your chosen API Key ID
    name: "My Application"
    public_key: "MCowBQYDK2VwAyEA..."   # Base64 or hex format (auto-detected)
    enabled: true
    rate_limit: 100
```

### Step 4: Run

```bash
# Set environment variables
export EVM_SIGNER_KEY_1=$(cat data/evm_signer_key.txt)

# Run the server (default config: config.yaml)
./remote-signer
# Or: ./remote-signer -config config.yaml
```

#### API Keys Configuration

API keys authenticate clients to the signing service. Each key consists of:
- **id**: Unique identifier used in the `X-API-Key-ID` header
- **public_key** or **public_key_env**: Ed25519 public key (hex or base64, auto-detected) or env var containing it
- **enabled**: Whether the key is active
- **rate_limit**: Max requests per minute (default: 100)
- **allowed_chain_types**: Restrict to specific chains (empty = all)
- **allowed_signers**: Restrict to specific signers (empty = all)

Keys defined in the config file are synced to the database on startup.

#### Foundry Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable Solidity expression rules |
| `forge_path` | string | `""` | Path to forge binary. Empty = auto-detect from PATH |
| `cache_dir` | string | `/tmp/...` | Cache directory for compiled Solidity scripts |
| `timeout` | duration | `30s` | Maximum execution time per rule evaluation |

#### Rules Configuration

Rules can be defined in config file or via API. See `config.example.yaml` for complete examples.

```yaml
rules:
  # Address list (whitelist mode = allow these addresses)
  - name: "Allow treasury"
    type: "evm_address_list"
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
| `signer_restriction` | Allow/block specific signer addresses |
| `sign_type_restriction` | Allow/block specific signing methods |
| `evm_address_list` | Allow/block recipient addresses (whitelist or blocklist mode) |
| `evm_contract_method` | Allow specific contract methods |
| `evm_value_limit` | Limit transaction value |
| `evm_solidity_expression` | Custom Solidity validation (requires Foundry) |

**Sign Types** (for `sign_type_restriction`):
- `hash` - Sign pre-hashed data (32 bytes)
- `raw_message` - Sign raw bytes
- `eip191` - Sign EIP-191 formatted message
- `personal` - Sign personal message (`eth_sign`, `personal_sign`)
- `typed_data` - Sign EIP-712 typed data (`eth_signTypedData_v4`)
- `transaction` - Sign transaction (Legacy/EIP-2930/EIP-1559)

**Rule Modes:**
- `whitelist`: Any match = auto-approve
- `blocklist`: Any match = block (checked first)

**Important: Solidity Expression Rules and Rule Modes**

For `evm_solidity_expression` rules, the `require()` statement semantics differ based on rule mode:

| Mode | `require()` passes | `require()` reverts |
|------|-------------------|---------------------|
| `whitelist` | Rule matches → **auto-approve** | Rule doesn't match → needs manual approval |
| `blocklist` | No violation → **allow** | Violation found → **block** |

Example blocklist rule to block burn address:
```yaml
- name: "Block burn address"
  type: "evm_solidity_expression"
  mode: "blocklist"
  config:
    expression: |
      require(to != 0x000000000000000000000000000000000000dEaD, "blocked: burn address");
```

In this blocklist rule:
- Normal address (e.g., `0x1234...`): `require(to != 0xdEaD)` **passes** → No violation → Transaction allowed
- Burn address (`0xdEaD`): `require(to != 0xdEaD)` **reverts** → Violation found → Transaction blocked with reason "blocked: burn address"

### TLS / mTLS Configuration

Remote-signer supports TLS (HTTPS) and mutual TLS (mTLS) where both server and client verify each other's certificates. mTLS is recommended for internal services.

#### Option 1: Generate Self-Signed CA + mTLS Certificates (Recommended for Internal Services)

The `gen-certs` command creates a complete self-signed CA trust chain with server and client certificates:

```bash
# Generate all certificates (auto-detects LAN IP)
./scripts/deploy.sh gen-certs

# Or with extra SAN IPs for LAN access
./scripts/deploy.sh gen-certs 10.0.0.5

# Generated files in certs/:
#   ca.crt / ca.key          - Certificate Authority
#   server.crt / server.key  - Server certificate (SAN: localhost, 127.0.0.1, ::1, LAN IP)
#   client.crt / client.key  - Client certificate (for mTLS)
```

#### Option 2: Use Let's Encrypt (Public-Facing Production)

For production environments exposed to the internet:

```bash
sudo certbot certonly --standalone -d signer.example.com

# Certificates at:
# /etc/letsencrypt/live/signer.example.com/fullchain.pem
# /etc/letsencrypt/live/signer.example.com/privkey.pem
```

#### Enable TLS/mTLS in Configuration

```yaml
server:
  host: "0.0.0.0"
  port: 8548
  tls:
    enabled: true
    cert_file: "./certs/server.crt"    # Server certificate
    key_file: "./certs/server.key"     # Server private key
    ca_file: "./certs/ca.crt"          # CA certificate (for verifying client certs)
    client_auth: true                  # Enable mTLS (require client certificate)
```

Set `client_auth: false` for TLS-only mode (no client certificate required).

#### Verify TLS/mTLS

```bash
# View certificate details
openssl x509 -in certs/server.crt -text -noout

# Test TLS connection
openssl s_client -connect localhost:8548 -CAfile certs/ca.crt

# Health check with mTLS
curl --cacert certs/ca.crt \
     --cert certs/client.crt \
     --key certs/client.key \
     https://localhost:8548/health

# Or use the auto-detecting status command
./scripts/deploy.sh status
```

#### TUI with TLS/mTLS

When connecting to a TLS-enabled server:

```bash
# With self-signed CA (TLS only, no mTLS)
SSL_CERT_FILE=certs/ca.crt ./remote-signer-tui \
  -url https://localhost:8548 \
  -api-key-id your-api-key-id \
  -private-key your-ed25519-private-key

# With mTLS, the TUI client needs client certificates
# (configure via environment or client SDK TLS options)
```

### Environment Variables

Set sensitive values via environment variables:

```bash
# EVM signer private key (hex, without 0x prefix) - see Step 2
export EVM_SIGNER_KEY_1="your_private_key_hex"

# Notification tokens (optional)
export SLACK_BOT_TOKEN="xoxb-..."
export PUSHOVER_APP_TOKEN="..."
```

## Deployment

Two deployment options:

| Mode | Description |
|------|-------------|
| **Direct build** | Compile the Go binary and run it on the host (optionally via `scripts/deploy.sh local-run`). Use SQLite or PostgreSQL. |
| **Docker** | Run with Docker Compose; includes PostgreSQL. Suited for production. |

The `scripts/deploy.sh` script supports both: **local** (direct build, no Docker) and **Docker**.

### Direct build (Local Deployment, recommended for development)

Run the binary directly on the host. It uses SQLite by default (no PostgreSQL needed) and supports interactive keystore password input via `screen`.

```bash
# 1. Initialize environment (creates directories, .env, config files)
./scripts/deploy.sh init

# 2. Generate TLS/mTLS certificates (CA + server + client)
./scripts/deploy.sh gen-certs
# Or with extra SAN IPs:
./scripts/deploy.sh gen-certs 10.0.0.5

# 3. Create local config with SQLite database
#    config.local.yaml is auto-preferred over config.yaml by local-run
#    Key difference: uses SQLite instead of PostgreSQL
#      dsn: "file:./data/remote-signer.db?_journal_mode=WAL&_busy_timeout=5000"
cp config.example.yaml config.local.yaml
# Edit config.local.yaml:
#   - Set database.dsn to SQLite path (see above)
#   - Enable TLS/mTLS if certs were generated
#   - Configure API keys, rules, etc.

# 4. Build & start (opens screen session for keystore password input)
./scripts/deploy.sh local-run
# >>> Enter keystore password when prompted
# >>> Press Ctrl+A then D to detach screen

# 5. Check status (auto-detects TLS and local/docker mode)
./scripts/deploy.sh status

# 6. View logs / reattach / stop
./scripts/deploy.sh local-logs
./scripts/deploy.sh local-attach
./scripts/deploy.sh local-down
```

#### Local Deploy Script Commands

| Command | Description |
|---------|-------------|
| `local-run` | Build Go binary & start in screen session (interactive for keystore password) |
| `local-down` | Stop locally running remote-signer |
| `local-logs` | Tail local log file |
| `local-attach` | Reattach to the running screen session |
| `gen-certs` | Generate self-signed CA + server + client TLS certificates |
| `status` | Auto-detect TLS/mTLS and local/docker mode, run health check |

#### Config Files

| File | Database | Used By |
|------|----------|---------|
| `config.local.yaml` | SQLite (local file) | `local-run` (preferred) |
| `config.yaml` | PostgreSQL | `local-run` (fallback), Docker |
| `config.example.yaml` | — | Template for both |

#### TLS/mTLS Verification

After starting with TLS enabled:

```bash
# Health check with mTLS (client certificate required)
curl --cacert certs/ca.crt \
     --cert certs/client.crt \
     --key certs/client.key \
     https://localhost:8548/health

# Or just use the status command (auto-detects TLS config)
./scripts/deploy.sh status
```

### Docker Deployment

For production deployment with PostgreSQL, use Docker with the provided scripts.

```bash
# 1. Initialize environment (creates directories, .env, config.yaml)
./scripts/deploy.sh init

# 2. Edit configuration files
# - Edit .env with your EVM signer private key
# - Edit config.yaml with your settings
# - Add the generated API public key to config.yaml

# 3. Generate TLS certificates (optional)
./scripts/deploy.sh gen-certs

# 4. Start remote-signer interactively (for keystore password)
./scripts/deploy.sh run
# Or start all services in background (no keystore password prompt)
./scripts/deploy.sh up

# 5. Check status
./scripts/deploy.sh status
```

#### Docker Deploy Script Commands

| Command | Description |
|---------|-------------|
| `init` | Initialize deployment environment (create directories, generate keys) |
| `up` | Start all services (background mode) |
| `run` | Start remote-signer interactively in screen (for password input) |
| `attach` | Reattach to running Docker screen session |
| `down` | Stop all services |
| `restart` | Restart remote-signer interactively |
| `logs` | View Docker service logs |
| `build` | Build Docker images |
| `clean` | Remove all containers and volumes |

### Generate Keys

```bash
# Generate API key pair
./scripts/generate-api-key.sh

# Generate API key with custom name
./scripts/generate-api-key.sh -n admin

# Generate TLS certificates (CA + server + client for mTLS)
./scripts/deploy.sh gen-certs

# Generate TLS certificates with extra SAN IPs
./scripts/deploy.sh gen-certs 10.0.0.5 172.16.0.1
```

### Environment Variables (.env)

```bash
# PostgreSQL (Docker mode only)
POSTGRES_USER=signer
POSTGRES_PASSWORD=your_secure_password
POSTGRES_DB=remote_signer

# EVM Signer (hex private key, without 0x prefix)
EVM_SIGNER_KEY_1=your_64_char_hex_private_key

# Optional: Notifications
SLACK_BOT_TOKEN=xoxb-...
PUSHOVER_APP_TOKEN=...
```

### Docker Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Docker Network                    │
│                                                     │
│  ┌─────────────────┐      ┌─────────────────────┐  │
│  │   PostgreSQL    │◄────►│   Remote Signer     │  │
│  │   (postgres)    │      │   (remote-signer)   │  │
│  │                 │      │                     │  │
│  │   Port: 5432    │      │   Port: 8548        │  │
│  └─────────────────┘      │   + Foundry (forge) │  │
│                           └─────────────────────┘  │
│                                    │               │
└────────────────────────────────────┼───────────────┘
                                     │
                                     ▼
                              External Access
                              (localhost:8548)
```

## TUI (Terminal User Interface)

The remote-signer includes a terminal-based management interface for monitoring and managing the signing service.

### Build the TUI

```bash
go build -o remote-signer-tui ./cmd/tui
```

### Run the TUI

```bash
# Using command line flags (supports both hex and base64 format, auto-detected)
./remote-signer-tui \
  -url http://localhost:8548 \
  -api-key-id your-api-key-id \
  -private-key your-ed25519-private-key

# Or using environment variables
export REMOTE_SIGNER_URL=http://localhost:8548
export REMOTE_SIGNER_API_KEY_ID=your-api-key-id
export REMOTE_SIGNER_PRIVATE_KEY=your-ed25519-private-key
./remote-signer-tui
```

### TUI Parameters

| Flag | Env Variable | Default | Description |
|------|--------------|---------|-------------|
| `-url` | `REMOTE_SIGNER_URL` | `http://localhost:8548` | Remote signer service URL |
| `-api-key-id` | `REMOTE_SIGNER_API_KEY_ID` | (required) | API key ID registered on the server |
| `-private-key` | `REMOTE_SIGNER_PRIVATE_KEY` | (required) | Ed25519 private key (hex or base64, auto-detected) |

### TUI Features

- **Dashboard**: Service health, request counts by status, rules summary
- **Requests**: View all sign requests, filter by status, approve/reject pending requests
- **Rules**: View/edit authorization rules, toggle enable/disable, delete rules
- **Audit Logs**: View all audit events, filter by event type or severity

### TUI Key Bindings

| Key | Action |
|-----|--------|
| `1-4` / `Tab` | Switch tabs (Dashboard, Requests, Rules, Audit) |
| `↑/↓` or `j/k` | Navigate lists |
| `Enter` | View details |
| `a` | Approve request (with optional rule generation) |
| `x` | Reject request |
| `t` | Toggle rule enabled/disabled |
| `d` | Delete rule |
| `f` | Filter lists |
| `r` | Refresh |
| `?` | Show help |
| `q` | Quit |

## Client SDKs

Remote-signer provides official client SDKs for Go and JavaScript/TypeScript.

### Go Client

```go
import client "github.com/ivanzzeth/remote-signer/pkg/client"

// Basic (no TLS)
c, err := client.NewClient(client.Config{
    BaseURL:       "http://localhost:8548",
    APIKeyID:      "my-api-key",
    PrivateKeyHex: "your-ed25519-private-key-hex",
})

// With TLS + mTLS (self-signed CA)
c, err := client.NewClient(client.Config{
    BaseURL:       "https://localhost:8549",
    APIKeyID:      "my-api-key",
    PrivateKeyHex: "your-ed25519-private-key-hex",
    TLSCAFile:     "certs/ca.crt",     // CA to verify server cert
    TLSCertFile:   "certs/client.crt", // Client certificate (mTLS)
    TLSKeyFile:    "certs/client.key", // Client private key (mTLS)
})
```

### JavaScript/TypeScript Client

```bash
npm install @remote-signer/client
```

**Browser (behind reverse proxy, standard HTTPS):**

```typescript
import { RemoteSignerClient } from '@remote-signer/client';

const client = new RemoteSignerClient({
  baseURL: 'https://signer.example.com', // Reverse proxy with public TLS cert
  apiKeyID: 'my-api-key',
  privateKey: 'your-ed25519-private-key-hex',
});

const health = await client.health();
```

**Node.js with TLS/mTLS (self-signed CA):**

```typescript
import { RemoteSignerClient } from '@remote-signer/client';
import fs from 'fs';

const client = new RemoteSignerClient({
  baseURL: 'https://localhost:8549',
  apiKeyID: 'my-api-key',
  privateKey: 'your-ed25519-private-key-hex',
  httpClient: {
    tls: {
      ca: fs.readFileSync('certs/ca.crt'),      // CA to verify server cert
      cert: fs.readFileSync('certs/client.crt'), // Client certificate (mTLS)
      key: fs.readFileSync('certs/client.key'),  // Client private key (mTLS)
    },
  },
});

const health = await client.health();
```

**Node.js with custom fetch (advanced):**

```typescript
const client = new RemoteSignerClient({
  baseURL: 'http://localhost:8548',
  apiKeyID: 'my-api-key',
  privateKey: 'your-ed25519-private-key-hex',
  httpClient: {
    fetch: myCustomFetch, // Any fetch-compatible function
  },
});
```

### Mixed Access Architecture

When you need both browser access (public) and internal service access (mTLS):

```
Browser / JS Client (HTTPS)
        │
        ▼
   Reverse Proxy (Nginx/Caddy)    ← Public TLS cert (Let's Encrypt)
        │                            Authenticates via API Key signatures
        ▼
   remote-signer (mTLS)           ← Internal, requires client certificate
        ▲
        │
   Go Client / Node.js            ← mTLS with client cert + key
```

- **Browser clients**: Connect to the reverse proxy with standard HTTPS. The reverse proxy handles mTLS to remote-signer using its own client certificate. Authentication is done via Ed25519 API key signatures.
- **Internal services**: Connect directly to remote-signer with mTLS client certificates + API key signatures.

## API Authentication

All API requests must be signed using Ed25519 key pairs.

### API Key Concept

An **API Key** in remote-signer consists of:
- **API Key ID** (`api_key_id`): A unique identifier for the key (e.g., `"my-app-key"`, `"admin-key-1"`)
- **Public Key**: Ed25519 public key stored on the server
- **Private Key**: Ed25519 private key kept by the client (never shared)

The server stores the API Key ID and its associated public key. When a client makes a request, it signs the request with its private key, and the server verifies the signature using the stored public key.

### Creating an API Key

See [Step 1: Generate API Key](#step-1-generate-api-key-ed25519) in Quick Start for detailed instructions.

**Summary:**
1. Generate Ed25519 key pair using `openssl`
2. Add public key to `config.yaml` under `api_keys`
3. Keep private key secret (for client to sign requests)

### Signing Requests

The client signs:
```
{timestamp}|{method}|{path}|{sha256(body)}
```

Required headers:
- `X-API-Key-ID`: API key identifier (the ID you registered)
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
├── cmd/
│   ├── remote-signer/      # Server application entry point
│   └── tui/                # TUI application entry point
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
├── pkg/
│   ├── client/             # Go client SDK
│   └── js-client/          # JavaScript/TypeScript client SDK
├── tui/                    # Terminal UI components
│   ├── views/              # UI views (dashboard, requests, rules, audit)
│   └── styles/             # Styling with lipgloss
├── docs/                   # Documentation
└── config.example.yaml     # Configuration template
```

## Testing

### Unit Tests

```bash
go test ./...
```

### E2E Tests

E2E tests verify the complete signing workflow against a running server.

#### Running with Internal Test Server (Default)

The simplest way to run e2e tests - automatically starts an in-memory test server:

```bash
go test -tags=e2e ./e2e/...
```

#### Running with External Server

For manual testing against your own running server:

1. Start your server with the signer and API keys configured
2. Set environment variables and run tests:

```bash
# Required environment variables
export E2E_EXTERNAL_SERVER=true
export E2E_BASE_URL=http://localhost:8548
export E2E_API_KEY_ID=your-admin-api-key-id
export E2E_PRIVATE_KEY=your-ed25519-private-key-hex  # 128 hex chars (64 bytes)

# Optional: customize signer for tests
export E2E_SIGNER_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
export E2E_CHAIN_ID=1

# Optional: non-admin client for permission tests
export E2E_NONADMIN_API_KEY_ID=your-nonadmin-api-key-id
export E2E_NONADMIN_PRIVATE_KEY=nonadmin-ed25519-private-key-hex

# Run tests
go test -tags=e2e ./e2e/...
```

#### E2E Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `E2E_EXTERNAL_SERVER` | No | `false` | Set to `true` to use external server |
| `E2E_BASE_URL` | No | `http://localhost:8548` | Server URL |
| `E2E_API_KEY_ID` | Yes* | - | Admin API key ID (*required for external server) |
| `E2E_PRIVATE_KEY` | Yes* | - | Admin Ed25519 private key (hex) |
| `E2E_SIGNER_ADDRESS` | No | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` | Signer address for tests |
| `E2E_CHAIN_ID` | No | `1` | Chain ID for tests |
| `E2E_NONADMIN_API_KEY_ID` | No | - | Non-admin API key ID (for permission tests) |
| `E2E_NONADMIN_PRIVATE_KEY` | No | - | Non-admin Ed25519 private key |

**Note:** When using external server mode, ensure your server has:
- The API key configured with matching public key
- A signer configured for the test signer address
- Appropriate whitelist rules to allow sign requests

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
- [x] **Terminal UI (TUI)**: Terminal-based management interface for monitoring and managing the signing service
- [x] **Go Client SDK**: Go SDK for interacting with the remote-signer API
- [x] **JS/TS Client SDK**: JavaScript/TypeScript SDK with TLS/mTLS support (Node.js + browser)
- [ ] **Solidity Rule Coverage Enforcement**: Integrate `forge coverage` to enforce minimum branch coverage threshold for `evm_solidity_expression` rules. Rules with insufficient test coverage would be rejected.
- [ ] **Solana Chain Support**: Add Solana signing adapter
- [ ] **Cosmos Chain Support**: Add Cosmos/Tendermint signing adapter
- [ ] **Bitcoin Chain Support**: Add Bitcoin signing adapter
- [ ] **Web UI**: Web-based admin dashboard for rule management and approval workflow
- [ ] **Audit Log Export**: Export audit logs to external systems (S3, Elasticsearch)

## License

MIT License
