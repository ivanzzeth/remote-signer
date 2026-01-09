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
- PostgreSQL 14+ (or SQLite for development)
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

# Run the server
./remote-signer -config config.yaml
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
| `signer_restriction` | Allow/block specific signer addresses |
| `sign_type_restriction` | Allow/block specific signing methods |
| `evm_address_whitelist` | Whitelist recipient addresses |
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

### TLS Configuration

To enable HTTPS for the signing service, you need to configure TLS with certificate and key files.

#### Option 1: Generate Self-Signed Certificate (Development/Testing)

```bash
# Create directory for TLS files
mkdir -p data/tls

# Generate self-signed certificate (valid for 365 days)
openssl req -x509 -newkey rsa:4096 -keyout data/tls/key.pem -out data/tls/cert.pem -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

# For production with specific domain:
openssl req -x509 -newkey rsa:4096 -keyout data/tls/key.pem -out data/tls/cert.pem -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=signer.example.com"
```

**Parameters explained:**
- `-x509`: Generate self-signed certificate (not a certificate request)
- `-newkey rsa:4096`: Generate new 4096-bit RSA key
- `-keyout`: Output file for private key
- `-out`: Output file for certificate
- `-days 365`: Certificate validity period
- `-nodes`: Don't encrypt the private key (no password required)
- `-subj`: Certificate subject (CN should match your domain)

#### Option 2: Generate Certificate with Subject Alternative Names (SAN)

For certificates that work with multiple domains/IPs:

```bash
# Create OpenSSL config file
cat > data/tls/openssl.cnf << EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_req

[dn]
C = US
ST = State
L = City
O = Organization
CN = signer.example.com

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = signer.example.com
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = 192.168.1.100
EOF

# Generate certificate with SAN
openssl req -x509 -newkey rsa:4096 -keyout data/tls/key.pem -out data/tls/cert.pem \
  -days 365 -nodes -config data/tls/openssl.cnf
```

#### Option 3: Use Let's Encrypt (Production)

For production environments, use Let's Encrypt for free, trusted certificates:

```bash
# Install certbot
# macOS
brew install certbot

# Ubuntu/Debian
sudo apt install certbot

# Generate certificate (standalone mode - stops any running server on port 80)
sudo certbot certonly --standalone -d signer.example.com

# Certificates will be at:
# /etc/letsencrypt/live/signer.example.com/fullchain.pem
# /etc/letsencrypt/live/signer.example.com/privkey.pem
```

#### Enable TLS in Configuration

Update your `config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 8548
  tls:
    enabled: true
    cert_file: "data/tls/cert.pem"    # Path to certificate
    key_file: "data/tls/key.pem"      # Path to private key

# For Let's Encrypt:
# tls:
#   enabled: true
#   cert_file: "/etc/letsencrypt/live/signer.example.com/fullchain.pem"
#   key_file: "/etc/letsencrypt/live/signer.example.com/privkey.pem"
```

#### Verify Certificate

```bash
# View certificate details
openssl x509 -in data/tls/cert.pem -text -noout

# Test TLS connection
openssl s_client -connect localhost:8548 -showcerts

# Test with curl (use -k for self-signed)
curl -k https://localhost:8548/health
```

#### TUI with TLS

When connecting to a TLS-enabled server:

```bash
# Using HTTPS URL
./remote-signer-tui \
  -url https://localhost:8548 \
  -api-key-id your-api-key-id \
  -private-key your-ed25519-private-key

# For self-signed certificates, you may need to set:
export SSL_CERT_FILE=data/tls/cert.pem
# Or disable verification (not recommended for production)
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

## Docker Deployment

For production deployment, use Docker with the provided scripts.

### Quick Start with Docker

```bash
# 1. Initialize environment (creates directories, .env, config.yaml)
./scripts/deploy.sh init

# 2. Edit configuration files
# - Edit .env with your EVM signer private key
# - Edit data/config.yaml with your settings
# - Add the generated API public key to data/config.yaml

# 3. Start services
./scripts/deploy.sh up

# 4. Check status
./scripts/deploy.sh status
```

### Deployment Scripts

| Script | Description |
|--------|-------------|
| `scripts/deploy.sh` | Main deployment script (init, up, down, logs, status) |
| `scripts/generate-api-key.sh` | Generate Ed25519 API key pair |
| `scripts/generate-tls-cert.sh` | Generate self-signed TLS certificate |

### Deploy Script Commands

```bash
# Initialize environment (first time setup)
./scripts/deploy.sh init

# Start all services
./scripts/deploy.sh up

# Stop all services
./scripts/deploy.sh down

# View logs
./scripts/deploy.sh logs
./scripts/deploy.sh logs -f  # Follow logs

# Check service status
./scripts/deploy.sh status

# Rebuild Docker images
./scripts/deploy.sh build

# Clean up (remove containers and volumes)
./scripts/deploy.sh clean
```

### Generate Keys

```bash
# Generate API key pair
./scripts/generate-api-key.sh

# Generate API key with custom name
./scripts/generate-api-key.sh -n admin

# Generate TLS certificate
./scripts/generate-tls-cert.sh

# Generate TLS certificate for specific domain
./scripts/generate-tls-cert.sh -d signer.example.com

# Generate TLS certificate with additional IPs
./scripts/generate-tls-cert.sh -d signer.example.com -i 192.168.1.100
```

### Docker Configuration Files

After running `./scripts/deploy.sh init`, you'll have:

```
remote-signer/
├── .env                    # Environment variables (PostgreSQL, EVM keys)
├── data/
│   ├── config.yaml         # Service configuration
│   ├── tls/                # TLS certificates (optional)
│   │   ├── cert.pem
│   │   └── key.pem
│   ├── api_private.pem     # API private key (for TUI client)
│   └── api_public.pem      # API public key (add to config.yaml)
└── docker-compose.yml
```

### Environment Variables (.env)

```bash
# PostgreSQL
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
│   └── client/             # Go client SDK
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
- [ ] **Solidity Rule Coverage Enforcement**: Integrate `forge coverage` to enforce minimum branch coverage threshold for `evm_solidity_expression` rules. Rules with insufficient test coverage would be rejected.
- [ ] **Solana Chain Support**: Add Solana signing adapter
- [ ] **Cosmos Chain Support**: Add Cosmos/Tendermint signing adapter
- [ ] **Bitcoin Chain Support**: Add Bitcoin signing adapter
- [ ] **Web UI**: Web-based admin dashboard for rule management and approval workflow
- [ ] **Audit Log Export**: Export audit logs to external systems (S3, Elasticsearch)

## License

MIT License
