**[中文](README.zh.md)** | English

---

# Remote Signer

A secure, policy-driven signing service for EVM chains. Controls **what** gets signed through a rule engine, not just **who** can sign.

## Features

- **Policy-Driven Signing** -- Whitelist/blocklist rules with Solidity expressions, JS rules, address lists, value limits
- **Multi-Chain Extensible** -- EVM today, Solana/Cosmos/Bitcoin ready architecture
- **Manual Approval Workflow** -- Slack, Pushover, and webhook notifications for pending approvals
- **Ed25519 API Authentication** -- Secure request signing with nonce + timestamp replay protection
- **Dynamic Signer Management** -- Create keystores and HD wallets (mnemonic wallets) at runtime via API or TUI
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

## Why Remote Signer

The most capable open-source signing service for EVM chains. Fireblocks-level policy control, self-hosted and free.

### Policy Engine

| Capability | remote-signer | Fireblocks | web3signer | Vault |
|-----------|:---:|:---:|:---:|:---:|
| Address whitelist/blocklist | Y | Y | Basic | - |
| Value limits + budgets | Y | Y | - | - |
| **JS scripting rules** | **Y** | - | - | - |
| **Solidity expression rules** | **Y** | - | - | - |
| **Composable delegation chains** | **Y** | - | - | - |
| **23 protocol templates** | **Y** | N/A | - | - |
| Multi-chain matrix presets | Y | N/A | - | - |

**23 rule templates** covering: ERC-20/721/1155, Permits (EIP-2612/4494), DEX (Uniswap V2/V3/V4), Staking, Safe + MultiSend, EIP-4337 Account Abstraction, EIP-2771 Meta-TX, Gas Cap, and more.

**Composable rules**: Safe -> MultiSend -> ERC20 transfer validation, all in a single recursive delegation chain.

### Security

| Capability | remote-signer | Fireblocks | web3signer | Vault |
|-----------|:---:|:---:|:---:|:---:|
| **OFAC dynamic blocklist** | **Y** | Paid | - | - |
| **Real-time admin alerts** | **Y** | Y | - | - |
| Ed25519 API authentication | Y | API key | API key | Token |
| IP whitelist | Y | Y | - | Y |
| TLS / mTLS | Y | Y | Y | Y |
| Per-key rate limiting | Y | Y | - | Y |
| Full audit trail | Y | Y | - | Y |
| Memory hardening (mlockall) | Y | N/A (SaaS) | - | Y |
| Spending budgets with reset | Y | Y | - | - |
| Manual approval workflow | Y | Y | - | - |

### Platform

| Capability | remote-signer | Fireblocks | web3signer | Vault |
|-----------|:---:|:---:|:---:|:---:|
| Open source | Y | - | Y | Y |
| Self-hosted | Y | - | Y | Y |
| SDKs (Go/TS/Rust/MCP) | 4 | 5+ | 1 | 3 |
| Terminal UI (TUI) | Y | Web UI | - | Web UI |
| One-line setup | Y | N/A | - | - |

**92,000+ lines of code** -- 48K production Go, 61K test code, 2,173 unit + 214 E2E tests.

See [Competitive Analysis](docs/competitive-analysis.md) for the full breakdown.

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

The server starts with no signers. To add your first signer (import a private key or HD wallet / mnemonic wallet), use the TUI: build it, connect with the `admin` key, then open the **Signers** tab to create a keystore or HD wallet. See [Adding Signers](#adding-signers) below.

### Manual Setup

If you prefer manual control, see [docs/configuration.md](docs/configuration.md) for the full config reference and use `config.example.yaml` as a starting point.

### Adding Signers

The server starts without signers. Add them after startup:

- **TUI** (recommended): Use `-api-key-file data/admin_private.pem` so you don't need to paste the key. Example (plain HTTP): `./remote-signer-tui -api-key-id admin -api-key-file data/admin_private.pem -url http://localhost:8548`. **If you enabled TLS** during setup, use `https://` and pass CA (and for mTLS, client cert/key), e.g. `-url https://localhost:8548 -tls-ca ./certs/ca.crt` or with mTLS: `-tls-ca ./certs/ca.crt -tls-cert ./certs/client.crt -tls-key ./certs/client.key`. See [docs/tui.md](docs/tui.md#tls--mtls). After setup (Docker), you can choose "Open TUI to add signers now?" to launch it. In the **Signers** tab create a keystore (import private key) or create/import an HD wallet. **Password requirements (enforced)**: at least 16 characters, and must include uppercase + lowercase + digit + symbol. 24+ characters recommended.
- **API**: `POST /api/v1/evm/signers` (admin only). See [docs/api.md](docs/api.md).
- **Config**: Edit `chains.evm.signers.private_keys` in your config file. See [docs/configuration.md](docs/configuration.md#chains-evm).

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
| [Competitive Analysis](docs/competitive-analysis.md) | Market positioning, feature comparison vs Fireblocks/web3signer/Vault |
| [Use Cases](docs/use-cases.md) | Treasury, bot, DeFi scenarios |
| [Architecture](docs/architecture.md) | System design, layers, adapters |

### Configure

| Document | Description |
|----------|-------------|
| [Configuration Reference](docs/configuration.md) | Full `config.yaml` reference |
| [Rules, Templates & Presets](docs/rules-templates-and-presets.md) | Concepts: rule templates, instances, presets, and examples |
| [Rule Syntax Reference](docs/rule-syntax.md) | All rule types: address list, value limit, Solidity, JS, message pattern |
| [JS Rules (evm_js)](docs/architecture/js-rules-v1.md) | In-process JavaScript rules via Sobek |
| [config.example.yaml](config.example.yaml) | Annotated configuration template |

### Integrate

| Document | Description |
|----------|-------------|
| [API Reference](docs/api.md) | Complete endpoint docs: authentication, signing, rules, audit |
| [Integration Guide](INTEGRATION.md) | JS/TS client library, MetaMask Snap |

### Deploy & Operate

| Document | Description |
|----------|-------------|
| [Deployment Guide](docs/deployment.md) | Docker, Kubernetes, HA, monitoring, backup |
| [TLS / mTLS Guide](docs/tls.md) | Certificate trust model, generation, production best practices |
| [TUI Guide](docs/tui.md) | Terminal UI: build, run, key bindings |

### Security

| Document | Description |
|----------|-------------|
| [Security Overview](docs/security.md) | Defense-in-depth: 8 layers from network to application |
| [Security Review](docs/security-review.md) | Findings, priorities, implementation status |

### Development

| Document | Description |
|----------|-------------|
| [Components](docs/components.md) | Core interfaces, data types, services |
| [Request Flow](docs/flow.md) | 8-step signing flow with state machine |
| [Testing Guide](docs/testing.md) | Unit tests, E2E, rule validation, coverage |

**Versioning** — The version shown in the TUI and `/health` follows the repository tag (e.g. tag `v0.1.1` → version `0.1.1`). When you change code under `tui/`, bump the version in `cmd/remote-signer/main.go`; the pre-commit hook enforces this.

## Roadmap

### Completed

- [x] EIP-712 Typed Data Validation
- [x] Terminal UI (TUI)
- [x] Go / TypeScript / Rust Client SDKs
- [x] MCP Server (AI agent integration)
- [x] 33 Rule Templates (ERC-20/721/1155, Permit, DEX, Safe, 4337, etc.)
- [x] Multi-chain Presets (USDC, Uniswap V2/V3/V4)
- [x] OFAC Dynamic Blocklist
- [x] Real-time Admin Operation Alerting
- [x] EIP-4337 Account Abstraction Support
- [x] RBAC Rule Ownership (owner/applied_to/status on every rule)
- [x] CLI `evm` Command Structure (sign/rule/signer with multi-chain ready architecture)
- [x] Transaction Simulation Engine (eth_simulateV1 RPC + anvil backends)
- [x] Signer Ownership & Access Control — per-signer owner model with access list, transfer, delete cascade, resource limits, API key encrypted keystore
- [x] Permit/Permit2 Spender Whitelist (fail-closed, allowed_spenders config)
- [x] Request Management CLI (list/get/approve/reject/preview-rule)
- [x] JS Client SDK v0.0.4 (SimulateService, executeBatch, signer access control)
- [x] MCP Server v0.0.5 (simulate, broadcast, guard resume tools)
- [x] Internal Transfer Rule — same-owner scope for multi-tenant signer isolation (ETH, ERC20/721/1155)

### Future

- [ ] Auto-Discovery Delegation (zero-config rule composition)
- [ ] Solana Chain Support
- [ ] Cosmos Chain Support
- [ ] Bitcoin Chain Support
- [ ] Web UI Dashboard
- [ ] MPC / TSS Integration

## License

MIT License
