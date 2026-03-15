# Remote-Signer Architecture

## Overview

Remote-Signer is a modular, secure signing service with multi-chain extensibility. Built on top of `ethsig` for EVM chains with an architecture ready for future Solana/Cosmos/Bitcoin support.

### Key Characteristics

- **Deep rule engine** — 10 rule types: address lists, value limits, Solidity expressions, JS sandbox, dynamic blocklist, and more
- **Composable delegation** — Rules can delegate inner call validation to other rules (Safe → MultiSend → ERC20)
- **Template system** — 33 parameterized rule templates with variable substitution and test cases
- **Preset system** — 27 ready-to-deploy presets including multi-chain matrix (Uniswap V2/V3/V4, USDC across 6-7 chains)
- **Budget enforcement** — Per-rule spending limits with time-window resets
- **Dynamic OFAC blocklist** — Runtime-synced sanctioned address list with local cache
- **Real-time alerts** — Instant notification on all high-risk admin operations
- **Multi-chain extensible** — EVM implemented, others planned
- **4 client SDKs** — Go, TypeScript, Rust, MCP Server (AI agent integration)
- **Terminal UI (TUI)** — Full management interface
- **Manual approval workflow** — Slack, Telegram, Pushover, Webhook notifications

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Client Applications                          │
│         Go SDK │ TypeScript SDK │ Rust SDK │ MCP Server           │
└───────────────────────────┬───────────────────────────────────────┘
                            │ HTTP + Ed25519 Auth + TLS/mTLS
┌───────────────────────────▼───────────────────────────────────────┐
│                    Remote Signer Service                           │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                   Middleware Pipeline                         │  │
│  │  IP Whitelist → Rate Limit → Auth → Admin Check → Logging   │  │
│  │                                                    ↓         │  │
│  │                        Security Alert Service (real-time)    │  │
│  └───────────────────────────┬─────────────────────────────────┘  │
│                              │                                     │
│  ┌───────────────────────────▼─────────────────────────────────┐  │
│  │                       Handlers                               │  │
│  │  Sign │ Rule CRUD │ Template │ Preset │ Signer │ HD Wallet  │  │
│  │  Approval │ Audit │ ACL │ Health                             │  │
│  └───────────────────────────┬─────────────────────────────────┘  │
│                              │                                     │
│  ┌───────────────────────────▼─────────────────────────────────┐  │
│  │                       Services                               │  │
│  │  SignService │ TemplateService │ ApprovalService │ Notify    │  │
│  └──────┬────────────────────┬──────────────────────────────────┘  │
│         │                    │                                     │
│  ┌──────▼──────┐  ┌─────────▼──────────┐  ┌──────────────────┐  │
│  │   Chain     │  │   Rule Engine      │  │  State Machine   │  │
│  │   Adapters  │  │   (2-tier eval)    │  │  (Request flow)  │  │
│  │   (EVM)     │  │                    │  │                  │  │
│  │             │  │  Evaluators:       │  └──────────────────┘  │
│  │  Signer     │  │  ├ AddressList     │                        │
│  │  Registry   │  │  ├ ValueLimit      │  ┌──────────────────┐  │
│  │             │  │  ├ ContractMethod   │  │  Budget Checker  │  │
│  │  Keystore   │  │  ├ SolidityExpr    │  │  (per-rule caps) │  │
│  │  Provider   │  │  ├ JS (Sobek)      │  └──────────────────┘  │
│  │             │  │  ├ DynamicBlocklist │                        │
│  │  HD Wallet  │  │  ├ SignerRestrict   │  ┌──────────────────┐  │
│  │  Provider   │  │  ├ ChainRestrict    │  │ Dynamic Blocklist│  │
│  │             │  │  ├ SignTypeRestrict  │  │ (OFAC sync)     │  │
│  └─────────────┘  │  └ MessagePattern   │  └──────────────────┘  │
│                    └────────────────────┘                         │
│  ┌───────────────────────────────────────────────────────────┐    │
│  │                      Storage Layer                         │    │
│  │  Rule │ Template │ Budget │ APIKey │ Audit │ Signer Repos │    │
│  └───────────────────────────┬───────────────────────────────┘    │
└──────────────────────────────┬────────────────────────────────────┘
                               │ SQL
                 ┌─────────────▼─────────────┐
                 │  PostgreSQL / SQLite       │
                 └───────────────────────────┘
```

## Package Structure

```
remote-signer/
├── cmd/
│   ├── remote-signer/           # API server entry point
│   ├── remote-signer-cli/       # CLI tool (preset management, rule validation)
│   ├── validate-rules/          # Rule/template validation tool
│   └── tui/                     # Terminal UI entry point
├── internal/
│   ├── api/                     # HTTP API layer
│   │   ├── handler/             # Request handlers
│   │   │   └── evm/             # EVM-specific (sign, rules, signers, HD wallets)
│   │   ├── middleware/          # Auth, rate limit, IP whitelist, logging, alerts
│   │   ├── router.go            # Route registration
│   │   └── server.go            # HTTP/TLS server
│   ├── audit/                   # Audit logging + anomaly monitor
│   ├── blocklist/               # Dynamic address blocklist (OFAC sync)
│   ├── chain/                   # Chain adapters
│   │   └── evm/                 # EVM implementation
│   │       ├── signer.go        # SignerRegistry (private keys, keystores, HD wallets)
│   │       ├── js_evaluator.go  # JS rule sandbox (Sobek)
│   │       ├── js_helpers.go    # rs.* JS helper library (45+ methods)
│   │       ├── solidity_evaluator.go  # Foundry-based Solidity rules
│   │       └── delegation_convert.go  # Delegation payload conversion
│   ├── config/                  # Configuration loading + sync
│   │   ├── config.go            # Config structs
│   │   ├── rule_init.go         # Rule sync (config → DB)
│   │   └── template_init.go     # Template sync (config → DB)
│   ├── core/                    # Business logic
│   │   ├── auth/                # Ed25519 verification + nonce replay protection
│   │   ├── rule/                # Rule engine (2-tier whitelist/blocklist)
│   │   ├── service/             # SignService, TemplateService
│   │   ├── statemachine/        # Request state transitions
│   │   └── types/               # Core data types (Rule, SignRequest, AuditRecord, etc.)
│   ├── notify/                  # Notifications (Slack, Telegram, Pushover, Webhook)
│   ├── preset/                  # Preset parser (single, composite, matrix, multi-rule)
│   ├── ruleconfig/              # Rule config validation
│   ├── secure/                  # Memory security (ZeroString, mlockall)
│   ├── storage/                 # GORM repositories
│   └── validate/                # Input validation
├── pkg/
│   ├── client/                  # Go client SDK
│   ├── js-client/               # TypeScript/Node.js client SDK
│   ├── rs-client/               # Rust client SDK
│   └── mcp-server/              # MCP Server for AI agent integration
├── tui/                         # Terminal UI (Bubbletea)
├── rules/
│   ├── templates/               # 33 rule templates (YAML + JS)
│   └── presets/                 # 27 presets (including multi-chain matrix)
└── docs/                        # Documentation
```

## Core Design Principles

### 1. Two-Tier Rule Evaluation

```
Request → Blocklist Rules (Fail-Closed) → Whitelist Rules (Fail-Open) → Decision
                │                                │
                │ Any violation                  │ Any match
                ▼                                ▼
             REJECT                         AUTO-APPROVE
                │                                │
                │ No violation                   │ No match
                ▼                                ▼
           Continue →                    MANUAL APPROVAL (or reject)
```

- **Blocklist** evaluated first — Fail-Closed: any error = immediate rejection
- **Whitelist** evaluated second — Fail-Open: evaluation errors skip the rule
- **Delegation**: whitelist rules can return a payload for recursive validation by target rules
- Budget check happens after rule match, before final approval

### 2. Composable Rule Delegation

Rules can delegate inner call validation to other rules, forming recursive chains:

```
Safe Rule → extracts inner call → delegates to:
  ├── MultiSend Rule → parses batch → delegates each item to:
  │     ├── ERC20 Rule (validates transfer params)
  │     └── ERC721 Rule (validates NFT transfer)
  └── Contract Guard Rule (validates method selector)

EIP-4337 Rule → parses callData → delegates execute() to:
  └── Any registered target rule
```

Delegation features:
- **Single mode**: one inner call delegated to one target rule
- **Per-item mode**: batch of items, each delegated independently (ALL must pass)
- **Target routing**: `delegate_to_by_target` maps inner addresses to specific rules
- **Depth limit**: max 6 levels, cycle detection, 256 items per batch
- **Blocklist enforcement**: delegated payloads checked against blocklist at every level

### 3. Failure Handling Strategy

| Rule Mode | On Evaluation Error | On Evaluator Missing | Rationale |
|-----------|--------------------|-----------------------|-----------|
| **Blocklist** | REJECT (Fail-Closed) | REJECT (Fail-Closed) | Security: unknown = dangerous |
| **Whitelist** | Skip rule (Fail-Open) | Skip rule (Fail-Open) | Availability: try next rule |

After all evaluators registered, the engine is **sealed** — no new evaluators can be added, preventing race conditions.

### 4. State Machine Pattern

Explicit state transitions with audit trail:

```
pending → authorizing → signing → completed
  │           │            │
  ▼           ▼            ▼
rejected   rejected      failed
```

### 5. Template & Preset System

- **Templates**: Parameterized rules with `${variable}` placeholders and built-in test cases
- **Instances**: Concrete rules created by binding variable values to templates
- **Presets**: Bundled configurations that create multiple rule instances at once
- **Matrix presets**: One rule per chain, with per-chain variable overrides (e.g., USDC across 6 chains)

## Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.24+ |
| Database | PostgreSQL (production) / SQLite (development) |
| ORM | GORM (auto-migration) |
| EVM Signing | ethsig library |
| JS Sandbox | Sobek (ES2024 compliant, in-process) |
| Solidity Rules | Foundry (forge) |
| TUI Framework | Charmbracelet Bubbletea |
| Config Format | YAML |
| Logging | slog (structured) |
| Notifications | Slack, Telegram, Pushover, Webhook |

## Security Model

### Authentication

- **Ed25519 signatures** on every request
- Signature format: `{timestamp_ms}|{method}|{path}|{sha256(body)}`
- **Nonce replay protection**: window-based with per-key TTL
- Timestamp validation (configurable max age, default 60s)

### Authorization

- **API Key features:**
  - Admin / non-admin roles
  - Per-key rate limiting
  - Chain type restrictions
  - Signer address restrictions
  - HD wallet restrictions

### Runtime Security

- **Dynamic OFAC blocklist**: hourly sync from external sources, local cache persistence
- **Real-time admin alerts**: instant notification on all privileged write operations
- **Budget enforcement**: per-rule spending limits with configurable reset periods
- **JS sandbox hardening**: dangerous globals removed, timeout (20ms), memory limit (32MB)
- **Memory hardening**: mlockall (prevent swap), PR_SET_DUMPABLE=0 (prevent core dumps), password zeroization

### Audit

- Every API request logged with full metadata
- Every state transition recorded
- Admin operations trigger real-time alerts
- Configurable retention with auto-cleanup
- Anomaly detection (auth failure spikes, high-frequency requests)

## Adding New Chain Support

To add support for a new chain (e.g., Solana):

1. Create chain package: `internal/chain/solana/`
2. Implement `ChainAdapter` interface
3. Implement signer registry and providers
4. Implement rule evaluators for chain-specific types
5. Add API handlers: `internal/api/handler/solana/`
6. Register adapter in `main.go`

## Related Documentation

- [Components](./components.md) — Core interfaces and data types
- [Request Flow](./flow.md) — 8-step signing flow with state machine
- [JS Rules](./architecture/js-rules-v1.md) — JS rule engine architecture and rs.* helpers
- [Rule Syntax](./rule-syntax.md) — All 10 rule types with examples
- [Security Overview](./security.md) — Defense-in-depth: 16 security layers
- [Competitive Analysis](./competitive-analysis.md) — Market positioning vs Fireblocks/web3signer
- [Deployment](./deployment.md) — Docker, Kubernetes, HA, monitoring
- [API Reference](./api.md) — Complete endpoint documentation
