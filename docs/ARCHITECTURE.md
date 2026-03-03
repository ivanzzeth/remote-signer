# Remote-Signer Architecture

## Overview

Remote-Signer is a modular, stateless, secure signing service with multi-chain extensibility. Built on top of `ethsig` for EVM chains with an architecture ready for future Solana/Cosmos/Bitcoin support.

### Key Characteristics

- **Multi-chain extensible architecture** - EVM implemented, others planned
- **Whitelist-based rule engine** - Any rule match = allow
- **Two-tier authorization** - Blocklist first, then whitelist
- **Manual approval workflow** - Slack/Pushover notifications
- **PostgreSQL storage** - GORM auto-migration
- **Terminal UI (TUI)** - For management
- **Go client SDK** - For integration

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Application                        │
│              (Go SDK or direct HTTP)                         │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTP + Ed25519 Auth
┌─────────────────────────▼───────────────────────────────────┐
│                  Remote Signer Service                       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                    HTTP Server                         │  │
│  │                   (Port: 8548)                         │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                          │                                   │
│  ┌───────────────────────▼───────────────────────────────┐  │
│  │              Middleware Pipeline                       │  │
│  │   IP Whitelist → Auth → Admin Check → Rate Limit      │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                          │                                   │
│  ┌───────────────────────▼───────────────────────────────┐  │
│  │                   Handlers                             │  │
│  │   Sign │ Request │ Approval │ Rule │ Audit            │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                          │                                   │
│  ┌───────────────────────▼───────────────────────────────┐  │
│  │                   Services                             │  │
│  │      SignService │ ApprovalService │ NotifyService    │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                          │                                   │
│  ┌──────────┬────────────┴────────────┬──────────────────┐  │
│  │          │                         │                   │  │
│  ▼          ▼                         ▼                   │  │
│  Chain   Rule Engine            State Machine             │  │
│  Adapters  (Whitelist/         (Request lifecycle)        │  │
│  (EVM)     Blocklist)                                     │  │
│  │                                    │                   │  │
│  └────────────────┬───────────────────┘                   │  │
│                   │                                        │  │
│  ┌────────────────▼──────────────────────────────────────┐  │
│  │                    Storage                             │  │
│  │   Request │ Rule │ APIKey │ Audit Repositories        │  │
│  └────────────────────────────────────────────────────────┘  │
└─────────────────────────┬───────────────────────────────────┘
                          │ SQL
              ┌───────────▼───────────┐
              │  PostgreSQL / SQLite  │  (configurable via database.dsn)
              └───────────────────────┘
```

## Package Structure

```
remote-signer/
├── cmd/                              # Entry points
│   ├── remote-signer/main.go         # API server
│   └── tui/main.go                   # Terminal UI
├── internal/
│   ├── api/                          # HTTP API layer
│   │   ├── handler/                  # Request handlers
│   │   │   ├── evm/                  # EVM-specific
│   │   │   └── audit.go              # Audit logs
│   │   ├── middleware/               # HTTP middleware
│   │   ├── router.go                 # Routing
│   │   └── server.go                 # HTTP server
│   ├── chain/                        # Chain adapters
│   │   ├── evm/                      # EVM implementation
│   │   │   ├── adapter.go            # ChainAdapter impl
│   │   │   ├── signer.go             # Signer
│   │   │   ├── signer_manager.go     # Dynamic creation
│   │   │   ├── rule_evaluator.go     # Rule dispatchers
│   │   │   ├── solidity_evaluator.go # Solidity eval
│   │   │   └── message_pattern_evaluator.go
│   │   └── registry.go               # Adapter registry
│   ├── config/                       # Configuration
│   │   ├── config.go                 # Config structs
│   │   ├── apikey_init.go            # API key init
│   │   └── rule_init.go              # Rule init
│   ├── core/                         # Business logic
│   │   ├── auth/                     # Ed25519 auth
│   │   ├── rule/                     # Rule engine
│   │   ├── service/                  # Business services
│   │   ├── statemachine/             # Request states
│   │   └── types/                    # Core data types
│   ├── logger/                       # Logging
│   ├── notify/                       # Notifications
│   └── storage/                      # Data access
├── pkg/
│   └── client/                       # Go client SDK
├── tui/                              # Terminal UI
├── docs/                             # Documentation
└── rules/                            # Rule examples
```

## Core Design Principles

### 1. Two-Tier Rule Evaluation

```
Request → Blocklist Rules → Whitelist Rules → Decision
              │                    │
              │ Any violation      │ Any match
              ▼                    ▼
           REJECT              AUTO-APPROVE
              │                    │
              │ No violation       │ No match
              ▼                    ▼
         Continue →          MANUAL APPROVAL
```

- **Blocklist** evaluated first (restrictive)
- **Whitelist** evaluated second (permissive)
- Any blocklist violation = immediate rejection (no manual approval)
- Any whitelist match = auto-approval
- No whitelist match = manual approval required

### 2. Failure Handling Strategy

> **Security Review Note**: Current Fail-Open design identified as CRITICAL risk.
> See [SECURITY_REVIEW.md](./SECURITY_REVIEW.md) for details and remediation plan.

**Current** (Fail-Open - TO BE CHANGED):
- Rule evaluation errors don't block requests
- Failed rules are skipped, not escalated
- Trade-off: availability over maximum security

**Planned** (Fail-Closed - P0 Priority):
- Rule evaluation errors → default REJECT
- Configurable degradation: `strict` (reject) or `degraded` (manual approval)
- All errors logged for audit and alerting

### 3. State Machine Pattern

Explicit state transitions with audit trail:

```
pending → authorizing → signing → completed
  │           │            │
  ▼           ▼            ▼
rejected   rejected      failed
```

### 4. Chain Adapter Registry

- Pluggable chain implementations
- Each chain handles its own signing logic
- Future chains added via registration

### 5. Repository Pattern

- Abstract data access
- Single responsibility per repository
- Easy to mock in tests

## Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.21+ |
| Database | PostgreSQL |
| ORM | GORM (auto-migration) |
| EVM Signing | ethsig library |
| TUI Framework | Charmbracelet Bubbletea |
| Config Format | YAML |
| Logging | zerolog |

## Security Model

### Authentication

- **Ed25519 signatures** on requests
- Signature format: `{timestamp_ms}|{method}|{path}|{sha256(body)}`
- Timestamp validation (max 5 minutes age)

### Authorization

- **API Key features:**
  - Rate limiting per key
  - Chain type restrictions
  - Signer address restrictions
  - Admin flag for management operations

### Audit

- Every state transition logged
- Immutable audit records
- Queryable by event type, severity, time range

## Security Considerations

> **Important**: This architecture has undergone security review. See [SECURITY_REVIEW.md](./SECURITY_REVIEW.md) for:
> - Identified vulnerabilities and risk ratings
> - Remediation action plan (P0-P3 priorities)
> - Deployment recommendations by asset value

**Key findings requiring attention**:
- P0: Fail-Open → Fail-Closed migration
- P1: Ed25519 nonce for replay protection
- P1: Foundry sandbox isolation
- P1: Multi-party approval for high-value operations

## Adding New Chain Support

To add support for a new chain (e.g., Solana):

1. Create chain package: `internal/chain/solana/`
2. Define types: `internal/chain/solana/types.go`
3. Implement `ChainAdapter` interface: `internal/chain/solana/adapter.go`
4. Implement signer registry: `internal/chain/solana/signer.go`
5. Implement rule evaluators: `internal/chain/solana/rule_evaluator.go`
6. Add API handlers: `internal/api/handler/solana/`
7. Register adapter in `main.go`

## Related Documentation

- [COMPONENTS.md](./COMPONENTS.md) - Detailed component documentation
- [FLOW.md](./FLOW.md) - Request signing flow
- [DEPLOYMENT.md](./DEPLOYMENT.md) - Deployment architecture
- [SECURITY_REVIEW.md](./SECURITY_REVIEW.md) - Security review and action plan
- [API.md](./API.md) - API reference
