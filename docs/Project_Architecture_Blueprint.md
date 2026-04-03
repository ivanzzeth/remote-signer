# Remote-Signer Project Architecture Blueprint

**Generated**: 2026-04-02  
**Version**: 1.0.0  
**Based on**: Code analysis of 162 Go source files (129 internal + 33 evm adapter)

---

## Executive Summary

Remote-Signer is a **policy-driven signing service** built in **Go 1.24+** for EVM chains (with Solana/Cosmos extensibility). It provides **Fireblocks-level policy control** through a sophisticated rule engine supporting 11 rule types, including JavaScript (Sobek) and Solidity (Foundry) execution. The system employs **defense-in-depth security** with 16 layers, **two-tier rule evaluation** (fail-closed blocklist → fail-open whitelist), and comprehensive **RBAC/ACL** for multi-tenant custody.

**Key Statistics**:
- **92,000+ lines of code**: 48K production Go, 44K test code
- **2,387 total tests**: 2,173 unit + 214 E2E
- **162 core source files**: 129 internal + 33 EVM adapter
- **11 rule types**: 4 chain-agnostic + 7 EVM-specific
- **6 sign types**: hash, raw_message, eip191, personal, typed_data, transaction
- **33 rule templates**: 23 protocol-specific + 10 generic
- **4 client SDKs**: Go, TypeScript, Rust, MCP Server

---

## 1. Architecture Detection and Analysis

### 1.1 Technology Stack (Detected)

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Language** | Go | 1.24+ | Primary application language |
| **Database** | PostgreSQL / SQLite | Latest | Production / Development |
| **ORM** | GORM | v1.25+ | Auto-migration, type-safe queries |
| **EVM Signing** | ethsig | Custom | Ethereum signature operations |
| **JS Engine** | Sobek | Latest | In-process JavaScript rule evaluation |
| **Solidity Execution** | Foundry (forge) | Latest | Solidity expression validation |
| **TUI Framework** | Bubbletea | Latest | Terminal user interface |
| **Web Framework** | net/http | Stdlib | HTTP server (no external framework) |
| **Logging** | slog | Stdlib | Structured logging |
| **Metrics** | Prometheus | Latest | Observability |

### 1.2 Architectural Pattern (Detected)

**Primary Pattern**: **Clean Architecture** + **Hexagonal Architecture** (Ports & Adapters)

**Evidence**:
1. **Domain core isolation**: `internal/core/types/` defines chain-agnostic abstractions
2. **Adapter pattern**: `ChainAdapter` interface with `EVMAdapter` implementation
3. **Dependency inversion**: Core depends on interfaces, adapters implement them
4. **Service layer**: `SignService`, `ApprovalService`, `TemplateService` orchestrate business logic
5. **Repository pattern**: Storage abstraction via interfaces, GORM implementation
6. **No framework lock-in**: Uses stdlib `net/http`, no Gin/Echo/Fiber

**Secondary Patterns**:
- **State Machine**: Explicit request lifecycle (`pending` → `authorizing` → `signing` → `completed`)
- **Strategy Pattern**: `RuleEvaluator` interface with 8 implementations
- **Chain of Responsibility**: Middleware pipeline (9 layers)
- **Registry Pattern**: `chain.Registry` maps `ChainType` to `ChainAdapter`
- **Provider Pattern**: `SignerProvider`/`SignerCreator`/`SignerUnlocker` interfaces

### 1.3 Project Structure

```
remote-signer/
├── cmd/
│   ├── remote-signer/           # API server main
│   ├── remote-signer-cli/       # CLI tool (33 commands)
│   ├── remote-signer-tui/       # Terminal UI
│   └── remote-signer-validate-rules/ # Rule validator
├── internal/
│   ├── core/                    # Domain layer (PURE, no external deps)
│   │   ├── types/               # Domain models (11 files)
│   │   ├── rule/                # Rule engine (5 files)
│   │   ├── service/             # Use cases (6 files)
│   │   ├── statemachine/        # Request lifecycle
│   │   └── auth/                # Authentication logic
│   ├── chain/                   # Adapter layer
│   │   ├── evm/                 # EVM implementation (33 files)
│   │   └── registry.go          # Chain registry
│   ├── api/                     # HTTP layer
│   │   ├── middleware/          # 9 middleware components
│   │   ├── handler/             # HTTP handlers
│   │   ├── router.go            # Route registration
│   │   └── server.go            # TLS server
│   ├── storage/                 # Persistence layer
│   │   ├── gorm.go              # GORM setup
│   │   ├── *_repo.go            # 11 repositories
│   │   └── migrations/          # SQL migrations
│   ├── audit/                   # Audit logging
│   ├── blocklist/               # Dynamic blocklist (OFAC)
│   ├── config/                  # Configuration sync
│   ├── notify/                  # Multi-channel notifications
│   ├── preset/                  # Preset parsing
│   ├── simulation/              # Anvil fork simulation
│   ├── validate/                # Input validation
│   ├── logger/                  # Structured logging
│   ├── metrics/                 # Prometheus metrics
│   └── secure/                  # Memory hardening
├── pkg/
│   ├── client/                  # Go SDK
│   ├── js-client/               # TypeScript SDK
│   ├── rs-client/               # Rust SDK
│   └── mcp-server/              # MCP Server (AI agents)
├── rules/
│   ├── templates/               # 33 rule templates
│   └── presets/                 # 27 ready-made presets
└── docs/                        # Documentation
```

---

## 2. Architectural Overview

### 2.1 System Context

Remote-Signer operates as a **centralized signing authority** that enforces **policy-driven access control** to private keys. It sits between:
- **Clients** (trading bots, frontend apps, scripts) that request signatures
- **Blockchains** (EVM chains) that require signed transactions/messages

**Problem Solved**: Traditional custody solutions (HSM, multi-sig wallets) control **who** can sign but not **what** gets signed. Remote-Signer adds **parameter-level policy enforcement** (address whitelist, value limits, custom logic) without modifying client code.

### 2.2 Guiding Principles

| Principle | Implementation |
|-----------|----------------|
| **Security First** | 16-layer defense-in-depth, fail-closed blocklist, memory hardening, sandbox isolation |
| **Zero Trust** | Every request authenticated (Ed25519 HMAC), nonce replay protection, IP whitelist |
| **Composability** | Rules delegate to other rules (Safe → MultiSend → ERC20), template system |
| **Fail Explicit** | No silent fallbacks, all errors logged, all constructors return `error` |
| **DRY** | Zero code duplication, template/preset system reuses logic |
| **Chain-Agnostic Core** | Domain layer has no EVM/Solana knowledge, adapters handle specifics |
| **No Framework Lock-In** | Uses stdlib `net/http`, no web framework dependency |

### 2.3 Architectural Boundaries

```
┌────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                             │
│  Go SDK │ TS SDK │ Rust SDK │ MCP Server │ curl │ TUI Client   │
└──────────────────────┬─────────────────────────────────────────┘
                       │ HTTP/TLS + Ed25519 Auth
┌──────────────────────▼─────────────────────────────────────────┐
│                      API LAYER (internal/api/)                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ Middleware Pipeline (9 layers)                           │  │
│  │  Security → Panic → IP → Logging → PreAuth-RateLimit →  │  │
│  │  Auth → RBAC → PostAuth-RateLimit → ContentType         │  │
│  └───────────────────────┬──────────────────────────────────┘  │
│                          │                                      │
│  ┌───────────────────────▼──────────────────────────────────┐  │
│  │ Handlers: Sign│Rule│Template│Preset│Signer│HDWallet│... │  │
│  └───────────────────────┬──────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────────────┐
│               SERVICE LAYER (internal/core/service/)            │
│  SignService│ApprovalService│TemplateService│SignerAccessSvc  │
└──────────────────────────┬─────────────────────────────────────┘
                           │
     ┌─────────────────────┼─────────────────────┐
     │                     │                     │
     ▼                     ▼                     ▼
┌─────────┐         ┌──────────┐        ┌──────────────┐
│  Rule   │         │  State   │        │   Chain      │
│ Engine  │         │ Machine  │        │  Adapter     │
└────┬────┘         └──────────┘        └──────┬───────┘
     │                                          │
     ▼                                          ▼
┌──────────────┐                      ┌──────────────────┐
│  Evaluators  │                      │ Signer Registry  │
│ (8 types)    │                      │ (3 providers)    │
└──────────────┘                      └──────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────────────┐
│              STORAGE LAYER (internal/storage/)                  │
│  RequestRepo│RuleRepo│APIKeyRepo│AuditRepo│BudgetRepo│...      │
└──────────────────────────┬─────────────────────────────────────┘
                           │ SQL (GORM)
                           ▼
                  ┌──────────────────┐
                  │ PostgreSQL/SQLite │
                  └──────────────────┘
```

---

## 3. Core Architectural Components

### 3.1 Domain Layer: Core Abstractions

**Location**: `internal/core/types/`

#### 3.1.1 ChainAdapter Interface

**Purpose**: Abstract blockchain-specific signing operations, enabling multi-chain support.

**File**: `internal/core/types/chain.go`

```go
type ChainAdapter interface {
    Type() ChainType  // "evm", "solana", "cosmos"
    
    // Two-level validation:
    ValidateBasicRequest(chainID, signerAddress, signType string, payload []byte) error  // Format/size only
    ValidatePayload(ctx context.Context, signType string, payload []byte) error          // Semantic validation
    
    // Signing:
    Sign(ctx context.Context, signerAddress, signType, chainID string, payload []byte) (*SignResult, error)
    
    // Rule evaluation support:
    ParsePayload(ctx context.Context, signType string, payload []byte) (*ParsedPayload, error)
    
    // Signer discovery:
    ListSigners(ctx context.Context) ([]SignerInfo, error)
    HasSigner(ctx context.Context, address string) bool
}
```

**Design Decisions**:
1. **Two-level validation**: `ValidateBasicRequest` (pre-persist) checks format/size → `ValidatePayload` (post-persist) checks semantics. This ensures **all well-formed requests** are persisted for audit, even if they fail semantic validation.
2. **ParsedPayload**: Extracts rule-relevant fields (`recipient`, `value`, `methodSig`, `contract`, `message`) so rule evaluators don't need chain-specific knowledge.
3. **Context-aware**: All methods take `context.Context` for cancellation/timeout.

**Implementation**: `EVMAdapter` (`internal/chain/evm/adapter.go`)

---

#### 3.1.2 Rule Type System

**File**: `internal/core/types/rule.go`

**Rule Types** (11 total):

| Category | Type | Mode | Description |
|----------|------|------|-------------|
| **Chain-Agnostic** | `signer_restriction` | W/B | Signer address allow/block list |
| | `chain_restriction` | W/B | Chain ID allow/block list |
| | `sign_type_restriction` | W/B | Sign type allow/block list |
| | `message_pattern` | W/B | Regex pattern matching for personal signs |
| **EVM-Specific** | `evm_address_list` | W/B | Recipient address allow/block list |
| | `evm_contract_method` | W/B | Contract + method selector matching |
| | `evm_value_limit` | W/B | Transaction value cap |
| | `evm_solidity_expression` | W/B | Foundry Solidity expression evaluation |
| | `evm_js` | W/B | Sobek JavaScript rule evaluation |
| | `evm_dynamic_blocklist` | B only | Runtime-synced blocklist (OFAC, scam lists) |
| | `evm_internal_transfer` | W only | Same-owner signer transfers (multi-tenant) |

**Mode Semantics**:
- **Whitelist (W)**: If rule matches, **auto-approve** (skip manual approval)
- **Blocklist (B)**: If rule matches, **reject immediately** (no manual approval)

**Scope Fields**:
```go
type Rule struct {
    ChainType     *ChainType  // nil = all chains
    ChainID       *string     // nil = all chain IDs
    SignerAddress *string     // nil = all signers
    Owner         string      // API key ID that created this rule
    AppliedTo     []string    // ["*"] = all keys, ["self"] = owner only, or specific list
    Status        RuleStatus  // "active", "pending_approval", "rejected", "revoked"
    Immutable     bool        // true = cannot be modified/deleted via API
}
```

**Lifecycle**:
```
           create (API or config)
                 ↓
         ┌───────▼──────┐
         │    active     │ ←────┐
         └───────┬───────┘      │
                 │               │
         ┌───────▼───────────┐  │
         │ pending_approval  │──┤ approve
         └───────┬───────────┘  │
                 │               │
         ┌───────▼───────┐      │
         │   rejected    │      │
         └───────────────┘      │
                                │
         ┌──────────────┐       │
         │   revoked    │───────┘
         └──────────────┘
```

---

#### 3.1.3 SignRequest Workflow

**File**: `internal/core/types/request.go`

**Status Enum**:
```go
const (
    StatusPending     SignRequestStatus = "pending"      // Initial, awaiting validation
    StatusAuthorizing SignRequestStatus = "authorizing"  // Validation passed, evaluating rules
    StatusSigning     SignRequestStatus = "signing"      // Approved, performing signature
    StatusCompleted   SignRequestStatus = "completed"    // Signature generated
    StatusRejected    SignRequestStatus = "rejected"     // Rejected by rule or manual review
    StatusFailed      SignRequestStatus = "failed"       // Signing operation failed
)
```

**State Transitions**:
```
pending ──────────────────> rejected
   │                            ▲
   │ ValidateBasicRequest OK    │
   ▼                            │
authorizing                     │
   │                            │
   ├─> Blocklist violation ─────┘
   │                            │
   ├─> Whitelist match ─────────┼──> signing ──┬──> completed
   │                            │               │
   └─> No match ───> Manual approval           └──> failed
                         │
                         └──> approve/reject
```

---

### 3.2 Rule Engine

**Location**: `internal/core/rule/`

#### 3.2.1 Two-Tier Evaluation

**File**: `internal/core/rule/engine.go`, `internal/core/rule/whitelist.go`

**Algorithm** (WhitelistRuleEngine):

```
INPUT: SignRequest + ParsedPayload
       ↓
┌────────────────────────────────────────────┐
│ PHASE 1: BLOCKLIST EVALUATION (Fail-Closed) │
│                                            │
│  for rule in blocklist_rules:             │
│    if ruleScopeMatches(rule, request):    │
│      result, err = evaluator.Evaluate()  │
│      if err != nil:                       │
│        → REJECT (fail-closed)             │
│      if result == true:                   │
│        → REJECT (blocklist violation)     │
└────────────────┬───────────────────────────┘
                 │ No violations
                 ▼
┌────────────────────────────────────────────┐
│ PHASE 2: WHITELIST EVALUATION (Fail-Open)  │
│                                            │
│  for rule in whitelist_rules:             │
│    if ruleScopeMatches(rule, request):    │
│      result, err = evaluator.Evaluate()  │
│      if err != nil:                       │
│        → SKIP (fail-open, try next)       │
│      if result == true:                   │
│        → APPROVE (auto-sign)              │
└────────────────┬───────────────────────────┘
                 │ No matches
                 ▼
┌────────────────────────────────────────────┐
│ PHASE 3: OUTCOME                            │
│                                            │
│  if manualApprovalEnabled:                │
│    → Send notification (Slack/Telegram)   │
│    → Status = "authorizing"               │
│    → Wait for admin approval              │
│  else:                                    │
│    → REJECT (no whitelist match)          │
└────────────────────────────────────────────┘
```

**Scope Matching** (`ruleScopeMatches`):
```go
func ruleScopeMatches(rule *types.Rule, req *types.SignRequest) bool {
    // nil scope field = "matches any"
    if rule.ChainType != nil && *rule.ChainType != req.ChainType {
        return false
    }
    if rule.ChainID != nil && *rule.ChainID != req.ChainID {
        return false
    }
    if rule.SignerAddress != nil && !strings.EqualFold(*rule.SignerAddress, req.SignerAddress) {
        return false
    }
    return true
}
```

**Key Design Decisions**:
1. **Fail-closed blocklist**: Any blocklist evaluation error → immediate reject (security first)
2. **Fail-open whitelist**: Whitelist evaluation error → skip rule, try next (availability)
3. **Nil = any**: Unset scope fields match all requests (broadest scope)
4. **Ordered evaluation**: Blocklist always evaluated before whitelist

---

#### 3.2.2 RuleEvaluator Interface

**File**: `internal/core/rule/engine.go`

```go
type RuleEvaluator interface {
    Type() RuleType
    
    // Returns:
    //   (true, reason, nil)  = rule matched (whitelist) OR violated (blocklist)
    //   (false, "", nil)     = no match
    //   (_, _, error)        = evaluation error
    Evaluate(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error)
}
```

**Implementations** (8 total):

| Evaluator | File | Whitelist Logic | Blocklist Logic |
|-----------|------|----------------|----------------|
| `AddressListEvaluator` | `evm/rule_evaluator.go` | `to` in addresses → allow | `to` in addresses → block |
| `ContractMethodEvaluator` | `evm/rule_evaluator.go` | contract + selector match → allow | contract + selector match → block |
| `ValueLimitEvaluator` | `evm/rule_evaluator.go` | value ≤ max → allow | value > max → block |
| `SignerRestrictionEvaluator` | `evm/rule_evaluator.go` | signer in list → allow | signer in list → block |
| `SignTypeRestrictionEvaluator` | `evm/rule_evaluator.go` | sign_type in list → allow | sign_type in list → block |
| `MessagePatternEvaluator` | `evm/message_pattern_evaluator.go` | message matches regex → allow | message matches regex → block |
| `JSRuleEvaluator` | `evm/js_evaluator.go` | script returns `{valid:true}` → allow | script returns `{valid:true}` → block |
| `InternalTransferEvaluator` | `evm/internal_transfer_evaluator.go` | same-owner transfer → allow | N/A (whitelist-only) |

---

#### 3.2.3 JavaScript Rule Execution

**File**: `internal/chain/evm/js_evaluator.go`

**Sobek VM Configuration**:
```go
vm := sobek.New()

// Security hardening:
vm.Set("eval", sobek.Undefined())
vm.Set("Function", sobek.Undefined())
vm.Set("require", sobek.Undefined())
vm.Set("Date", sobek.Undefined())  // Prevents timing oracle attacks
vm.Set("Math.random", sobek.Undefined())  // Non-deterministic source

// Allowed globals:
vm.Set("input", ruleInput)   // RuleInput object
vm.Set("config", variables)  // Template variables
vm.Set("fail", failFunc)     // return fail("reason")
vm.Set("ok", okFunc)         // return ok()
// ... other helpers (eq, keccak256, selector, toChecksum, isAddress, abi, rs)

// Timeout enforcement:
vm.SetInterruptHandler(func() { if time.Since(start) > 20*time.Millisecond { panic(ErrTimeout) }})

// Execute:
result, err := vm.RunString(script + "\nvalidate(input, config)")
```

**RuleInput Structure**:
```javascript
{
  sign_type: "transaction",  // "typed_data", "personal_sign", etc.
  chain_id: 137,
  signer: "0x...",  // checksum address
  
  transaction: {   // only present if sign_type == "transaction"
    from: "0x...",  // REQUIRED (always set by engine)
    to: "0x...",
    value: "0x0",   // hex string
    data: "0x...",
    methodId: "0xa9059cbb"  // 4-byte selector
  },
  
  typed_data: { ... },      // only present if sign_type == "typed_data"
  personal_sign: { ... }    // only present if sign_type == "personal_sign"
}
```

**rs.* Helpers** (namespace reserved for composable utils):
```javascript
// rs.tx - transaction validation
var ctx = rs.tx.require(input);  // throws if not transaction
var calldata = rs.tx.getCalldata(ctx.tx);

// rs.addr - address checks
rs.addr.requireInList(ctx.tx.to, config.allowed_contracts, "contract not allowed");
rs.addr.requireZero(msg.taker, "taker must be zero");

// rs.bigint - safe BigInt parsing
var amount = rs.bigint.parse(dec[1]);  // throws on invalid
rs.bigint.requireLte(amount, config.max_amount, "exceeds cap");

// rs.typedData - EIP-712 validation
var td = rs.typedData.require(input, "Order");
rs.typedData.requireDomain(td.domain, { chainId: 1, allowedContracts: [config.exchange] });

// rs.gnosis.safe - Safe transaction parsing
var safe = rs.gnosis.safe.parseExecTransactionData(ctx.tx.data);
require(safe.operationCALL, "only CALL allowed");

// rs.multisend - batch transaction parsing
var batch = rs.multisend.parseBatch(payloadHex, input.chain_id, input.signer);

// rs.delegate - delegation routing
var ruleId = rs.delegate.resolveByTarget(innerTo, config.byTarget, config.defaultRule);
```

**Security Guarantees**:
1. **Timeout**: 20ms per evaluation (prevents infinite loops)
2. **Memory limit**: 32MB allocation growth cap (prevents DoS)
3. **Sandbox**: No filesystem, network, or system access
4. **Deterministic**: No Date, Math.random, or other non-deterministic sources
5. **No eval**: Cannot construct new code dynamically

---

#### 3.2.4 Solidity Rule Execution

**File**: `internal/chain/evm/solidity_evaluator.go`, `internal/chain/evm/solidity_validator.go`

**Foundry Integration**:
```
Rule Config (YAML)
   ↓
Generate Solidity test file:
   contract Generated_Test {
      function testValidate() {
          // Inject context variables:
          address tx_to = 0x...;
          uint256 tx_value = ...;
          bytes4 tx_selector = 0x...;
          uint256 ctx_chainId = ...;
          address ctx_signer = 0x...;
          
          // User expression:
          require(tx_value <= 1 ether, "value too high");
          require(tx_to == 0x..., "invalid recipient");
      }
   }
   ↓
Execute: forge test --match-test testValidate
   ↓
Parse output:
   - All assertions passed → Rule matches
   - Any assertion failed → Rule does not match
   - Compilation error → Validation error
```

**Supported Modes**:

1. **Expression** (Transaction):
```yaml
config:
  expression: |
    require(tx_value <= 1 ether, "exceeds limit");
    require(tx_to == 0x9Ce3316B..., "invalid recipient");
```

2. **Functions** (Transaction):
```yaml
config:
  functions: |
    function transfer(address recipient, uint256 amount) external {
        require(amount <= 10000e6, "exceeds limit");
        require(recipient == 0x..., "unauthorized recipient");
    }
```

3. **Typed Data Expression**:
```yaml
config:
  typed_data_expression: |
    require(eip712_domainChainId == 137, "must be Polygon");
    require(value <= 1000000e6, "permit exceeds limit");
```

**Context Variables**:

| Prefix | Variables | Available In |
|--------|-----------|--------------|
| `tx_` | `to`, `value`, `selector`, `data` | Transaction rules |
| `ctx_` | `signer`, `chainId` | All rules |
| `eip712_` | `primaryType`, `domainName`, `domainVersion`, `domainChainId`, `domainContract` | Typed data rules |

**Security**:
- **Dangerous cheatcodes blocked**: `vm.ffi`, `vm.readFile`, `vm.writeFile`, `vm.rpc`, `vm.broadcast`
- **Sandboxed execution**: Foundry runs in isolated subprocess
- **Timeout**: Configurable (default 2s per evaluation)

---

#### 3.2.5 Budget Tracking

**File**: `internal/core/rule/budget.go`

**Purpose**: Track spending per rule (e.g., "max 10,000 USDT per day" or "max 100 transactions per month").

**Budget Unit Types**:
1. **Native**: Fixed identifier (e.g., `"native"` = wei)
2. **Dynamic**: Token address (e.g., `"0xA0b8...` = USDC address)
3. **Named**: Custom identifier (e.g., `"tx_count"`, `"sign_count"`)

**Spend Measurement Methods**:

| Method | Description | Config |
|--------|-------------|--------|
| `none` | No budget tracking | `budget_metering: null` |
| `count_only` | Each request = 1 unit | `method: "count_only"` |
| `tx_value` | Transaction value field | `method: "tx_value"` |
| `calldata_param` | Extract uint from calldata | `method: "calldata_param"`, `param_index: 1` |
| `typed_data_field` | Extract from EIP-712 field | `method: "typed_data_field"`, `field_path: "message.amount"` |
| `js` | Custom JS function | `method: "js"` (script must define `validateBudget(input)`) |

**Budget Record** (per rule + unit):
```go
type Budget struct {
    RuleID       types.RuleID  // Which rule
    Unit         string        // Budget unit (e.g., "native", "0xA0b8...", "tx_count")
    MaxTotal     *big.Int      // Total budget cap
    MaxPerTx     *big.Int      // Per-transaction cap
    MaxTxCount   *uint64       // Transaction count cap
    Spent        *big.Int      // Current spent amount
    TxCount      uint64        // Current transaction count
    PeriodStart  *time.Time    // Period start (for renewal)
    Period       *time.Duration // Renewal period (e.g., 24h)
    AlertPct     *float64      // Alert threshold (e.g., 80%)
}
```

**Renewal Logic**:
```go
if budget.Period != nil && budget.PeriodStart != nil {
    now := time.Now()
    periodEnd := budget.PeriodStart.Add(*budget.Period)
    if now.After(periodEnd) {
        // Reset spent and tx_count
        budget.Spent = big.NewInt(0)
        budget.TxCount = 0
        budget.PeriodStart = &periodEnd  // Start next period
    }
}
```

---

### 3.3 State Machine

**File**: `internal/core/statemachine/machine.go`

**StateMachine** orchestrates request lifecycle transitions:

```go
type StateMachine struct {
    requestRepo storage.RequestRepository
    auditRepo   storage.AuditRepository
    logger      *slog.Logger
}

// Transitions:
func (sm *StateMachine) ValidateAndStartAuthorizing(ctx, reqID) (*TransitionResult, error)
func (sm *StateMachine) RejectOnValidation(ctx, reqID, reason) (*TransitionResult, error)
func (sm *StateMachine) ApproveForSigning(ctx, reqID, ruleID, approvedBy, reason) (*TransitionResult, error)
func (sm *StateMachine) RejectOnAuthorization(ctx, reqID, rejectedBy, reason) (*TransitionResult, error)
func (sm *StateMachine) CompleteWithSignature(ctx, reqID, signature, signedData) (*TransitionResult, error)
func (sm *StateMachine) FailSigning(ctx, reqID, errMsg) (*TransitionResult, error)
```

**Audit Logging**: Every transition generates an audit record (`types.AuditEventType`).

---

### 3.4 EVM Chain Adapter

**Location**: `internal/chain/evm/`

#### 3.4.1 SignerRegistry & Providers

**Purpose**: Manage private keys for signing (PrivateKey, Keystore, HD Wallet).

**Architecture**:
```
SignerRegistry (internal/chain/evm/signer.go)
   │
   ├─> []SignerProvider (ordered list)
   │      ├─> PrivateKeyProvider   (in-memory key pairs)
   │      ├─> KeystoreProvider     (encrypted JSON keystores)
   │      └─> HDWalletProvider     (BIP-39 mnemonic wallets)
   │
   └─> SignerManager (internal/chain/evm/signer_manager.go)
          ├─> CreateSigner()
          ├─> UnlockSigner()
          ├─> LockSigner()
          ├─> DiscoverLockedSigners()  // Scan disk for unlisted keystores/HD wallets
          └─> HDWalletManager()
```

**Provider Interfaces**:

```go
type SignerProvider interface {
    List(ctx context.Context) ([]types.SignerInfo, error)
    Get(ctx context.Context, address string) (*types.SignerInfo, error)
}

type SignerCreator interface {
    Create(ctx context.Context, req types.CreateSignerRequest) (*types.SignerInfo, error)
}

type SignerDiscoverer interface {
    DiscoverLocked(ctx context.Context) ([]types.SignerInfo, error)  // Scan disk for unlisted signers
}

type SignerUnlocker interface {
    Unlock(ctx context.Context, address string, password string) error
}

type SignerLocker interface {
    Lock(ctx context.Context, address string) error
}

type SignerDeleter interface {
    Delete(ctx context.Context, address string) error
}

type HDWalletManager interface {
    CreateWallet(ctx context.Context, password string) (*types.HDWallet, error)
    ImportWallet(ctx context.Context, mnemonic string, password string) (*types.HDWallet, error)
    DeriveAddress(ctx context.Context, parentAddress string, index uint32) (string, error)
    ListDerived(ctx context.Context, parentAddress string) ([]string, error)
}
```

**HD Wallet Derivation Path**: `m/44'/60'/0'/0/{index}` (BIP-44 Ethereum standard)

**Signer Auto-Lock**:
```go
type SignerManager struct {
    autoLockTimeout time.Duration  // e.g., 1h
    // ...
}

// After each Sign operation:
if signer.UnlockedAt != nil && time.Since(*signer.UnlockedAt) > autoLockTimeout {
    signer.Lock()
    audit.LogEvent(types.AuditEventTypeSignerAutoLocked)
}
```

---

## 4. Architectural Layers and Dependencies

### 4.1 Layer Hierarchy

```
┌──────────────────────────────────────────────────────────────────┐
│ PRESENTATION LAYER (cmd/)                                        │
│  - CLI (remote-signer-cli): 33 commands                          │
│  - TUI (remote-signer-tui): Bubbletea interface                  │
│  - API Server (remote-signer): HTTP/TLS server                   │
└───────────────────────────┬──────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────┐
│ API LAYER (internal/api/)                                         │
│  - Middleware Pipeline: 9 layers (security, auth, RBAC, etc.)    │
│  - Handlers: Sign, Rule, Template, Preset, Signer, Audit         │
│  - Router: Route registration + TLS server setup                 │
│  DEPENDS ON: Service Layer + Adapter Layer                       │
└───────────────────────────┬──────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────┐
│ SERVICE LAYER (internal/core/service/)                            │
│  - SignService: Orchestrates sign requests                        │
│  - ApprovalService: Manual approval workflow                      │
│  - TemplateService: Template expansion + instantiation            │
│  - SignerAccessService: Multi-tenant access control (RBAC/ACL)   │
│  DEPENDS ON: Domain Layer + Adapter Layer + Storage Layer        │
└───────────────────────────┬──────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────┐
│ DOMAIN LAYER (internal/core/)                                     │
│  - types/: Domain models (ChainAdapter, Rule, SignRequest, ...)  │
│  - rule/: Rule engine (two-tier evaluation)                       │
│  - statemachine/: Request lifecycle transitions                   │
│  - auth/: Ed25519 HMAC authentication                             │
│  DEPENDS ON: NOTHING (pure domain logic)                          │
└───────────────────────────┬──────────────────────────────────────┘
                            │
         ┌──────────────────┴──────────────────┐
         │                                     │
┌────────▼──────────┐              ┌───────────▼────────────┐
│ ADAPTER LAYER     │              │ STORAGE LAYER          │
│ (internal/chain/) │              │ (internal/storage/)    │
│  - EVMAdapter     │              │  - 11 Repositories     │
│  - SignerRegistry │              │  - GORM ORM            │
│  - Providers      │              │  - SQL migrations      │
│  - Evaluators     │              │  TECH: PostgreSQL/     │
│  TECH: ethsig,    │              │        SQLite          │
│        Sobek, Foundry │          └────────────────────────┘
└───────────────────┘
```

### 4.2 Dependency Rules

| From Layer | To Layer | Rule | Enforcement |
|-----------|----------|------|-------------|
| Domain | ANY | **NO dependencies** | Domain layer must be pure (no imports from api/, chain/, storage/) |
| Service | Domain, Adapter, Storage | **Interfaces only** | Service layer depends on interfaces, not implementations |
| Adapter | Domain | **One-way** | Adapters implement domain interfaces |
| Storage | Domain | **One-way** | Repositories implement domain interfaces |
| API | Service, Adapter | **Via interfaces** | Handlers call services, not adapters directly |

**Dependency Inversion Example**:
```go
// Domain layer defines interface:
package types
type ChainAdapter interface { ... }

// Service layer depends on interface:
package service
type SignService struct {
    chainRegistry *chain.Registry  // Registry of ChainAdapter implementations
}

// Adapter layer implements interface:
package evm
type EVMAdapter struct { ... }
func (a *EVMAdapter) Type() types.ChainType { return types.ChainTypeEVM }
// ... implement all ChainAdapter methods ...
var _ types.ChainAdapter = (*EVMAdapter)(nil)  // Compile-time check

// Main wires it up:
package main
evmAdapter, _ := evm.NewEVMAdapter(...)
chainRegistry.Register(evmAdapter)
signService, _ := service.NewSignService(chainRegistry, ...)
```

---

## 5. Data Architecture

### 5.1 Domain Models

**Core Entities**:

| Entity | Table | Primary Key | Key Relationships |
|--------|-------|-------------|-------------------|
| `SignRequest` | `sign_requests` | `id` (varchar(64)) | → `rules` (RuleMatchedID), → `api_keys` (APIKeyID) |
| `Rule` | `rules` | `id` (varchar(64)) | → `api_keys` (Owner), → `templates` (TemplateID) |
| `APIKey` | `api_keys` | `id` (varchar(64)) | → `rules` (many), → `sign_requests` (many) |
| `AuditRecord` | `audit_records` | `id` (bigserial) | → `sign_requests` (RequestID), → `rules` (RuleID) |
| `Budget` | `budgets` | `(rule_id, unit)` | → `rules` (RuleID) |
| `Template` | `templates` | `id` (varchar(128)) | → `rules` (many instances) |
| `SignerOwnership` | `signer_ownership` | `(address, chain_type)` | → `api_keys` (OwnerID) |
| `SignerAccess` | `signer_access` | `(signer_address, api_key_id)` | → `signer_ownership`, → `api_keys` |
| `WalletCollection` | `wallet_collections` | `id` (bigserial) | → `api_keys` (OwnerID) |

### 5.2 Entity Relationships

```
┌────────────┐           ┌────────────────┐           ┌──────────┐
│  APIKey    │ 1     n   │  SignRequest   │ n     0..1│  Rule    │
│            │───────────│                │───────────│          │
│ - id       │  creates  │ - id           │  matched  │ - id     │
│ - role     │           │ - status       │    by     │ - type   │
│ - public_key│          │ - chain_type   │           │ - mode   │
└──────┬─────┘           │ - signer       │           │ - config │
       │                 └────────────────┘           └─────┬────┘
       │ owns                                               │
       │                                              0..1  │ template
       │                                                    │
       │ 1                                                  │
       ▼                                                    ▼
┌────────────────┐                              ┌────────────────┐
│ SignerOwnership│                              │   Template     │
│                │                              │                │
│ - address      │ 1                  1..n      │ - id           │
│ - owner_id     │──────────────────────────────│ - variables    │
│ - status       │      instantiates            │ - rules        │
└────────┬───────┘                              └────────────────┘
         │
         │ 1
         │
         │ n
         ▼
┌────────────────┐
│ SignerAccess   │
│                │
│ - signer_addr  │
│ - api_key_id   │
│ - granted_at   │
└────────────────┘

┌────────────┐           ┌────────────────┐
│  Rule      │ 1     n   │    Budget      │
│            │───────────│                │
│ - id       │   tracks  │ - rule_id      │
│            │  spending │ - unit         │
└────────────┘           │ - spent        │
                         │ - max_total    │
                         └────────────────┘
```

### 5.3 Database Schema Highlights

**PostgreSQL/SQLite Dual Support**:
```go
// internal/storage/gorm.go
func NewDB(config config.DatabaseConfig) (*gorm.DB, error) {
    switch config.Type {
    case "postgres":
        return gorm.Open(postgres.Open(dsn), &gorm.Config{...})
    case "sqlite":
        return gorm.Open(sqlite.Open(dsn), &gorm.Config{...})
    }
}
```

**Automatic Migrations** (append-only):
```go
// internal/storage/migrate.go
func AutoMigrate(db *gorm.DB) error {
    return db.AutoMigrate(
        &types.SignRequest{},
        &types.Rule{},
        &types.APIKey{},
        &types.AuditRecord{},
        &types.Budget{},
        &types.Template{},
        &types.SignerOwnership{},
        &types.SignerAccess{},
        &types.WalletCollection{},
        // ... more models ...
    )
}
```

**Indexes** (for query performance):
```go
type SignRequest struct {
    APIKeyID  string `gorm:"index"`           // Filter by API key
    ChainType string `gorm:"index"`           // Filter by chain
    Status    string `gorm:"index"`           // Filter by status
    SignerAddress string `gorm:"index"`       // Filter by signer
}

type Rule struct {
    Type        string `gorm:"index"`         // Filter by rule type
    Mode        string `gorm:"index"`         // Filter by whitelist/blocklist
    Enabled     bool   `gorm:"index"`         // Filter active rules
    Status      string `gorm:"index"`         // Filter by approval status
    Owner       string `gorm:"index"`         // Filter by owner
}
```

---

## 6. Cross-Cutting Concerns Implementation

### 6.1 Authentication & Authorization

#### 6.1.1 Ed25519 HMAC Authentication

**File**: `internal/core/auth/verifier.go`

**Signature Format**:
```
message = "{timestamp_ms}|{nonce}|{method}|{path}|{sha256(body)}"
signature = Ed25519.Sign(private_key, message)
```

**HTTP Headers**:
```
X-API-Key-ID: {api_key_id}
X-Timestamp: {unix_timestamp_ms}
X-Nonce: {random_string}
X-Signature: {hex_encoded_ed25519_signature}
```

**Verification Steps**:
```go
func (v *Verifier) Verify(req *http.Request) (*types.APIKey, error) {
    // 1. Extract headers
    apiKeyID := req.Header.Get("X-API-Key-ID")
    timestamp := req.Header.Get("X-Timestamp")
    nonce := req.Header.Get("X-Nonce")
    signature := req.Header.Get("X-Signature")
    
    // 2. Validate timestamp (within ±5 min default)
    ts, err := strconv.ParseInt(timestamp, 10, 64)
    if time.Since(time.Unix(0, ts*1e6)) > v.maxRequestAge {
        return nil, ErrRequestExpired
    }
    
    // 3. Read body (max 10MB)
    body, err := io.ReadAll(io.LimitReader(req.Body, 10*1024*1024))
    
    // 4. Reconstruct signed message
    bodyHash := sha256.Sum256(body)
    message := fmt.Sprintf("%s|%s|%s|%s|%x", timestamp, nonce, req.Method, req.URL.Path, bodyHash)
    
    // 5. Verify Ed25519 signature
    apiKey, err := v.apiKeyRepo.Get(ctx, apiKeyID)
    publicKey := hex.DecodeString(apiKey.PublicKey)
    if !ed25519.Verify(publicKey, []byte(message), signature) {
        return nil, ErrInvalidSignature
    }
    
    // 6. Check nonce replay (if enabled)
    if v.nonceRequired {
        if v.nonceStore.Exists(apiKeyID, nonce) {
            return nil, ErrNonceReplay
        }
        v.nonceStore.Store(apiKeyID, nonce, ts)
    }
    
    return apiKey, nil
}
```

**Nonce Store** (in-memory, TTL-based):
```go
type NonceStore struct {
    mu     sync.RWMutex
    nonces map[string]map[string]int64  // apiKeyID -> nonce -> timestamp
}

func (s *NonceStore) Exists(apiKeyID, nonce string) bool {
    s.mu.RLock()
    defer s.mu.RUnlock()
    nonces, ok := s.nonces[apiKeyID]
    if !ok {
        return false
    }
    _, exists := nonces[nonce]
    return exists
}
```

---

#### 6.1.2 RBAC (Role-Based Access Control)

**File**: `internal/api/middleware/rbac.go`

**Roles**:
```go
type APIKeyRole string

const (
    RoleAdmin    APIKeyRole = "admin"     // Full access
    RoleDev      APIKeyRole = "dev"       // Development/testing
    RoleAgent    APIKeyRole = "agent"     // Automated systems
    RoleStrategy APIKeyRole = "strategy"  // Trading strategies (read-only + sign)
)
```

**Permission Matrix** (27 permissions):

| Permission | Admin | Dev | Agent | Strategy |
|-----------|:-----:|:---:|:-----:|:--------:|
| `sign_request` | ✓ | ✓ | ✓ | ✓ |
| `list_own_requests` | ✓ | ✓ | ✓ | ✓ |
| `list_all_requests` | ✓ | - | - | - |
| `approve_request` | ✓ | - | - | - |
| `list_rules` | ✓ | ✓ | ✓ | - |
| `create_rule_self` | ✓ | ✓ | ✓ | - |
| `create_rule_any` | ✓ | - | - | - |
| `modify_own_rule` | ✓ | ✓ | ✓ | - |
| `modify_any_rule` | ✓ | - | - | - |
| `delete_own_rule` | ✓ | ✓ | - | - |
| `delete_any_rule` | ✓ | - | - | - |
| `approve_rule` | ✓ | - | - | - |
| `read_budgets` | ✓ | ✓ | ✓ | - |
| `read_templates` | ✓ | ✓ | ✓ | - |
| `instantiate_template` | ✓ | ✓ | - | - |
| `read_presets` | ✓ | - | - | - |
| `apply_preset` | ✓ | - | - | - |
| `read_signers` | ✓ | ✓ | ✓ | ✓ |
| `create_signers` | ✓ | - | - | - |
| `unlock_signer` | ✓ | - | - | - |
| `read_hd_wallets` | ✓ | ✓ | - | - |
| `create_hd_wallet` | ✓ | - | - | - |
| `manage_api_keys` | ✓ | - | - | - |
| `read_audit` | ✓ | - | - | - |
| `read_metrics` | ✓ | - | - | - |
| `read_acls` | ✓ | - | - | - |
| `resume_guard` | ✓ | - | - | - |
| `approve_signer` | ✓ | - | - | - |
| `manage_collections` | ✓ | ✓ | - | - |

**Permission Check**:
```go
func RequirePermission(permission Permission) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            apiKey := middleware.GetAPIKey(r.Context())
            if !hasPermission(apiKey.Role, permission) {
                writeError(w, http.StatusForbidden, ErrorCodeForbidden, "insufficient permissions")
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}
```

---

#### 6.1.3 Multi-Tenant Access Control (ACL)

**Files**: `internal/core/service/signer_access.go`, `internal/storage/signer_ownership_repo.go`, `internal/storage/signer_access_repo.go`

**Three-Layer Model**:

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. OWNERSHIP (SignerOwnership)                                  │
│    - One owner per signer (API key ID)                          │
│    - Owner has full control (approve, grant, revoke, delete)    │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│ 2. ACCESS GRANTS (SignerAccess)                                 │
│    - Owner grants access to other API keys                      │
│    - Granted keys can use signer for signing                    │
│    - Cannot further grant or modify                             │
└────────────────────────┬────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────────┐
│ 3. RUNTIME CHECKS                                                │
│    - SignService checks ownership + access before signing       │
│    - ApprovalService checks ownership before manual approval    │
└─────────────────────────────────────────────────────────────────┘
```

**API Operations**:

| Operation | Endpoint | Auth | Description |
|-----------|----------|------|-------------|
| Create Signer | `POST /api/v1/evm/signers` | Admin | Creates signer, sets caller as owner |
| Grant Access | `POST /api/v1/evm/signers/{addr}/access` | Owner | Grant access to another API key |
| Revoke Access | `DELETE /api/v1/evm/signers/{addr}/access/{keyId}` | Owner | Revoke access from an API key |
| Transfer Ownership | `POST /api/v1/evm/signers/{addr}/ownership` | Owner | Transfer ownership, **clears all access grants** |
| List Access | `GET /api/v1/evm/signers/{addr}/access` | Owner | List all API keys with access |
| Delete Signer | `DELETE /api/v1/evm/signers/{addr}` | Owner | Delete signer + ownership + access records |

**Runtime Permission Check** (Sign Handler):
```go
// internal/api/handler/evm/sign.go
func (h *SignHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    apiKey := middleware.GetAPIKey(r.Context())
    var req SignRequest
    json.NewDecoder(r.Body).Decode(&req)
    
    // Check signer permission (ownership OR access grant)
    if !h.accessService.CheckSignerPermission(r.Context(), apiKey.ID, req.SignerAddress) {
        writeError(w, http.StatusForbidden, ErrorCodeForbidden, "no permission to use this signer")
        return
    }
    
    resp, err := h.signService.Sign(r.Context(), &service.SignRequest{...})
    writeJSON(w, resp, http.StatusOK)
}
```

---

### 6.2 Error Handling & Resilience

#### 6.2.1 Constructors Return Error

**Principle**: All constructors (NewXXX) **must** return `error`. No panics in constructors.

```go
// CORRECT:
func NewSignService(
    chainRegistry *chain.Registry,
    requestRepo storage.RequestRepository,
    ruleEngine rule.RuleEngine,
    stateMachine *statemachine.StateMachine,
    approvalService *ApprovalService,
    logger *slog.Logger,
) (*SignService, error) {
    if chainRegistry == nil {
        return nil, fmt.Errorf("chain registry is required")
    }
    if requestRepo == nil {
        return nil, fmt.Errorf("request repository is required")
    }
    // ... all dependencies validated
    return &SignService{...}, nil
}

// WRONG:
func NewSignService(...) *SignService {
    return &SignService{...}  // No error handling
}
```

**Enforcement**: Manual code review + test coverage for nil dependencies.

---

#### 6.2.2 Explicit Error Propagation

**Principle**: Never swallow errors. Always propagate or log.

```go
// FORBIDDEN:
_ = someOperation()  // Ignores error

// CORRECT:
if err := someOperation(); err != nil {
    return fmt.Errorf("operation failed: %w", err)
}
```

---

#### 6.2.3 Approval Guard (Leak Detection)

**File**: `internal/core/service/approval_guard.go`

**Purpose**: Detect compromised API keys by monitoring **consecutive rejections** (blocklist violations + manual approval needs).

**Configuration**:
```yaml
security:
  approval_guard:
    enabled: true
    window: "5m"          # Time window for counting
    threshold: 10         # Consecutive rejections to trigger pause
    resume_after: "2h"    # Auto-resume after this duration (0 = manual only)
```

**State Machine**:
```
     active
       │
       │ consecutive_rejections ≥ threshold
       ▼
     paused ────────────────────────┐
       │                            │
       │ after resume_after         │ admin resume
       │ (if > 0)                   │
       ▼                            │
     active ←───────────────────────┘
```

**Integration** (SignService):
```go
func (s *SignService) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
    // Check guard BEFORE validation
    if s.approvalGuard != nil && s.approvalGuard.IsPaused() {
        return nil, fmt.Errorf("sign requests paused due to approval guard; use admin API to resume")
    }
    
    // ... normal flow ...
    
    // After rule evaluation:
    if result.Blocked {
        s.approvalGuard.RecordRejection()  // Count rejection
        return nil, BlockedError{...}
    }
    if !result.Allowed {
        s.approvalGuard.RecordRejection()  // Count manual approval need
        return &SignResponse{Status: "authorizing"}, nil
    }
    
    s.approvalGuard.Reset()  // Reset on successful whitelist match
    // ... sign ...
}
```

**Admin Resume**:
```bash
curl -X POST http://localhost:8548/api/v1/evm/guard/resume \
  -H "X-API-Key-ID: admin-key" \
  -H "X-Signature: ..." \
  -H "X-Timestamp: ..."
```

---

### 6.3 Logging & Monitoring

#### 6.3.1 Structured Logging (slog)

**File**: `internal/logger/logger.go`

```go
import "log/slog"

logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))

logger.Info("sign request created",
    "request_id", reqID,
    "chain_type", chainType,
    "signer", signerAddr,
    "sign_type", signType,
)
```

**Log Levels**:
- **DEBUG**: Rule evaluation details, state transitions
- **INFO**: Request lifecycle events (created, authorized, completed)
- **WARN**: Non-critical errors (rule evaluation failures in whitelist mode)
- **ERROR**: Critical errors (blocklist evaluation failures, signing failures)

---

#### 6.3.2 Audit Logging

**File**: `internal/audit/logger.go`

**15 Audit Event Types**:

| Event Type | Severity | Trigger |
|-----------|----------|---------|
| `auth_success` | Info | API key authenticated |
| `auth_failure` | Critical | Invalid signature / expired timestamp |
| `sign_request` | Info | Sign request created |
| `sign_complete` | Info | Signature generated |
| `sign_failed` | Critical | Signing operation failed |
| `sign_rejected` | Warning | Rejected by rule or manual review |
| `rule_matched` | Info | Whitelist rule auto-approved |
| `rule_created` | Warning | New rule added |
| `rule_updated` | Warning | Rule modified |
| `rule_deleted` | Warning | Rule removed |
| `approval_request` | Info | Request awaiting manual approval |
| `approval_granted` | Warning | Admin approved request |
| `approval_denied` | Warning | Admin rejected request |
| `rate_limit_hit` | Warning | Rate limit exceeded |
| `ip_blocked` | Critical | IP whitelist violation |

**Audit Record Structure**:
```go
type AuditRecord struct {
    ID          string
    EventType   AuditEventType
    Severity    AuditSeverity   // "info", "warning", "critical"
    RequestID   *string         // Related sign request (if applicable)
    RuleID      *string         // Related rule (if applicable)
    APIKeyID    *string         // Actor API key
    Actor       string          // API key ID or "system"
    Details     json.RawMessage // Event-specific metadata
    CreatedAt   time.Time
}
```

**Retention Policy**:
```yaml
audit:
  retention_days: 90  # Auto-delete records older than 90 days
```

---

#### 6.3.3 Prometheus Metrics

**File**: `internal/metrics/metrics.go`

**Exposed Metrics**:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `sign_requests_total` | Counter | `chain_type`, `status` | Total sign requests |
| `sign_duration_seconds` | Histogram | `chain_type` | Sign operation duration |
| `rule_evaluations_total` | Counter | `rule_type`, `mode`, `outcome` | Rule evaluations |
| `rule_evaluation_duration_seconds` | Histogram | `rule_type` | Rule evaluation duration |
| `auth_failures_total` | Counter | `reason` | Authentication failures |
| `rate_limit_hits_total` | Counter | `type` | Rate limit violations |
| `approval_guard_pauses_total` | Counter | - | Approval guard activations |

**Endpoint**: `GET /metrics` (no auth required)

---

### 6.4 Validation

#### 6.4.1 Input Validation (Entry Points)

**File**: `internal/validate/validate.go`

**Ethereum Address Validation**:
```go
func IsValidEthereumAddress(addr string) bool {
    if !strings.HasPrefix(addr, "0x") {
        return false
    }
    if len(addr) != 42 {  // 0x + 40 hex chars
        return false
    }
    _, err := hex.DecodeString(addr[2:])
    return err == nil
}
```

**Sign Type Validation**:
```go
var ValidSignTypes = map[string]bool{
    "hash":         true,
    "raw_message":  true,
    "eip191":       true,
    "personal":     true,
    "typed_data":   true,
    "transaction":  true,
}
```

**Payload Size Limits**:
```go
const (
    maxTransactionDataSize = 128 * 1024   // 128 KB
    maxMessageSize         = 1024 * 1024  // 1 MB
    maxRawMessageSize      = 256 * 1024   // 256 KB
    maxPayloadSize         = 2 * 1024 * 1024 // 2 MB (whole payload)
)
```

---

#### 6.4.2 JS Rule Security Validation

**File**: `internal/chain/evm/js_validator.go`, `internal/validate/js_security.go`

**Forbidden Patterns**:
```go
var forbiddenPatterns = []string{
    `eval\s*\(`,          // eval(...)
    `Function\s*\(`,      // new Function(...)
    `require\s*\(`,       // require(...)
    `import\s*\(`,        // import(...)
    `import\s+`,          // import ...
    `process\.`,          // process.env, process.exit
    `globalThis\.`,       // globalThis access
    `__proto__`,          // prototype pollution
}
```

**Validation** (at rule creation/update):
```go
func ValidateJSRule(script string) error {
    for _, pattern := range forbiddenPatterns {
        if regexp.MustCompile(pattern).MatchString(script) {
            return fmt.Errorf("forbidden pattern: %s", pattern)
        }
    }
    
    // Check script size
    if len(script) > 64*1024 {
        return fmt.Errorf("script exceeds 64KB limit")
    }
    
    // Validate function signature
    if !strings.Contains(script, "function validate(") {
        return fmt.Errorf("script must define validate(input, config) function")
    }
    
    return nil
}
```

---

### 6.5 Configuration Management

#### 6.5.1 Config Sync (File → DB)

**File**: `internal/config/rule_init.go`, `internal/config/template_init.go`, `internal/config/apikey_init.go`

**Sync Strategy**: Upsert (insert or update existing)

**Rule Sync**:
```go
func (ri *RuleInitializer) SyncFromConfig(ctx context.Context, configRules []ConfigRule) error {
    for _, cfgRule := range configRules {
        // Expand template instances
        if cfgRule.Type == "instance" {
            rules, err := ri.expandInstance(cfgRule)
            // ... insert expanded rules ...
        }
        
        // Upsert rule
        existingRule, err := ri.ruleRepo.GetByID(ctx, cfgRule.ID)
        if err == nil {
            // Rule exists, update if changed
            if !rulesEqual(existingRule, cfgRule) {
                ri.ruleRepo.Update(ctx, toRule(cfgRule))
                ri.auditLogger.LogEvent(ctx, types.AuditEventTypeRuleUpdated)
            }
        } else {
            // Rule doesn't exist, create
            ri.ruleRepo.Create(ctx, toRule(cfgRule))
            ri.auditLogger.LogEvent(ctx, types.AuditEventTypeRuleCreated)
        }
    }
    return nil
}
```

**Template Sync** (similar pattern for templates):
- Load templates from `rules/templates/*.yaml`
- Upsert to `templates` table
- Audit log only on **actual changes** (not every startup)

---

#### 6.5.2 Hot Reload (SIGHUP)

**File**: `cmd/remote-signer/main.go`

```go
sigChan := make(chan os.Signal, 1)
signal.Notify(sigChan, syscall.SIGHUP)

go func() {
    for sig := range sigChan {
        if sig == syscall.SIGHUP {
            logger.Info("SIGHUP received, reloading config")
            
            // Reload config file
            newCfg, err := config.Load(configPath)
            if err != nil {
                logger.Error("config reload failed", "error", err)
                continue
            }
            
            // Re-sync rules, templates, API keys
            ruleInit.SyncFromConfig(ctx, newCfg.Rules)
            templateInit.SyncFromConfig(ctx, newCfg.Templates)
            apiKeyInit.SyncFromConfig(ctx, newCfg.APIKeys)
            
            // Audit log
            auditLogger.LogEvent(ctx, types.AuditEventTypeConfigReloaded)
            
            logger.Info("config reloaded successfully")
        }
    }
}()
```

**Usage**:
```bash
kill -HUP $(cat /var/run/remote-signer.pid)
# OR
pkill -HUP remote-signer
```

---

## 7. Technology-Specific Architectural Patterns (Go)

### 7.1 Dependency Injection

**Pattern**: Constructor-based DI (no framework)

```go
// Service depends on interfaces:
type SignService struct {
    chainRegistry   *chain.Registry
    requestRepo     storage.RequestRepository  // Interface
    ruleEngine      rule.RuleEngine             // Interface
    stateMachine    *statemachine.StateMachine
    approvalService *ApprovalService
    logger          *slog.Logger
}

// Constructor validates all dependencies:
func NewSignService(...) (*SignService, error) {
    if chainRegistry == nil {
        return nil, fmt.Errorf("chain registry is required")
    }
    // ... validate all deps ...
    return &SignService{...}, nil
}

// Main wires everything:
func main() {
    db, _ := storage.NewDB(cfg.Database)
    requestRepo, _ := storage.NewGormRequestRepository(db)
    ruleRepo, _ := storage.NewGormRuleRepository(db)
    
    ruleEngine := rule.NewWhitelistRuleEngine(ruleRepo, logger)
    stateMachine, _ := statemachine.NewStateMachine(requestRepo, auditRepo, logger)
    signService, _ := service.NewSignService(chainRegistry, requestRepo, ruleEngine, stateMachine, approvalService, logger)
}
```

---

### 7.2 Interface Segregation

**Pattern**: Small, focused interfaces (no God interfaces)

```go
// GOOD: Small interfaces
type SignerProvider interface {
    List(ctx context.Context) ([]types.SignerInfo, error)
    Get(ctx context.Context, address string) (*types.SignerInfo, error)
}

type SignerCreator interface {
    Create(ctx context.Context, req types.CreateSignerRequest) (*types.SignerInfo, error)
}

type SignerUnlocker interface {
    Unlock(ctx context.Context, address string, password string) error
}

// Implementation can choose which interfaces to implement:
type KeystoreProvider struct { ... }
func (p *KeystoreProvider) List(...) { ... }      // SignerProvider
func (p *KeystoreProvider) Get(...) { ... }       // SignerProvider
func (p *KeystoreProvider) Create(...) { ... }    // SignerCreator
func (p *KeystoreProvider) Unlock(...) { ... }    // SignerUnlocker

// Compile-time checks:
var _ SignerProvider = (*KeystoreProvider)(nil)
var _ SignerCreator = (*KeystoreProvider)(nil)
var _ SignerUnlocker = (*KeystoreProvider)(nil)
```

---

### 7.3 Concurrency Patterns

#### 7.3.1 Goroutine Lifecycle Management

```go
// Start background worker with context:
func (s *Service) Start(ctx context.Context) {
    s.wg.Add(1)
    go func() {
        defer s.wg.Done()
        ticker := time.NewTicker(1 * time.Hour)
        defer ticker.Stop()
        
        for {
            select {
            case <-ctx.Done():
                return  // Graceful shutdown
            case <-ticker.C:
                s.doWork()
            }
        }
    }()
}

// Shutdown waits for all goroutines:
func (s *Service) Shutdown(ctx context.Context) error {
    s.cancel()  // Cancel context
    
    done := make(chan struct{})
    go func() {
        s.wg.Wait()
        close(done)
    }()
    
    select {
    case <-done:
        return nil
    case <-ctx.Done():
        return ctx.Err()  // Timeout
    }
}
```

---

#### 7.3.2 Mutex for Shared State

```go
type NonceStore struct {
    mu     sync.RWMutex
    nonces map[string]map[string]int64
}

func (s *NonceStore) Store(apiKeyID, nonce string, ts int64) {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    if s.nonces[apiKeyID] == nil {
        s.nonces[apiKeyID] = make(map[string]int64)
    }
    s.nonces[apiKeyID][nonce] = ts
}

func (s *NonceStore) Exists(apiKeyID, nonce string) bool {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    nonces, ok := s.nonces[apiKeyID]
    if !ok {
        return false
    }
    _, exists := nonces[nonce]
    return exists
}
```

---

### 7.4 Error Wrapping (Go 1.13+)

```go
// Wrap errors with context:
func (s *SignService) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
    adapter, err := s.chainRegistry.Get(req.ChainType)
    if err != nil {
        return nil, fmt.Errorf("failed to get chain adapter: %w", err)
    }
    
    if err := adapter.ValidateBasicRequest(...); err != nil {
        return nil, fmt.Errorf("basic request validation failed: %w", err)
    }
    
    // ...
}

// Unwrap errors:
if errors.Is(err, rule.ErrBlockedByRule) {
    // Handle blocklist violation
}
```

---

### 7.5 Context Propagation

```go
// Pass context through all layers:
func (s *SignService) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
    // Add timeout
    ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()
    
    // Pass to adapter
    result, err := adapter.Sign(ctx, ...)
    
    // Check cancellation
    select {
    case <-ctx.Done():
        return nil, ctx.Err()
    default:
    }
    
    return result, nil
}
```

---

## 8. Implementation Patterns

### 8.1 Repository Pattern

**Interface** (domain layer):
```go
package storage

type RequestRepository interface {
    Create(ctx context.Context, req *types.SignRequest) error
    Get(ctx context.Context, id types.SignRequestID) (*types.SignRequest, error)
    Update(ctx context.Context, req *types.SignRequest) error
    CompareAndUpdate(ctx context.Context, req *types.SignRequest, expectedStatus types.SignRequestStatus) error
    List(ctx context.Context, filter RequestFilter) ([]*types.SignRequest, error)
    Count(ctx context.Context, filter RequestFilter) (int, error)
}
```

**Implementation** (storage layer):
```go
package storage

type GormRequestRepository struct {
    db *gorm.DB
}

func NewGormRequestRepository(db *gorm.DB) (RequestRepository, error) {
    if db == nil {
        return nil, fmt.Errorf("db is required")
    }
    return &GormRequestRepository{db: db}, nil
}

func (r *GormRequestRepository) Create(ctx context.Context, req *types.SignRequest) error {
    return r.db.WithContext(ctx).Create(req).Error
}

func (r *GormRequestRepository) CompareAndUpdate(ctx context.Context, req *types.SignRequest, expectedStatus types.SignRequestStatus) error {
    result := r.db.WithContext(ctx).
        Model(req).
        Where("id = ? AND status = ?", req.ID, expectedStatus).
        Updates(req)
    
    if result.Error != nil {
        return result.Error
    }
    if result.RowsAffected == 0 {
        return fmt.Errorf("request status mismatch (expected %s)", expectedStatus)
    }
    return nil
}
```

---

### 8.2 State Machine Pattern

**File**: `internal/core/statemachine/machine.go`

```go
type StateMachine struct {
    requestRepo storage.RequestRepository
    auditRepo   storage.AuditRepository
    logger      *slog.Logger
}

// All transitions return TransitionResult + error:
type TransitionResult struct {
    PreviousStatus types.SignRequestStatus
    NewStatus      types.SignRequestStatus
    Reason         string
}

func (sm *StateMachine) transition(
    ctx context.Context,
    reqID types.SignRequestID,
    expectedStatus types.SignRequestStatus,
    newStatus types.SignRequestStatus,
    reason string,
) (*TransitionResult, error) {
    req, err := sm.requestRepo.Get(ctx, reqID)
    if err != nil {
        return nil, fmt.Errorf("failed to get request: %w", err)
    }
    
    if req.Status != expectedStatus {
        return nil, fmt.Errorf("invalid state transition: cannot move from %s to %s", req.Status, newStatus)
    }
    
    now := time.Now()
    prevStatus := req.Status
    req.Status = newStatus
    req.UpdatedAt = now
    
    if err := sm.requestRepo.CompareAndUpdate(ctx, req, expectedStatus); err != nil {
        return nil, fmt.Errorf("failed to update request: %w", err)
    }
    
    sm.logAudit(ctx, req, auditEventForTransition(prevStatus, newStatus), reason)
    
    return &TransitionResult{
        PreviousStatus: prevStatus,
        NewStatus:      newStatus,
        Reason:         reason,
    }, nil
}
```

---

### 8.3 Strategy Pattern (RuleEvaluator)

**Interface**:
```go
type RuleEvaluator interface {
    Type() RuleType
    Evaluate(ctx context.Context, rule *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error)
}
```

**Registry**:
```go
type RuleEngine struct {
    evaluators map[types.RuleType]RuleEvaluator
    sealed     bool
}

func (e *RuleEngine) RegisterEvaluator(evaluator RuleEvaluator) {
    if e.sealed {
        panic("cannot register evaluator after engine is sealed")
    }
    e.evaluators[evaluator.Type()] = evaluator
}

func (e *RuleEngine) Seal() {
    e.sealed = true
}
```

**Main wires strategies**:
```go
func main() {
    ruleEngine := rule.NewWhitelistRuleEngine(...)
    
    // Register all evaluators:
    ruleEngine.RegisterEvaluator(evm.NewAddressListEvaluator())
    ruleEngine.RegisterEvaluator(evm.NewContractMethodEvaluator())
    ruleEngine.RegisterEvaluator(evm.NewValueLimitEvaluator())
    ruleEngine.RegisterEvaluator(evm.NewJSRuleEvaluator(...))
    // ... more evaluators ...
    
    ruleEngine.Seal()  // Prevent further registrations
}
```

---

### 8.4 Middleware Chain

**Pattern**: Closure-based middleware (no framework)

```go
type Middleware func(http.Handler) http.Handler

func Chain(middlewares ...Middleware) Middleware {
    return func(final http.Handler) http.Handler {
        for i := len(middlewares) - 1; i >= 0; i-- {
            final = middlewares[i](final)
        }
        return final
    }
}

// Usage:
handler := Chain(
    SecurityHeadersMiddleware(),
    RecoveryMiddleware(),
    LoggingMiddleware(logger),
    AuthMiddleware(verifier),
)(finalHandler)
```

**Individual Middleware**:
```go
func AuthMiddleware(verifier *auth.Verifier) Middleware {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            apiKey, err := verifier.Verify(r)
            if err != nil {
                writeError(w, http.StatusUnauthorized, ErrorCodeUnauthorized, err.Error())
                return
            }
            
            // Store in context
            ctx := context.WithValue(r.Context(), apiKeyCtxKey{}, apiKey)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

---

## 9. Testing Architecture

### 9.1 Test Organization

```
remote-signer/
├── internal/
│   ├── core/
│   │   ├── rule/
│   │   │   ├── engine.go
│   │   │   └── engine_test.go        # Unit tests
│   │   ├── service/
│   │   │   ├── sign.go
│   │   │   └── sign_test.go
│   │   └── ...
│   ├── chain/
│   │   └── evm/
│   │       ├── adapter.go
│   │       ├── adapter_test.go
│   │       ├── js_evaluator.go
│   │       └── js_evaluator_test.go
│   └── ...
├── e2e/
│   ├── sign_test.go                  # End-to-end tests
│   ├── rule_test.go
│   ├── approval_test.go
│   └── tui_test.go
└── pkg/
    └── client/
        └── client_test.go            # SDK integration tests
```

### 9.2 Test Statistics

- **Total Tests**: 2,387
  - **Unit Tests**: 2,173 (91%)
  - **E2E Tests**: 214 (9%)
- **Coverage**: 95%+ for core components (rule engine, state machine, adapters)

### 9.3 Test Patterns

#### 9.3.1 Table-Driven Tests

```go
func TestAddressListEvaluator_Evaluate(t *testing.T) {
    tests := []struct {
        name        string
        rule        *types.Rule
        request     *types.SignRequest
        parsed      *types.ParsedPayload
        wantMatched bool
        wantReason  string
        wantErr     bool
    }{
        {
            name: "whitelist mode: address in list",
            rule: &types.Rule{
                Mode: types.RuleModeWhitelist,
                Config: mustJSON(t, evm.AddressListConfig{
                    Addresses: []string{"0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"},
                }),
            },
            parsed: &types.ParsedPayload{
                Recipient: ptr("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"),
            },
            wantMatched: true,
            wantReason:  "recipient in allowed addresses",
        },
        // ... more test cases ...
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            evaluator := evm.NewAddressListEvaluator()
            matched, reason, err := evaluator.Evaluate(ctx, tt.rule, tt.request, tt.parsed)
            
            if (err != nil) != tt.wantErr {
                t.Errorf("wantErr=%v, got err=%v", tt.wantErr, err)
            }
            if matched != tt.wantMatched {
                t.Errorf("wantMatched=%v, got matched=%v", tt.wantMatched, matched)
            }
            if reason != tt.wantReason {
                t.Errorf("wantReason=%q, got reason=%q", tt.wantReason, reason)
            }
        })
    }
}
```

---

#### 9.3.2 Mock Repositories (Interfaces)

```go
type MockRequestRepository struct {
    CreateFunc func(ctx context.Context, req *types.SignRequest) error
    GetFunc    func(ctx context.Context, id types.SignRequestID) (*types.SignRequest, error)
    // ... more methods ...
}

func (m *MockRequestRepository) Create(ctx context.Context, req *types.SignRequest) error {
    if m.CreateFunc != nil {
        return m.CreateFunc(ctx, req)
    }
    return nil
}

// Usage in test:
func TestSignService_Sign(t *testing.T) {
    mockRepo := &MockRequestRepository{
        CreateFunc: func(ctx context.Context, req *types.SignRequest) error {
            // Verify request fields
            if req.ChainType != types.ChainTypeEVM {
                t.Errorf("unexpected chain type")
            }
            return nil
        },
    }
    
    signService, _ := service.NewSignService(chainRegistry, mockRepo, ...)
    // ... test sign service ...
}
```

---

#### 9.3.3 E2E Tests (SQLite In-Memory)

```go
func TestE2E_SignRequest(t *testing.T) {
    // Setup in-memory SQLite database
    db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
    require.NoError(t, err)
    storage.AutoMigrate(db)
    
    // Setup repositories
    requestRepo, _ := storage.NewGormRequestRepository(db)
    ruleRepo, _ := storage.NewGormRuleRepository(db)
    apiKeyRepo, _ := storage.NewGormAPIKeyRepository(db)
    // ... more repos ...
    
    // Setup services
    ruleEngine := rule.NewWhitelistRuleEngine(ruleRepo, logger)
    // ... register evaluators ...
    signService, _ := service.NewSignService(...)
    
    // Setup HTTP server
    router := api.NewRouter(authVerifier, signService, ...)
    server := httptest.NewServer(router)
    defer server.Close()
    
    // Create test API key
    apiKey := &types.APIKey{
        ID:        "test-key",
        PublicKey: hex.EncodeToString(publicKey),
        Role:      types.RoleAdmin,
    }
    apiKeyRepo.Create(ctx, apiKey)
    
    // Test: Sign request
    payload := `{"chain_id":"1","signer_address":"0x...","sign_type":"transaction","payload":{...}}`
    signature := signPayload(privateKey, timestamp, nonce, "POST", "/api/v1/evm/sign", payload)
    
    req, _ := http.NewRequest("POST", server.URL+"/api/v1/evm/sign", strings.NewReader(payload))
    req.Header.Set("X-API-Key-ID", "test-key")
    req.Header.Set("X-Timestamp", timestamp)
    req.Header.Set("X-Nonce", nonce)
    req.Header.Set("X-Signature", signature)
    
    resp, _ := http.DefaultClient.Do(req)
    assert.Equal(t, http.StatusOK, resp.StatusCode)
    
    var signResp service.SignResponse
    json.NewDecoder(resp.Body).Decode(&signResp)
    assert.Equal(t, types.StatusCompleted, signResp.Status)
    assert.NotEmpty(t, signResp.Signature)
}
```

---

## 10. Deployment Architecture

### 10.1 Deployment Topology

**Production (Kubernetes)**:
```
┌──────────────────────────────────────────────────────────────┐
│                      Load Balancer                            │
│                   (MetalLB / Cloud LB)                        │
└───────────────────────┬──────────────────────────────────────┘
                        │
                        │ TLS/mTLS
                        ▼
┌──────────────────────────────────────────────────────────────┐
│                    Ingress / Traefik                          │
│              - TLS termination                                │
│              - Rate limiting (IP-level)                       │
│              - IP whitelist (optional)                        │
└───────────────────────┬──────────────────────────────────────┘
                        │
         ┌──────────────┼──────────────┐
         │              │              │
         ▼              ▼              ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ Pod 1       │  │ Pod 2       │  │ Pod 3       │
│             │  │             │  │             │
│ remote-     │  │ remote-     │  │ remote-     │
│  signer     │  │  signer     │  │  signer     │
│             │  │             │  │             │
│ - API       │  │ - API       │  │ - API       │
│ - Signers   │  │ - Signers   │  │ - Signers   │
│   (locked)  │  │   (locked)  │  │   (locked)  │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │
       └────────────────┼────────────────┘
                        │
                        ▼
              ┌────────────────────┐
              │    PostgreSQL      │
              │  (Persistent Data) │
              │                    │
              │ - Rules            │
              │ - Sign Requests    │
              │ - API Keys         │
              │ - Audit Log        │
              │ - Budgets          │
              └────────────────────┘
```

**Notes**:
1. **Stateless pods**: No in-memory session state, scales horizontally
2. **Locked signers**: Private keys encrypted at rest, must be unlocked via API (admin only)
3. **Shared database**: All pods share PostgreSQL for consistency
4. **Persistent volumes**: Keystore/HD wallet files on persistent volumes (ReadWriteMany or per-pod)

---

### 10.2 Docker Deployment

**Docker Compose** (single-node development):

```yaml
version: '3.8'

services:
  remote-signer:
    image: remote-signer:latest
    ports:
      - "8548:8548"  # API
    volumes:
      - ./config.yaml:/app/config.yaml
      - ./data:/app/data  # Keystores + HD wallets
      - ./rules:/app/rules  # Templates + presets
    environment:
      - POSTGRES_HOST=postgres
      - POSTGRES_PORT=5432
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=remote_signer
      - KEYSTORE_PASSWORD=${KEYSTORE_PASSWORD}  # Injected from .env
      - HDWALLET_PASSWORD=${HDWALLET_PASSWORD}
    depends_on:
      - postgres
    restart: unless-stopped
    
  postgres:
    image: postgres:15
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=remote_signer
    restart: unless-stopped
    
volumes:
  postgres_data:
```

**Healthcheck**:
```yaml
healthcheck:
  test: ["CMD", "wget", "--spider", "http://localhost:8548/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 60s
```

---

### 10.3 Configuration Management

**Secrets** (never commit to git):
- **KEYSTORE_PASSWORD**: Keystore file decryption password
- **HDWALLET_PASSWORD**: HD wallet mnemonic decryption password
- **TELEGRAM_BOT_TOKEN**: Telegram bot token (for notifications)
- **SLACK_WEBHOOK_URL**: Slack webhook URL

**Inject via**:
1. **Environment variables**: `${VAR_NAME}` in config.yaml
2. **Secret managers**: Kubernetes Secrets, Vault, AWS Secrets Manager
3. **Encrypted files**: git-crypt, SOPS

---

## 11. Extension and Evolution Patterns

### 11.1 Adding a New Chain (e.g., Solana)

**Steps**:

1. **Define Solana types** (`internal/chain/solana/types.go`):
```go
package solana

type SolanaSignPayload struct {
    Transaction string `json:"transaction"`  // Base58-encoded transaction
    Message     string `json:"message"`      // Optional: message sign
}
```

2. **Implement ChainAdapter** (`internal/chain/solana/adapter.go`):
```go
package solana

type SolanaAdapter struct {
    signerRegistry *SignerRegistry
}

func (a *SolanaAdapter) Type() types.ChainType {
    return types.ChainTypeSolana
}

func (a *SolanaAdapter) ValidateBasicRequest(chainID, signerAddress, signType string, payload []byte) error {
    // Validate Solana address format (base58, 32-44 chars)
    // Validate chain ID (Solana cluster: mainnet-beta, devnet, testnet)
    // ...
}

func (a *SolanaAdapter) Sign(ctx context.Context, signerAddress, signType, chainID string, payload []byte) (*types.SignResult, error) {
    // Sign Solana transaction/message
    // ...
}

// ... implement all ChainAdapter methods ...

var _ types.ChainAdapter = (*SolanaAdapter)(nil)  // Compile-time check
```

3. **Register adapter in main.go**:
```go
solanaAdapter, err := solana.NewSolanaAdapter(solanaSignerRegistry)
if err != nil {
    return err
}
chainRegistry.Register(solanaAdapter)
```

4. **Add Solana-specific rule evaluators**:
```go
// internal/chain/solana/rule_evaluator.go
type SolanaAddressListEvaluator struct{}

func (e *SolanaAddressListEvaluator) Type() types.RuleType {
    return types.RuleTypeSolanaAddressList  // New rule type
}

func (e *SolanaAddressListEvaluator) Evaluate(...) (bool, string, error) {
    // Evaluate Solana address against list
    // ...
}
```

5. **Update API handlers** (`internal/api/handler/solana/sign.go`):
```go
package solana

func NewSignHandler(signService service.SignServiceAPI, ...) http.Handler {
    // Similar to EVM sign handler
    // ...
}
```

6. **Register Solana routes** (`internal/api/router.go`):
```go
r.mux.Handle("/api/v1/solana/sign", solanaSignHandler)
r.mux.Handle("/api/v1/solana/signers", solanaSignersHandler)
// ...
```

---

### 11.2 Adding a New Rule Type

**Example**: Add `evm_gas_limit` rule (block transactions with gas > limit)

**Steps**:

1. **Define rule type constant** (`internal/core/types/rule.go`):
```go
const (
    // ... existing types ...
    RuleTypeEVMGasLimit RuleType = "evm_gas_limit"
)
```

2. **Define config struct** (`internal/chain/evm/types.go`):
```go
type GasLimitConfig struct {
    MaxGas uint64 `json:"max_gas"`  // Maximum gas allowed
}
```

3. **Implement evaluator** (`internal/chain/evm/rule_evaluator.go`):
```go
type GasLimitEvaluator struct{}

func NewGasLimitEvaluator() *GasLimitEvaluator {
    return &GasLimitEvaluator{}
}

func (e *GasLimitEvaluator) Type() types.RuleType {
    return types.RuleTypeEVMGasLimit
}

func (e *GasLimitEvaluator) Evaluate(
    ctx context.Context,
    rule *types.Rule,
    req *types.SignRequest,
    parsed *types.ParsedPayload,
) (bool, string, error) {
    // Parse config
    var cfg GasLimitConfig
    if err := json.Unmarshal(rule.Config, &cfg); err != nil {
        return false, "", fmt.Errorf("invalid gas limit config: %w", err)
    }
    
    // Parse EVM payload
    var payload evm.EVMSignPayload
    if err := json.Unmarshal(req.Payload, &payload); err != nil {
        return false, "", fmt.Errorf("invalid EVM payload: %w", err)
    }
    
    // Check gas limit
    if payload.Transaction != nil && payload.Transaction.Gas != nil {
        gas := payload.Transaction.Gas.Uint64()
        if gas > cfg.MaxGas {
            return true, fmt.Sprintf("gas %d exceeds limit %d", gas, cfg.MaxGas), nil
        }
    }
    
    return false, "", nil
}

var _ rule.RuleEvaluator = (*GasLimitEvaluator)(nil)
```

4. **Register evaluator** (`cmd/remote-signer/main.go`):
```go
ruleEngine.RegisterEvaluator(evm.NewGasLimitEvaluator())
```

5. **Add validation** (`internal/validate/validate.go`):
```go
func ValidateGasLimitConfig(cfg []byte) error {
    var c evm.GasLimitConfig
    if err := json.Unmarshal(cfg, &c); err != nil {
        return err
    }
    if c.MaxGas == 0 {
        return fmt.Errorf("max_gas must be positive")
    }
    return nil
}
```

6. **Document** (`docs/rule-syntax.md`):
```markdown
## Rule Type: `evm_gas_limit`

Check transaction gas limit.

### Config Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `max_gas` | uint64 | Yes | Maximum gas allowed |

### Example

\`\`\`yaml
- name: "Gas limit 500k"
  type: "evm_gas_limit"
  mode: "whitelist"
  config:
    max_gas: 500000
\`\`\`
```

---

### 11.3 Adding a New SDK (e.g., Python)

**Structure**:
```
pkg/py-client/
├── remote_signer/
│   ├── __init__.py
│   ├── client.py         # Main client class
│   ├── auth.py           # Ed25519 signing
│   ├── types.py          # Type definitions
│   └── exceptions.py     # Exception classes
├── tests/
│   ├── test_client.py
│   └── test_auth.py
├── setup.py
└── README.md
```

**Client Implementation** (`remote_signer/client.py`):
```python
import hashlib
import json
from typing import Optional
from nacl.signing import SigningKey
from . import types, auth, exceptions

class RemoteSignerClient:
    def __init__(self, base_url: str, api_key_id: str, private_key: bytes):
        self.base_url = base_url.rstrip('/')
        self.api_key_id = api_key_id
        self.signing_key = SigningKey(private_key)
        
    def sign(self, req: types.SignRequest) -> types.SignResponse:
        """Submit a sign request."""
        url = f"{self.base_url}/api/v1/evm/sign"
        payload = json.dumps(req.to_dict())
        
        # Generate signature
        timestamp_ms = int(time.time() * 1000)
        nonce = secrets.token_hex(16)
        signature = auth.sign_request(
            self.signing_key,
            timestamp_ms,
            nonce,
            "POST",
            "/api/v1/evm/sign",
            payload
        )
        
        # Make request
        headers = {
            "X-API-Key-ID": self.api_key_id,
            "X-Timestamp": str(timestamp_ms),
            "X-Nonce": nonce,
            "X-Signature": signature.hex(),
            "Content-Type": "application/json",
        }
        
        resp = requests.post(url, data=payload, headers=headers)
        if resp.status_code != 200:
            raise exceptions.SignError(resp.json())
        
        return types.SignResponse.from_dict(resp.json())
```

---

## 12. Architectural Decision Records (ADRs)

### ADR-001: Two-Tier Rule Evaluation (Fail-Closed Blocklist + Fail-Open Whitelist)

**Status**: Accepted  
**Date**: 2024-01-15

**Context**:
- Need to support both **permissive** (allow by default, block specific) and **restrictive** (block by default, allow specific) policies
- Rule evaluation errors must be handled safely (security vs availability trade-off)

**Decision**:
- **Blocklist rules evaluated first** (fail-closed): Any evaluation error → reject request
- **Whitelist rules evaluated second** (fail-open): Evaluation errors skip rule, try next
- **Manual approval fallback**: If no whitelist match and manual approval enabled → notify admin

**Consequences**:
- **Positive**: Security-first (blocklist errors don't allow unintended signatures), availability-friendly (whitelist errors don't block valid requests)
- **Negative**: Whitelist rule bugs may go unnoticed (skipped silently)
- **Mitigation**: Comprehensive test coverage (2,173 unit tests), audit logging for all rule evaluations

---

### ADR-002: Chain-Agnostic Core + Chain-Specific Adapters

**Status**: Accepted  
**Date**: 2024-01-20

**Context**:
- Support multiple blockchains (EVM, Solana, Cosmos, Bitcoin) without mixing chain-specific code in core logic
- Enable adding new chains without modifying core services

**Decision**:
- **Domain layer** (`internal/core/types/`) defines `ChainAdapter` interface
- **Service layer** (`internal/core/service/`) depends only on `ChainAdapter`, not concrete implementations
- **Adapter layer** (`internal/chain/{evm,solana,...}`) implements chain-specific logic

**Consequences**:
- **Positive**: Clean separation, easy to add new chains, core logic remains simple
- **Negative**: Slight indirection overhead (interface calls instead of direct calls)
- **Trade-off**: Accepted, benefits outweigh performance cost (negligible for I/O-bound operations)

---

### ADR-003: Constructor-Based Dependency Injection (No Framework)

**Status**: Accepted  
**Date**: 2024-01-25

**Context**:
- Need dependency injection for testability and modularity
- Avoid framework lock-in (wire, dig, fx)

**Decision**:
- **All constructors** (`NewXXX`) take dependencies as parameters and return `(object, error)`
- **Main** wires everything manually
- **Interfaces** used for dependencies, not concrete types

**Consequences**:
- **Positive**: No framework dependency, explicit dependency graph, easy to understand
- **Negative**: Manual wiring in main (verbose for large projects)
- **Mitigation**: Keep number of top-level services low (6 services in main)

---

### ADR-004: Ed25519 HMAC Authentication (Not JWT)

**Status**: Accepted  
**Date**: 2024-02-01

**Context**:
- Need stateless authentication for API requests
- JWT widely used but has known security issues (algorithm confusion, weak secrets)

**Decision**:
- **Ed25519 signature** on every request: `Sign(timestamp|nonce|method|path|sha256(body))`
- **Nonce replay protection**: Server stores used nonces (TTL = max request age)
- **No bearer tokens**: Public key stored in server, client signs each request

**Consequences**:
- **Positive**: No token expiration/refresh logic, no token storage, immune to JWT attacks
- **Negative**: Client must sign every request (slight CPU overhead), nonce storage in memory
- **Trade-off**: Accepted, security benefit outweighs CPU cost (< 1ms per signature)

---

### ADR-005: Sobek JS Engine (Not Goja or V8)

**Status**: Accepted  
**Date**: 2024-02-10

**Context**:
- Need in-process JavaScript execution for rule evaluation (low latency requirement: < 5ms)
- Options: Goja (Go JS VM), Sobek (Goja fork with ES2024 support), V8 (CGo binding)

**Decision**:
- **Sobek** (Go-native JS VM)
- **No V8** (requires CGo, complicates cross-compilation)

**Consequences**:
- **Positive**: Pure Go (no CGo), easy to build/deploy, ES2024 support, good performance (< 5ms)
- **Negative**: Not 100% ES spec compliant (some edge cases), slower than V8
- **Trade-off**: Accepted, simplicity and cross-compilation support more important than edge case compliance

---

### ADR-006: Foundry for Solidity Rules (Not Hardhat/Remix)

**Status**: Accepted  
**Date**: 2024-02-15

**Context**:
- Need Solidity expression evaluation for advanced rules
- Options: Foundry (forge), Hardhat, Remix, custom Solidity parser

**Decision**:
- **Foundry** (`forge test` to evaluate expressions)
- **Generate test file** with user expression + context variables

**Consequences**:
- **Positive**: Full Solidity syntax support, battle-tested (used by top protocols), fast (< 100ms cold start)
- **Negative**: External dependency (forge binary), slower than JS (100ms vs 5ms)
- **Trade-off**: Accepted, Solidity rules are for high-value transactions where extra latency is acceptable

---

### ADR-007: PostgreSQL Primary, SQLite Development

**Status**: Accepted  
**Date**: 2024-02-20

**Context**:
- Need production-grade persistence (ACID, concurrent writes, audit log)
- Need fast local development (no Docker required)

**Decision**:
- **PostgreSQL** for production (high write concurrency, JSONB queries, full-text search)
- **SQLite** for development/testing (single file, zero config, fast test setup)
- **GORM** abstracts differences (auto-migration, dialect support)

**Consequences**:
- **Positive**: Fast local dev (SQLite), robust production (PostgreSQL), minimal code differences
- **Negative**: Must test on both databases (some query differences), SQLite not suitable for high concurrency
- **Mitigation**: E2E tests run on both databases, clear docs on which to use

---

### ADR-008: GORM Auto-Migration (Append-Only Schema Changes)

**Status**: Accepted  
**Date**: 2024-03-01

**Context**:
- Need schema migrations for database evolution
- Options: Manual SQL migrations (migrate, goose), GORM auto-migration

**Decision**:
- **GORM Auto-Migrate** on startup
- **Append-only schema changes**: New columns added, never removed (backward compatible)
- **Major changes**: Manual migration scripts if needed

**Consequences**:
- **Positive**: Zero-config startup, no migration files to manage, backward compatible
- **Negative**: Cannot remove columns automatically, schema drift possible if not careful
- **Mitigation**: Clear policy: only add columns, never remove; use `gorm:"-"` to ignore fields

---

## 13. Architecture Governance

### 13.1 Code Review Checklist

**For every PR**:
- [ ] **Constructors return error**: All `NewXXX()` functions return `(object, error)`
- [ ] **No `_ = xxx`**: Errors are never silently ignored
- [ ] **No hardcoded fallbacks**: Failures are explicit, not silent defaults
- [ ] **Interface compilation checks**: `var _ Interface = (*Implementation)(nil)` for all adapters
- [ ] **Context propagation**: All I/O operations take `context.Context`
- [ ] **Test coverage**: New code has unit tests (95%+ coverage for core components)
- [ ] **Docs updated**: Architecture docs updated if adding new patterns

---

### 13.2 Architectural Consistency

**Enforcement**:
1. **Compile-time checks**: Interface implementation verified with `var _ Interface = (*Impl)(nil)`
2. **Test coverage**: CI fails if coverage drops below 90% for core packages
3. **Linter**: `golangci-lint` enforces code quality (40+ linters enabled)
4. **Manual review**: All PRs reviewed by at least one maintainer

**Red Flags** (reject in code review):
- Domain layer imports from adapter/api/storage layers
- Services calling adapters directly (should go through chain registry)
- Swallowed errors (`_ = xxx`)
- Constructors that panic instead of returning error
- Missing context.Context in I/O operations

---

## 14. Blueprint for New Development

### 14.1 Adding a New Feature (Generic Workflow)

1. **Requirements**: Clarify scope, acceptance criteria, security implications
2. **Design**: Write ADR if architectural decision needed
3. **Interface**: Define interfaces in domain layer (`internal/core/types/`)
4. **Implementation**: Implement in appropriate layer (service/adapter/storage)
5. **Tests**: Write unit tests (table-driven), integration tests (SQLite in-memory), E2E tests
6. **Docs**: Update architecture docs, API docs, user-facing docs
7. **Review**: Submit PR, address feedback
8. **Deploy**: Merge to main, tag release, deploy to production

---

### 14.2 Common Tasks

#### Task: Add New Rule Type

**Steps**: See [§11.2 Adding a New Rule Type](#112-adding-a-new-rule-type)

**Files to modify**:
1. `internal/core/types/rule.go` (add constant)
2. `internal/chain/evm/types.go` (add config struct)
3. `internal/chain/evm/rule_evaluator.go` (implement evaluator)
4. `cmd/remote-signer/main.go` (register evaluator)
5. `internal/validate/validate.go` (add validation)
6. `docs/rule-syntax.md` (document syntax)
7. `rules/templates/xxx.template.yaml` (create template, optional)

**Tests to write**:
- Unit test for evaluator (`rule_evaluator_test.go`)
- E2E test for rule (`e2e/rule_test.go`)

---

#### Task: Add New API Endpoint

**Steps**:

1. **Define handler** (`internal/api/handler/{chain}/xxx.go`):
```go
type NewHandler struct {
    service  service.SomeServiceAPI
    logger   *slog.Logger
}

func NewNewHandler(service service.SomeServiceAPI, logger *slog.Logger) *NewHandler {
    return &NewHandler{service: service, logger: logger}
}

func (h *NewHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    apiKey := middleware.GetAPIKey(r.Context())
    
    // Parse request
    var req SomeRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, ErrorCodeInvalidRequest, err.Error())
        return
    }
    
    // Call service
    resp, err := h.service.SomeMethod(r.Context(), &req)
    if err != nil {
        writeError(w, http.StatusInternalServerError, ErrorCodeInternalError, err.Error())
        return
    }
    
    writeJSON(w, resp, http.StatusOK)
}
```

2. **Register route** (`internal/api/router.go`):
```go
newHandler := NewNewHandler(someService, logger)
r.mux.Handle("/api/v1/evm/new-endpoint", middleware.Chain(
    middleware.RequirePermission(middleware.PermissionSomeNew),
)(newHandler))
```

3. **Update RBAC** (`internal/api/middleware/rbac.go`):
```go
const PermissionSomeNew Permission = "some_new"

// Add to permission matrix
```

4. **Document** (`docs/api.md`):
```markdown
### POST /api/v1/evm/new-endpoint

Description...

**Request**:
\`\`\`json
{
  "field": "value"
}
\`\`\`

**Response**:
\`\`\`json
{
  "result": "value"
}
\`\`\`
```

5. **Test**:
```go
func TestNewHandler(t *testing.T) {
    mockService := &MockSomeService{}
    handler := NewNewHandler(mockService, logger)
    
    req := httptest.NewRequest("POST", "/api/v1/evm/new-endpoint", strings.NewReader(`{"field":"value"}`))
    rec := httptest.NewRecorder()
    
    handler.ServeHTTP(rec, req)
    
    assert.Equal(t, http.StatusOK, rec.Code)
}
```

---

#### Task: Add New Chain Support

**Steps**: See [§11.1 Adding a New Chain](#111-adding-a-new-chain-eg-solana)

**Files to create**:
1. `internal/chain/{chain}/adapter.go` (implement ChainAdapter)
2. `internal/chain/{chain}/types.go` (chain-specific types)
3. `internal/chain/{chain}/signer.go` (signer registry)
4. `internal/chain/{chain}/provider.go` (signer providers)
5. `internal/chain/{chain}/rule_evaluator.go` (chain-specific evaluators)
6. `internal/api/handler/{chain}/sign.go` (sign handler)
7. `cmd/remote-signer/main.go` (register adapter)

---

### 14.3 Common Pitfalls

| Pitfall | Solution |
|---------|----------|
| **Forgetting to register evaluator** | Evaluator implemented but not registered in main → rule type silently fails | **Always register in main.go** |
| **Swallowing errors** | `_ = xxx` ignores error → hard to debug | **Always propagate or log** |
| **Missing context** | I/O operation without context → cannot cancel | **Always pass context.Context** |
| **Hardcoded values** | Hardcoded chain ID, address, etc. → not reusable | **Use config or parameters** |
| **No nil checks** | Interface is nil → panic at runtime | **Validate in constructor** |
| **No compile-time checks** | Interface implementation not verified → runtime error | **Add `var _ Interface = (*Impl)(nil)`** |
| **Database schema drift** | Manual schema changes → GORM out of sync | **Only use AutoMigrate** |
| **Test coverage regression** | New code without tests → bugs slip through | **CI enforces 90%+ coverage** |

---

## 15. Appendix

### 15.1 File Count by Module

| Module | Files (non-test) | Purpose |
|--------|------------------|---------|
| `internal/core/types` | 11 | Domain models |
| `internal/core/rule` | 5 | Rule engine |
| `internal/core/service` | 6 | Use cases |
| `internal/core/statemachine` | 1 | Request lifecycle |
| `internal/core/auth` | 1 | Authentication |
| `internal/chain/evm` | 33 | EVM adapter |
| `internal/chain` | 1 | Chain registry |
| `internal/api/handler` | 10 | HTTP handlers |
| `internal/api/middleware` | 9 | HTTP middleware |
| `internal/api` | 2 | Router + server |
| `internal/storage` | 13 | Repositories |
| `internal/audit` | 2 | Audit logging |
| `internal/blocklist` | 3 | Dynamic blocklist |
| `internal/config` | 5 | Config sync |
| `internal/notify` | 6 | Notifications |
| `internal/simulation` | 5 | Anvil fork simulation |
| `internal/validate` | 3 | Input validation |
| `internal/preset` | 1 | Preset parsing |
| `internal/logger` | 1 | Logging setup |
| `internal/metrics` | 1 | Prometheus metrics |
| `internal/secure` | 1 | Memory hardening |
| **Total** | **129** | |

---

### 15.2 Key Files Reference

| File | Purpose | LOC |
|------|---------|-----|
| `internal/core/types/chain.go` | ChainAdapter interface | 74 |
| `internal/core/types/rule.go` | Rule domain model | 130 |
| `internal/core/types/request.go` | SignRequest domain model | 99 |
| `internal/core/rule/engine.go` | RuleEvaluator interface | 150 |
| `internal/core/rule/whitelist.go` | Two-tier evaluation engine | 450 |
| `internal/core/service/sign.go` | SignService orchestration | 600 |
| `internal/core/statemachine/machine.go` | State transitions | 250 |
| `internal/chain/evm/adapter.go` | EVM ChainAdapter implementation | 400 |
| `internal/chain/evm/signer_manager.go` | Signer registry + providers | 550 |
| `internal/chain/evm/js_evaluator.go` | JavaScript rule execution | 700 |
| `internal/chain/evm/solidity_evaluator.go` | Solidity rule execution | 500 |
| `internal/api/router.go` | HTTP route registration | 800 |
| `internal/api/middleware/auth.go` | Ed25519 authentication | 350 |
| `internal/api/middleware/rbac.go` | RBAC permission checks | 400 |
| `cmd/remote-signer/main.go` | Application bootstrap | 1200 |

---

### 15.3 Architecture Metrics

| Metric | Value |
|--------|-------|
| **Lines of Code (Production)** | 48,000 |
| **Lines of Code (Test)** | 44,000 |
| **Test Count (Unit)** | 2,173 |
| **Test Count (E2E)** | 214 |
| **Test Coverage (Core)** | 95%+ |
| **Number of Packages** | 32 |
| **Number of Interfaces** | 47 |
| **Number of Concrete Types** | 150+ |
| **Max Cyclomatic Complexity** | 15 (rule engine evaluation loop) |
| **Avg Function LOC** | 25 |
| **Max File LOC** | 1200 (main.go) |

---

## Conclusion

Remote-Signer implements a **Clean Architecture** with **Hexagonal (Ports & Adapters)** pattern, providing:

1. **Chain-agnostic core**: Domain layer depends on interfaces, not implementations
2. **Two-tier rule evaluation**: Fail-closed blocklist + fail-open whitelist
3. **Composable rules**: Delegation mechanism (Safe → MultiSend → ERC20)
4. **Defense-in-depth security**: 16 layers (Ed25519 auth, nonce replay protection, IP whitelist, rate limiting, approval guard, dynamic blocklist, sandbox isolation, memory hardening)
5. **Multi-tenant RBAC/ACL**: 4 roles, 27 permissions, signer ownership model
6. **4 client SDKs**: Go, TypeScript, Rust, MCP Server
7. **92,000+ lines of code**: 48K production, 44K test, 2,387 tests

**Key Strengths**:
- **Extensibility**: Add new chains, rules, evaluators without modifying core
- **Security**: Fail-closed by default, comprehensive audit logging, real-time alerts
- **Testability**: Constructor DI, interface-driven design, 95%+ test coverage
- **Maintainability**: Clean separation of concerns, no framework lock-in, explicit dependencies

**Future Evolution**:
- **HSM support**: Hardware-backed key custody
- **Solana/Cosmos/Bitcoin adapters**: Multi-chain expansion
- **Distributed rate limiting**: Redis-backed rate limiter for HA deployments
- **Real-time policy updates**: WebSocket-based rule push (no SIGHUP)

---

**Document Last Updated**: 2026-04-02  
**Based on Code Analysis**: remote-signer @ commit `adabf05`  
**Maintainers**: Ivan (@ivanzzeth)
