# Components Documentation

## Core Interfaces

### ChainAdapter

The main abstraction for chain-specific signing operations.

```go
interface ChainAdapter {
    Type() ChainType
    ValidatePayload(ctx, signType, payload) error
    Sign(ctx, signerAddress, signType, chainID, payload) (*SignResult, error)
    ParsePayload(ctx, signType, payload) (*ParsedPayload, error)
    ListSigners(ctx) ([]SignerInfo, error)
    HasSigner(ctx, address) bool
}
```

**Implementations:**
- `EVMAdapter` - EVM chain signing (Ethereum, Polygon, BSC, etc.)

### RuleEngine

Two-tier rule evaluation engine.

```go
interface RuleEngine {
    Evaluate(ctx, req, parsed) (*RuleID, reason, error)
    EvaluateWithResult(ctx, req, parsed) *EvaluationResult
    RegisterEvaluator(evaluator RuleEvaluator)
}
```

**Evaluation Flow:**
1. Check blocklist rules (any violation = reject)
2. Check whitelist rules (any match = approve)
3. No match = requires manual approval

### RuleEvaluator

Handles evaluation of specific rule types.

```go
interface RuleEvaluator {
    Type() RuleType
    Evaluate(ctx, rule, req, parsed) (matched bool, reason string, error)
}
```

**Implementations:**
- `SignerRestrictionEvaluator`
- `SignTypeRestrictionEvaluator`
- `EVMAddressListEvaluator`
- `EVMContractMethodEvaluator`
- `EVMValueLimitEvaluator`
- `EVMSolidityExpressionEvaluator`
- `EVMMessagePatternEvaluator`

---

## Data Types

### SignRequest

Request state machine with lifecycle tracking.

```go
type SignRequest struct {
    ID            string
    ChainType     ChainType
    SignType      SignType
    Signer        string
    ChainID       uint64
    Payload       json.RawMessage
    Status        RequestStatus
    Signature     string
    SignedData    string
    MatchedRuleID *string
    RejectedBy    *string
    RejectionReason *string
    CreatedAt     time.Time
    UpdatedAt     time.Time
}
```

**Status Values:**
| Status | Description |
|--------|-------------|
| `pending` | Initial state, awaiting validation |
| `authorizing` | Validation passed, checking rules |
| `signing` | Approved, performing signature |
| `completed` | Signature generated successfully |
| `rejected` | Rejected by rule or manual review |
| `failed` | Signing operation failed |

### Rule

Authorization rule definition.

```go
type Rule struct {
    ID          string
    Name        string
    Description string
    ChainType   ChainType
    RuleType    RuleType
    Mode        RuleMode    // "whitelist" or "blocklist"
    Priority    int
    Enabled     bool
    Config      json.RawMessage
    MatchCount  int64
    CreatedAt   time.Time
    UpdatedAt   time.Time
}
```

**Rule Types:**

| Type | Description | Config Fields |
|------|-------------|---------------|
| `signer_restriction` | Allow/block signer addresses | `signers []string` |
| `sign_type_restriction` | Allow/block sign methods | `sign_types []string` |
| `evm_address_list` | Whitelist/blocklist addresses | `addresses []string`, `field string` |
| `evm_contract_method` | Contract method restrictions | `contract string`, `methods []string` |
| `evm_value_limit` | Transaction value limits | `max_value string`, `min_value string` |
| `evm_solidity_expression` | Solidity validation | `expression string` or `functions []` |
| `evm_message_pattern` | Message pattern matching | `patterns []string` |

**Rule Modes:**
- `whitelist` - Any match = auto-approve
- `blocklist` - Any violation = block (checked first)

### APIKey

API key with Ed25519 public key.

```go
type APIKey struct {
    ID            string
    Name          string
    PublicKey     string      // Ed25519 public key (hex)
    IsAdmin       bool
    RateLimit     *RateLimitConfig
    AllowedChains []ChainType
    AllowedSigners []string
    CreatedAt     time.Time
    UpdatedAt     time.Time
}
```

### AuditRecord

Immutable audit log entry.

```go
type AuditRecord struct {
    ID          string
    EventType   AuditEventType
    Severity    AuditSeverity
    RequestID   *string
    RuleID      *string
    APIKeyID    *string
    Actor       string
    Details     json.RawMessage
    CreatedAt   time.Time
}
```

**Event Types:**
- `request_created`, `request_approved`, `request_rejected`
- `signature_generated`, `signature_failed`
- `rule_matched`, `rule_created`, `rule_updated`, `rule_deleted`
- `auth_success`, `auth_failure`

---

## Services

### SignService

Main orchestration service for signing requests.

**Responsibilities:**
- Create and validate sign requests
- Coordinate with chain adapters
- Trigger rule evaluation
- Manage state transitions
- Generate audit records

**Key Methods:**
```go
func (s *SignService) Sign(ctx, req *SignRequest) (*SignResponse, error)
func (s *SignService) GetRequest(ctx, id string) (*SignRequest, error)
func (s *SignService) ListRequests(ctx, filter *RequestFilter) ([]*SignRequest, error)
```

### ApprovalService

Handles manual approval workflow.

**Responsibilities:**
- Process approval/rejection decisions
- Generate rules from approved requests
- Trigger notifications

**Key Methods:**
```go
func (s *ApprovalService) Approve(ctx, requestID string, actor string, generateRule bool) error
func (s *ApprovalService) Reject(ctx, requestID string, actor string, reason string) error
func (s *ApprovalService) GenerateRuleFromRequest(ctx, requestID string) (*Rule, error)
```

### NotifyService

Notification dispatch service.

**Channels:**
- Slack - Direct to channels
- Pushover - Mobile push notifications

**Key Methods:**
```go
func (s *NotifyService) NotifyApprovalNeeded(ctx, req *SignRequest) error
func (s *NotifyService) NotifyApproved(ctx, req *SignRequest) error
func (s *NotifyService) NotifyRejected(ctx, req *SignRequest, reason string) error
```

---

## Chain Adapters

### EVMAdapter

Implementation of `ChainAdapter` for EVM-compatible chains.

**Supported Sign Types:**

| Type | Description |
|------|-------------|
| `hash` | Sign pre-hashed data (32 bytes) |
| `raw_message` | Sign raw bytes |
| `eip191` | EIP-191 formatted message |
| `personal` | Personal message (`eth_sign`) |
| `typed_data` | EIP-712 typed data |
| `transaction` | Transaction (Legacy/EIP-2930/EIP-1559) |

**Signer Types:**
- **PrivateKey** - Direct private key (from env var)
- **Keystore** - Encrypted JSON keystore (password-protected)

**Components:**
- `EVMSigner` - Wraps ethsig for signing operations
- `EVMSignerManager` - Dynamic signer creation
- `PasswordProvider` - Keystore password retrieval

### Solidity Expression Evaluator

Validates requests using Solidity code (Foundry-based).

**Modes:**

1. **Expression Mode:**
```solidity
// Config: {"expression": "require(value <= 1 ether, 'value too high');"}
// Context variables: to, value, selector, data, chainId, signer
```

2. **Function Mode:**
```solidity
// Config: {"functions": [{"selector": "0xa9059cbb", "code": "..."}]}
// Validates specific contract method calls
```

**Security:**
Dangerous Foundry cheatcodes disabled:
- `vm.ffi` - FFI execution
- `vm.readFile` / `vm.writeFile` - File system access
- `vm.rpc` - External RPC access

---

## Storage Repositories

### RequestRepository

```go
interface RequestRepository {
    Create(ctx, req *SignRequest) error
    GetByID(ctx, id string) (*SignRequest, error)
    Update(ctx, req *SignRequest) error
    List(ctx, filter *RequestFilter) ([]*SignRequest, int64, error)
    UpdateStatus(ctx, id string, status RequestStatus) error
}
```

### RuleRepository

```go
interface RuleRepository {
    Create(ctx, rule *Rule) error
    GetByID(ctx, id string) (*Rule, error)
    Update(ctx, rule *Rule) error
    Delete(ctx, id string) error
    List(ctx, filter *RuleFilter) ([]*Rule, error)
    ListEnabled(ctx, chainType ChainType) ([]*Rule, error)
    IncrementMatchCount(ctx, id string) error
}
```

### APIKeyRepository

```go
interface APIKeyRepository {
    Create(ctx, key *APIKey) error
    GetByID(ctx, id string) (*APIKey, error)
    Update(ctx, key *APIKey) error
    Delete(ctx, id string) error
    List(ctx) ([]*APIKey, error)
}
```

### AuditRepository

```go
interface AuditRepository {
    Create(ctx, record *AuditRecord) error
    List(ctx, filter *AuditFilter) ([]*AuditRecord, int64, error)
}
```

---

## Middleware

### Authentication Middleware

Verifies Ed25519 signatures on requests.

**Signature Format:**
```
{timestamp_ms}|{method}|{path}|{sha256(body)}
```

**Headers Required:**
- `X-API-Key-ID` - API key identifier
- `X-Timestamp` - Unix timestamp in milliseconds
- `X-Signature` - Ed25519 signature (hex)

### Rate Limit Middleware

Per-API-key rate limiting.

**Config:**
```go
type RateLimitConfig struct {
    RequestsPerSecond int
    BurstSize         int
}
```

### IP Whitelist Middleware

Restricts access by IP address.

**Config:**
```yaml
security:
  ip_whitelist:
    - "10.0.0.0/8"
    - "192.168.1.100"
```

### Admin Check Middleware

Verifies admin flag for management operations.

**Protected Endpoints:**
- Rule management (`/api/v1/rules/*`)
- API key management (`/api/v1/apikeys/*`)
- Approval operations (`/api/v1/requests/*/approve`)

---

## Terminal UI (TUI)

Built with Charmbracelet Bubbletea framework.

**Views:**

| View | Description |
|------|-------------|
| Dashboard | Service health, request stats, rule summary |
| Requests | List with filtering, approve/reject |
| Request Detail | Full request info, rule preview |
| Rules | Create, edit, delete, toggle enabled |
| Rule Detail | Full rule config, match statistics |
| Audit | Filter by event type, severity |
| Signers | List available signers |

**Keybindings:**

| Key | Action |
|-----|--------|
| Tab | Switch views |
| ↑/↓ | Navigate |
| Enter | View details |
| a | Approve request |
| x | Reject request |
| t | Toggle rule enabled |
| d | Delete item |
| q | Quit |

---

## Client SDK

Go client for integrating with Remote-Signer.

**Initialization:**
```go
client, err := client.NewClient(&client.Config{
    BaseURL:    "http://localhost:8548",
    APIKeyID:   "my-key-id",
    PrivateKey: privateKey, // Ed25519
})
```

**Operations:**

```go
// Sign request
resp, err := client.Sign(ctx, &SignRequest{
    ChainType: "evm",
    SignType:  "transaction",
    Signer:    "0x...",
    ChainID:   1,
    Payload:   txPayload,
})

// Get request status
req, err := client.GetRequest(ctx, "request-id")

// Approve request (admin)
err := client.ApproveSignRequest(ctx, "request-id", true) // generateRule=true

// List rules
rules, err := client.ListRules(ctx, &RuleFilter{Enabled: true})
```

**Mock Client:**
```go
mock := client.NewMockClient()
mock.OnSign(func(req *SignRequest) (*SignResponse, error) {
    return &SignResponse{Signature: "0x..."}, nil
})
```
