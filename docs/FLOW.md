# Request Signing Flow

## Overview

This document describes the complete flow of a signing request through the Remote-Signer system.

## High-Level Flow

```
┌──────────┐     ┌──────────────┐     ┌───────────────┐     ┌─────────────┐
│  Client  │────▶│  HTTP Layer  │────▶│  SignService  │────▶│  Response   │
└──────────┘     └──────────────┘     └───────────────┘     └─────────────┘
                       │                     │
                       ▼                     ▼
                 ┌───────────┐        ┌────────────┐
                 │ Middleware │        │ ChainAdapter│
                 │ Pipeline   │        │ RuleEngine │
                 └───────────┘        │ StateMachine│
                                      └────────────┘
```

## Detailed Flow

### 1. Client Submits Request

```
POST /api/v1/evm/sign
Headers:
  X-API-Key-ID: {key_id}
  X-Timestamp: {timestamp_ms}
  X-Signature: {ed25519_signature}
Body:
  {
    "sign_type": "transaction",
    "signer_address": "0x...",
    "chain_id": "1",
    "payload": { ... }
  }
```

**Signature Generation:**
```
message = "{timestamp_ms}|POST|/api/v1/evm/sign|{sha256(body)}"
signature = ed25519.Sign(private_key, message)
```

### 2. Middleware Pipeline

```
Request
   │
   ▼
┌─────────────────┐
│  IP Whitelist   │──▶ 403 Forbidden (if not allowed)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Authentication  │──▶ 401 Unauthorized (if signature invalid)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Rate Limit    │──▶ 429 Too Many Requests (if exceeded)
└────────┬────────┘
         │
         ▼
    Handler
```

### 3. Sign Handler Processing

The sign handler uses the standard library `net/http` interface (`ServeHTTP`):

```go
func (h *SignHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // 1. Method and auth (API key from middleware context)
    if r.Method != http.MethodPost { ... }
    apiKey := middleware.GetAPIKey(r.Context())
    if apiKey == nil { ... }
    if !middleware.CheckChainPermission(apiKey, types.ChainTypeEVM) { ... }

    // 2. Parse and validate request body (SignRequest: chain_id, signer_address, sign_type, payload)
    var req SignRequest
    json.NewDecoder(r.Body).Decode(&req)
    // validate chain_id, signer_address, sign_type, payload; CheckSignerPermission(apiKey, req.SignerAddress)

    // 3. Build service request and call SignService
    signReq := &service.SignRequest{
        APIKeyID: apiKey.ID, ChainType: types.ChainTypeEVM,
        ChainID: req.ChainID, SignerAddress: req.SignerAddress, SignType: req.SignType, Payload: req.Payload,
    }
    resp, err := h.signService.Sign(r.Context(), signReq)

    // 4. Return JSON response or error
    h.writeJSON(w, resp, http.StatusOK)  // or writeError(w, ...)
}
```

### 4. SignService Orchestration

```
SignService.Sign()
       │
       ▼
┌──────────────────┐
│ Get ChainAdapter │──▶ Error: unsupported chain type
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Validate Signer  │──▶ Error: signer not found
│ Exists           │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Validate Payload │──▶ Error: invalid payload format
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Create Request   │  Status: pending
│ Record           │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Transition to    │  Status: authorizing
│ Authorizing      │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Parse Payload    │  Extract: to, value, selector, etc.
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Evaluate Rules   │──▶ See "Rule Evaluation" section
└────────┬─────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
 Blocked   Approved
    │         │
    ▼         ▼
 Reject   ┌──────────────────┐
          │ Transition to    │  Status: signing
          │ Signing          │
          └────────┬─────────┘
                   │
                   ▼
          ┌──────────────────┐
          │ Perform Sign     │
          └────────┬─────────┘
                   │
              ┌────┴────┐
              │         │
              ▼         ▼
           Success    Failure
              │         │
              ▼         ▼
          Completed   Failed
```

### 5. Rule Evaluation

```
RuleEngine.Evaluate()
       │
       ▼
┌──────────────────────────────────────────┐
│          Load Enabled Rules               │
│  (ordered by priority, descending)        │
└────────────────┬─────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────┐
│        PHASE 1: Blocklist Rules          │
│                                          │
│  for each rule where mode == "blocklist" │
│    if rule matches request:              │
│      → REJECT immediately                │
│      → No manual approval allowed        │
│                                          │
│  (any blocklist violation = hard reject) │
└────────────────┬─────────────────────────┘
                 │ No violations
                 ▼
┌──────────────────────────────────────────┐
│        PHASE 2: Whitelist Rules          │
│                                          │
│  for each rule where mode == "whitelist" │
│    if rule matches request:              │
│      → AUTO-APPROVE                      │
│      → Record matched rule ID            │
│      → Return immediately                │
│                                          │
│  (first whitelist match = approve)       │
└────────────────┬─────────────────────────┘
                 │ No matches
                 ▼
┌──────────────────────────────────────────┐
│        PHASE 3: Manual Approval          │
│                                          │
│  → Send notification (Slack/Pushover)    │
│  → Wait for human approval/rejection     │
│  → Optionally generate rule from request │
└──────────────────────────────────────────┘
```

### 6. State Transitions

```
                    ┌──────────────────────────┐
                    │         pending          │
                    │   (initial state)        │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
                    ▼                         ▼
           validation OK             validation failed
                    │                         │
                    ▼                         ▼
           ┌──────────────┐          ┌──────────────┐
           │ authorizing  │          │   rejected   │
           └──────┬───────┘          └──────────────┘
                  │
     ┌────────────┼────────────┐
     │            │            │
     ▼            ▼            ▼
 blocklist    whitelist    no match
 violation     match       (notify)
     │            │            │
     ▼            ▼            ▼
┌──────────┐ ┌──────────┐ ┌──────────────┐
│ rejected │ │ signing  │ │ await manual │
└──────────┘ └────┬─────┘ └──────┬───────┘
                  │              │
                  │    ┌─────────┴─────────┐
                  │    │                   │
                  │    ▼                   ▼
                  │ approved            rejected
                  │    │                   │
                  │    ▼                   ▼
                  │ ┌──────────┐    ┌──────────┐
                  └▶│ signing  │    │ rejected │
                    └────┬─────┘    └──────────┘
                         │
                ┌────────┴────────┐
                │                 │
                ▼                 ▼
            success            failure
                │                 │
                ▼                 ▼
         ┌───────────┐     ┌──────────┐
         │ completed │     │  failed  │
         └───────────┘     └──────────┘
```

### 7. Signing Operation

```
ChainAdapter.Sign()
       │
       ▼
┌──────────────────┐
│  Get Signer      │  (from registry by address)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Decode Payload  │  (sign_type specific)
└────────┬─────────┘
         │
    Sign Type?
         │
    ┌────┴────┬──────────┬──────────┬───────────┐
    │         │          │          │           │
    ▼         ▼          ▼          ▼           ▼
  hash    raw_msg    eip191    typed_data   transaction
    │         │          │          │           │
    ▼         ▼          ▼          ▼           ▼
┌─────────────────────────────────────────────────────┐
│                   ethsig Library                     │
│  SignHash() │ SignMessage() │ SignTypedData() │ ... │
└─────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│  Return Result   │  {signature, signed_data}
└──────────────────┘
```

### 8. Response

**Success Response:**
```json
{
  "request_id": "req_abc123",
  "status": "completed",
  "signature": "0x...",
  "signed_data": "0x..." // for transactions
}
```

**Pending Approval Response:**
```json
{
  "request_id": "req_abc123",
  "status": "authorizing",
  "message": "Request requires manual approval"
}
```

**Error Response:**
```json
{
  "error": "rule_blocked",
  "message": "Request blocked by rule: max_value_exceeded",
  "rule_id": "rule_xyz"
}
```

## Manual Approval Flow

```
┌──────────┐                    ┌─────────────┐
│  Client  │                    │   Admin     │
└────┬─────┘                    └──────┬──────┘
     │                                 │
     │  POST /sign                     │
     │─────────────▶                   │
     │                                 │
     │  202 {status: authorizing}      │
     │◀─────────────                   │
     │                                 │
     │             ┌──────────────┐    │
     │             │ Notification │    │
     │             │ (Slack/Push) │────┼────▶ Received
     │             └──────────────┘    │
     │                                 │
     │                                 │  POST /requests/{id}/approve
     │                                 │────────────────▶
     │                                 │
     │                                 │  200 OK
     │                                 │◀────────────────
     │                                 │
     │  GET /requests/{id}             │
     │─────────────▶                   │
     │                                 │
     │  200 {status: completed,        │
     │       signature: "0x..."}       │
     │◀─────────────                   │
     │                                 │
```

## Audit Trail

Every state transition generates an audit record:

```
┌─────────────────────────────────────────────────────────────┐
│ Event: request_created                                      │
│ Severity: info                                              │
│ Request ID: req_abc123                                      │
│ Actor: api_key_123                                          │
│ Details: {signer: "0x...", sign_type: "transaction"}        │
│ Timestamp: 2024-01-15T10:00:00Z                             │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Event: rule_matched                                         │
│ Severity: info                                              │
│ Request ID: req_abc123                                      │
│ Rule ID: rule_xyz                                           │
│ Actor: system                                               │
│ Details: {rule_name: "allow_transfers", reason: "..."}      │
│ Timestamp: 2024-01-15T10:00:01Z                             │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Event: signature_generated                                  │
│ Severity: info                                              │
│ Request ID: req_abc123                                      │
│ Actor: system                                               │
│ Details: {signer: "0x...", chain_id: 1}                     │
│ Timestamp: 2024-01-15T10:00:02Z                             │
└─────────────────────────────────────────────────────────────┘
```

## Error Handling

| Error | HTTP Status | Response |
|-------|-------------|----------|
| Invalid signature | 401 | `{"error": "auth_failed"}` |
| Signer not found | 400 | `{"error": "signer_not_found"}` |
| Invalid payload | 400 | `{"error": "invalid_payload"}` |
| Blocklist violation | 403 | `{"error": "rule_blocked"}` |
| Rate limit exceeded | 429 | `{"error": "rate_limited"}` |
| Signing failed | 500 | `{"error": "signing_failed"}` |

## Timeouts

| Operation | Default Timeout |
|-----------|----------------|
| Request timestamp validity | 5 minutes |
| Manual approval | No timeout (persisted) |
| HTTP request | 30 seconds |
| Signing operation | 10 seconds |
