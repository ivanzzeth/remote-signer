# Internal Transfer Rule (Phase 4b)

## Status: Completed

## Overview

A whitelist rule that allows transfers between signers owned by the same API key (or user, when auth integration is enabled). This enables multi-tenant custodial signing where each tenant's signers are isolated.

## Problem

In multi-tenant scenarios, API key A's signers should be able to transfer funds to each other, but NOT to API key B's signers (without explicit rules or manual approval). Currently, every transfer requires either:
1. A blanket whitelist rule (too permissive)
2. Manual approval (too tedious for internal operations)

## Solution

A new rule type `evm_internal_transfer` that matches when:
- The recipient address is a signer managed by the same owner as the sender
- Supports ETH transfers AND token transfers (ERC20/721/1155)

## Design

### Rule Type

```go
RuleTypeEVMInternalTransfer RuleType = "evm_internal_transfer"
```

### Config Schema

```yaml
# Minimal config - ownership info from DB
type: evm_internal_transfer
mode: whitelist
config: {}  # Empty, all info from ownership repo

# Future: with auth service integration
config:
  match_mode: "owner_id"  # "owner_id" (default) | "user_id" (requires auth)
```

### Evaluation Logic

```
1. Filter: sign_type != "transaction" → neutral (skip)
2. Extract recipient:
   a. Parse calldata for known token transfer methods → extract actual recipient
   b. Fallback to tx.To for ETH transfers
3. Lookup ownership:
   - Get recipient ownership from DB
   - Get sender ownership from DB
4. Match conditions:
   - recipient not a signer → neutral
   - recipient.status != "active" → neutral
   - sender.owner_id == recipient.owner_id → MATCH
   - else → neutral
```

### Supported Token Standards

| Standard | Method | Selector | Recipient Offset |
|----------|--------|----------|------------------|
| ETH | (native transfer) | N/A | tx.To |
| ERC20 | `transfer(address,uint256)` | `0xa9059cbb` | calldata[4:36] |
| ERC20 | `transferFrom(address,address,uint256)` | `0x23b872dd` | calldata[36:68] |
| ERC721 | `transferFrom(address,address,uint256)` | `0x23b872dd` | calldata[36:68] |
| ERC721 | `safeTransferFrom(address,address,uint256)` | `0x42842e0e` | calldata[36:68] |
| ERC721 | `safeTransferFrom(address,address,uint256,bytes)` | `0xb88d4fde` | calldata[36:68] |
| ERC1155 | `safeTransferFrom(address,address,uint256,uint256,bytes)` | `0xf242432a` | calldata[36:68] |
| ERC1155 | `safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)` | `0x2eb2c2d6` | calldata[36:68] |

### Multi-Tenancy Extension Path

**Current (Phase 4b):**
```
API Key (owner_id)
    ↓ ownership
  Signers

Match: signer_a.owner_id == signer_b.owner_id
```

**Future (with auth service):**
```
User (external auth)
    ↓ 1:N
  API Keys
    ↓ ownership
  Signers

Match: signer_a.owner.user_id == signer_b.owner.user_id
```

**Implementation:**
```go
type InternalTransferEvaluator struct {
    ownershipRepo storage.SignerOwnershipRepository
    apiKeyRepo    storage.APIKeyRepository  // For user_id lookup (future)
    matchMode     string                    // "owner_id" | "user_id"
}

type InternalTransferConfig struct {
    MatchMode string `json:"match_mode,omitempty"` // defaults to "owner_id"
}
```

**Backward Compatibility:**
- Default `match_mode: "owner_id"` works without auth service
- `match_mode: "user_id"` requires auth service + `user_id` field on api_keys table
- No breaking changes to existing deployments

### Security Considerations

| Scenario | Behavior | Defense |
|----------|----------|---------|
| Self-registration attack | Attacker creates signer → pending → not matched | Two-layer: pending status + owner_id check |
| Cross-owner transfer | neutral → needs other rules or manual approval | Owner isolation |
| External address recipient | neutral → fallback to other rules | Only matches internal signers |
| Pending signer as recipient | neutral → not matched | Status check |
| Malicious calldata | Safe parsing with bounds checking | Validate calldata length before extraction |

### Files

| File | Change |
|------|--------|
| `internal/core/types/rule.go` | Add `RuleTypeEVMInternalTransfer` |
| `internal/chain/evm/internal_transfer_evaluator.go` | New evaluator + calldata parsing |
| `internal/chain/evm/internal_transfer_evaluator_test.go` | Unit tests |

### Unit Tests (18 test cases)

| Test | Description | Expected |
|------|-------------|----------|
| `TestInternalTransferEvaluator_Type` | Type() returns correct constant | RuleTypeEVMInternalTransfer |
| `TestInternalTransferEvaluator_NewEvaluator_NilRepo` | Nil repo allowed for validation | error on evaluate |
| `TestETHTransfer_SameOwner` | ETH transfer between same-owner signers | match |
| `TestETHTransfer_DifferentOwner` | ETH transfer to different-owner signer | neutral |
| `TestERC20Transfer_SameOwner` | ERC20 transfer (calldata parsing) | match |
| `TestERC721SafeTransfer_SameOwner` | ERC721 safeTransferFrom | match |
| `TestERC1155BatchTransfer_SameOwner` | ERC1155 batch transfer | match |
| `TestTransfer_ToExternalAddress` | Transfer to non-signer address | neutral |
| `TestTransfer_ToPendingSigner` | Recipient is pending_approval | neutral |
| `TestNonTransaction_Neutral` | typed_data or personal sign | neutral |
| `TestMalformedCalldata_Neutral` | Truncated calldata | neutral |
| `TestTransfer_DifferentOwner_ERC20` | Cross-owner token transfer | neutral |
| `TestTransferFrom_SameOwner` | ERC20/721 transferFrom | match |
| `TestNilParsedPayload_Neutral` | Nil parsed payload | neutral |
| `TestNilRecipient_Neutral` | Nil recipient | neutral |
| `TestInvalidConfig_Error` | Invalid JSON config | error |
| `TestUnsupportedMatchMode_Error` | user_id mode (not yet supported) | error |
| `TestExtractRecipientFromCalldata_AllSelectors` | All 6 selectors | correct address |

### E2E Tests

| Test | Description |
|------|-------------|
| `TestInternalTransfer_ETH_Allowed` | Admin signer A → Admin signer B (ETH) |
| `TestInternalTransfer_ERC20_Allowed` | Admin signer A → Admin signer B (ERC20) |
| `TestInternalTransfer_CrossOwner_Blocked` | Admin signer A → Agent signer C → 403 |

### Usage Example

```yaml
# config.yaml
rules:
  - name: "Allow internal transfers"
    type: evm_internal_transfer
    mode: whitelist
    enabled: true
    owner: admin
    applied_to: ["*"]  # Applies to all API keys
```

```bash
# CLI
remote-signer-cli evm rule create \
  --name "Allow internal transfers" \
  --type evm_internal_transfer \
  --mode whitelist
```

### Relation to Other Rules

The `evm_internal_transfer` rule is a **whitelist-only** rule. It does NOT:
- Block external transfers (use other whitelist rules for that)
- Override value limits or budget rules
- Bypass blocklist checks

Typical rule setup for multi-tenant:
1. Blocklist: OFAC addresses, known scams
2. Whitelist: Internal transfer rule (same-owner)
3. Whitelist: Specific external allowlist (optional)
4. Fallback: Manual approval for everything else

## Implementation Checklist

- [x] Add `RuleTypeEVMInternalTransfer` constant
- [x] Implement `InternalTransferEvaluator` struct
- [x] Implement calldata parsing for token standards
- [x] Implement ownership lookup and matching
- [x] Register evaluator in EVM adapter
- [x] Unit tests (18 test cases)
- [ ] E2E tests
- [x] Update rule-syntax.md documentation
