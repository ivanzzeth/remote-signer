# Internal Signer Transfer Rules

**Status**: Planned
**Priority**: Medium
**Author**: Ivan
**Date**: 2026-03-16

## Problem

When operating multiple signers (wallets), transferring assets between them (native tokens, ERC20, ERC721, ERC1155) is a common and safe operation. Currently, operators must manually configure whitelist rules for every signer-pair combination, which is:
- O(n²) configuration for n signers
- Error-prone (miss a pair = blocked transfer)
- Must be updated whenever signers are added/removed

## Desired Behavior

A single rule (or JS helper) that allows transfers between the system's own managed signers. Works standalone and as a delegation target in chains like Safe → MultiSend → internal transfer.

## Design

### Phase 1: `rs.signers.isManaged(addr)` JS Helper

Add a new JS runtime helper that checks if an address is a **trusted signer**:

```javascript
rs.signers.isManaged("0x1234...")  // → true if trusted signer, false otherwise
```

This is the foundation — any JS rule template can use it.

### Phase 2: `internal_transfer.template.js.yaml`

A template that validates transfers where the recipient is a managed signer:

```javascript
function validate(input) {
  // Detect transfer type: native / ERC20 / ERC721 / ERC1155
  // Extract real recipient from calldata
  // Check: rs.signers.isManaged(recipient)
  // If managed → ok(), else → revert
}
```

Supported operations:
- Native transfer: `tx.to` is recipient
- ERC20 `transfer(to, amount)`: decode `to`
- ERC20 `transferFrom(from, to, amount)`: decode `to`
- ERC721 `transferFrom(from, to, tokenId)`: decode `to`
- ERC721 `safeTransferFrom(from, to, tokenId[, data])`: decode `to`
- ERC1155 `safeTransferFrom(from, to, id, amount, data)`: decode `to`
- ERC1155 `safeBatchTransferFrom(from, to, ids, amounts, data)`: decode `to`

**NOT allowed** (even if target is managed signer):
- `approve(spender, amount)` — approval is not a transfer
- `setApprovalForAll(operator, approved)` — approval is not a transfer
- Any `DELEGATECALL` operation

### Phase 3: Integration with Auto-Discovery (Future)

When [auto-discovery delegation](./auto-discovery-delegation.md) is implemented, the internal transfer template can declare `discoverable: true`. This enables:

```
Safe → MultiSend → internal_transfer (auto-discovered)
EIP-4337 → execute → internal_transfer (auto-discovered)
```

Zero explicit delegation configuration needed.

## Critical Security: Trusted Signer Set

### The Attack

If `rs.signers.isManaged()` queries the **runtime SignerRegistry**, an attacker with a compromised admin API key can:

1. Create a new signer via API (address controlled by attacker)
2. New signer enters SignerRegistry automatically
3. `rs.signers.isManaged(attacker_addr)` returns true
4. Internal transfer rule allows transfer to attacker address
5. **Funds stolen**

### The Defense: TrustedSignerSet

`rs.signers.isManaged()` MUST NOT query the runtime SignerRegistry. Instead, it queries a **TrustedSignerSet** — an immutable set built from config at startup.

```go
// TrustedSignerSet contains ONLY signers declared in config.yaml at startup.
// API-created signers are NOT included. Immutable after construction.
type TrustedSignerSet struct {
    addrs map[string]bool // checksum address → true
}

// Built from config.yaml signer declarations:
// - chains.evm.signers.private_keys[].address
// - chains.evm.signers.keystores[].address
// - chains.evm.signers.hd_wallets[].address + derived addresses
//
// NOT included:
// - Signers created via API at runtime
// - Signers discovered from disk after startup
```

### Security Properties

| Property | Guarantee |
|----------|-----------|
| Immutable after startup | Runtime API cannot modify the trusted set |
| Config-only source | Only signers in config.yaml are trusted |
| HD derived included | Derived addresses from config HD wallets are trusted |
| Restart to update | Adding a new trusted signer requires config change + restart |
| Admin API compromise | Attacker cannot add addresses to trusted set |

### Alternative: Explicit Trusted List

For maximum control, operators can explicitly declare trusted addresses instead of auto-deriving from signer config:

```yaml
internal_transfer:
  trusted_addresses:
    - "0x1111..."
    - "0x2222..."
    - "0x3333..."
```

This is even more restrictive — only listed addresses are trusted, not all config signers.

## Implementation Plan

### Files to Create/Modify

| File | Change |
|------|--------|
| `internal/chain/evm/trusted_signers.go` | New: TrustedSignerSet struct + builder |
| `internal/chain/evm/js_helpers.go` | Add `rs.signers.isManaged()` helper |
| `internal/chain/evm/js_evaluator.go` | Inject TrustedSignerSet into JS evaluator |
| `cmd/remote-signer/main.go` | Build TrustedSignerSet from config at startup |
| `rules/templates/internal_transfer.template.js.yaml` | New: template |
| `rules/presets/internal_transfer.preset.js.yaml` | New: preset |
| Tests | Unit + e2e |

### Config Addition

```yaml
# config.yaml
chains:
  evm:
    # Existing signer config...
    signers:
      private_keys: [...]
      keystores: [...]
      hd_wallets: [...]

# The trusted signer set is automatically derived from the signers above.
# No additional config needed. rs.signers.isManaged() only trusts these addresses.
```

## Usage Examples

### Standalone: Direct ERC20 Transfer Between Signers

```yaml
rules:
  - name: "Internal ERC20 transfers"
    type: "evm_js"
    mode: "whitelist"
    config:
      script: |
        function validate(input) {
          var ctx = rs.tx.require(input);
          var transferSel = selector('transfer(address,uint256)');
          if (!eq(ctx.selector, transferSel)) revert('only transfer allowed');
          var dec = abi.decode(ctx.payloadHex, ['address', 'uint256']);
          require(rs.signers.isManaged(dec[0]), 'recipient not a managed signer');
          return ok();
        }
```

### With Delegation: Safe → MultiSend → Internal Transfer

```yaml
rules:
  # Safe rule delegates to MultiSend
  - name: "Safe wallet"
    type: "evm_js"
    config:
      delegate_to_by_target: "0xMultisend:multisend-rule"
      # ...

  # MultiSend delegates to internal transfer rule
  - name: "MultiSend"
    id: "multisend-rule"
    type: "evm_js"
    config:
      delegate_to: "internal-transfer-rule"
      # ...

  # Internal transfer rule uses rs.signers.isManaged()
  - name: "Internal transfers"
    id: "internal-transfer-rule"
    type: "evm_js"
    config:
      script: |
        function validate(input) {
          // ... extract recipient from native/ERC20/ERC721/ERC1155
          require(rs.signers.isManaged(recipient), 'not internal');
          return ok();
        }
```

### Future: With Auto-Discovery (Zero Config)

```yaml
rules:
  - name: "Safe wallet"
    type: "evm_js"
    config:
      # No delegate_to needed!
      script: |
        function validate(input) {
          // Extract inner call, return { valid: true, payload }
        }

  - name: "Internal transfers"
    type: "evm_js"
    config:
      discoverable: true
      handles_contracts: "*"  # Matches any contract (since it checks recipient, not contract)
      script: |
        function validate(input) {
          // ... extract recipient
          require(rs.signers.isManaged(recipient), 'not internal');
          return ok();
        }
```

## Dependencies

- [Auto-Discovery Delegation](./auto-discovery-delegation.md) — for Phase 3 zero-config delegation
