# Auto-Discovery Delegation System

**Status**: Planned
**Priority**: Medium
**Author**: Ivan
**Date**: 2026-03-16

## Problem

Current delegation requires explicit configuration. For example, a Safe template must declare `delegate_to: "multisend-rule-id"` or `delegate_to_by_target: "0xMultisend:multisend-rule-id"`. This means operators must know the full delegation chain upfront, which increases configuration complexity and reduces composability.

## Desired Behavior

Rules self-register as "discoverable" by declaring which contracts/selectors they handle. The engine auto-discovers matching rules when a delegation payload has no explicit `delegate_to`.

Example flow without any explicit delegation config:
```
tx → Safe → MultiSend → ERC20
```
- Safe extracts inner call (to=0xMultisend, data=multiSend(...)), returns payload
- Engine discovers MultiSend rule (handles_contracts: 0xMultisend)
- MultiSend extracts batch items, returns per-item payloads
- Engine discovers ERC20 rule (handles_contracts: 0xUSDC) for each item

## Design

### Rule Configuration

New optional fields in rule config:

```yaml
config:
  discoverable: true                                    # opt-in to auto-discovery
  handles_contracts: "0xA0b8...,0x1234..."              # contracts this rule handles
  handles_selectors: "0xa9059cbb,0x095ea7b3"            # optional: method selectors
```

For template-based rules, `handles_contracts: "${token_address}"` is substituted at instantiation.

### Engine Lookup Flow

```
delegate_to non-empty?
  ├── Yes → explicit ID lookup (unchanged)
  └── No, payload non-empty?
       ├── No → return upstream ok()
       └── Yes → auto-discover:
            1. Convert payload → SignRequest
            2. Extract tx.to from payload
            3. Lookup DiscoverableIndex[tx.to]
            4. Filter by scope (chain, signer) + sign_type + selector
            5. Try each match until one allows
            6. Not found → return upstream ok()
```

### Index Structure

```go
type DiscoverableIndex struct {
    mu         sync.RWMutex
    byContract map[string][]*types.Rule  // checksum address → rules
}
```

- Rebuilt on rule load/reload (SIGHUP, API CRUD)
- O(1) contract lookup + small N for scope filtering

### Security Rules

1. **Explicit priority**: `delegate_to` always overrides auto-discovery
2. **Strict scope**: discovered rule must match same chain_type + chain_id + api_key_id + signer_address
3. **Whitelist only**: only whitelist-mode rules can be discoverable (blocklist already runs globally)
4. **Exact contract match**: no wildcards in `handles_contracts`
5. **Default off**: `discoverable: false` by default, must opt-in
6. **Blocklist still runs**: delegated payload checked against blocklist before target evaluation (unchanged)
7. **Depth/cycle limits**: same max depth=6, max items=256, cycle detection (unchanged)

### Multi-Match Strategy

When multiple discoverable rules match the same contract:
- Try each in order until one allows (same as existing multi-target logic)
- Order: more specific rules first (contract + selector > contract only)

## Impact on Existing System

| Component | Change |
|-----------|--------|
| `internal/core/rule/discoverable.go` | New file: index + discovery logic |
| `internal/core/rule/whitelist.go` | `resolveDelegation`: add auto-discover fallback branch |
| `internal/core/rule/engine.go` | Store DiscoverableIndex on engine |
| `internal/config/rule_init.go` | Build index after rule sync |
| Templates | No change required (can add discoverable fields optionally) |
| Existing explicit delegation | No change, still works |

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Unexpected rule match | High | Strict scope + contract + opt-in |
| Stale index after API CRUD | Low | Rebuild on rule change events |
| Performance | Low | O(1) map lookup, small N per contract |
| Operator confusion | Medium | Logging + audit trail of auto-discovered chains |

## Example: Before vs After

### Before (explicit)
```yaml
# Safe rule
config:
  delegate_to_by_target: "0xMultisend:multisend-rule,0xUSDC:erc20-usdc-rule"

# MultiSend rule
config:
  delegate_to: "erc20-usdc-rule"
```

### After (auto-discovery)
```yaml
# Safe rule — no delegate_to needed
config:
  script: |
    function validate(input) {
      // ... extract inner call, return { valid: true, payload }
    }

# MultiSend rule — discoverable, no delegate_to needed
config:
  discoverable: true
  handles_contracts: "0xMultisend"
  script: |
    function validate(input) {
      // ... parse batch, return { valid: true, items: [...] }
    }

# ERC20 USDC rule — discoverable
config:
  discoverable: true
  handles_contracts: "0xUSDC"
  script: |
    function validate(input) {
      // ... validate transfer params
    }
```

Engine auto-discovers: Safe → MultiSend → ERC20, zero explicit wiring.

## Future Extensions

- **Selector-level discovery**: match not just by contract but by method selector
- **Priority/weight system**: when multiple rules match, use explicit priority
- **Discovery audit log**: log which rules were auto-discovered for each request
- **Dry-run mode**: preview discovery chain without executing
