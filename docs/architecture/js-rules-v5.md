# JS Rules Architecture Plan (v5.1 — Final Production Ready)

**Low-latency rule evaluation via in-process JS (Sobek/Goja).**  
**Unified contract**: Every JS rule exposes a single `validate(input)` function. The engine performs basic validation then passes a normalized `RuleInput` through; the rule decides validity. No declarative layer — only template variables + pure JS. Optional `payload` return enables **delegation** for composition (e.g. multisend → erc20).

**This document is the single source of truth.** It defines when to use JS vs Solidity, the exact contract, config schema, security guarantees, delegation semantics, observability, and a concrete implementation checklist.

---

## 1. Goals

- Low latency: <5ms per rule (vs Foundry 100ms–2s+).
- Simple mental model: `validate(input)` → `{ valid: boolean, reason?: string, payload?: object }`.
- Composition via delegation: Small, independent rules; complex flows via `payload` + engine delegation.
- Template + pure JS only: Variables injected exclusively as `config` object. No string substitution.

---

## 2. Current Solidity Rules (Reference Only)

Solidity rules (Foundry) coexist unchanged. Same scope and allow/block semantics.

---

## 3. Single JS Rule Type

**Rule type**: `evm_js`

**Contract**

- **Input**: Normalized `RuleInput` (§11.1). Hashes/digests computed in Go.
- **Output**:
  ```ts
  {
    valid: boolean,           // required
    reason?: string,          // sanitized
    payload?: object          // for delegation
  }
  ```

Invalid return / throw / timeout → wrapper converts to `{ valid: false, reason: "..." }` (§11.2).

---

## 4. Delegation

**Config per rule** (Rule.Config):

- `delegate_to`: string — **rule ID(s)** of the target rule(s). Single ID, or **comma-separated** list (e.g. `"e2e-erc20,e2e-erc721"`). The engine tries each target in order until **one** allows: for `single` mode the payload is evaluated by each target until one allows; for `per_item` each item must be allowed by at least one target. Use when batch content can match different rule types (e.g. Multisend items may be ERC20 or ERC721). List IDs: `validate-rules -config <path> -list-rule-ids`.
- `delegate_mode`: `"single"` | `"per_item"` (default `"single"`)

**Config-file delegation**: For rules defined in YAML (or expanded from templates), set `delegate_to` and optional `delegate_mode` under the rule’s `config`. For template instances (e.g. Safe), the template may expose variables `delegate_to` and `delegate_mode`; instance variables are substituted into the rule config so the engine sees them. Unsubstituted placeholders (e.g. `${delegate_to}`) are treated as empty (no delegation).

**Custom rule ID**: Any rule in config can set an optional top-level `id`; instance rules use `config.id` so the single expanded rule gets that id. The id must be unique and is the rule's stable identifier (use in `delegate_to` for maintainability, e.g. `id: "e2e-multisend"`, `delegate_to: "e2e-multisend"`). If `id` is omitted, a deterministic id is generated from config order (prefix `cfg_`).
- `items_key`: string (required for `"per_item"`; default `"items"`; missing → reject `"per_item requires items_key"`)
- `payload_key`: string (optional for `"single"`)

**Script may return** `delegate_to`: string (optional). When `valid === true` and `payload` is present, if the script returns `delegate_to` it overrides config `delegate_to`, enabling routing by payload (e.g. Safe rule delegates to different rules by inner `to` address for composability).

**Behavior**:

- If `valid === true` + `payload` + (script `delegate_to` or config `delegate_to`):
  - Enforce permission, payload size, max depth, cycle (§11.8).
  - **Multiple targets** (comma-separated `delegate_to`): try each target in order until one allows; if none allow, the delegation fails.
  - `"single"`: pass `payload` (or `payload[payload_key]`) to the target(s).
  - `"per_item"`: `payload[items_key]` must be array. For each item, try each target until one allows; if no target allows an item, the whole delegation fails.
- **Hybrid**: Payload conforms to `RuleInput` (or subset). JS → Solidity supported. Solidity → JS supported if compatible (future bridge).

---

## 5. Request Shape (RuleInput)

```ts
interface RuleInput {
  sign_type: 'transaction' | 'typed_data' | 'personal_sign';
  chain_id: number;
  signer: string;                    // checksum address

  transaction?: {
    from: string;                    // REQUIRED
    to: string;
    value: string;                   // hex
    data: string;                    // hex
    gas?: string;
    methodId?: string;
  };

  typed_data?: { /* EIP-712 standard */ };
  personal_sign?: { /* EIP-191 standard */ };
}
```

`transaction.from`: **REQUIRED**. Engine MUST populate when derivable. If not, reject `"from address not derivable"`. Rules can assume `from` is set.

---

## 6. Template & Instance

- Variables exclusively injected as `config` object (JSON). String substitution forbidden.
- One script per rule/template.

---

## 7. Test Cases

- `input`: `RuleInput` (or synthetic payload)
- `expect_pass`, `expect_reason?`
- Support **mock_targets** per test case: `{ "<rule_id>": { valid, reason?, payload? } }`
- Engine uses production wrapper.

---

## 8. Execution Flow

1. Basic validation → build `RuleInput`.
2. Select JS rules by scope.
3. Execute via mandatory wrapper (§11.2).
4. `valid === false` or limit hit → reject entire request (fail-closed).
5. `valid === true` + `payload` + `delegate_to` → §11.8 checks → delegate.
6. Final `valid === true` no payload → allow.

---

## 9. Summary

| Dimension | Choice |
|-----------|--------|
| Rule type | `evm_js`: `validate(input)` |
| Input | `RuleInput` (host-computed hashes) |
| Output | `{ valid, reason?, payload? }` (wrapped + sanitized) |
| Composition | Payload + delegation (single / per_item) |
| Variables | Config object only |
| Security | Hardened sandbox + verifiable tests |
| Failure semantics | Any failure → entire request reject |

---

## 10. JS vs Solidity

**JS**: speed, simple rules.  
**Solidity**: precision, state-aware, high-value rules.  
**Hybrid**: JS fast filter → Solidity precise gate for high-value txs.

---

## 11. Implementation Spec

### 11.1 RuleInput (see above)

### 11.2 Output Wrapper (Mandatory)

```go
func wrappedValidate(vm *sobek.Runtime, fn sobek.Value, input sobek.Value) map[string]any {
    res, err := fn.ToObject(vm).Call("call", nil, input)
    if err != nil {
        return map[string]any{"valid": false, "reason": sanitizeReason("script error", err.Error())}
    }
    if !isValidResult(res) {
        return map[string]any{"valid": false, "reason": "invalid return shape"}
    }
    return sanitizeResult(res)
}
```

**Reason sanitization** (mandatory):
- Production: fixed codes (`"script_error"`, `"timeout"`, `"invalid_shape"`)
- Debug: truncate 120 chars, strip control chars, escape `\n` → `\\n`

### 11.7 Security: Sandbox (Mandatory + Verifiable)

**Hardening Checklist** (all required):

1. Interrupt + watchdog: 15–20ms per rule + secondary timeout.
2. Globals: Allow-list only (`input`, `config`, `fail`, `ok`, `eq`, `keccak256`, `selector`, `toChecksum`, `isAddress`, `toWei`, `fromWei`, `abi`). Delete `eval`, `Function`, `Date`, `Math.random`, `console`, `require`, etc.
3. Memory: No Goja quota. **Priority**: (1) cgroup (production, 64–256MB/pod); (2) MemStats polling (50ms sample, 50MB threshold); (3) document "container bound". Typical rule <10MB. Acceptance: huge alloc reject <200ms, memory growth ≤50MB.
4. VM lifecycle: Default one per invocation. Reuse: strict clear + pollution test.
5. Acceptance test suite (CI mandatory):

| # | Test | Pass condition |
|---|------|----------------|
| 1 | Infinite loop | Reject in timeout; no block. |
| 2 | Huge alloc `Array(1e8)` | Reject <200ms; memory ≤50MB. |
| 3 | Prototype pollution | Next rule no see pollution. |
| 4 | Pollution + second rule | Isolation proven; no crash. |
| 5 | Global pollution | Second rule no see mutation. |
| 6 | `new Function()` | Reject. |
| 7 | Date abuse | Reject/no hang. |
| 8 | Invalid return | Reject "invalid shape". |
| 9 | OOM-like | Reject/hit limit; no panic. |

### 11.8 Delegation Limits & Security

- Max depth: 6
- Cycle detection: per path; per-item independent
- Payload size: max 256 items
- Permission check:
  ```go
  if !currentScope.CanAccess(targetRule.Scope) { reject("delegation target not allowed") }
  ```

### 11.9 Variable Injection

Config object only. No substitution.

### 11.11 Helpers

**eq**, **keccak256**, **selector**, **toChecksum**, **isAddress**, **toWei**, **fromWei**. **abi** (Solidity-aligned, via go-ethereum/abi): **abi.encode(types[], values[])** and **abi.decode(dataHex, types[])**; types can be strings (`"address"`, `"uint256"`, `"bool"`, `"bytes32"`, `"bytes"`, `"string"`) or **tuple** spec: `{ type: "tuple", components: [ { name: "x", type: "uint256" }, { name: "y", type: "uint256" } ] }`. Decoded tuple is an object with field names as keys.

---

## 13. Implementation Checklist

- [x] Add `evm_js`
- [x] Enforce `RuleInput`; `from` required
- [x] Mandatory wrapper + sanitization
- [x] Sandbox + all 9 tests in CI
- [x] Delegation: permission, size limit, items_key required for per_item
- [x] Config object only
- [x] RuleEvaluator abstraction
- [x] Mock delegation in tests
- [x] Observability: existing rule metrics (rule_type=evm_js, outcome, duration); circuit breaker deferred
- [x] Document from README
