# JS Rules Architecture Plan (v5.1 — Final Production Ready)

**Canonical doc:** [docs/architecture/js-rules-v5.md](../architecture/js-rules-v5.md) — implement from there.

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

- `delegate_to`: string (target rule ID)
- `delegate_mode`: `"single"` | `"per_item"` (default `"single"`)
- `items_key`: string (required for `"per_item"`; default `"items"`; missing → reject `"per_item requires items_key"`)
- `payload_key`: string (optional for `"single"`)

**Behavior**:

- If `valid === true` + `payload` + `delegate_to`:
  - Enforce permission, payload size, max depth, cycle (§11.8).
  - `"single"`: pass `payload` (or `payload[payload_key]`)
  - `"per_item"`: `payload[items_key]` must be array (missing/non-array → reject `"per_item requires payload.<items_key> to be an array"`). Call next rule per element (normalized `RuleInput`).
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
2. Globals: Allow-list only (`input`, `config`, helpers). Delete `eval`, `Function`, `Date`, `Math.random`, `console`, `require`, etc.
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

**eq** (strict), **keccak256**, **selector**, **toChecksum**, **isAddress**, **toWei**, **fromWei**, **encodeAbi** (basic types only; full in v2).

---

## 13. Implementation Checklist

- [ ] Add `evm_js`
- [ ] Enforce `RuleInput`; `from` required
- [ ] Mandatory wrapper + sanitization
- [ ] Sandbox + all 9 tests in CI
- [ ] Delegation: permission, size limit, items_key required for per_item
- [ ] Config object only
- [ ] RuleEvaluator abstraction
- [ ] Mock delegation in tests
- [ ] Observability + circuit breaker
- [ ] Document from README
