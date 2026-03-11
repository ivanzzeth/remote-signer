# JS Rules Architecture (v1)

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

Delegation lets one rule allow a request only if another rule allows a **derived** payload (e.g. Safe validates SafeTx, then delegates the inner transaction to a protocol rule). The delegating rule returns `valid: true`, a `payload`, and a target **rule ID**; the engine evaluates that target rule with the payload. Semantics: `delegate_to` is always a **rule ID** that exists in the engine (see §4.1).

### 4.1 Rule IDs and instance namespacing

- **Single-rule instance**: If an instance expands to **one** rule and has `config.id`, that rule's ID is exactly `config.id` (e.g. `id: "erc20"` → rule ID `"erc20"`). Use it in `delegate_to` as-is.
- **Multi-rule instance**: If an instance expands to **multiple** rules and has `config.id`, each template rule that defines an `id` in the template gets a **namespaced** rule ID: `<instance_id>#<template_rule_id>`. The separator `#` is fixed (see `InstanceIDRuleIDSeparator` in code). Example: instance `id: "polymarket"`, template rule `id: "transactions"` → engine rule ID `"polymarket#transactions"`. So `delegate_to` must be that full string (e.g. `delegate_to: "polymarket#transactions"`). Do not use `#` inside instance or template ids.
- **No instance id**: If the instance has no `config.id`, single-rule expansion keeps an auto-generated id (e.g. `cfg_...`); multi-rule expansion keeps each template rule's id as-is. To avoid ID collisions when using the same template in multiple instances, give each instance a unique `config.id`.
- **Listing IDs**: Run `remote-signer-validate-rules -config <path> -list-rule-ids` (or `remote-signer-cli validate -config <path> -list-rule-ids`) to see the exact rule IDs after expansion; use those strings in `delegate_to`.

### 4.2 Config: delegate_to and delegate_mode

**Config per rule** (Rule.Config):

- `delegate_to`: string — **Rule ID(s)** of the target rule(s). One ID, or **comma-separated** list (e.g. `"erc20,erc721"`). For multi-rule instances use the namespaced form (e.g. `"polymarket#transactions"`).
- `delegate_mode`: `"single"` | `"per_item"` (default `"single"`).
- `items_key`: string (required for `"per_item"`; default `"items"`).
- `payload_key`: string (optional for `"single"`).

**Config-file**: Set `delegate_to` and optionally `delegate_mode` under the rule config. For template instances (e.g. Safe), the template exposes variables `delegate_to` and `delegate_mode`; the instance variables are substituted in. Example: Safe instance sets `variables.delegate_to: "polymarket#transactions"` so the Safe rule delegates nested calls to that rule.

### 4.3 How to write a JS rule that delegates

1. **Target rule ID**: Use a single-rule instance id (e.g. `"erc20"`) or a namespaced id (e.g. `"polymarket#transactions"`). Confirm with `remote-signer-validate-rules -config <path> -list-rule-ids` or `remote-signer-cli validate -config <path> -list-rule-ids`.
2. **In config**: Set the rule `config.delegate_to` to that ID (and optionally `config.delegate_mode`). For instances, set via template variables (e.g. Safe template variables `delegate_to`, `delegate_mode`).
3. **In script**: When the request is allowed and you have a derived payload, return `{ valid: true, payload: <RuleInput-like object>, delegate_to: "<target_rule_id>" }`. If you return `delegate_to`, it **overrides** `config.delegate_to` for this request (e.g. to route by inner `to` address). The payload must match what the target rule expects (e.g. `sign_type`, `chain_id`, `signer`, `transaction` or `typed_data`).
4. **Single vs per_item**: **single** — one payload; target runs once (e.g. Safe → one inner call). **per_item** — `payload[items_key]` must be an array; the engine runs the target for each item (e.g. Multisend → each batch item).

**Behavior**: If `valid === true` and `payload` is present and (script returns `delegate_to` or `config.delegate_to` is set), the engine enforces depth, cycle, and size limits (§11.8), resolves target rule(s) by **rule ID** (exact string, including `instance_id#template_rule_id`), and evaluates the payload. **Multiple targets** (comma-separated): try each in order until one allows. **Hybrid**: JS ↔ Solidity when payload shape is compatible.

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

- Variables exclusively injected as `config` object (JSON). String substitution into script source is forbidden.
- One script per rule/template.
- For instances that expand to multiple rules, set `config.id` so rule IDs are namespaced for `delegate_to` (see §4.1).

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

**rs** (reserved namespace): Composable module for evm_js rules. See [evm_js_rs_api.md](../evm_js_rs_api.md) for full API. Sandbox allow-list includes **rs**.

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
