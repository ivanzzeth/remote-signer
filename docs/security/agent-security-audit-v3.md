# Security Audit v3: Full Attack Surface Deep Analysis

**Date:** 2026-03-20
**Method:** Two-phase audit:
- Phase 1: 7 parallel Explore agents by attack surface (broad scan) → 25 findings, ~60% false positive rate
- Phase 2: 5 parallel Opus agents with mandatory exploit path verification → 10 verified findings, 0% false positive
**Prior Audits:** `agent-security-audit-v2.md` (ALL RESOLVED), `agent-feature-audit.md`
**Status:** TRIAGE COMPLETE — 8 FIX, 2 ACCEPT

---

## Audit Methodology

### Phase 1 (Broad Scan — High False Positive Rate)

7 Explore-type agents scanned by attack surface (auth, crypto, sandbox, network, data, API, state).
Produced 25 findings but ~60% were false positives because agents:
- Reported theoretical risks without tracing full attack paths
- Missed existing mitigations (middleware error sanitization, rate limiting, SQL atomicity)
- Flagged Go language limitations as code bugs

### Phase 2 (Deep Verification — Zero False Positive)

5 Opus-model agents re-analyzed the same codebase with strict requirements:
- Must trace complete attack path from HTTP entry to vulnerable code
- Must check ALL mitigations along the path
- Must write concrete exploit steps and verify each
- Must self-mark FALSE POSITIVE if any step is blocked

**Result:** 10 verified real findings, 15 confirmed false positives.

### Key Learnings for Future Audits

1. **Explore agents are too shallow** for security audits — use reasoning-heavy models
2. **"Find vulnerabilities" prompts produce false positives** — use "verify if exploitable" prompts
3. **Require full attack path tracing** — most "vulnerabilities" are mitigated by other layers
4. **Smaller scope per agent** produces higher quality findings

---

## Verified Findings

### V3-1: Simulation RPC Response No Size Limit

**Severity:** MEDIUM
**Source:** deep-network
**Component:** `internal/simulation/rpc_simulator.go:285`

```go
respBody, err := io.ReadAll(resp.Body)  // No LimitReader — unbounded allocation
```

All equivalent code in `rpc_provider.go` uses `io.LimitReader(resp.Body, 1<<20)` (1MB cap). The simulation path omits this.

**Attack path:** Authenticated user → `POST /api/v1/evm/simulate` → `callSimulateV1()` → unbounded `io.ReadAll` → OOM if RPC returns large response.

**Mitigations present:** Authentication required, rate limiting, 60s HTTP timeout.
**Mitigations absent:** No response size limit, no batch simulate transaction count cap.

**Fix:** Add `io.LimitReader(resp.Body, 1<<20)` consistent with `rpc_provider.go`. Add `maxBatchSimulateSize` cap.

---

### V3-2: Batch Sign Error Leaks Internal Details to Client

**Severity:** MEDIUM
**Source:** deep-disclosure
**Component:** `internal/api/handler/evm/sign_batch.go:371`

```go
h.writeError(w, fmt.Sprintf("batch sign failed at tx %d: %s", i, signErr.Error()), http.StatusInternalServerError)
```

The single-sign handler (`sign.go:193-242`) properly categorizes errors and returns sanitized messages. The batch handler passes raw `signErr.Error()` which may contain DB paths, keystore errors, or state machine internals.

**Fix:** Apply the same error categorization from `sign.go` to the batch handler.

---

### V3-3: encodeSignature Incorrect V-byte for EIP-155 Legacy Transactions

**Severity:** MEDIUM
**Source:** deep-signing
**Component:** `internal/chain/evm/adapter.go:534-550`

For legacy transactions with EIP-155, `go-ethereum` stores `v = recovery_id + 35 + chainID*2` in `LegacyTx.V`. `RawSignatureValues()` returns this value directly.

The code does `sig[64] = byte(v.Uint64() - 27)`:
- chainID=1: v=37 → sig[64]=10 (should be 0 or 1)
- chainID=137: v=309 → sig[64]=282 → byte overflow

**Impact:** `SignedData` (RLP-encoded) is correct — on-chain broadcast works. But the API response `Signature` field has wrong v-byte. Any consumer using `ecrecover` with this 65-byte signature gets wrong address.

**Fix:** For legacy tx, compute `recovery_id = (V - 35 - chainID*2)` instead of `V - 27`. Use go-ethereum's own logic from `recoverPlain`.

---

### V3-4: ValidateJSCodeSecurity Not Called on API Rule Creation

**Severity:** MEDIUM
**Source:** deep-sandbox
**Component:** `internal/ruleconfig/validate.go:199` (`validateJSRuleConfig`)

`ValidateJSCodeSecurity()` (regex-based static analysis blocking `__proto__`, `constructor.constructor`, `Object.defineProperty`, etc.) is only called in the test-case runner path (`js_validator.go:82`). It is NOT called when:
- Creating rules via REST API (`POST /api/v1/evm/rules`)
- Loading rules from config file

The runtime poisoning (`removeGlobals`) is the primary defense and is always active. This is a defense-in-depth gap.

**Fix:** Add `ValidateJSCodeSecurity(script)` call in `validateJSRuleConfig`.

---

### V3-5: Batch Sign Response Exposes Rule Names

**Severity:** LOW-MEDIUM
**Source:** deep-disclosure
**Component:** `internal/api/handler/evm/sign_batch.go:284`

```go
h.writeError(w, fmt.Sprintf("batch rejected: tx %d blocked by rule %s: %s", i, blockedErr.RuleName, blockedErr.Reason), http.StatusForbidden)
```

Rule names and rejection reasons are returned to the client. An attacker can probe different tx params to learn the security policy. Note: single-sign path has the same behavior (`service/sign.go` returns rule name in `SignResponse.Message`).

**Fix:** Replace rule names with generic "blocked by security policy" in HTTP responses.

---

### V3-6: Dynamic Budget Unit Count TOCTOU

**Severity:** LOW
**Source:** deep-budget
**Component:** `internal/core/rule/budget.go:385-391`, `internal/chain/evm/simulation_rule.go:459`

`CountByRuleID()` and `CreateOrGet()` are separate operations. Concurrent requests for different units can all pass the count check and all create, exceeding `MaxDynamicUnits`.

**Impact bounded:** Overshoot limited by server concurrency (tens, not thousands). Each extra unit still has its own `max_total` cap. Same issue exists in both rule path and simulation path.

**Fix:** Wrap count+create in serializable transaction, or re-check count after CreateOrGet and delete if exceeded.

---

### V3-7: Blocklist Source HTTP Client Follows Redirects

**Severity:** LOW
**Source:** deep-network
**Component:** `internal/blocklist/source.go:40`

```go
httpClient = &http.Client{Timeout: 30 * time.Second}  // No CheckRedirect
```

Both `rpc_provider.go` and `rpc_simulator.go` disable redirects. Blocklist source does not. Requires compromised admin-configured domain to exploit.

**Fix:** Add `CheckRedirect` that returns error.

---

### V3-8: AsyncFunction Constructor Not Explicitly Poisoned

**Severity:** LOW
**Source:** deep-sandbox
**Component:** `internal/chain/evm/js_evaluator.go:671-679`

`removeGlobals()` poisons `Function.prototype.constructor` and `GeneratorFunction.prototype.constructor` but not `AsyncFunction.prototype.constructor`. Likely mitigated by prototype chain (AsyncFunction inherits from Function), but should be explicitly hardened.

**Fix:** Add explicit AsyncFunction constructor poisoning in `removeGlobals()`.

---

### V3-9: Budget Alert Uses Stale Pre-Spend Data

**Severity:** INFO
**Source:** deep-budget
**Component:** `internal/core/rule/budget.go:249`

Alert goroutine receives pre-AtomicSpend budget snapshot. Alert threshold calculated with old `Spent` value. Alerts delayed by one transaction; missed entirely if budget exhausted in single large tx.

**Not a security vulnerability** — budget enforcement via AtomicSpend is correct. Operational monitoring concern only.

**Fix:** Re-fetch budget after AtomicSpend before passing to alert goroutine.

---

### V3-10: Signer Locked vs Not-Found Distinguishable

**Severity:** LOW
**Source:** deep-disclosure
**Component:** `internal/api/handler/evm/sign.go:194-212`

Different HTTP responses for locked (403) vs not-found (404) signers. Behind authentication + signer access control, so exploitability is minimal.

**Fix (optional):** Return generic "signer not available" for both cases to authenticated non-admin users.

---

## Confirmed False Positives (from Phase 1)

| Phase 1 ID | Claim | Why False Positive |
|---|---|---|
| CRIT-2 | Nonce reuse after cleanup | Timestamp validation (MaxRequestAge=TTL) blocks replay even if nonce cleaned |
| CRIT-3 | Timing side-channel in hex decode | Fixed-length input (32 bytes) = constant time; real issue was error messages (already sanitized) |
| HIGH-1 | Query string canonicalization | Signature covers exact `RawQuery`; any modification fails verification |
| HIGH-2 | API key enumeration via errors | Middleware returns generic "unauthorized" for all auth failures |
| HIGH-3 | Nonce store unavailability | Code returns error (fail-closed); NonceRequired validated at startup |
| HIGH-5 | RPC response 10MB | Rate limiting bounds concurrent evaluations; 10MB transient is reasonable |
| HIGH-7 | Budget period reset race | SQL `WHERE updated_at < ?` makes reset idempotent |
| HIGH-8 | Nonce store DoS | Rate limiting (200 req/min) × TTL (5min) × entry size (200B) = 200KB/IP max |
| MED-3 | ChainID mismatch | Only one chainID source in code path |
| MED-4 | encodeSignature r/s panic | secp256k1 mathematically guarantees r,s ≤ 32 bytes |
| MED-7 | Webhook payload size | Messages are server-generated from bounded internal values, not user input |
| MED-8 | Notification credentials | Code does not log credentials; infrastructure concern only |
| DATA-4 | BudgetPeriodStart future | Future start = never resets = MORE restrictive, not less |
| DATA-5 | Rule shallow clone | Variables is []byte, callers don't mutate post-clone |
| CONC-1/2/4 | Various state races | SQL-level CAS/idempotent WHERE clauses prevent all |

---

## Positive Findings (Verified Strong)

| Area | Verification |
|------|-------------|
| **SQL injection** | All GORM queries parameterized — no raw user input in SQL |
| **AtomicSpend** | Single SQL UPDATE with WHERE clause — budget cannot be exceeded |
| **State machine** | DB-level compare-and-swap prevents double-transitions |
| **JS VM isolation** | Fresh `sobek.New()` per request — no shared mutable state |
| **Auth error sanitization** | Middleware returns generic "unauthorized" for all failures |
| **RPC method allowlist** | Dual blocklist + allowlist — only 3 read methods allowed |
| **Nonce replay** | TTL-based + timestamp validation double defense |
| **Rate limiting** | Per-IP + per-key + global RPC rate limiting |
| **Memory protection** | mlockall + disable core dumps + swap detection |
| **HD wallet zeroize** | Mnemonic + password properly zeroized via defer |

---

## Priority Triage

| # | ID | Severity | Triage | Notes |
|---|---|---|---|---|
| 1 | V3-1 | MEDIUM | FIX | Simulation response size limit |
| 2 | V3-2 | MEDIUM | FIX | Batch sign error sanitization |
| 3 | V3-3 | MEDIUM | FIX | encodeSignature EIP-155 V value (ethsig library) |
| 4 | V3-4 | MEDIUM | FIX | ValidateJSCodeSecurity on API creation |
| 5 | V3-5 | LOW-MEDIUM | ACCEPT | Rule name in response — needed for agent UX |
| 6 | V3-6 | LOW | FIX | Dynamic unit count TOCTOU |
| 7 | V3-7 | LOW | FIX | Blocklist source redirect |
| 8 | V3-8 | LOW | FIX | AsyncFunction constructor |
| 9 | V3-9 | INFO | FIX | Budget alert stale data |
| 10 | V3-10 | LOW | ACCEPT | Signer status — needed for agent UX |
