# Security Audit: Agent Preset & Dynamic Budget Feature

**Auditor:** Security Auditor (automated)
**Date:** 2026-03-16
**Scope:** Design document + implementation code (Phases 1-4)
**Status:** Implementation review (updated from design-only audit)
**Files reviewed:**
- `docs/features/agent-preset-and-dynamic-budget.md` (design)
- `internal/core/rule/budget.go` (budget engine, dynamic budget auto-creation)
- `internal/chain/evm/js_evaluator.go` (JS sandbox, wrappedValidateBudget)
- `internal/chain/evm/js_rpc_helpers.go` (RPC injection into JS)
- `internal/chain/evm/rpc_provider.go` (RPC provider, method allowlist)
- `internal/chain/evm/token_metadata.go` (token metadata cache)
- `internal/api/middleware/auth.go` (authentication)
- `internal/api/middleware/agent.go` (agent role middleware)
- `internal/api/router.go` (route-level access control)
- `internal/core/rule/whitelist.go` (rule evaluation engine)
- `internal/core/types/auth.go` (APIKey struct with Agent field)
- `internal/core/types/budget.go` (BudgetResult, BudgetID)
- `internal/core/types/template.go` (BudgetMetering, UnitConf)
- `internal/storage/budget_repo.go` (AtomicSpend, budget persistence)

---

## Executive Summary

The implementation shows strong security foundations. Several design-level concerns from the initial audit have been **properly addressed** in code (address validation, allowlist-only RPC methods, parameterized DB queries, decimals range validation). However, key gaps remain around dynamic budget abuse, HTTP client hardening, signer visibility, and the JS timeout conflict with RPC.

**Finding counts:** 1 Critical, 3 High, 5 Medium, 3 Low, 3 Info

---

## Findings

### CRITICAL-1: Dynamic Budget Auto-Creation Has No Unit Count Limit

**Severity:** Critical
**Component:** `internal/core/rule/budget.go:227-308` (`autoCreateDynamicBudget`)

**Description:** The `autoCreateDynamicBudget` function creates a new budget record in the DB for every unique dynamic unit returned by JS `validateBudget`. There is **no limit** on how many dynamic units can be created per rule. An attacker can exploit this:

1. **Unbounded total exposure:** Craft transactions to N different token addresses, each getting its own `unknown_default` budget. Total spend = N * `unknown_default.max_total`. With max_total="1000" and N=1000 tokens, the effective budget is 1,000,000 tokens.
2. **Storage exhaustion:** Each unit creates a new `rule_budgets` row. An attacker sending transactions to millions of unique addresses creates millions of DB rows.
3. **No global cap:** There is no `max_dynamic_units` or `max_total_all_units` field in `BudgetMetering` or `UnitConf`.

Verified in code: `autoCreateDynamicBudget` at line 295 calls `bc.budgetRepo.Create(ctx, budget)` unconditionally, with no count check.

**Recommendation:**
- Add `MaxDynamicUnits int` to `BudgetMetering` (default 100). Before auto-creation, count existing budget records for the rule and reject if at limit.
- Add optional `MaxTotalAllUnits string` to `BudgetMetering` for aggregate cross-unit cap.
- Use `INSERT ... ON CONFLICT (rule_id, unit) DO NOTHING` (upsert) instead of plain `Create` to handle concurrent auto-creation of the same unit.

---

### HIGH-1: HTTP Client Missing Redirect Protection and SSRF Hardening

**Severity:** High (downgraded from Critical -- address validation partially mitigates)
**Component:** `internal/chain/evm/rpc_provider.go:51-62` (`NewRPCProvider`)

**Description:** The implementation correctly validates addresses via `common.IsHexAddress()` in `js_rpc_helpers.go:127-132` and uses an allowlist of RPC methods (`eth_call`, `eth_getCode` only). This significantly reduces SSRF risk. However, the HTTP client has no redirect protection:

```go
client: &http.Client{
    Timeout: rpcCallTimeout,
}
```

A compromised or misconfigured RPC gateway could return a 3xx redirect to an internal service. The default Go HTTP client follows redirects automatically.

**Recommendation:**
```go
client: &http.Client{
    Timeout: rpcCallTimeout,
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
        return http.ErrUseLastResponse // never follow redirects
    },
}
```

### HIGH-2: JS Timeout (20ms) Conflicts with RPC Calls (5s per call)

**Severity:** High
**Component:** `internal/chain/evm/js_evaluator.go:21` and `rpc_provider.go:15`

**Description:** The JS sandbox timeout is 20ms (`jsRuleTimeout = 20 * time.Millisecond`). The RPC call timeout is 5s (`rpcCallTimeout = 5 * time.Second`). When a JS rule calls `web3.call()`, the Go-side HTTP call takes up to 5s, but the JS VM will be interrupted after 20ms via `time.AfterFunc(jsRuleTimeout, func() { vm.Interrupt("timeout") })`.

The `vm.Interrupt` call will NOT interrupt a synchronous Go function call from within Sobek. The Go HTTP call runs to completion (or its own 5s timeout), and the interrupt is checked when control returns to JS. So the effective timeout for RPC-enabled rules is actually 5s + 20ms, not 20ms. This is not a security bug per se (the RPC call does time out), but:

1. The 20ms timeout becomes misleading -- it doesn't actually limit RPC-enabled evaluations.
2. Multiple RPC calls (up to 10) could take 50s total, far exceeding any expected evaluation time.
3. There is no **total evaluation timeout** for RPC-enabled rules. The 15s total specified in the design is not implemented.

**Recommendation:**
- Pass a `context.WithTimeout(rpcCtx.Ctx, 15*time.Second)` total evaluation context that is shared by all RPC calls
- Use this context in `RPCProvider.Call()` instead of creating a new one per call
- Set `jsRuleTimeout` to 15s for RPC-enabled rules (or better, use the context for timeout)
- Alternatively, track cumulative RPC time in `RPCCallCounter` and fail if > 15s total

### HIGH-3: Signer Endpoint Not Filtering for Agent Keys

**Severity:** High
**Component:** `internal/api/handler/evm/signer.go`, `internal/api/router.go:214`

**Description:** The design specifies agent keys should only see "own signers" (Section 7.2). However:

1. The signer endpoint uses `withAuth` (not `withAuthAndAgentOrAdmin`), meaning any authenticated key (including dev keys) can list signers.
2. The signer handler has **no agent-specific filtering**. Grep for "Agent" or "agent" in `signer.go` returns no matches.
3. When `allow_all_signers: true` is set on an agent key, the agent can see ALL signer addresses.

The design table says `GET /evm/signers` for agent should show "own signers", but the implementation does not enforce this.

**Recommendation:**
- In the signer handler's GET path, check if `apiKey.Agent` and if so, filter the response to only `apiKey.AllowedSigners`
- If `apiKey.AllowAllSigners && apiKey.Agent`, decide: either show all (document this) or block (too permissive for agent)
- Add test: agent key with `allowed_signers: ["0xA"]` should only see `0xA`, not `0xB`

---

### MEDIUM-1: Budget Auto-Creation Race Condition (TOCTOU)

**Severity:** Medium (downgraded from Critical -- AtomicSpend serializes the actual spend)
**Component:** `internal/core/rule/budget.go:157-167`

**Description:** Concurrent requests for the same new dynamic unit both see "not found" and both call `autoCreateDynamicBudget`. The second `Create` will fail with a primary key conflict (BudgetID is deterministic via SHA256). The error propagates as `failed to create budget record`, causing a fail-closed denial.

This is safe (no budget bypass) but causes unnecessary request failures. The first concurrent request succeeds, the second fails with an error even though the budget record exists.

**Recommendation:**
- After `Create` fails, retry `GetByRuleID` once (the record was created by the other goroutine)
- Or use GORM's `FirstOrCreate` with the deterministic BudgetID
- Or use `INSERT ... ON CONFLICT DO NOTHING` + re-SELECT

### MEDIUM-2: Token Metadata Cache Poisoning via Malicious Contract

**Severity:** Medium
**Component:** `internal/chain/evm/token_metadata.go:65-93` (`GetDecimals`)

**Description:** The `decodeUint8FromHex` function at line 258 correctly validates decimals range (0-255). Good. However, a malicious contract can return any value in that range. If a proxy contract returns `decimals=0` before being initialized (or a malicious contract returns `decimals=1`), the cached value is wrong.

With `unit_decimal: true`, `max_total: "1000"` with `decimals=1` becomes raw `10000` instead of the expected `1000000000` (if true decimals should be 6). This gives 100,000x less budget than intended, blocking legitimate transactions.

Conversely, if decimals is spoofed higher than actual, the budget becomes too permissive.

**Recommendation:**
- For `known_units` with explicit `Decimals` in config: the implementation already uses config decimals (line 259 in budget.go). Verified correct.
- For `unknown_default` without explicit decimals: currently fails closed ("RPC auto-query not yet implemented" at line 263). This is safe for now.
- When Phase 2 connects RPC decimals to budget: add a "common decimals" sanity check (warn if not in {0, 6, 8, 9, 18})

### MEDIUM-3: Agent Safety Blocklist Incompleteness (Design-Level, Not Yet Implemented)

**Severity:** Medium
**Component:** Design Section 5.4 (not yet in code -- Phase 3 pending)

**Description:** The agent safety rule in the design has an incorrect selfdestruct check and missing patterns. Since Phase 3 is pending, this is flagged for implementation review:
- The `selfdestruct` check (`data.substring(2,4) === 'ff'`) is wrong -- 0xFF is an EVM opcode, not callable via calldata
- Missing: delegatecall operation check, proxy upgrade selectors, ownership transfer selectors
- `setApprovalForAll` is logged but allowed

**Recommendation:** See original audit findings MEDIUM-4. Address during Phase 3 implementation.

### MEDIUM-4: No Dynamic Unit String Validation

**Severity:** Medium
**Component:** `internal/chain/evm/js_evaluator.go:438-453` (`parseBudgetResultObject`)

**Description:** The `unit` field from JS `validateBudget` return value is only checked for non-empty string. There is no format validation. A malicious or buggy JS rule could return unit strings like:
- Very long strings (limited only by varchar(512) in DB)
- Special characters that might cause issues in logging, monitoring, or future SQL contexts
- Strings that collide with other units after normalization

The `NormalizeBudgetUnit` lowercases the string, and GORM uses parameterized queries, so SQL injection is not possible. But storage abuse is: 512-char unit strings * thousands of records = significant storage.

**Recommendation:**
- Validate unit string format: `^[a-zA-Z0-9:_.-]{1,128}$` or similar
- Or truncate to reasonable length (64 chars) before use
- Add this validation in `parseBudgetResultObject` before returning

### MEDIUM-5: ERC165 Cache Only Stores Positive Results

**Severity:** Medium
**Component:** `internal/chain/evm/token_metadata.go:184-204` (`IsERC721`)

**Description:** The `IsERC721` and `IsERC1155` functions only cache positive results (`if result { c.upsertField(...) }`). Negative results are always re-queried via RPC. This means:
1. A contract that is NOT ERC721 triggers an RPC call on every evaluation (cache miss every time)
2. Since most ERC20 tokens are not ERC721, the typical `transferFrom` disambiguation path always makes an RPC call
3. This burns through the 10-call-per-evaluation limit quickly

**Recommendation:**
- Cache negative results too (e.g., `IsERC721Checked bool` + `IsERC721 bool`)
- Or use a separate in-memory LRU cache for ERC165 results with short TTL

---

### LOW-1: personal_sign Message Length Check is Byte vs Character (Design-Level)

**Severity:** Low
**Component:** Design Section 5.3 (Phase 3, not yet implemented)

**Description:** `msg.length` in JavaScript checks UTF-16 code units, not byte length. A 1024-char message could be up to 4096 bytes.

**Recommendation:** Check byte length if the concern is payload size.

### LOW-2: RPC Response Body Limit is 1MB

**Severity:** Low
**Component:** `internal/chain/evm/rpc_provider.go:141`

**Description:** `io.LimitReader(resp.Body, 1<<20)` limits response to 1MB. This is reasonable for `eth_call` and `eth_getCode`, but a malicious RPC gateway could still force 1MB * 10 calls = 10MB of memory allocation per evaluation. The process-wide memory monitor (32MB limit) provides some protection.

**Recommendation:** Consider reducing to 256KB (sufficient for any reasonable eth_call result).

### LOW-3: Budget Alert Uses Stale Budget Data

**Severity:** Low
**Component:** `internal/core/rule/budget.go:222`

**Description:** `go bc.checkAlertThreshold(rule.ID, unit, budget)` passes the `budget` pointer read before `AtomicSpend`. After `AtomicSpend`, the actual `Spent` and `TxCount` values in DB are different from the passed struct. The alert percentage calculation uses stale data, potentially triggering late or not at all.

**Recommendation:** Re-read budget after AtomicSpend, or pass the amount and compute in-goroutine.

---

### INFO-1: JS Sandbox Memory Monitor is Process-Wide

**Severity:** Info
**Component:** `internal/chain/evm/js_evaluator.go:366-390`

Already documented in code comments. Defense-in-depth, not precise per-evaluation enforcement.

### INFO-2: AgentOrAdminMiddleware Correctly Implemented

**Severity:** Info (positive finding)
**Component:** `internal/api/middleware/agent.go`

The `AgentOrAdminMiddleware` is well-implemented:
- Admin gets full access (pass-through)
- Agent is restricted to GET only (non-GET returns 403)
- Neither admin nor agent: denied with logging and alert
- Used in router for `/api/v1/evm/rules` and `/api/v1/presets` endpoints

This addresses the design concern from HIGH-3 in the original audit. The middleware itself is correct.

### INFO-3: RPC Method Allowlist is Properly Dual-Checked

**Severity:** Info (positive finding)
**Component:** `internal/chain/evm/rpc_provider.go:20-34`

The RPC provider uses both a blocklist AND an allowlist:
```go
if blockedRPCMethods[method] { return error }
if !allowedRPCMethods[method] { return error }
```

This defense-in-depth approach means even if the blocklist is incomplete, only `eth_call` and `eth_getCode` are allowed. Excellent security pattern.

---

## Resolved Design Concerns (Verified in Code)

1. **SSRF address validation:** `validateAddress()` in `js_rpc_helpers.go:127` uses `common.IsHexAddress()`. Properly implemented.
2. **RPC call rate limit:** `RPCCallCounter` in `rpc_provider.go:166-186` enforces 10 calls per evaluation. Properly implemented.
3. **Decimals range validation:** `decodeUint8FromHex` in `token_metadata.go:249-261` validates 0-255. Properly implemented.
4. **Data hex validation:** `jsWeb3Call` validates `0x` prefix on data parameter. Properly implemented.
5. **Fail-closed on unknown unit without config:** `autoCreateDynamicBudget` returns error when no `unknown_default` is configured. Properly implemented.
6. **Negative amount rejection:** `exportedToBigInt` checks `Sign() < 0` for all types. Properly implemented.
7. **Parameterized queries:** All GORM queries use parameterized `?` placeholders. No SQL injection via dynamic unit strings.
8. **Agent cannot create/modify rules:** `AgentOrAdminMiddleware` blocks non-GET methods for agent keys. Templates remain admin-only (`withAuthAndAdmin`).

---

## Remaining Code Patterns to Watch

1. **Phase 3 (Agent Template):** Apply findings MEDIUM-3, LOW-1 when implementing the safety blocklist and sign rule.
2. **Phase 5 (Integration):** Test concurrent dynamic budget creation, RPC timeout behavior, and agent endpoint access control matrix.
3. **Unit string validation:** Add format check before accepting JS-returned unit strings.
4. **Max dynamic units:** Add cap before auto-creating budget records.
5. **HTTP redirect protection:** Add `CheckRedirect` to RPC provider HTTP client.
6. **Total RPC timeout:** Implement 15s total evaluation timeout for RPC-enabled rules.
