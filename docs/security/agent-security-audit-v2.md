# Security Audit v2: Agent Interaction Paths

**Auditor:** Security review (manual + automated)
**Date:** 2026-03-19
**Scope:** Agent interaction paths — how a compromised AI agent (e.g., via prompt injection) can abuse the signing service
**Reference:** `docs/agent.md`, `docs/security/agent-feature-audit.md`, `docs/security/agent-interaction-gaps.md`
**Status:** Reviewed with project owner

---

## Executive Summary

The remote-signer has strong security foundations: Ed25519 auth, 2-tier rule engine (blocklist→whitelist), JS/Solidity sandboxing, simulation-based budget enforcement, RBAC with ownership scoping, and an approval guard. Previous audits (`agent-feature-audit.md`, `agent-interaction-gaps.md`) have addressed several critical issues.

This audit focuses on remaining gaps from the agent's perspective. All findings have been discussed and triaged with the project owner.

**Roles in the system:** admin, dev, agent, strategy (no "user" role).

---

## Findings

### BUG-1: Strategy Role Should Not Fall Through to Simulation Fallback

**Severity:** Bug
**Component:** `internal/core/service/sign.go:252`
**Status:** TODO — fix required

**Description:** The simulation budget fallback in `SignService.Sign()` applies to all API key roles without role filtering. Strategy keys represent scenarios where all behaviors are covered by explicit rules. Falling through to simulation means rules are misconfigured — this should be rejected, not auto-approved by simulation.

**Fix:** Add role check before simulation fallback. Strategy role should skip simulation and go directly to reject / manual approval path.

```go
// Strategy keys must have explicit rules for all operations.
// Reaching simulation fallback means rule misconfiguration — reject.
if s.simulationRule != nil && s.simulationRule.Available() && !apiKey.IsStrategy() {
    ...
}
```

---

### CFG-1: Simulation Requires budgetDefaults at Startup

**Severity:** Configuration
**Component:** `internal/chain/evm/simulation_rule.go:423-427`
**Status:** TODO — startup validation required

**Description:** When `SimBudgetDefaults` is nil and simulation is enabled, `autoCreateBudget` returns nil (allow without limit). This means all simulation-approved transactions have no budget tracking — effectively unlimited signing.

Setting budget to 0 would block all legitimate transactions. Returning `no_match` would force everything to manual approval, defeating agent flexibility.

**Fix:** Validate at startup: if simulation is enabled, `budgetDefaults` must be configured. Refuse to start otherwise.

```go
// cmd/remote-signer/main.go startup
if simulationEnabled && budgetDefaults == nil {
    log.Fatal("simulation enabled but budget_defaults not configured — refusing to start")
}
```

---

### CFG-2: `require_approval_for_agent_rules` Default Should Be `true`

**Severity:** Configuration / Documentation
**Component:** `internal/config/config.go:280-283`, `config.yaml:79`
**Status:** TODO — default change + documentation

**Description:** `require_approval_for_agent_rules` defaults to `false`. When false, agent-created whitelist rules (including template instantiation with custom variables like `allowed_spenders`) become active immediately without admin review.

Dev role is intentionally exempt — dev keys are given minimal funds for flexible development.

**Fix:**
- Change default to `true` in `config.go`
- Document the risk in `config.example.yaml`
- Reference from security documentation

---

### ENH-1: Unified `trusted_contracts` Whitelist

**Severity:** Feature gap (MEDIUM)
**Component:** Agent template rules, simulation approval detection
**Status:** TODO — feature enhancement

**Description:** Currently `allowed_spenders` only checks Permit-type typed_data spender field. Other high-privilege operations lack contract-level validation:

| Signature Type | Field to Check | Current Behavior |
|---------------|----------------|------------------|
| Permit/Permit2 typed_data | `message.spender` | Checked against `allowed_spenders` ✓ |
| Non-Permit typed_data | `domain.verifyingContract` | No check — auto-approved with sign_count budget |
| approve() transaction | calldata spender param | Simulation detects → manual approval |

**Fix:** Introduce a unified `trusted_contracts` config (or expand `allowed_spenders` scope):
- Permit → spender must be in whitelist (existing behavior)
- Non-Permit typed_data → `verifyingContract` must be in whitelist, otherwise manual approval
- approve() transaction → if spender in whitelist, auto-approve; otherwise manual approval

This keeps agent autonomous with known contracts while requiring human review for unknown ones.

---

### ENH-2: Simulation Budget `MaxDynamicUnits` Config

**Severity:** Configuration enhancement (LOW)
**Component:** `internal/chain/evm/simulation_rule.go:370-490`
**Status:** TODO — config enhancement

**Description:** The rule-path `autoCreateDynamicBudget` enforces `MaxDynamicUnits=100` to prevent budget amplification (N tokens × max_total per token). The simulation-path `autoCreateBudget` has no such limit.

In practice, attack surface is limited by the signer wallet's actual token holdings (simulation reverts if no balance). This is a known risk — a tradeoff between security and agent flexibility.

**Fix:** Add `MaxDynamicUnits` as a configuration option for the simulation budget path (default 100, matching rule path). Users who need more flexibility can increase it.

---

### ENH-3: JS and RPC Timeout Independence

**Severity:** Improvement (MEDIUM)
**Component:** `internal/chain/evm/js_evaluator.go:21`, `internal/chain/evm/rpc_provider.go:15`
**Status:** TODO — improvement

**Description:** JS sandbox timeout is 20ms, RPC call timeout is 5s per call (max 10 calls). The JS timeout timer runs during RPC calls, but `vm.Interrupt` doesn't interrupt Go-side HTTP calls. Effective timeout is misleading.

**Fix:** Pause JS timeout timer during RPC Go callbacks, resume when control returns to JS. This makes 20ms purely measure JS CPU time. RPC total time tracked separately (existing `RPCCallCounter` + cumulative time field, cap at 15s total).

---

### IMP-1: Approval Guard Sliding Window

**Severity:** Improvement (MEDIUM)
**Component:** `internal/core/service/approval_guard.go`
**Status:** TODO — improvement

**Description:** Guard triggers after N consecutive rejections. An agent can alternate legitimate and malicious transactions to reset the counter, preventing the guard from ever triggering.

**Fix:** Replace consecutive counter with a sliding window: if rejection rate exceeds threshold (e.g., >50%) within a time window (e.g., last 1 hour), pause signing. Budget limits still provide the primary safety net.

---

### IMP-2: ERC165 Negative Result Caching

**Severity:** Improvement (LOW)
**Component:** `internal/chain/evm/token_metadata.go:184-204`
**Status:** TODO — performance optimization

**Description:** `IsERC721` and `IsERC1155` only cache positive results. Negative results trigger an RPC call every time. Since most ERC20 tokens are not ERC721, every `transferFrom` disambiguation burns an RPC call from the 10-call-per-evaluation limit.

**Fix:** Cache negative results with short TTL (e.g., 1 hour).

---

### IMP-3: Token Decimals Anomaly Alert

**Severity:** Improvement (LOW)
**Component:** `internal/chain/evm/simulation_rule.go:443-446`, `internal/chain/evm/token_metadata.go`
**Status:** TODO — monitoring enhancement

**Description:** When decimals query fails, simulation defaults to 18. An uninitialized proxy returning 0 gets overridden to 18, potentially making budget too permissive. Conversely, a malicious contract returning unusual decimals could distort budget calculations.

**Fix:** When queried decimals are anomalous (> 24 or == 0 for a non-native token), send alert to configured Slack/Telegram notification channels. Do not block — alert only.

---

### IMP-4: Agent Safety Blocklist Expansion

**Severity:** Improvement (LOW)
**Component:** `rules/templates/agent.template.js.yaml:300-348`
**Status:** TODO — future enhancement

**Description:** Current blocklist covers 5 selectors: `setApprovalForAll(true)`, `transferOwnership`, `renounceOwnership`, `upgradeTo`, `upgradeToAndCall`. Missing patterns include `changeAdmin()`, `changeProxyAdmin()`, Gnosis Safe `execTransaction`, `increaseAllowance` (infinite approve pattern).

Simulation-level `DetectDangerousStateChanges` catches most of these post-hoc, so this is defense-in-depth.

**Fix:** Add TODO in code. Maintain a community-level dangerous selector list, update periodically.

---

### QOL-1: typed_data `message.value` Type Validation

**Severity:** Code quality (LOW)
**Component:** `rules/templates/agent.template.js.yaml:196`
**Status:** TODO — error message improvement

**Description:** `BigInt(td.message.value)` with a non-string/non-number value throws an exception in the JS sandbox, which Go catches and returns fail-closed (error). **Not a security vulnerability** — the request is rejected. However, the error message (`validateBudget: ...`) is unclear.

**Fix:** Add explicit type check before `BigInt()` conversion for better error messages:
```js
var rawVal = (td.message || {}).value || (td.message || {}).amount || '0';
if (typeof rawVal !== 'string' && typeof rawVal !== 'number') {
  revert('invalid Permit value type: expected string or number, got ' + typeof rawVal);
}
var value = BigInt(rawVal);
```

---

## Documentation Notes

### Simulation Fallback is Agent-Specific (in Practice)

The simulation budget fallback applies to all API key roles at the code level. However, in practice it is agent-specific:
- **Admin/Dev:** Have explicit whitelist rules covering their operations; should not reach simulation fallback
- **Strategy:** Must have explicit rules for all operations (BUG-1 enforces this)
- **Agent:** The primary consumer — handles arbitrary dApp interactions via simulation

This should be documented in `docs/agent.md` and `config.example.yaml`.

---

## Positive Findings (Verified Strong)

| Area | Verdict |
|------|---------|
| RBAC ownership scoping | Agent rules forced to `applied_to=["self"]` — cannot affect other users |
| Blocklist fail-closed | Dynamic blocklist unavailable → block all |
| RPC method allowlist | Dual check (blocklist + allowlist) — only eth_call, eth_getCode, eth_getTransactionCount |
| Nonce replay detection | DB-backed NonceStore prevents replay attacks |
| Simulation approval detection | Approval events for managed signers trigger manual approval |
| Dangerous state change detection | OwnershipTransferred, Upgraded, AdminChanged caught regardless of call path |
| Budget atomic spend | TOCTOU-safe via CreateOrGet + AtomicSpend |
| Dynamic unit cap (rule path) | MaxDynamicUnits=100 prevents budget amplification |
| Memory security | Private keys zeroized after loading; swap disabled; core dumps disabled; mlock |
| JS sandbox | Dangerous globals removed; Function constructor poisoned; timeout + memory monitor |
| validateBudget fail-closed | JS exception → Go error → request rejected (not budget bypass) |

---

## Priority Summary

| Priority | ID | Action | Effort |
|----------|----|--------|--------|
| 1 | BUG-1 | Strategy role skip simulation fallback | Low |
| 2 | CFG-1 | Startup validation: simulation requires budgetDefaults | Low |
| 3 | ENH-1 | Unified trusted_contracts whitelist | Medium |
| 4 | CFG-2 | require_approval default true + docs | Low |
| 5 | ENH-2 | Simulation MaxDynamicUnits config | Low |
| 6 | ENH-3 | JS/RPC timeout independence | Medium |
| 7 | IMP-1 | Approval guard sliding window | Medium |
| 8 | IMP-2 | ERC165 negative result caching | Low |
| 9 | IMP-3 | Token decimals anomaly → Slack/TG alert | Low |
| 10 | IMP-4 | Expand agent safety blocklist (TODO in code) | Low |
| 11 | QOL-1 | typed_data value type check for better errors | Low |
