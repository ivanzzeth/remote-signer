# Security & Code Quality Audit Report

**Date:** 2025-02-26  
**Scope:** Project minimum requirements (coverage, input validation, e2e, validation parity, rule tests, startup validation, funds safety)  
**Method:** Step-by-step review, full test runs, validate-rules on all rules + config.e2e.yaml, actual program start with config.e2e.yaml.

---

## Executive Summary & BUGs (Must Fix)

| # | Requirement | Status | Notes |
|---|-------------|--------|--------|
| 1 | Overall coverage ≥ 85% | ❌ | **~33.2%** total (needs significant improvement) |
| 2 | Core/rules coverage ≥ 95% | ❌ | internal/chain/evm ~51.9%, internal/core/rule ~32.4% |
| 3 | Strict input validation | ✅ | Sign/rule/template validated; rule create validates chain_type/signer_address |
| 4 | E2E covers all rules/ and templates | ✅ | e2e runs validate-rules on every rules/*.yaml and rules/templates/*.yaml; all 31 pass |
| 5 | Production = validate-rules validation | ✅ | Solidity + evm_js + message_pattern validated at startup (same code paths) |
| 6 | Each rule ≥1 positive + ≥1 negative test | ✅ | Enforced for evm_js, message_pattern, and Solidity |
| 7 | Startup validates all rules, fail and exit on failure | ✅ | Implemented (Solidity, evm_js, message_pattern) |
| 8 | All tests pass + e2e + validate-rules + config.e2e.yaml | ✅ | Unit tests all pass; e2e all pass; validate-rules -config config.e2e.yaml → 20/20 pass |
| 9 | Actual program start: reach password or ready | ✅ | Server starts and reaches listening state with config.e2e.yaml |
| 10 | Funds safety (millions USDT) | ✅ | Blocklist fail-closed; startup validation; all rules/templates validated; BUG-4 fixed |

### BUG-1: validate-rules -config config.e2e.yaml fails — ✅ FIXED (round 1)

**Status:** ✅ Fixed in previous round. Verified in round 2: `go run ./cmd/validate-rules/ -config config.e2e.yaml` → **20 passed, 0 failed**.

---

### BUG-2: Program does not reach password/listening — ✅ FIXED (round 1+2)

**Status:** ✅ Fixed. Server starts successfully with config.e2e.yaml and reaches listening state. Verified: process runs until externally killed (exit code 124 from `timeout 20`), not from internal error.

---

### BUG-3 (potential): Unit test flake — ✅ No longer observed

**Status:** ✅ All unit tests pass reliably in round 2 (`go test ./...` — 0 failures).

---

### BUG-4 (NEW): polymarket_safe.template.yaml fails standalone validate-rules — ✅ FIXED

**Requirement:** "使用 validate-rules 工具验证 rules 目录下的所有模板和规则"

**Observed:**
- `go run ./cmd/validate-rules/ rules/templates/polymarket_safe.template.yaml` → Solidity compilation error:
  ```
  Error (6933): Expected primary expression.
    --> syntax_check_*.sol:45:5:
     |
  45 |     in(eip712_domainContract, 0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837),
     |     ^^
  ```
- Same issue affects `opinion_safe.template.yaml` (also uses `in()` in `typed_data_expression`).

**Root cause:** `GenerateTypedDataExpressionSyntaxCheckScriptWithStruct()` in `internal/chain/evm/solidity_evaluator.go` did not preprocess the custom `in()` operator before embedding expressions into Solidity code. Other modes (Functions, TypedDataFunctions) and the execution path all properly called `processInOperatorToMappings()` + `preprocessInOperator()`.

**Fix:** Added `processInOperatorToMappings(expression, nil)` and `preprocessInOperator(ir.Modified)` at the start of the function, with `ir.Declarations` injected into the generated contract for mapping-based `in()` calls.

**Verification:**
- `go run ./cmd/validate-rules/ rules/*.yaml rules/templates/*.yaml` → **31 passed, 0 failed** ✅
- `go run ./cmd/validate-rules/ -config config.e2e.yaml` → **20 passed, 0 failed** ✅
- All unit tests pass ✅
- All e2e tests pass ✅

**Impact:** Without this fix, `polymarket_safe.template.yaml` and `opinion_safe.template.yaml` cannot be validated standalone, breaking the CI gate requirement. The `-config` path was unaffected because it uses the execution code path which already preprocesses `in()`.

---

### Required fixes (summary)

1. **config.e2e.yaml must pass validate-rules:**  
   - Add at least 2 test cases (1 positive, 1 negative) to “E2E Delegate Single” and “E2E Delegate Target” evm_js rules.  
   - Fix or relax expanded template test cases so they pass in the config.e2e.yaml context (e.g. rule order so blocklist does not mask JS negative cases; or adjust expect_reason / expect_pass for combined blocklist+whitelist behavior).

2. **Program must start with config.e2e.yaml:**  
   - Same as above: after config passes validate-rules, startup validation will pass and the process will reach password/listening.

3. **Stabilize TestRulesDirectoryValidation** when run with rest of suite and coverage (e.g. isolate temp dirs / Forge cache, or skip under race/cover if needed).

4. **Coverage:** Raise overall to ≥85% and core/rules to ≥95% (see §1 below).

---

## 1. Test Coverage

### 1.1 Current State

| Requirement | Target | Actual | Status |
|-------------|--------|--------|--------|
| **Overall** | ≥ 85% | **~33.9%** (total from `go tool cover -func`) | ❌ **FAIL** |
| **Core / rules** | ≥ 95% | **internal/chain/evm: 51.9%**, **internal/core/rule: 32.6%** | ❌ **FAIL** |

**Package-level coverage (relevant):**

| Package | Coverage | Note |
|---------|----------|------|
| `internal/chain/evm` | 51.9% | Core rule evaluators (JS, Solidity, address, value, contract_method, message_pattern); many evaluators 0% |
| `internal/core/rule` | 32.6% | Engine, whitelist, delegation, budget |
| `internal/ruleconfig` | 66.1% | `validateSignerRestrictionConfig`, `validateSolidityExpressionConfig`, `ValidateJSRuleTestCasesRequirement` at 0% |
| `internal/validate` | **0%** | No `*_test.go` in package; used by sign handler, ruleconfig, API |
| `internal/config` | 33.0% | Template/rule init, expand; sync paths untested |
| `internal/api/handler/evm` | 0% | Sign, rule, approval handlers not unit-tested |
| `cmd/validate-rules` | 0% | CLI logic untested (only `main_test.go` uses validators) |
| `cmd/remote-signer` | 0% | Main startup/validation untested |

### 1.2 Recommendations

- Add **`internal/validate/validate_test.go`** and reach ≥ 95% for `IsValidEthereumAddress`, `IsValidWeiDecimal`, `NormalizeRuleType`, `ValidateRuleMode`, `ValidSignTypes`, `IsValidChainType`, etc.
- Raise **`internal/ruleconfig`** to ≥ 95%: cover `validateSignerRestrictionConfig`, `validateSolidityExpressionConfig`, `ValidateJSRuleTestCasesRequirement`, and unknown rule type.
- Raise **`internal/chain/evm`** (core) to ≥ 95%: add tests for `rule_evaluator.go` (address, contract_method, value_limit, signer_restriction, sign_type_restriction), `js_evaluator.go` (delegation, edge cases), `adapter.ValidatePayload`, `ValidateBasicRequest` (already 80.6%), and `js_validator` / `message_pattern_validator`.
- Add unit tests for **`internal/api/handler/evm`** (sign, rule create/update, approval) and **`internal/core/rule`** (engine Evaluate, EvaluateWithResult, delegation).
- Add integration or unit tests for **`cmd/remote-signer`** startup (e.g. validateSolidityRules path) and **`cmd/validate-rules`** run path so critical validation paths are covered.

---

## 2. Input Validation

### 2.1 Sign Request (`/api/v1/evm/sign`)

- **Handler** (`internal/api/handler/evm/sign.go`): Validates `chain_id` (required, decimal), `signer_address` (required, `validate.IsValidEthereumAddress`), `sign_type` (required, `validate.ValidSignTypes`), `payload` (required, max 2 MB). ✅
- **Service** (`internal/core/service/sign.go`): Calls `adapter.ValidateBasicRequest()` (format + size). ✅
- **Adapter** (`internal/chain/evm/adapter.go`): `ValidateBasicRequest` checks same fields and payload JSON shape per `sign_type`; `ValidatePayload` enforces EVM-specific format (hash length, typed_data, transaction fields). ✅

No critical gaps at sign entry; validation is layered (handler → service → adapter).

### 2.2 Rule API (Create / Update)

- **CreateRule** (`internal/api/handler/evm/rule.go`): Validates `name`, `type`, `mode` (whitelist/blocklist); calls `ruleconfig.ValidateRuleConfig(req.Type, req.Config)`. ✅
- **Gaps:**
  - **`req.Type`**: Not checked against `validate.ValidRuleTypes` before use; unknown type is only rejected inside `ValidateRuleConfig`. Acceptable but could explicitly reject earlier.
  - **`req.ChainType`**: If present, stored as-is **without** `validate.IsValidChainType()`. Invalid `chain_type` (e.g. `"invalid"`) can be persisted. ❌ **Recommendation:** Validate optional `chain_type` with `validate.IsValidChainType` when non-nil.
  - **`req.SignerAddress`**: If present, not validated as Ethereum address. ❌ **Recommendation:** When provided, validate with `validate.IsValidEthereumAddress`.
  - **`req.ChainID`**: No format check (e.g. decimal string). Optional; consider validating if present.

### 2.3 Template API

- Create/update template: `validate.ValidateRuleMode(req.Mode)` used. Variables and config validated via ruleconfig when instantiating. ✅

### 2.4 Approval / Rejection

- `validate.ValidateRuleMode(req.RuleMode)` used. ✅

### 2.5 Auth Middleware

- Body size capped (e.g. 10 MB in auth middleware); header length checks mentioned. ✅

### 2.6 Summary

- Sign and template/approval entry points are well validated.
- **Fix:** Validate optional `chain_type` and `signer_address` on rule create/update.

---

## 3. E2E Coverage of Rules and Templates

### 3.1 Requirement

> e2e必须覆盖rules下面所有的模板和规则文件

### 3.2 Files Under `rules/`

| File | In config.e2e.yaml / e2e? | E2E coverage |
|------|----------------------------|--------------|
| `rules/security.example.yaml` | No | ❌ Not loaded in e2e |
| `rules/treasury.example.yaml` | No | ❌ Not loaded in e2e |
| `rules/templates/erc20.template.js.yaml` | Yes (template) | ✅ Loaded |
| `rules/templates/erc721.template.js.yaml` | Yes (template) | ✅ Loaded |
| `rules/templates/multisend.template.js.yaml` | Yes (template) | ✅ Loaded |
| `rules/templates/opinion_safe.template.yaml` | No | ❌ Not loaded in e2e |
| `rules/templates/polymarket_safe.template.yaml` | No | ❌ Not loaded in e2e |
| `rules/templates/polymarket_safe.template.js.yaml` | Yes (template) | ✅ Loaded |
| `rules/templates/predict_eoa.template.yaml` | No | ❌ Not loaded in e2e |
| `rules/templates/safe.template.js.yaml` | Yes (template) | ✅ Loaded |

E2E uses **config.e2e.yaml**, which references only **5 templates** (safe, multisend, erc20, erc721, polymarket_safe.template.js) plus `e2e/fixtures/minimal_template.yaml`. It does **not** load:

- `rules/security.example.yaml`
- `rules/treasury.example.yaml`
- `rules/templates/opinion_safe.template.yaml`
- `rules/templates/polymarket_safe.template.yaml`
- `rules/templates/predict_eoa.template.yaml`

There is **no** e2e test that runs **validate-rules** (or equivalent) over **all** files under `rules/` and `rules/templates/`.

### 3.3 Recommendations

- Add an **e2e test** (or CI step) that:
  - Runs **validate-rules** for every YAML under `rules/` and `rules/templates/` (e.g. `validate-rules rules/*.yaml rules/templates/*.yaml`), or
  - Uses **validate-rules -config** with a config that includes all these files, and asserts exit code 0.
- Alternatively (or in addition): add e2e tests that load each missing file (e.g. via config or API) and perform at least one sign or rule-evaluation scenario per file so that “all templates and rule files” are covered by e2e.

---

## 4. Production vs validate-rules Validation Parity

### 4.1 Requirement

> 生产环境和validate-rules工具对规则的验证必须完全一致，验证必须完全闭环

### 4.2 Current Behavior

- **Config load (production)**  
  `internal/config/rule_init.go` → `syncRule()`:
  - Calls `ruleconfig.ValidateRuleConfig(ruleCfg.Type, ruleCfg.Config)` for non-file rules. ✅ Same as validate-rules for config shape.

- **Production startup** (`cmd/remote-signer/main.go`):
  - Only **Solidity expression rules** are validated at startup: `validateSolidityRules()` → `validator.ValidateRulesBatch(ctx, rules)`. ✅
  - **evm_js** rules are **not** validated at startup (no test-case run, no engine run). ❌

- **validate-rules** (`cmd/validate-rules/main.go`):
  - For **evm_js**: builds rule engine, runs each rule’s test cases through **ruleEngine.EvaluateWithResult()** (same as production evaluation path). ✅
  - For **evm_solidity_expression**: uses **SolidityRuleValidator.ValidateRulesBatch()**. ✅ Same as production.
  - For declarative types: **ruleconfig.ValidateRuleConfig** only. ✅

So:

- **Config validation:** Production (rule_init) and validate-rules both use `ruleconfig.ValidateRuleConfig` for rule config. ✅
- **Solidity:** Production startup and validate-rules both use `ValidateRulesBatch`. ✅
- **evm_js:** validate-rules runs test cases through the engine; production does **not** run evm_js test cases at startup. ❌ **Gap:** A broken or malicious evm_js rule can pass config load and start in production; only validate-rules would catch test-case failures.

### 4.3 Recommendations

- **Option A (recommended):** At server startup, after loading config and rules, run **the same evm_js validation** as validate-rules: for each loaded evm_js rule with `test_cases`, run them through the same rule engine and fail startup if any test case fails. Reuse the same code path as validate-rules (e.g. shared function that takes rule engine + rules and runs test cases).
- **Option B:** Document that evm_js rules are only validated by running `validate-rules -config config.yaml` before deploy; add CI that runs it and fails the build if validation fails. This keeps startup fast but ensures parity is enforced in CI rather than in process.

Either way, ensure a single implementation (used by both validate-rules and, if chosen, production startup) so validation is **fully closed-loop** and identical.

---

## 5. Each Rule: At Least One Positive and One Negative Test

### 5.1 Requirement

> 每个规则至少1个正向测试1个反向测试

### 5.2 Enforcement

- **evm_js:** validate-rules enforces “at least 2 test cases” and **ruleconfig.ValidateJSRuleTestCasesRequirement(pos, neg)** requires at least one positive and one negative. ✅
- **evm_solidity_expression:** Test cases are run by Solidity validator; there is no explicit check in code that each rule has ≥1 positive and ≥1 negative. The YAML files under `rules/` that use `test_cases` (e.g. `security.example.yaml`) do include both pass and fail cases. **Recommendation:** Add the same requirement for Solidity rules (e.g. in `validateSolidityRules` or in the validator) and document it.

### 5.3 Declarative Rules

- **evm_address_list**, **evm_value_limit**, **sign_type_restriction**, **signer_restriction**, **evm_contract_method**, **chain_restriction**, **message_pattern** (when without test_cases): No test_cases in YAML; validation is “config shape only”. The requirement “每个规则至少1个正向测试1个反向测试” is interpreted as applying to **rule types that support test_cases** (evm_js, evm_solidity_expression). For those, enforce 1+1; for declarative-only types, N/A.

### 5.4 Template / Example Files

- Reviewed YAMLs: evm_js and solidity rules that have `test_cases` contain both `expect_pass: true` and `expect_pass: false`. ✅

---

## 6. Summary Table

| # | Requirement | Status | Action |
|---|-------------|--------|--------|
| 1 | Overall coverage ≥ 85% | ❌ ~34% | Add tests (validate, ruleconfig, chain/evm, core/rule, api/handler/evm, cmd) |
| 2 | Core/rules coverage ≥ 95% | ❌ ~52% / ~33% | Target internal/chain/evm, internal/core/rule, internal/ruleconfig |
| 3 | Strict input validation | ⚠️ | Add chain_type + signer_address validation on rule create/update |
| 4 | E2E covers all rules/ and templates | ❌ | E2e or CI: validate-rules over all rules/*.yaml and rules/templates/*.yaml |
| 5 | Production = validate-rules validation | ⚠️ | evm_js: add startup validation or enforce validate-rules in CI |
| 6 | Each rule 1 positive + 1 negative test | ✅ evm_js; ⚠️ solidity | Enforce 1+1 for solidity in code or CI; keep evm_js as is |

---

## 7. Suggested Priority

1. **High:** Add evm_js validation at startup (or enforce validate-rules in CI) so production and validate-rules are aligned.
2. **High:** E2e/CI: run validate-rules on all `rules/*.yaml` and `rules/templates/*.yaml`.
3. **High:** Validate optional `chain_type` and `signer_address` on rule create/update.
4. **Medium:** Add `internal/validate` tests and reach ≥ 95% for ruleconfig and core rule/chain packages.
5. **Medium:** Add unit tests for API handlers (evm sign, rule, approval) and increase overall coverage toward 85%.

This report can be updated as items are implemented and re-measured.

---

## 8. Implementation Status (post-review, round 1)

| # | Item | Status | Notes |
|---|------|--------|------|
| 3 | Validate optional `chain_type` and `signer_address` on rule create/update | ✅ Done | **Create:** already validated. **Update:** `UpdateRuleRequest` now includes `chain_type`, `chain_id`, `api_key_id`, `signer_address`; all validated with `validate.IsValidChainType` / `validate.IsValidEthereumAddress` when provided (`internal/api/handler/evm/rule.go`). |
| 4 | E2E: validate-rules over all rules/ and rules/templates/ | ✅ Done | **e2e/e2e_validate_rules_test.go:** `TestValidateRules_AllRulesAndTemplates` runs `go run ./cmd/validate-rules/` on every `rules/*.yaml` and `rules/templates/*.yaml` and asserts exit code 0. |
| 5 | Production = validate-rules validation (evm_js at startup) | ✅ Done | **cmd/remote-signer/main.go:** After `validateSolidityRules`, calls `validateEVMJSRulesAtStartup(ctx, expandedRules, ruleRepo, solidityEval, log)`. Builds same engine as production, runs each evm_js rule’s test cases from expanded config (1+1 enforced via `ruleconfig.ValidateJSRuleTestCasesRequirement`). **internal/config:** `EffectiveRuleID(idx, ruleCfg)` exported for startup validation. |
| 6 | Solidity: 1 positive + 1 negative test per rule | ✅ Already enforced | **internal/chain/evm/solidity_validator.go** (lines 202–227): `ValidateRulesBatch` requires ≥2 test cases and at least one `expect_pass: true` and one `expect_pass: false` per rule before running batch. |
| 7 | message_pattern validated at startup | ✅ Done | **cmd/remote-signer/main.go:** `validateMessagePatternRulesAtStartup(ctx, ruleRepo, log)` runs after evm_js validation; uses same `MessagePatternRuleValidator.ValidateRule` as validate-rules. |

---

## 9. Implementation Status (post-review, round 2 — 2026-02-27)

| # | Item | Status | Notes |
|---|------|--------|------|
| BUG-1 | `validate-rules -config config.e2e.yaml` fails | ✅ Fixed (round 1) | All 20 expanded rules pass. |
| BUG-2 | Program does not reach password/listening with config.e2e.yaml | ✅ Fixed (round 1+2) | Startup now passes all validation (Solidity, evm_js, message_pattern) and reaches listening state. Verified: process runs until externally killed (exit code 124 from timeout, not internal error). |
| BUG-3 | TestRulesDirectoryValidation flake under coverage | ✅ No longer observed | All unit tests pass reliably (0 failures in full `go test ./...`). |
| BUG-4 | **NEW** — `polymarket_safe.template.yaml` fails `validate-rules` standalone | ✅ Fixed | `GenerateTypedDataExpressionSyntaxCheckScriptWithStruct` did not preprocess `in()` operators. Added `processInOperatorToMappings` + `preprocessInOperator` calls at the start of the function. Now all 31 rule/template files pass `validate-rules`. |
| - | validate-rules on all rules/*.yaml + templates/*.yaml | ✅ Passing | `go run ./cmd/validate-rules/ rules/*.yaml rules/templates/*.yaml` → 31 passed, 0 failed. |
| - | validate-rules -config config.e2e.yaml | ✅ Passing | 20 passed, 0 failed. |
| - | Program startup with config.e2e.yaml | ✅ Passing | Server starts successfully, reaches listening state. |
| - | E2E tests | ✅ All passing | `go test -tags=e2e ./e2e/...` → PASS (29.2s). |
| - | Unit tests | ✅ All passing | `go test ./...` → all packages pass. |

---

## 10. Security Audit Findings (round 2 — 2026-02-27)

### 10.1 BUG-4 (FIXED): TypedDataExpression syntax check missing `in()` preprocessing

**Severity:** HIGH (blocks template validation; broken CI gate)
**File:** `internal/chain/evm/solidity_evaluator.go` — `GenerateTypedDataExpressionSyntaxCheckScriptWithStruct()`
**Root cause:** The function embeds raw typed_data_expression code into a Solidity contract for syntax checking, but did not run `processInOperatorToMappings()` or `preprocessInOperator()` first. When templates use `in(eip712_domainContract, ${allowed_safe_addresses})`, after variable substitution the expression contains `in(expr, 0xAddr)` which is not valid Solidity.
**Impact:** `polymarket_safe.template.yaml` and `opinion_safe.template.yaml` failed standalone validation. Config-path validation was unaffected because it uses the execution path (which already preprocesses `in()`).
**Fix:** Added `processInOperatorToMappings(expression, nil)` + `preprocessInOperator(ir.Modified)` at the top of the function, and added `ir.Declarations` to the generated contract (mapping declarations for variable-based `in()`).

### 10.2 Confirmed Security Properties (Positive Findings)

| Property | Status | Evidence |
|----------|--------|----------|
| Blocklist Fail-Closed | ✅ Correct | `whitelist.go` lines 219-252: blocklist evaluation errors and missing evaluators return `RuleEvaluationError` (immediate rejection). |
| Whitelist Fail-Open (by design) | ✅ Correct | `whitelist.go` lines 277-281: whitelist evaluation errors skip to next rule. This is intentional — one broken whitelist rule shouldn't block all requests. |
| JS type assertion fail-closed | ✅ Safe | `js_evaluator.go` line 334: `valid, _ := obj["valid"].(bool)` — if script returns wrong type, `valid=false`. For whitelist: no match (safe). For blocklist: violation detected → block (safe). Both directions are fail-closed. |
| Startup rule validation parity | ✅ Correct | Production startup validates Solidity, evm_js, and message_pattern rules using the same code paths as `validate-rules`. |
| Dangerous Foundry cheatcode blocking | ✅ Correct | `solidity_validator.go` lines 23-59: Static analysis blocks `vm.ffi`, `vm.readFile`, `vm.writeFile`, etc. Runtime env vars `FOUNDRY_FFI=false`, `FOUNDRY_FS_PERMISSIONS=[]` provide defense-in-depth. |
| Input validation layered | ✅ Correct | Sign requests validated at handler → service → adapter layers. Address, chain_id, sign_type, payload size/format all checked. |

### 10.3 Remaining Observations (LOW/ACCEPTED)

| # | Finding | Severity | Status | Notes |
|---|---------|----------|--------|-------|
| 1 | `IncrementMatchCount` uses `context.Background()` in goroutine | LOW | ACCEPTED | Match count is statistical only; losing counts on shutdown is acceptable. Adding timeout would add complexity for non-critical stats. |
| 2 | Delegation target `repo.Get()` conflates "not found" and "DB error" | LOW | ACCEPTED | Both cases result in delegation failure (request not allowed) — fail-closed behavior. Separating would improve logging but security posture is already correct. |
| 3 | `ManualApprovalGuard.recordRejection()` unlocks before `sendPauseAlert()` | LOW | ACCEPTED | The alert is informational only. The `paused` flag is already set under lock. Racing with `Resume()` at most causes a stale alert — not a security bypass. |
| 4 | `AppliesToSignType` returns `true` on JSON unmarshal error | LOW | ACCEPTED | Conservative behavior — applies rule to all sign types if config is malformed. Better to over-apply than under-apply. |

---

## 11. Funds safety (百万 USDT 托管)

- **Startup validation:** All Solidity, evm_js, and message_pattern rules are validated at startup; any failure prevents process start. Reduces risk of deploying broken or malicious rules.
- **Blocklist-first:** Rule engine evaluates blocklist rules before whitelist; a single blocklist match blocks the request (fail-closed).
- **Input validation:** Sign and rule APIs validate format and scope (address, chain_id, sign_type, payload size, rule config shape).
- **Config gate:** ✅ `config.e2e.yaml` now passes both `validate-rules -config` and actual startup. For production, run `validate-rules -config <production-config>` and start the binary in staging to confirm it reaches listening state before deploying.
- **Template validation:** ✅ All 31 rules/templates under `rules/` pass standalone `validate-rules` validation. The `in()` preprocessing bug (BUG-4) is fixed.
- **Test coverage:** Overall ~33.2% (target ≥85%), core/rules ~52%/33% (target ≥95%). Coverage improvement is the main remaining gap.
