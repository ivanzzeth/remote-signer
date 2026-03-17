# Rule Ownership, Scoping & API Key Roles Design

**Status:** Draft (Security Audited)
**Version:** 1.0.0 (breaking change — no v0.x backward compatibility)
**Author:** Ivan + Claude
**Date:** 2026-03-17

## 1. Problem

Current rule system has no concept of ownership or scoping:
- All rules apply globally to all API keys
- Only admin can create/modify/delete rules
- No fine-grained API key roles (only admin vs non-admin)
- A single malicious or misconfigured rule affects all signers
- Agents cannot self-manage rules for autonomous operation
- Automated strategies have unnecessary read access to sensitive config

## 2. API Key Roles

Four roles, from highest to lowest privilege:

| Role | Purpose | Example Use Case |
|------|---------|------------------|
| **admin** | Full control, human operator | DevOps managing the service |
| **dev** | High privilege minus fatal ops | Developer testing/debugging |
| **agent** | Autonomous AI, read + propose rules | Trading bot, dApp automator |
| **strategy** | Pure execution, minimal surface | Arbitrage script, cron job |

### 2.1 Role Design Rationale

- **admin**: The human who deploys and maintains the service. Can do anything. Only role that can approve agent-proposed rules, manage API keys, and set rules affecting other keys.

- **dev**: A developer or CI pipeline that needs broad access for testing. Can sign, read rules/budgets, and create rules that apply to themselves. Excluded from fatal operations (e.g. deleting other keys' rules, revoking all signers). Practically: admin minus the ability to affect other API keys' rules and minus API key management. **Note**: dev can see ALL rules (including other agents' rules) — this is intentional for debugging. Dev role is for development/staging only; production environments should not have dev API keys.

- **agent**: An AI agent (Claude, GPT, custom bot) that operates autonomously. Can sign, read rules/templates/presets/budgets (to understand its constraints and adapt behavior), and create **declarative** rules (no JS code — see SA-1). Cannot see config secrets, other agents' rules, or modify rules it doesn't own.

- **strategy**: A headless script (trading strategy, keeper, liquidator) deployed by a developer who already configured the rules at setup time. Has zero runtime introspection — can only sign, check its own request status, and read its own signers. This is intentional: if a strategy script is compromised (stolen API key, prompt injection), the attacker gains nothing beyond signing (which is already bounded by pre-configured rules and budgets). No rule/template/budget read access means no reconnaissance.

### 2.2 Permission Matrix

| Endpoint | admin | dev | agent | strategy |
|----------|-------|-----|-------|----------|
| **Signing** |
| POST /evm/sign | ✅ | ✅ | ✅ | ✅ |
| **Request Management** |
| GET /evm/requests (own) | ✅ | ✅ | ✅ | ✅ |
| GET /evm/requests (all) | ✅ | ✅ | ❌ | ❌ |
| POST /evm/requests/:id/approve | ✅ | ❌ | ❌ | ❌ |
| **Rules** |
| GET /evm/rules (all) | ✅ | ✅ | own + applied_to=self | ❌ |
| GET /evm/rules/:id | ✅ | ✅ | own + applied_to=self | ❌ |
| POST /evm/rules (applied_to=self, declarative only) | ✅ | ✅ | ✅ (may need approval) | ❌ |
| POST /evm/rules (applied_to=*) | ✅ | ❌ | ❌ | ❌ |
| POST /evm/rules (evm_js type) | ✅ | ✅ | ❌ | ❌ |
| PUT /evm/rules/:id (own) | ✅ | ✅ | ✅ (declarative only) | ❌ |
| PUT /evm/rules/:id (other's) | ✅ | ❌ | ❌ | ❌ |
| DELETE /evm/rules/:id (own) | ✅ | ✅ | ✅ | ❌ |
| DELETE /evm/rules/:id (other's) | ✅ | ❌ | ❌ | ❌ |
| POST /evm/rules/:id/approve | ✅ | ❌ | ❌ | ❌ |
| POST /evm/rules/:id/reject | ✅ | ❌ | ❌ | ❌ |
| **Budgets** |
| GET /evm/rules/:id/budgets | ✅ | ✅ | own rules only | ❌ |
| **Templates** |
| GET /templates | ✅ | ✅ | ✅ (read-only) | ❌ |
| POST /templates (instantiate) | ✅ | ✅ | ❌ | ❌ |
| **Presets** |
| GET /presets | ✅ | ✅ | ✅ (read-only) | ❌ |
| POST /presets/:id/apply | ✅ | ❌ | ❌ | ❌ |
| **Signers** |
| GET /evm/signers | ✅ | own signers | own signers | own signers (read-only) |
| POST /evm/signers (create) | ✅ | ❌ | ❌ | ❌ |
| POST /evm/signers/:addr/unlock | ✅ | ❌ | ❌ | ❌ |
| **HD Wallets** |
| GET /evm/hdwallets | ✅ | own wallets | own wallets | ❌ |
| POST /evm/hdwallets (create/import) | ✅ | ❌ | ❌ | ❌ |
| **API Keys** |
| GET /api-keys | ✅ | ❌ | ❌ | ❌ |
| POST /api-keys | ✅ | ❌ | ❌ | ❌ |
| DELETE /api-keys | ✅ | ❌ | ❌ | ❌ |
| **Audit** |
| GET /audit (all) | ✅ | ✅ | own events | ❌ |
| **System** |
| GET /health | ✅ | ✅ | ✅ | ✅ |
| GET /metrics | ✅ | ✅ | ❌ | ❌ |

### 2.3 Data Model

```go
type APIKeyRole string

const (
    RoleAdmin    APIKeyRole = "admin"
    RoleDev      APIKeyRole = "dev"
    RoleAgent    APIKeyRole = "agent"
    RoleStrategy APIKeyRole = "strategy"
)

type APIKey struct {
    ID              string     `json:"id"`
    Name            string     `json:"name"`
    Role            APIKeyRole `json:"role"`
    PublicKey       string     `json:"public_key"`
    Enabled         bool       `json:"enabled"`
    RateLimit       int        `json:"rate_limit"`
    AllowAllSigners bool       `json:"allow_all_signers"`
    AllowedSigners  []string   `json:"allowed_signers"`
}
```

Config:
```yaml
api_keys:
  - id: "admin"
    name: "Admin"
    role: admin
    public_key_file: ./data/admin_public.pem
    enabled: true

  - id: "trading-agent"
    name: "Trading Agent"
    role: agent
    public_key: "..."
    enabled: true
    rate_limit: 300
    allowed_signers:
      - "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

  - id: "arb-strategy"
    name: "Arbitrage Strategy"
    role: strategy
    public_key: "..."
    enabled: true
    rate_limit: 100
    allowed_signers:
      - "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
```

---

## 3. Rule Ownership & Scoping

### 3.1 New Fields on Rule

```go
type Rule struct {
    // ... existing fields ...

    // Owner is the API key ID that created this rule.
    // "config" for rules from config file / preset CLI (admin-owned, immutable via API).
    Owner string `json:"owner" gorm:"type:varchar(64);not null;default:'config';index"`

    // AppliedTo controls which API keys this rule affects at runtime.
    // Stored as PostgreSQL text array for safe multi-value support (no comma injection).
    // ["*"] = all keys (admin only), ["self"] = owner only (default for non-admin),
    // ["key-1", "key-2"] = specific keys (admin only, validated for existence at creation).
    AppliedTo pq.StringArray `json:"applied_to" gorm:"type:text[];not null"`

    // Status: "active", "pending_approval", "rejected", "revoked"
    Status RuleStatus `json:"status" gorm:"type:varchar(32);not null;default:'active';index"`

    // ApprovedBy: admin key ID that approved a pending rule.
    ApprovedBy *string `json:"approved_by,omitempty" gorm:"type:varchar(64)"`
}
```

### 3.2 Rule Resolution at Runtime

When evaluating a sign request from API key `K`:

```
Applicable rules = rules WHERE:
  status = "active"
  AND (
    "*" = ANY(applied_to)
    OR K = ANY(applied_to)
    OR ("self" = ANY(applied_to) AND owner = K)
  )
  AND (chain_type/chain_id/signer_address scope matches request)
```

> **Implementation note**: The evaluation order described below is a *semantic guarantee*, not a code structure requirement. The existing two-phase engine (blocklist → whitelist) naturally satisfies this ordering as long as the rule filter (above) correctly scopes which rules are evaluated. No engine restructuring needed.

### 3.3 Evaluation Order (Semantic Guarantee)

```
1. Blocklist rules (applied_to contains K or "*")  → reject if match
   - Admin blocklist (owner=admin/config) evaluated alongside caller's own blocklist
   - Any blocklist match → reject, regardless of whitelist rules
2. Whitelist rules (applied_to contains K or "*")   → allow if first match
3. No match                                         → reject (fail-closed)
```

**Invariant**: Admin blocklist ALWAYS wins. An agent cannot create a whitelist that overrides an admin blocklist. This is the fundamental security guarantee.

**Note on agent self-created blocklist**: Agent-created blocklist rules (owner=agent, applied_to=self) are advisory — the agent can delete them at any time. Only admin/config-created blocklist rules are authoritative. If a blocklist is security-critical, admin must create it (applied_to includes the agent's key or "*").

### 3.4 Agent Rule Creation Rules

When agent creates a rule via API:
- `owner` = auto-set to agent's API key ID (cannot override, server-enforced)
- `applied_to` = forced to `["self"]` (cannot set `["*"]` or other keys, server-enforced)
- `status`:
  - If `require_approval_for_agent_rules: false` (default): `"active"` immediately
  - If `require_approval_for_agent_rules: true`: `"pending_approval"`
- **Allowed rule types** (declarative only):
  - `evm_address_list` — whitelist/blocklist specific contract addresses
  - `evm_contract_method` — whitelist/blocklist specific method selectors
  - `evm_value_limit` — cap transaction value
  - `sign_type_restriction` — restrict sign types (personal, typed_data, etc.)
  - `message_pattern` — restrict personal_sign message patterns
- **Blocked rule types** (require admin/dev):
  - `evm_js` — arbitrary JS code execution risk (SA-1: even in sandbox, agent could write `validate() { return ok() }` to bypass all checks)
  - `signer_restriction` — could affect signer assignment
  - `evm_solidity_expression` — arbitrary expression execution

### 3.5 Config-Sourced Rules (config.yaml only)

Rules from config.yaml are **global security rules only**:
- `owner = "config"` (treated as admin-owned)
- `applied_to = ["*"]` (global — applies to ALL API keys)
- `status = "active"`
- Read-only via API (when `rules_api_readonly: true`)

**Design Decision (2026-03-17):** Config rules are exclusively for global security policies
(e.g. `evm_dynamic_blocklist`, OFAC sanctions). Scoped rules (agent presets, per-key budgets)
MUST be created via API after server starts, so RBAC properly assigns `owner` and `applied_to`:
- Agent preset → created via `POST /evm/rules` with agent API key → `owner=agent, applied_to=["self"]`
- Admin rules for specific keys → created via API → `applied_to=["key-1", "key-2"]`

**Rationale:** Putting scoped rules in config bypasses RBAC (hardcoded `owner="config", applied_to=["*"]`),
which means agent budget rules would incorrectly constrain admin/dev/strategy signing.
The CLI (`remote-signer-cli`) must support full CRUD (matching `pkg/client` SDK) so setup.sh
can create scoped rules after server startup.

### 3.6 Setup Flow for Scoped Rules

```
setup.sh:
  1. Generate config.yaml (global rules only: dynamic_blocklist, etc.)
  2. Start server (Docker or local)
  3. Wait for health check
  4. CLI: create agent preset rules via API (owner=agent, applied_to=["self"])
     remote-signer-cli preset apply agent.preset.js.yaml \
       --api-key-id agent --api-key-file data/agent_private.pem \
       --url https://localhost:8548 [--tls-*]
```

This ensures agent rules go through the standard API path with proper RBAC enforcement.

---

## 4. Security Considerations

### 4.1 Privilege Escalation Prevention

**Attack**: Agent creates whitelist bypassing admin blocklist.
**Defense**: Blocklist evaluation always runs first; admin blocklist (applied_to=*) matches all callers.

**Attack**: Agent creates rule with `applied_to = ["*"]`.
**Defense**: API enforces `applied_to = ["self"]` for non-admin roles. Server-side enforcement, not client-side.

**Attack**: Agent creates `signer_restriction` rule to access unauthorized signers.
**Defense**: `signer_restriction` type blocked for agent/dev/strategy roles.

**Attack**: Agent creates `evm_js` rule with `validate() { return ok() }` to bypass all checks.
**Defense**: `evm_js` type blocked for agent role. Only admin and dev can create JS rules. (SA-1)

### 4.2 Reconnaissance Prevention (Strategy)

**Attack**: Compromised strategy key reads rules to understand system config.
**Defense**: Strategy role has zero read access to rules/templates/presets/budgets. Can only read own signers.

### 4.3 Rule Bomb Prevention

**Attack**: Agent creates thousands of rules to degrade performance.
**Defense**: Per-API-key rule count limit. Rule CRUD operations are also subject to the existing per-key rate limit. (SA-7)

```yaml
security:
  max_rules_per_api_key: 50
  require_approval_for_agent_rules: false
```

### 4.4 Budget Isolation

- Each agent's self-created rules have independent budget records
- Admin-scoped rules (`applied_to = ["*"]`) share budget across all keys
- Agent cannot see or affect another agent's budget

### 4.5 Audit Completeness

Every rule lifecycle event is logged with full before/after diff for modifications (SA-5):
- `rule_created` — actor, owner, applied_to, status, full config
- `rule_updated` — actor, `old_config` JSON, `new_config` JSON (complete diff)
- `rule_deleted` — actor, deleted rule snapshot
- `rule_approved` — admin actor, original owner, applied_to changes (if widened)
- `rule_rejected` — admin actor, original owner, reason

### 4.6 Input Validation

- `applied_to` is stored as PostgreSQL text array (`pq.StringArray`), not comma-separated string. No injection risk. (SA-2)
- When admin creates a rule with `applied_to = ["key-1", "key-2"]`, each key ID is validated for existence at creation time. Non-existent key IDs are rejected with 400. (SA-6)
- Key IDs are validated against `^[a-zA-Z0-9_-]{1,64}$` regex — no special characters allowed.

### 4.7 Immutable Rules

Admin can mark a rule as `immutable: true`. Immutable rules cannot be modified or deleted via API — they can only be changed by editing config.yaml and restarting the service. This is useful for security-critical blocklist rules. (SA-12)

```go
type Rule struct {
    // ...
    Immutable bool `json:"immutable" gorm:"default:false"`
}
```

---

## 5. API Changes

### 5.1 Create Rule (agent — declarative types only)

```
POST /api/v1/evm/rules
X-API-Key-ID: trading-agent

{
  "name": "Allow Uniswap V3 Router",
  "type": "evm_address_list",
  "mode": "whitelist",
  "config": { "addresses": ["0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"] }
}
```

Response:
```json
{
  "id": "rule_abc123",
  "owner": "trading-agent",
  "applied_to": ["self"],
  "status": "active",
  ...
}
```

### 5.2 Approve/Reject (admin)

```
POST /api/v1/evm/rules/:id/approve
POST /api/v1/evm/rules/:id/reject  { "reason": "..." }
```

### 5.3 List Rules (scoped by role)

```
GET /api/v1/evm/rules                    # admin/dev: all; agent: own + applied to self
GET /api/v1/evm/rules?owner=self         # agent: only own rules
GET /api/v1/evm/rules?status=pending     # admin: pending approvals
```

---

## 6. Code Impact Analysis

### 6.1 Reuse (no change or trivial)

| File | Reason |
|------|--------|
| `middleware/auth.go` | Ed25519 auth unchanged; just reads APIKey from context |
| `middleware/ratelimit.go` | Already covers all routes including rule CRUD |
| `middleware/ipwhitelist.go` | Unchanged |
| `middleware/security_headers.go` | Unchanged |
| `middleware/security_alert.go` | Unchanged |
| `middleware/content_type.go` | Unchanged |
| `middleware/logging.go` | Unchanged |
| `internal/core/rule/whitelist.go` (core evaluation) | Two-phase engine (blocklist → whitelist) unchanged; add pre-filter only |
| `internal/core/service/sign.go` | Sign flow unchanged |
| `internal/core/service/approval.go` | Sign request approval unchanged; rule approval reuses same pattern |
| `internal/core/service/approval_guard.go` | Unchanged |
| `internal/audit/logger.go` (framework) | Reuse audit framework; add new event types + diff |

### 6.2 Delete & Rewrite

| File | Action |
|------|--------|
| `middleware/admin.go` | **DELETE** — replaced by rbac.go |
| `middleware/agent.go` | **DELETE** — replaced by rbac.go |
| **NEW** `middleware/rbac.go` | Static permission matrix, `RequirePermission(perm)` middleware |
| `internal/core/types/auth.go` | **REWRITE** APIKey struct: `Admin bool` + `Agent bool` → `Role APIKeyRole` |
| `internal/config/config.go` (APIKeyConfig) | **REWRITE** `Admin bool` + `Agent bool` → `Role string` |
| `internal/config/apikey_init.go` | **REWRITE** all `.Admin` / `.Agent` → `.Role` |
| `internal/api/handler/apikey.go` | **REWRITE** request/response structs: Admin/Agent bools → Role |
| `internal/api/router.go` | **REWRITE** `withAuthAndAdmin()` / `withAuthAndAgentOrAdmin()` → `withAuth(rbac.Require(Perm))` |

### 6.3 Extend (medium changes)

| File | Changes |
|------|---------|
| `internal/core/types/rule.go` | Add `Owner`, `AppliedTo pq.StringArray`, `Status`, `ApprovedBy`, `Immutable`; delete `APIKeyID` |
| `internal/api/handler/evm/rule.go` | Owner/applied_to enforcement on CRUD; type restriction for agent; approve/reject endpoints |
| `internal/api/handler/evm/signer.go` | Delete ~5 `apiKey.Admin`/`apiKey.Agent` checks (rbac middleware handles) |
| `internal/api/handler/evm/hdwallet.go` | Delete ~2 `apiKey.Admin` checks |
| `internal/api/handler/evm/request.go` | Delete ~2 `apiKey.Admin` checks |
| `internal/config/rule_init.go` | Config-sourced rules set `owner="config"`, `applied_to=["*"]`, `status="active"` |
| `internal/audit/logger.go` | `LogRuleUpdated` adds old/new config JSON diff; new `LogRuleApproved`, `LogRuleRejected` |
| `internal/core/rule/whitelist.go` | `Evaluate` entry adds rule pre-filter by `applied_to` + `status` |

### 6.4 Summary

| Category | Files | Effort |
|----------|-------|--------|
| Reuse (no change) | 10+ | Zero |
| Delete & Rewrite | 8 (2 delete, 1 new, 5 rewrite) | High |
| Extend | 8 | Medium |
| **Total touched** | **~16 files** | |

---

## 7. Implementation Plan

**This is v1.0.0 — a clean break. No backward compatibility with pre-v1 config/schema.**

### Phase 1: Data Model
- **APIKey**: delete `Admin bool` + `Agent bool`, add `Role APIKeyRole` enum (admin/dev/agent/strategy)
- **Rule**: delete `APIKeyID *string`, add `Owner string`, `AppliedTo pq.StringArray`, `Status RuleStatus`, `ApprovedBy *string`, `Immutable bool`
- **DB**: GORM AutoMigrate (add new columns; old columns cleaned up manually or via migration script)
- **Config**: new format only (`role: admin`), old format (`admin: true`) is parse error

### Phase 2: RBAC Middleware (refactor)
- **Delete**: `middleware/admin.go`, `middleware/agent.go`
- **Create**: `middleware/rbac.go` — static permission matrix (not Casbin — overkill for 4 fixed roles)
- **Define**: `Permission` enum matching Section 2.2
- **Map**: `Role → []Permission` compile-time constant
- **Route registration**: `router.POST("/evm/sign", rbac.Require(PermSignRequest), handler)` — handler never checks role
- **Delete all `apiKey.Admin` / `apiKey.Agent` checks from handlers** — handlers are role-agnostic

### Phase 3: Rule Scoping at Runtime
- Update rule engine `LoadRules` to filter by `applied_to` + `status = active`
- Add `Owner` to rule creation flow (auto-set from request context)
- Config-sourced rules: `owner = "config"`, `applied_to = ["*"]`, `status = "active"`
- Keep existing two-phase evaluation (blocklist → whitelist), filter ensures correct scope

### Phase 4: Agent Rule CRUD + Approval Flow + Immutable Rules
- Agent can create/modify/delete own **declarative** rules via API
- Middleware enforces: `owner = caller`, `applied_to = ["self"]` for non-admin
- Per-key rule count limit (`security.max_rules_per_api_key`)
- Block `evm_js`, `signer_restriction`, `evm_solidity_expression` for agent role
- Validate `applied_to` key IDs exist at creation time
- **Approval flow** (reuses existing approval pattern from sign request approval):
  - `security.require_approval_for_agent_rules` config option
  - Pending status for agent whitelist rules (when enabled)
  - `POST /evm/rules/:id/approve`, `POST /evm/rules/:id/reject` (same state machine pattern as `POST /evm/requests/:id/approve`)
  - Notification on pending rule creation (if notifier configured)
- **Immutable rules**: `immutable: true` flag — blocks API modification/deletion
- **Audit diff**: rule update logs record full `old_config` + `new_config` JSON

### Phase 6: E2E Tests

Every case below MUST be an E2E test (real server, real HTTP requests). Not unit test mocks.

#### Group A: Role Permission Boundaries (per role × per endpoint)

**A1. admin**
- A1.1 admin can sign → 200
- A1.2 admin can create rule with applied_to=["*"] → 200
- A1.3 admin can create rule with applied_to=["agent-key-1","agent-key-2"] → 200
- A1.4 admin can create evm_js rule → 200
- A1.5 admin can modify any rule → 200
- A1.6 admin can delete any rule → 200
- A1.7 admin can approve pending rule → 200
- A1.8 admin can reject pending rule → 200
- A1.9 admin can list all rules → 200, returns all
- A1.10 admin can list all API keys → 200
- A1.11 admin can manage signers (create/unlock) → 200
- A1.12 admin is NOT subject to rule count limit → create 100+ rules

**A2. dev**
- A2.1 dev can sign → 200
- A2.2 dev can create rule (applied_to=["self"]) → 200
- A2.3 dev can create evm_js rule (applied_to=["self"]) → 200
- A2.4 dev CANNOT create rule (applied_to=["*"]) → 403
- A2.5 dev CANNOT create rule (applied_to=["other_key"]) → 403
- A2.6 dev can modify own rule → 200
- A2.7 dev CANNOT modify other's rule → 403
- A2.8 dev can delete own rule → 200
- A2.9 dev CANNOT delete other's rule → 403
- A2.10 dev can list all rules (read-only) → 200
- A2.11 dev CANNOT approve/reject rules → 403
- A2.12 dev CANNOT manage API keys → 403
- A2.13 dev can read own signers → 200
- A2.14 dev can read budgets → 200
- A2.15 dev can read templates/presets → 200
- A2.16 dev CANNOT create signer_restriction rule → 403

**A3. agent**
- A3.1 agent can sign → 200
- A3.2 agent can create declarative rule (evm_address_list, applied_to=["self"]) → 200 (or 202 if pending)
- A3.3 agent CANNOT create evm_js rule → 403
- A3.4 agent CANNOT create evm_solidity_expression rule → 403
- A3.5 agent CANNOT create signer_restriction rule → 403
- A3.6 agent CANNOT create rule (applied_to=["*"]) → 403
- A3.7 agent CANNOT create rule (applied_to=["other_key"]) → 403
- A3.8 agent creates rule → applied_to forced to ["self"] even if body says ["*"]
- A3.9 agent creates rule → owner = agent's key ID (not settable via body)
- A3.10 agent can modify own declarative rule → 200
- A3.11 agent CANNOT modify own rule to evm_js type → 403
- A3.12 agent CANNOT modify admin's rule → 403
- A3.13 agent CANNOT modify other agent's rule → 403
- A3.14 agent can delete own rule → 200
- A3.15 agent CANNOT delete admin's rule → 403
- A3.16 agent can list rules: sees own + rules applied_to self → verify scoped
- A3.17 agent CANNOT see other agent's rules (different owner, applied_to=["self"]) → not in list
- A3.18 agent can read templates (read-only) → 200
- A3.19 agent can read presets (read-only) → 200
- A3.20 agent can read budgets for own rules → 200
- A3.21 agent CANNOT read budgets for other's rules → 403
- A3.22 agent can read own signers → 200
- A3.23 agent CANNOT manage API keys → 403
- A3.24 agent CANNOT approve/reject rules → 403

**A4. strategy**
- A4.1 strategy can sign → 200
- A4.2 strategy can get own request status → 200
- A4.3 strategy CANNOT list rules → 403
- A4.4 strategy CANNOT read any single rule → 403
- A4.5 strategy CANNOT create rules → 403
- A4.6 strategy CANNOT read templates → 403
- A4.7 strategy CANNOT read presets → 403
- A4.8 strategy CANNOT read budgets → 403
- A4.9 strategy can read own signers (read-only) → 200
- A4.10 strategy CANNOT create/unlock signers → 403
- A4.11 strategy CANNOT manage API keys → 403
- A4.12 strategy CANNOT read metrics → 403
- A4.13 strategy CANNOT read audit logs → 403

#### Group B: Rule Ownership & Scoping

**B1. Owner auto-set**
- B1.1 agent creates rule → owner = agent's key ID (not settable via request body)
- B1.2 admin creates rule → owner = admin's key ID
- B1.3 config-sourced rule → owner = "config"

**B2. applied_to enforcement**
- B2.1 agent creates rule → applied_to forced to ["self"] even if request body says ["*"]
- B2.2 admin creates rule with applied_to=["*"] → allowed
- B2.3 admin creates rule with applied_to=["agent-key-1","agent-key-2"] → allowed
- B2.4 admin creates rule with applied_to=["nonexistent-key"] → 400 (key not found) (SA-6)
- B2.5 dev creates rule → applied_to forced to ["self"]

**B3. Scoped rule evaluation**
- B3.1 agent-A creates whitelist rule → agent-A's sign request matches → allowed
- B3.2 agent-A creates whitelist rule → agent-B's sign request does NOT match (different owner, applied_to=["self"])
- B3.3 admin creates whitelist rule (applied_to=["*"]) → both agent-A and agent-B match
- B3.4 admin creates whitelist rule (applied_to=["agent-A"]) → only agent-A matches
- B3.5 strategy's sign request matches config-sourced rules (applied_to=["*"]) → allowed
- B3.6 strategy's sign request does NOT match agent-A's rule (applied_to=["self"], owner=agent-A)

**B4. Evaluation order (security critical)**
- B4.1 admin blocklist + agent whitelist → admin blocklist wins, request rejected
- B4.2 agent own blocklist + agent own whitelist → blocklist wins
- B4.3 admin whitelist only → request allowed
- B4.4 agent whitelist only (no admin rules for this scope) → request allowed
- B4.5 no rules match → request rejected (fail-closed)
- B4.6 admin blocklist (applied_to=["*"]) + agent whitelist (owner=agent, applied_to=["self"]) for SAME address → blocklist wins

#### Group C: Rule Lifecycle

**C1. Immediate activation (default)**
- C1.1 agent creates whitelist rule → status=active → sign request uses it immediately

**C2. Approval flow (require_approval_for_agent_rules=true)**
- C2.1 agent creates whitelist rule → status=pending_approval
- C2.2 pending rule NOT evaluated at runtime → sign request not affected
- C2.3 admin approves → status=active → sign request now uses it
- C2.4 admin rejects → status=rejected → sign request still not affected
- C2.5 agent creates blocklist rule → status=active immediately (self-restriction always OK)

**C3. Revocation**
- C3.1 admin revokes agent's active rule → status=revoked → no longer evaluated
- C3.2 agent cannot un-revoke admin-revoked rule → 403

**C4. Deletion**
- C4.1 agent deletes own active rule → rule removed, sign requests no longer match
- C4.2 agent deletes own pending rule → rule removed
- C4.3 agent CANNOT delete config-sourced rule → 403

**C5. Immutable rules**
- C5.1 admin creates immutable rule → 200
- C5.2 admin CANNOT modify immutable rule via API → 403
- C5.3 admin CANNOT delete immutable rule via API → 403
- C5.4 immutable rule can only be changed via config file + restart

#### Group D: Safety Limits

**D1. Rule count limit**
- D1.1 agent creates rules up to max_rules_per_api_key → all succeed
- D1.2 agent creates one more → 403 with "rule limit exceeded"
- D1.3 admin is NOT subject to rule count limit

**D2. Blocked rule types (agent)**
- D2.1 agent CANNOT create evm_js rule → 403
- D2.2 agent CANNOT create signer_restriction rule → 403
- D2.3 agent CANNOT create evm_solidity_expression rule → 403
- D2.4 agent CAN create evm_address_list rule → 200
- D2.5 agent CAN create evm_contract_method rule → 200
- D2.6 agent CAN create evm_value_limit rule → 200
- D2.7 agent CAN create sign_type_restriction rule → 200
- D2.8 agent CAN create message_pattern rule → 200
- D2.9 dev CANNOT create signer_restriction rule → 403
- D2.10 dev CAN create evm_js rule → 200
- D2.11 admin CAN create any rule type → 200

**D3. Rate limiting on CRUD**
- D3.1 agent rapid-fire creates/deletes same rule → rate limited after N requests

#### Group E: Config-Sourced Rules (Global Security Only)

- E1 config-sourced rules have applied_to=["*"] → affect all keys
- E2 config-sourced rules have owner="config"
- E3 config-sourced rules cannot be deleted via API (when rules_api_readonly)
- E4 agent sign request matches config-sourced blocklist → rejected (global security)
- E5 strategy sign request matches config-sourced blocklist → rejected (global security)
- E6 agent preset rules are NOT config-sourced — created via API (owner=agent, applied_to=["self"])
- E7 config should only contain global security rules (blocklist, sanctions), not scoped rules

#### Group F: Audit

- F1 agent creates rule → audit log entry with actor=agent-key, full config snapshot
- F2 admin approves rule → audit log entry with actor=admin-key
- F3 admin rejects rule → audit log entry with reason
- F4 agent modifies rule → audit log entry with old_config + new_config diff (SA-5)
- F5 agent deletes own rule → audit log entry with deleted rule snapshot
- F6 agent can read own audit events → 200
- F7 strategy CANNOT read audit events → 403

#### Group G: Multi-Agent Isolation

- G1 agent-A creates whitelist for token X → agent-A can sign for X
- G2 agent-B CANNOT sign for token X (no matching rule for B)
- G3 agent-A's budget for token X is independent of agent-B
- G4 agent-A CANNOT see agent-B's rules in list
- G5 agent-A CANNOT read agent-B's rule by ID
- G6 agent-A CANNOT read agent-B's budget

---

## 7. Resolved Questions

1. **Dev creating rules for strategy**: No. Strategy rules come from admin/config only. Strategy is designed to be fully pre-configured at deploy time.
2. **Agent temporary rules with expiry**: Yes, supported via existing `expires_at` field. No design changes needed.
3. **Rate limit scope**: Per key (existing behavior). Rule CRUD operations are covered by the same rate limiter.
4. **Strategy as separate role**: Yes. Explicit role makes security boundaries auditable. "dev minus read" is the practical description, but having a named role is clearer.

---

## 8. Scale Considerations (Future Optimization)

**Target**: 10M+ API keys, each with up to 50 rules = 500M+ rule rows.

### 8.1 Problem

Current design queries applicable rules per sign request:
```sql
WHERE status = 'active'
  AND ('*' = ANY(applied_to) OR K = ANY(applied_to) OR ('self' = ANY(applied_to) AND owner = K))
```

At 500M rows, this query is too slow for real-time signing (target < 50ms).

### 8.2 Solution: Three-Query Split + Layered Cache

Replace single complex query with three targeted queries:

| Query | What | Index | Cardinality |
|-------|------|-------|-------------|
| Q1: Global rules | `WHERE '*' = ANY(applied_to) AND status = 'active'` | GIN on applied_to | Very low (tens) |
| Q2: Owner's rules | `WHERE owner = K AND status = 'active'` | B-tree on (owner, status) | Low (≤50 per key) |
| Q3: Targeted rules | `WHERE K = ANY(applied_to) AND K != '*' AND status = 'active'` | GIN on applied_to | Low (admin-assigned) |

Merge Q1 ∪ Q2 ∪ Q3 → applicable rules.

### 8.3 Cache Hierarchy

```
Sign request (API key = K)
    │
    ▼
L1: In-memory LRU cache (per API key → compiled rule set)
    - TTL: 60s
    - Size: 100K entries (~top active keys)
    - Invalidation: on rule CRUD via channel/event
    │ miss
    ▼
L2: Redis (per API key → serialized rule IDs)
    - TTL: 5min
    - Invalidation: pub/sub on rule change events
    │ miss
    ▼
L3: PostgreSQL (three-query split above)
    - Populate L2 + L1 on miss
```

**Global rules (Q1)** cached separately with longer TTL — they change infrequently.

### 8.4 DB Partitioning

If rules table exceeds 100M rows:
- Hash partition by `owner` (distribute per-key queries across partitions)
- Global rules (`owner = "config"`) stay in a dedicated partition
- Partition count: 64 or 256 (depends on growth rate)

```sql
CREATE TABLE rules (
    id VARCHAR(64),
    owner VARCHAR(64) NOT NULL,
    ...
) PARTITION BY HASH (owner);

CREATE TABLE rules_p0 PARTITION OF rules FOR VALUES WITH (MODULUS 64, REMAINDER 0);
CREATE TABLE rules_p1 PARTITION OF rules FOR VALUES WITH (MODULUS 64, REMAINDER 1);
-- ... up to p63
```

### 8.5 Per-Key Rule Count

`COUNT(*) WHERE owner = K` on partitioned table is fast (scans one partition). Alternatively, maintain a counter in the API key record:

```go
type APIKey struct {
    // ...
    RuleCount int `json:"rule_count" gorm:"default:0"` // maintained atomically on rule CRUD
}
```

Avoids COUNT query entirely. Increment/decrement in the same transaction as rule create/delete.

### 8.6 Implementation Priority

- **v1.0.0**: No cache, direct DB queries, three-query split. Sufficient for <100K keys.
- **v1.1**: Add L1 in-memory cache with event-based invalidation. Sufficient for <1M keys.
- **v1.2**: Add L2 Redis cache + DB partitioning. Targets 10M+ keys.

Each phase is additive — no breaking changes between phases.
