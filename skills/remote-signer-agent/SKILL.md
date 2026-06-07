---
name: remote-signer-agent
description: >
  Agent-facing remote-signer operations with the agent API key. Use when the agent
  submits or inspects sign requests, chooses the right rule tier (existing instance,
  catalog preset apply, agent-rule unblock, or new template/preset), reads/updates
  agent-owned rules, checks budgets, unblocks `authorizing` requests, or diagnoses
  `rejected` simulation failures. Covers the policy resolution ladder, pre-flight,
  RBAC, and authorizing unblock. For rule authoring see remote-signer-rule-development.
  For installation, TLS, or SDK see reference files.
---

# Remote Signer — Agent

Agent operations against remote-signer using the **agent** API key. Admin-only actions (approve requests, manage keys, create signers) are documented for user handoff, not agent execution.

## When to Activate

- User asks to interact with a **dApp** or sign anything (transaction, typed data, personal message, hash)
- Before starting a dApp session — pick the **lowest sufficient rule tier** (see Policy Resolution Ladder below)
- A web3-agent-browser interaction triggers a signing request that enters `authorizing`
- A sign request is **`rejected`** and `error_message` mentions **simulation** (especially `transaction simulation reverted`)
- Installing or configuring remote-signer → [references/installation.md](references/installation.md)
- Managing API keys or RBAC → [references/rbac-auth.md](references/rbac-auth.md)
- Configuring TLS/mTLS or IP whitelist → [references/tls-security.md](references/tls-security.md)
- Integrating via MCP or SDKs → [references/sdk-integration.md](references/sdk-integration.md)
- CLI command reference → [references/cli-reference.md](references/cli-reference.md)

---

## Policy Resolution Ladder

When the user wants to use a dApp, **do not jump straight to updating `trusted_contracts`**. Work top-down: reuse what already exists, escalate only when needed.

```
User: "去 Uniswap / Stargate / … 交互"
  │
  ▼
L0 已有实例规则能覆盖？ ──Yes──► 直接交互（匹配则自动批准）
  │ No
  ▼
L1 目录里有该协议/场景的 preset？ ──Yes──► 建议 preset apply（一次性配置，长期复用）
  │ No
  ▼
L2 仅 agent 通用规则 ──► 正常交互；未匹配 → authorizing / simulation
  │
  ▼（卡住时）
L3 authorizing ──► 更新 agent 规则（加合约白名单）+ 用户批准规则变更
  │
  ▼（长期高频）
L4 无合适 preset ──► 编写 template + preset（remote-signer-rule-development）
```

### L0 — Existing instance rules (best: zero setup)

**When:** Agent or user already applied a protocol preset; instance rules are **active**.

```bash
remote-signer evm rule list --owner agent --json \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv
```

Look for rule names like `Stargate — …`, `Uniswap — …` (from `preset apply`). If present and `status: active`, **start the dApp interaction directly**. Matching signs auto-approve; no per-request admin approve, no agent `trusted_contracts` patch.

Use `evm request preview-rule <id>` on a stuck request to confirm whether an existing instance *should* have matched.

### L1 — Catalog preset exists, not yet applied (recommended path)

**When:** L0 empty, but `preset remote-list` has a preset for this dApp/protocol.

**Agent can apply presets** (`PermApplyPreset` on agent role). Creates rules `owner=agent`, `applied_to=["self"]`.

```bash
# Discover — always query live catalogue; never maintain a static dApp→preset table
remote-signer preset remote-list \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv

# Fuzzy search by protocol/dApp keyword (id, name, description, template_ids)
remote-signer preset remote-list --q stargate \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv

# Or pipe full list through grep when scripting
remote-signer preset remote-list -o json ... | jq '.presets[] | select(.id|test("stargate";"i"))'

remote-signer preset remote-get <preset-id> \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv
```

**Matching rule:** Extract keywords from user intent + dApp URL (e.g. `stargate.finance` → `stargate`, `app.uniswap.org` → `uniswap`). Search with `--q`; if multiple hits, prefer the preset whose `template_ids` match the observed sign flow (approve + typed_data vs swap-only). If zero hits, fall through to L2/L3.

**Workflow:**

1. `preset remote-get` — read variables, defaults, `template_ids`, `matrix`
2. Assess default danger (see `remote-signer-rule-development` skill)
3. **Ask user** to confirm scope-limiting variables (`max_*`, token allowlists, etc.)
4. `preset apply <id> --set key=value ...` with **agent** key
5. If server `require_approval` is on, new whitelist rules may be `pending_approval` → tell user to **approve rules once** (admin). After that, same-protocol signs auto-approve.

```bash
remote-signer preset apply stargate \
  --set max_input_amount=1000000000000000000 \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv
```

**Why prefer L1 over L3:** Presets encode **parameter-level** validation (spender, tokens, EIP-712 fields, amounts). They avoid relying on generic `agent-sign` `trusted_contracts` or simulation-budget fallback. One apply, many sessions.

**Caveats (be honest with user):**

- Presets may still define **budgets** (e.g. Stargate approve cap) — that is intentional fund safety, not the agent simulation budget.
- First `preset apply` may need **one-time admin rule approval** if `require_approval` is enabled — still cheaper than approving every sign request.
- Do **not** use `agent` preset / `trusted_contracts` for protocol typed_data (e.g. Aori `Order`) when a dedicated preset exists — use `stargate` + `evm/aori`.

### L2 — Generic agent rules only (default)

**When:** No matching instance, no catalog preset. User already has `evm/agent` preset applied.

Proceed with web3-agent-browser. Signs either auto-approve (whitelist match), hit **simulation + budget** (complex txs), or stall in **`authorizing`** (no rule match).

### L3 — AUTHORIZING unblock (reactive, one-off)

**When:** Request is `authorizing`, L0/L1 not available or not yet applied.

Inspect → safety analysis → update **matching** agent-owned rule (`trusted_contracts`, `allowed_spenders`, etc.) → user approves **rule change** (admin if `pending_approval`). See [AUTHORIZING: Agent Self-Service Unblock](#authorizing-agent-self-service-unblock) below.

Use for: unknown dApp, first-time contract, or urgent single session before L4 is ready.

**Do NOT** treat L3 as the default for known protocols that already ship a preset (Stargate, Uniswap, …) — suggest L1 first.

### L4 — Author template + preset (strategic)

**When:** User will interact with this protocol **often**; L3 patches are repetitive; no upstream preset exists.

Hand off to **`remote-signer-rule-development`** skill: observe real sign payloads → template (protocol) → preset (dApp) → validate → `preset apply`. Upstream PR to remote-signer repo when stable.

---

## Pre-Flight Checklist

Run these checks **before** calling any signing tool. Fail fast if any check fails.

### 1. Server is running

```bash
curl -fsS "http://127.0.0.1:8548/health" 2>/dev/null
```

If not running, start it: `./remote-signer &`

### 2. Agent API key is configured and loads correctly

The agent interacts with remote-signer exclusively through its **agent API key**. Verify the key file exists and the CLI can load it:

```bash
# Check key file exists (never print contents)
test -f ~/.remote-signer/apikeys/agent.key.priv || echo "MISSING: ~/.remote-signer/apikeys/agent.key.priv"

# Verify CLI can load the key (a simple health check confirms auth works)
remote-signer health \
  --url http://127.0.0.1:8548 \
  --api-key-id agent \
  --api-key-file ~/.remote-signer/apikeys/agent.key.priv
```

If the key file is missing, the agent **cannot** interact with remote-signer at all. Tell the user to create an agent key.

### 3. At least one signer exists, is unlocked, and assigned to this agent

```bash
remote-signer evm signer list \
  --url http://127.0.0.1:8548 \
  --api-key-id agent \
  --api-key-file ~/.remote-signer/apikeys/agent.key.priv
```

If the signer list is **empty**, diagnose the cause:

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `[]` (admin) | No signers created yet | Admin creates a signer |
| `[]` (agent) | No signers assigned to this agent | Admin grants access: `evm signer access grant <address> --to agent` (as owner/admin) |
| Signer exists, `status: pending_approval` | Non-admin created signer; admin must approve **signer** before any sign | Admin: `evm signer approve <address>` or Web UI Signers → Approve |
| Signer exists but `locked: true` | Signer was locked | Owner/admin unlocks: `evm signer unlock <address>` |
| Signer exists but `enabled: false` | Signer is disabled | Admin enables it |
| `403 not authorized for this signer` on sign | Often `pending_approval` (misleading message) or no access grant | Approve signer first; check `evm signer access list <address>` |
| `material_status: missing` | Keystore file not on disk | Check `~/.remote-signer/keystores/` |

**Do NOT guess or assume signer availability.** Always run the diagnosis above and report the exact cause.

---

## API Key Configuration

All agent-to-remote-signer commands use these flags. Set once and use consistently:

```bash
--url http://127.0.0.1:8548 \
--api-key-id agent \
--api-key-file ~/.remote-signer/apikeys/agent.key.priv
```

CLI auto-discovery: when `--api-key-file` is omitted, the CLI auto-discovers:
- `--api-key-id agent` → looks for `agent.key.priv` PEM in `~/.remote-signer/apikeys/`
- `--api-key-id admin` → looks for `admin.keystore.json` in `~/.remote-signer/apikeys/`

The agent should always use the **agent** API key for every operation it performs. The **admin** key is for the user only — the agent never holds it.

---

## RBAC: What the Agent Can and Cannot Do

**This table is the single source of truth.** Check it before attempting any operation.

| Capability | `agent` | Who can | CLI command |
|------------|:---:|---------|-------------|
| Submit sign requests | Yes | agent | (via browser extension proxy) |
| View own request status | Yes | agent | `evm request list --api-key-id agent` |
| View own request detail + payload | Yes | agent | `evm request get <id> --api-key-id agent` |
| Preview rule for a request | Yes | agent | `evm request preview-rule <id> --api-key-id agent` |
| View own request simulation | Yes | agent | `evm request simulation <id> --api-key-id agent` |
| Read rules | Yes | agent | `evm rule list --api-key-id agent` |
| Read presets (catalog) | Yes | agent | `preset remote-list` / `preset remote-get` |
| Apply presets (create own rules) | Yes | agent | `preset apply <id> --api-key-id agent` |
| Read budgets | Yes | agent | `evm budget list --api-key-id agent` |
| Update own rules | Yes | agent | `evm rule update <id> --api-key-id agent` |
| Create rules | Yes | agent | `evm rule create --api-key-id agent` |
| List signers available to agent | Yes | agent | `evm signer list --api-key-id agent` |
| Create signers (keystore) | Yes | agent | `evm signer create` → **`pending_approval` until admin `evm signer approve`** |
| Approve/reject sign **requests** | **No** | admin | `evm request approve/reject --api-key-id admin` |
| Approve pending **signers** | **No** | admin | `evm signer approve <address> --api-key-id admin` |
| View all requests (all users) | **No** | admin | `evm request list --api-key-id admin` |
| Manage API keys | **No** | admin | `api-key create/delete --api-key-id admin` |
| Manage templates | **No** | admin | `template create/update/delete --api-key-id admin` |

**Critical rules:**
- The agent **can** inspect stuck requests, read rules/budgets, check simulations, update whitelist rules, and **create signers** (they start as `pending_approval`).
- The agent **cannot** approve sign requests, approve signers, or manage API keys. These require admin.
- When a `require_approval` rule update creates a pending rule, only admin can approve the rule change. Once approved, the server auto-approves matching stuck requests.
- **Every CLI command in this skill MUST show which key to use.** `--api-key-id agent` for agent operations, `--api-key-id admin` for user operations.

---

## Managing Your Rules (Agent Self-Service)

The agent's rules are created by applying the `agent` preset (or manually). The agent **owns** these rules (`owner=agent`) and can read/update them with its own API key.

### List your rules

```bash
# List ALL rules visible to the agent (filtered by owner + applied_to):
remote-signer evm rule list \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv

# List only rules owned by the agent (fastest way to find your rules):
remote-signer evm rule list --owner agent \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv

# List in JSON for easy parsing:
remote-signer evm rule list --owner agent --json \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv
```

### Get a single rule's full config

```bash
remote-signer evm rule get <rule-id> \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv
```

### Update a rule (e.g. add a contract address to the whitelist)

```bash
# Agent rules typically use variables like `trusted_contracts`.
# Update the rule's variables to add a new contract address.
# Existing addresses are preserved — only pass the fields you want to change.
remote-signer evm rule update <rule-id> \
  --variables '{"trusted_contracts":"0xExisting,0xNewContract"}' \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv
```

### Typical agent rule architecture (from `agent` preset)

When the user applies `evm/agent` preset, the agent gets **6 rules** from 4 composed templates:

| Template | Rules | Purpose |
|----------|-------|---------|
| `evm/agent` | agent-sign, agent-safety | personal_sign + typed_data whitelist (`trusted_contracts`); blocklist for dangerous selectors |
| `evm/erc20` | erc20-transfer-limit, erc20-approve-limit | ERC20 `approve` to `trusted_contracts`; transfers blocked (`max_transfer_amount: 0`) |
| `evm/erc721` | erc721-transfer-approve-allowlists | NFT `approve` / `setApprovalForAll` to `trusted_contracts`; transfers blocked (`auth_only: true`) |
| `evm/erc1155` | erc1155-transfer-approve-allowlists | ERC1155 `setApprovalForAll` to `trusted_contracts`; transfers blocked (`auth_only: true`) |

Other transactions (swap, bridge, native send) fall through to **SimulationBudgetRule** (simulation + budget).

**To unblock a stuck dApp interaction**, branch by `sign_type` / calldata:

| Request type | Rule to update | Variable |
|--------------|----------------|----------|
| `personal_sign` / `typed_data` (Permit, SIWE) | **Agent — Agent Signature** (`agent-sign`) | `trusted_contracts` |
| ERC20 `approve(spender)` tx | **Agent — ERC20 approve limit** (`erc20-approve-limit`) | `trusted_contracts` (or `allowed_spenders`) |
| ERC721 `approve` / `setApprovalForAll` | **Agent — ERC721 …** (`erc721-transfer-approve-allowlists`) | `trusted_contracts` (or `allowed_approve_to` / `allowed_operators`) |
| ERC1155 `setApprovalForAll` | **Agent — ERC1155 …** (`erc1155-transfer-approve-allowlists`) | `trusted_contracts` (or `allowed_operators`) |
| Other tx (no matching whitelist) | Simulation budget — **cannot** whitelist via `trusted_contracts` alone | Adjust budget or user approves single request |

Find rules with `evm rule list --owner agent`. Use `evm request preview-rule <id>` to see which rule would match after an update.

**Do NOT** update only `agent-sign` for an ERC20 `approve` transaction — that rule handles signatures, not on-chain approve calldata.

---

## Unified Signing Workflow

```
Pre-flight checks (server, key, signer) — see above
  │
  ▼
Sign request submitted via web3-agent-browser (or CLI/MCP)
  │
  ├─ Auto-approved → signature returned → DONE
  ├─ Auto-blocked  → rejected → see "Simulation rejection" below if simulation-related
  └─ No rule match → authorizing ⬇
```

### REJECTED: Simulation failure diagnosis

**Trigger:** `status: rejected` and `error_message` contains `transaction simulation reverted` (or `simulation budget exceeded`).

Simulation already ran during sign evaluation. You are **reading the persisted snapshot**, not re-simulating — except when you explicitly dry-run again (see step 4).

**Step 1 — Summary (one call)**

```bash
remote-signer evm request get <id> \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv \
  -o json
```

Check `error_message`. On current daemons it embeds the decoded revert, e.g.:

```
transaction simulation reverted: TransactionDeadlinePassed()
```

Use this for a quick verdict. Do **not** stop here if the message is vague (`transaction reverted`) or you need selector/signature/confidence/events.

**Step 2 — Simulation snapshot (second call, required for full diagnosis)**

```bash
remote-signer evm request simulation <id> \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv \
  -o json
```

API: `GET /api/v1/evm/requests/{id}/simulation`

| Field | Meaning |
|-------|---------|
| `decision` | `deny` when simulation blocked the sign |
| `reason` | Rule-level reason (often mirrors `error_message`) |
| `success` | `false` when the tx reverted on-chain simulation |
| `revert_reason` | Human-readable revert (prefer over generic RPC text) |
| `raw_result` | Full `SimulationResult` JSON — **`revert_signature`**, `revert_selector`, `revert_confidence`, `events`, `balance_changes` live here when present |

**Prefer JS/SDK** (`client.evm.requests.getSimulation`) over Go CLI for this endpoint: the Go client's `SimulateResponse` type omits `raw_result` and structured revert fields. Parse `raw_result` for the full Revert panel.

**Step 3 — Interpret common reverts**

| `revert_signature` / reason | Meaning | Agent action |
|----------------------------|---------|--------------|
| `TransactionDeadlinePassed()` | Swap/router deadline expired before broadcast | Tell user to **re-initiate in the dApp** (fresh deadline). Do not replay old calldata. |
| Slippage / `STF()` / `TooLittleReceived()` | Price moved or insufficient output | Adjust slippage or retry swap in dApp. |
| `InsufficientAllowance()` / allowance errors | Token not approved for spender | Run approve flow first, then retry. |
| `simulation budget exceeded` | Simulated outflow exceeds agent budget rule | Check `balance_changes` in snapshot; adjust budget or tx size — not a chain revert. |

**Step 4 — Optional: re-simulate current chain state**

Only when the snapshot is **stale** (old request before daemon upgrade, or user wants "what would happen now"):

```bash
# Web UI: request detail → Simulate again, or /simulate?request_id=<id>
remote-signer evm simulate tx --chain-id <id> --from 0x... --to 0x... --data 0x... \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv \
  -o json
```

Gas/value accept decimal or hex; the daemon normalizes before `eth_simulateV1`.

**Do NOT** treat simulation reject like `authorizing` — agent cannot whitelist past a reverting tx. Fix the underlying tx (deadline, slippage, allowance) or ask the user to change the dApp action.

---

### AUTHORIZING: Agent Self-Service Unblock

> **Ladder position:** This is **L3** (reactive). Before updating agent rules, confirm **L0** (instance already applied?) and **L1** (catalog preset available?) — prefer `preset apply` for known protocols.

**Step 1 — Inspect request** (agent key)
```bash
remote-signer evm request get <id> \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv \
  --json
```

**Step 2 — Check simulation** (agent key)
```bash
remote-signer evm request simulation <id> \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv \
  --json
```

**Step 3 — Check existing rules** (agent key)
```bash
remote-signer evm rule list \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv \
  --json
```

**Step 4 — Preview rule** (agent key)
```bash
remote-signer evm request preview-rule <id> \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv \
  --json
```

**Step 5 — Safety analysis** (agent's own reasoning, no API call). Use the "Safety Analysis Template" below.

**Step 6 — Decision**

| Verdict | Action |
|---------|--------|
| **SAFE** | Update whitelist rule (agent key), tell user to approve the rule change. Once approved, the stuck request auto-approves + future same-contract interactions pass. |
| **UNSAFE** | Ask user to manually approve this single request (admin key). Do not update rules. |

**SAFE path — Update the matching whitelist rule** (agent key):

```bash
# Example: ERC20 approve to Stargate spender — update erc20-approve-limit rule
remote-signer evm rule update <erc20-approve-rule-id> \
  --variables '{"trusted_contracts":"<existing>,<new_spender>"}' \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv

# Example: typed_data Permit — update agent-sign rule
remote-signer evm rule update <agent-sign-rule-id> \
  --variables '{"trusted_contracts":"<existing>,<new_contract>"}' \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv
```

Use `--variables` (not `--config-json`) — variable values live in the rule's `variables` column and apply across all composed templates that reference `trusted_contracts`.
Then tell user: "Rule updated, please approve." User (admin) approves:
```bash
remote-signer evm rule approve <rule-id> \
  --url http://127.0.0.1:8548 --api-key-id admin
```

**UNSAFE path — User manually approves single request** (admin key):
```bash
remote-signer evm request approve <id> \
  --url http://127.0.0.1:8548 --api-key-id admin
```

---

## Step Details: Request Inspection

### Decode the payload by sign_type

| sign_type | What to decode | Key fields to check |
|-----------|---------------|-------------------|
| `transaction` | Decode the EVM transaction | `to` (target contract), `value` (ETH sent), `data` (calldata), `from` |
| `typed_data` | Parse EIP-712 typed data | `primaryType`, `domain.verifyingContract`, message fields |
| `personal_sign` | Decode the signed message text | Full message content, SIWE fields if applicable |
| `hash` | Raw hash bytes | Usually not decodable — treat with extra caution |

### For Permit2 (Uniswap swap pattern)

- `PermitSingle.details.token` = token being spent (e.g. USDT)
- `PermitSingle.details.amount` = amount (uint160 max = unlimited allowance)
- `PermitSingle.spender` = who can spend (Uniswap Universal Router)
- `domain.verifyingContract` = Permit2 contract (`0x000000000022d473030f116ddee9f6b43ac78ba3` — verified canonical address)

Permit2 with unlimited amount to a known Uniswap router is standard and safe.

---

## Safety Analysis Template

Before updating any rule, the agent MUST produce this analysis for the user:

```
## Safety Review: Sign Request <id>

### What is being signed?
- Sign type: <type>
- Target contract: <address> (<contract name if known>)
- Chain: <chain name> (<chain_id>)

### What does it do?
- For typed_data: primaryType, verifyingContract, and key message fields
- For transaction: method signature, decoded parameters, and on-chain outcome

### Why is this safe?
<Explain why this specific request is legitimate:
 - Is the target a known/verified contract?
 - Is the value zero or within budget?
 - Does the payload match expected patterns for this dApp?
 - Are there no suspicious approvals or unlimited allowances to unknown spenders?>

### Rule update
- Rule ID: <agent's whitelist rule>
- Adding: <contract address(es) being trusted>
- This allows: <description of what the rule now permits>
```

### Red flags that MUST prevent rule updates

- `value > 0` on a transaction to an unverified contract
- `approve()` with unlimited allowance (`uint256_max`) to an unknown spender
- `transfer()` of tokens to an unknown address
- Signer address is not the expected agent-controlled address
- The dApp URL or contract is not a known/reputable service
- typed_data with unexpected `verifyingContract`
- `personal_sign` of an unrecognized message format

---

## References

| Reference | When to Read |
|-----------|-------------|
| [references/rbac-auth.md](references/rbac-auth.md) | Full RBAC table, Ed25519 signing, scoping, signer ownership |
| [references/installation.md](references/installation.md) | Install methods, bootstrap, first-time setup guide |
| [references/cli-reference.md](references/cli-reference.md) | Complete CLI command list, auth flags, preset protocol |
| [references/tls-security.md](references/tls-security.md) | TLS/mTLS, IP whitelist, security baseline, sandboxing |
| [references/sdk-integration.md](references/sdk-integration.md) | MCP server, TypeScript/Go/Rust SDKs |
