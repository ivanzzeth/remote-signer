---
name: remote-signer-agent
description: >
  Agent-facing remote-signer operations with the agent API key. Use when the agent
  submits or inspects sign requests, reads/updates agent-owned rules, checks budgets,
  or unblocks `authorizing` requests via self-service whitelist updates. Covers
  pre-flight checks, agent RBAC, and the authorizing unblock workflow. For
  installation, admin operations, TLS, or SDK integration, see reference files.
---

# Remote Signer — Agent

Agent operations against remote-signer using the **agent** API key. Admin-only actions (approve requests, manage keys, create signers) are documented for user handoff, not agent execution.

## When to Activate

- User asks to sign anything (transaction, typed data, personal message, hash)
- A web3-agent-browser interaction triggers a signing request that enters `authorizing`
- Installing or configuring remote-signer → [references/installation.md](references/installation.md)
- Managing API keys or RBAC → [references/rbac-auth.md](references/rbac-auth.md)
- Configuring TLS/mTLS or IP whitelist → [references/tls-security.md](references/tls-security.md)
- Integrating via MCP or SDKs → [references/sdk-integration.md](references/sdk-integration.md)
- CLI command reference → [references/cli-reference.md](references/cli-reference.md)

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
| `[]` (agent) | No signers assigned to this agent | Admin grants access: `remote-signer evm signer grant-access <address> --api-key-id agent --api-key-id admin` |
| Signer exists but `locked: true` | Signer was locked | Admin unlocks |
| Signer exists but `enabled: false` | Signer is disabled | Admin enables it |
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
| Read budgets | Yes | agent | `evm budget list --api-key-id agent` |
| Update own rules | Yes | agent | `evm rule update <id> --api-key-id agent` |
| Create rules | Yes | agent | `evm rule create --api-key-id agent` |
| List signers available to agent | Yes | agent | `evm signer list --api-key-id agent` |
| Approve/reject requests | **No** | admin | `evm request approve --api-key-id admin` |
| View all requests (all users) | **No** | admin | `evm request list --api-key-id admin` |
| Manage API keys | **No** | admin | `api-key create/delete --api-key-id admin` |
| Create signers | **No** | admin | `evm signer create --api-key-id admin` |
| Manage templates | **No** | admin | `template create/update/delete --api-key-id admin` |

**Critical rules:**
- The agent **can** inspect stuck requests, read rules/budgets, check simulations, and update whitelist rules — all with its own agent key.
- The agent **cannot** approve requests, manage API keys, or create signers. These require admin.
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

When the user applies `evm/agent` preset, the agent gets:
- **Agent — Agent Whitelist** (`evm_address_list`, `whitelist`): personal_sign + typed_data whitelist. Uses `trusted_contracts` variable for allowed contracts.
- **Agent — Agent Safety** (`evm_js`, `blocklist`): blocks unsafe patterns. Transaction signing falls through to simulation budget.

**To unblock a stuck dApp interaction**, the agent typically needs to add the dApp's contract address to `trusted_contracts` on the whitelist rule. Find the whitelist rule with `evm rule list --owner agent`, then update its variables.

---

## Unified Signing Workflow

```
Pre-flight checks (server, key, signer) — see above
  │
  ▼
Sign request submitted via web3-agent-browser (or CLI/MCP)
  │
  ├─ Auto-approved → signature returned → DONE
  ├─ Auto-blocked  → rejected → tell user why
  └─ No rule match → authorizing ⬇
```

### AUTHORIZING: Agent Self-Service Unblock

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

**SAFE path — Update whitelist rule** (agent key):
```bash
remote-signer evm rule update <agent-rule-id> \
  --config-json '{"trusted_contracts":"<existing>,<new>"}' \
  --url http://127.0.0.1:8548 \
  --api-key-id agent --api-key-file ~/.remote-signer/apikeys/agent.key.priv
```
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
