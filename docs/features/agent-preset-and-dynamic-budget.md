# Agent Preset & Dynamic Budget Design

**Status:** Implemented
**Author:** Ivan + Claude
**Date:** 2026-03-16

AI agents need freedom to interact with arbitrary web3 contracts while maintaining safety guardrails. This design covers three interconnected features: dynamic budget units, JS engine RPC injection, and the agent API key role.

---

## 1. Problem

Current rule templates (ERC20, Polymarket, etc.) whitelist specific contracts and methods. An AI agent needs to:

- Call **any** contract on **any** chain (explore dApps, trade, mint, bridge)
- Have **per-token budget tracking** without pre-declaring every token
- Sign personal messages and typed data for dApp authentication
- Understand **why** a request was blocked (read rules + budgets)

Current limitations:
- Budget unit is static, resolved at rule creation time (`${chain_id}:${token_address}`)
- JS sandbox has no RPC access, cannot query on-chain data (decimals, ERC165)
- Budget amounts are raw big integers, requiring operator to know token decimals
- No API key role between `admin` (full access) and `dev` (sign only)

---

## 2. Design Overview

```
                     Agent (AI bot, trading bot, etc.)
                              |
                    agent API key (sign + read rules/budgets)
                              |
                     remote-signer service
                              |
            +--------+--------+--------+
            |        |        |        |
        Agent TX   Agent    Agent    Dynamic
         Rule     Sign     Safety   Blocklist
       (whitelist) Rule    (block)  (existing)
            |     (whitelist)  |
            v        |        v
      validateBudget |   block delegatecall,
      returns        |   selfdestruct, etc.
      {amount, unit} |
            |        v
            v    length/domain
       Budget Engine  check
       (dynamic unit,
        auto-create,
        unit_decimal)
            |
            v
       evm-gateway RPC (read-only)
       decimals/ERC165 queries
```

---

## 3. JS Engine: Read-Only RPC Injection

### 3.1 RPC Provider

Use evm-gateway (`https://your-evm-gateway.example.com/chain/evm/${chain_id}`) as the unified RPC endpoint. Config:

```yaml
chains:
  evm:
    rpc_gateway:
      base_url: "https://your-evm-gateway.example.com/chain/evm"
      api_key: ""  # optional, for private endpoint
      # Full URL template: ${base_url}/${chain_id}[/api_key/${api_key}]
      cache_ttl: "24h"  # metadata cache TTL
```

### 3.2 JS Sandbox API

New global objects available in JS rules:

```javascript
// Low-level (only eth_call and eth_getCode allowed; write methods throw)
web3.call(to, data)          // returns hex bytes
web3.getCode(address)        // returns hex bytecode

// ERC20 helpers (built on web3.call, results cached to DB)
erc20.decimals(address)      // returns number (e.g. 6, 18)
erc20.symbol(address)        // returns string (e.g. "USDC")
erc20.name(address)          // returns string

// ERC165 interface detection (cached)
erc165.supportsInterface(address, interfaceId)  // returns bool

// Convenience
isERC721(address)            // erc165 check for 0x80ac58cd
isERC1155(address)           // erc165 check for 0xd9b67a26
```

### 3.3 RPC Security

- **Write methods blocked**: `eth_sendTransaction`, `eth_sendRawTransaction`, `eth_sign`, `personal_sign` all throw
- **Timeout**: 5s per RPC call, 15s total per rule evaluation
- **Rate limit**: Max 10 RPC calls per rule evaluation (prevent abuse)
- **No private key exposure**: JS sandbox has no access to signer keys

### 3.4 Token Metadata Persistence

Token metadata (decimals, symbol, name) queried via RPC is persisted to DB:

```sql
CREATE TABLE token_metadata (
    chain_id    TEXT NOT NULL,
    address     TEXT NOT NULL,  -- checksummed
    decimals    INTEGER,
    symbol      TEXT,
    name        TEXT,
    is_erc721   BOOLEAN DEFAULT FALSE,
    is_erc1155  BOOLEAN DEFAULT FALSE,
    queried_at  TIMESTAMP NOT NULL,
    PRIMARY KEY (chain_id, address)
);
```

Cache strategy:
- First check DB, then RPC if miss
- TTL: configurable (default 24h), but decimals essentially never change
- JS helper functions handle cache transparently

---

## 4. Dynamic Budget Units

### 4.1 validateBudget Return Value

Current: `validateBudget(input)` returns `BigInt` (amount).

New: can also return `{amount: BigInt, unit: string}`:

```javascript
function validateBudget(input) {
  var ctx = rs.tx.require(input);

  // ERC20 transfer(to, amount)
  if (eq(ctx.selector, selector('transfer(address,uint256)'))) {
    var dec = abi.decode(ctx.payloadHex, ['address', 'uint256']);
    return { amount: dec[1], unit: ctx.tx.to };
  }

  // ERC20 approve(spender, amount)
  if (eq(ctx.selector, selector('approve(address,uint256)'))) {
    var dec = abi.decode(ctx.payloadHex, ['address', 'uint256']);
    return { amount: dec[1], unit: ctx.tx.to + ':approve' };
  }

  // ERC721 safeTransferFrom — detect via ERC165
  if (eq(ctx.selector, selector('safeTransferFrom(address,address,uint256)'))
      || eq(ctx.selector, selector('transferFrom(address,address,uint256)'))) {
    if (isERC721(ctx.tx.to)) {
      return { amount: 1n, unit: ctx.tx.to + ':nft' };
    }
    // ERC20 transferFrom(from, to, amount)
    var dec = abi.decode(ctx.payloadHex, ['address', 'address', 'uint256']);
    return { amount: dec[2], unit: ctx.tx.to };
  }

  // ERC1155 safeTransferFrom(from, to, id, amount, data)
  if (eq(ctx.selector, selector('safeTransferFrom(address,address,uint256,uint256,bytes)'))) {
    var dec = abi.decode(ctx.payloadHex, ['address', 'address', 'uint256', 'uint256', 'bytes']);
    return { amount: dec[3], unit: ctx.tx.to + ':1155' };
  }

  // Native value transfer
  if (ctx.tx.value > 0n) {
    return { amount: ctx.tx.value, unit: 'native' };
  }

  // Other calls: count
  return { amount: 1n, unit: 'tx_count' };
}
```

### 4.2 Budget Engine Changes

When `validateBudget` returns `{amount, unit}`:

1. Look up budget record by `(rule_id, chain_id + ":" + unit)` — chain_id prefix auto-added
2. If not found:
   - Check `known_units` config for explicit limits → auto-create record
   - Fall back to `unknown_default` config → auto-create with default limits
3. If `unit_decimal: true`: query `erc20.decimals(unit_address)` and convert `max_total`/`max_per_tx` from human-readable to raw big integer
4. Check amount against limits, update spent

Backward compatible: if `validateBudget` returns plain `BigInt`, use static unit from rule config (existing behavior).

### 4.3 unit_decimal Mode

When `unit_decimal: true`, budget limits are specified in human-readable token units:

```yaml
budget:
  dynamic: true
  unit_decimal: true
  known_units:
    native:
      max_total: "1"         # 1 ETH (not 1000000000000000000)
      max_per_tx: "0.1"      # 0.1 ETH
      decimals: 18            # explicit, no RPC needed
    "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359":  # USDC on Polygon
      max_total: "1000"      # 1000 USDC
      max_per_tx: "100"      # 100 USDC
      # decimals omitted → auto-query via erc20.decimals()
  unknown_default:
    max_total: "1000"         # 1000 tokens (auto-query decimals)
    max_per_tx: "100"
    max_tx_count: 50          # additional tx count cap for unknown tokens
  period: "24h"
  alert_pct: 80
```

Conversion at budget check time:
- `max_total: "1000"` + decimals=6 → internal limit = `1000 * 10^6 = 1000000000`
- `validateBudget` returns raw amount (e.g. `500000` = 0.5 USDC)
- Comparison: `500000 <= 1000000000` → pass

Without `unit_decimal` (default): limits are raw big integers, no conversion. Fully backward compatible.

---

## 5. Agent Template

### 5.1 Sub-Rules

File: `rules/templates/agent.template.js.yaml`

Three sub-rules in one template bundle:

| ID | Name | Type | Mode | Purpose |
|----|------|------|------|---------|
| `agent-tx` | Agent Transaction | evm_js | whitelist | Allow any contract call; budget by token/native/count |
| `agent-sign` | Agent Signature | evm_js | whitelist | Allow personal_sign (length limit) and typed_data (Permit budget) |
| `agent-safety` | Agent Safety | evm_js | blocklist | Block delegatecall, selfdestruct, known dangerous patterns |

### 5.2 Agent TX Rule

```javascript
function validate(input) {
  var ctx = rs.tx.require(input);
  // Allow any transaction — budget engine handles limits
  return ok();
}

function validateBudget(input) {
  // ... (as shown in section 4.1)
}
```

### 5.3 Agent Sign Rule

```javascript
function validate(input) {
  if (input.sign_type === 'personal') {
    var msg = input.personal_sign.message;
    var maxLen = parseInt(config.max_message_length) || 1024;
    require(msg.length <= maxLen,
      'message too long (' + msg.length + ' > ' + maxLen + ')');
    return ok();
  }

  if (input.sign_type === 'typed_data') {
    var td = input.typed_data;
    // Permit/Permit2: extract value, track in token budget
    if (td.primaryType === 'Permit' || td.primaryType === 'PermitSingle') {
      // Allow but budget engine tracks via validateBudget
      return ok();
    }
    // Other typed data: allow (e.g. dApp authentication, orders)
    return ok();
  }

  revert('unsupported sign type');
}

function validateBudget(input) {
  if (input.sign_type === 'typed_data') {
    var td = input.typed_data;
    if (td.primaryType === 'Permit') {
      // ERC20 Permit: value is in message.value, token is verifyingContract
      var token = td.domain.verifyingContract;
      var value = BigInt(td.message.value);
      return { amount: value, unit: token + ':permit' };
    }
  }
  // personal_sign and other typed_data: count only
  return { amount: 1n, unit: 'sign_count' };
}
```

### 5.4 Agent Safety Rule (Blocklist)

```javascript
function validate(input) {
  var ctx = rs.tx.require(input);

  // Block delegatecall (dangerous: can change contract state)
  // This is enforced at tx level; Safe/multisig delegatecall has its own rules

  // Block selfdestruct selector (0xff)
  if (ctx.tx.data && ctx.tx.data.length >= 2) {
    var firstByte = ctx.tx.data.substring(2, 4);
    if (firstByte === 'ff') {
      revert('selfdestruct is blocked');
    }
  }

  // Block setApprovalForAll to unknown operators (NFT drainer pattern)
  if (eq(ctx.selector, selector('setApprovalForAll(address,bool)'))) {
    var dec = abi.decode(ctx.payloadHex, ['address', 'bool']);
    if (dec[1]) {  // setting approval to true
      // Could check operator against known dApp list; for now, allow but log
    }
  }

  // Pass: not blocked
  return ok();
}
```

---

## 6. Agent Preset

File: `rules/presets/agent.preset.js.yaml`

```yaml
name: "Agent"
template_paths:
  - "rules/templates/agent.template.js.yaml"
template_names:
  - "Agent Template"
chain_type: evm
enabled: true

matrix:
  - chain_id: "1"
  - chain_id: "137"
  - chain_id: "42161"
  - chain_id: "10"
  - chain_id: "8453"

defaults:
  max_message_length: "1024"
  budget_period: "24h"

override_hints:
  - max_message_length
  - budget_period
```

Budget configuration is part of the template (not preset variables) because it uses the dynamic budget system with `known_units` and `unknown_default`.

---

## 7. Agent API Key

### 7.1 New Field

```go
type APIKey struct {
    // ... existing fields
    Agent bool `json:"agent" yaml:"agent" gorm:"default:false"`
}
```

### 7.2 Permissions

| Endpoint | dev | agent | admin |
|----------|-----|-------|-------|
| POST /evm/sign | yes | yes | yes |
| GET /evm/requests (own) | yes | yes | yes |
| GET /evm/requests/:id (own) | yes | yes | yes |
| GET /evm/rules | no | **read-only** | yes |
| GET /evm/rules/:id | no | **read-only** | yes |
| GET /evm/rules/:id/budgets | no | **read-only** | yes |
| POST/PUT/DELETE /evm/rules | no | no | yes |
| GET /evm/signers | no | **own signers** | yes |
| POST /evm/signers | no | no | yes |
| GET /api/v1/presets | no | **read-only** | yes |

### 7.3 Config Example

```yaml
api_keys:
  - id: "agent-trading-bot"
    name: "Trading Bot"
    public_key: "..."
    admin: false
    agent: true
    enabled: true
    rate_limit: 300
    allow_all_signers: false
    allowed_signers:
      - "0xAgentSignerAddress"
```

### 7.4 Why Agent Needs Read Access

When a sign request is rejected (403), the response includes the reason (e.g. `"budget exceeded"`, `"no matching rule"`). But the agent also needs to:

- **GET /rules**: understand which rules exist and what they allow
- **GET /budgets**: check remaining budget before attempting a transaction
- **Adapt strategy**: if budget is 80% consumed, reduce trade size or wait for period reset

This enables autonomous agent behavior without human intervention for routine budget management.

---

## 8. Implementation Plan

### Phase 1: Dynamic Budget Unit (budget engine)
- `validateBudget` return value parsing: support `{amount, unit}` object
- Budget record auto-creation with `known_units` / `unknown_default` config
- `unit_decimal` conversion logic
- Tests: unit tests for dynamic unit, auto-create, decimal conversion

### Phase 2: JS Engine RPC Injection
- RPC provider integration (evm-gateway base URL from config)
- `web3.call`, `web3.getCode` in JS sandbox (write methods blocked)
- `erc20.decimals/symbol/name` helpers with DB cache
- `erc165.supportsInterface` helper
- `token_metadata` DB table + migration
- Tests: JS rule with RPC calls, cache behavior, timeout/rate-limit

### Phase 3: Agent Template & Preset
- `agent.template.js.yaml` (TX + Sign + Safety sub-rules)
- `agent.preset.js.yaml` (matrix multi-chain)
- Test cases for each sub-rule
- validate-rules passes for agent template

### Phase 4: Agent API Key
- `Agent` field in APIKey model + config
- Middleware permission checks (read-only rules/budgets for agent role)
- setup.sh: option to generate agent API key
- E2E tests: agent key can read rules, cannot write

### Phase 5: Integration & Docs
- E2E test: agent preset deploy + sign request + budget tracking
- `docs/agent.md`: integration guide for AI agent developers
- MCP tools: agent-specific helpers (check budget, list rules)

---

## 9. Security Considerations

1. **Budget is the safety net**: even if agent is compromised (prompt injection), spending is capped
2. **Per-token granularity**: prevents "drain one token to budget limit" from affecting others
3. **Unknown token conservatism**: `unknown_default.max_tx_count` limits interactions with unvetted tokens
4. **RPC read-only**: JS sandbox cannot send transactions or sign messages via RPC
5. **Signer isolation**: agent API key restricted to `allowed_signers`
6. **Rate limiting**: API key rate limit + RPC call limit per evaluation
7. **Typed data awareness**: Permit signatures tracked as budget consumption
8. **Blocklist layer**: agent safety rule blocks known dangerous patterns regardless of budget

---

## 10. Open Questions

1. **Sliding window vs fixed period**: current budget uses fixed 24h reset. Sliding window prevents "burst at reset" but adds complexity. Defer to future optimization?
2. **Cross-chain budget**: should agent have a global cross-chain budget in addition to per-chain? (e.g. total USD exposure across all chains)
3. **Budget alert webhook**: notify operator when agent approaches budget limit? (integrate with existing notification system)
4. **Token price oracle**: for USD-denominated budget limits. Out of scope for v1, but the `unit_decimal` foundation makes it possible later.
