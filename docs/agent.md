# Agent Integration Guide

This guide covers how AI agents interact with the remote-signer service. The agent feature provides a controlled environment where bots can sign transactions and messages across multiple chains, with per-token budget tracking and safety guardrails.

## Overview

The agent feature consists of:

- **Agent Template** (`rules/templates/agent.template.js.yaml`): Two sub-rules that define what an agent can do
  - `agent-sign` (whitelist): Allows `personal_sign` (with length limit) and `typed_data` (Permit/Permit2 requires `allowed_spenders` whitelist, budget tracked)
  - `agent-safety` (blocklist): Blocks dangerous admin functions (transferOwnership, upgradeTo, setApprovalForAll(true), etc.)
- **Simulation Budget Rule** (fallback): Transactions that don't match any whitelist rule are simulated via `eth_simulateV1`. Budget is tracked based on actual balance changes (not declared intent). Approve events for managed signers require manual approval.
- **Agent Preset** (`rules/presets/agent.preset.js.yaml`): Deploys the template with configurable budgets
- **Agent API Key**: A role between `admin` and `dev` that can sign + read rules/budgets but cannot modify rules
- **Dynamic Budget**: Automatically tracks spending per token without pre-declaring every token. Decimals queried from chain. Gas cost included in native budget.

## Setup

### 1. Deploy Agent Preset

Apply the agent preset via API to create **instance rules** (modifiable via API):

> **IMPORTANT**: Do NOT use `--config config.yaml --write`. That creates config-sourced rules which cannot be modified via API. Always use the Preset API to create instance rules.

Via API (admin key required):

```
POST /api/v1/presets/agent.preset.js.yaml/apply
Content-Type: application/json

{
  "variables": {
    "max_message_length": "2048",
    "budget_period": "24h"
  }
}
```

This creates 5 rule instances (one per chain). Each rule is a bundle containing the three sub-rules.

### 2. Create Agent API Key

Add to `config.yaml`:

```yaml
api_keys:
  - id: "trading-bot"
    name: "Trading Bot"
    public_key: "<ed25519-public-key-hex>"
    role: dev
    role: agent
    enabled: true
    rate_limit: 300
    allow_all_signers: false
    allowed_signers:
      - "0xYourAgentSignerAddress"
```

Or create via API:

```
POST /api/v1/api-keys
Content-Type: application/json

{
  "id": "trading-bot",
  "name": "Trading Bot",
  "public_key": "<ed25519-public-key-hex>",
  "admin": false,
  "agent": true,
  "rate_limit": 300,
  "allow_all_signers": false,
  "allowed_signers": ["0xYourAgentSignerAddress"]
}
```

### 3. Agent Permissions

| Endpoint | Agent | Admin | Dev |
|----------|-------|-------|-----|
| POST /evm/sign | yes | yes | yes |
| GET /evm/requests (own) | yes | yes | yes |
| GET /evm/rules | **read-only** | yes | no |
| GET /evm/rules/:id | **read-only** | yes | no |
| GET /evm/rules/:id/budgets | **read-only** | yes | no |
| POST/PUT/DELETE /evm/rules | no | yes | no |
| GET /evm/signers | **own signers** | yes | no |

## Usage

### Sign a Transaction

```
POST /api/v1/evm/sign
Content-Type: application/json

{
  "sign_type": "transaction",
  "chain_id": "1",
  "signer": "0xYourAgentSignerAddress",
  "transaction": {
    "from": "0xYourAgentSignerAddress",
    "to": "0xTokenContract",
    "value": "0x0",
    "data": "0xa9059cbb..."
  }
}
```

The agent-tx rule allows any transaction target. Budget is dynamically tracked:
- ERC20 `transfer`/`transferFrom`: tracked by token contract address
- ERC20 `approve`: tracked by `<contract>:approve`
- Native ETH transfer: tracked as `native`
- Other calls: tracked as `tx_count`

### Sign a Personal Message

```
POST /api/v1/evm/sign
Content-Type: application/json

{
  "sign_type": "personal",
  "chain_id": "1",
  "signer": "0xYourAgentSignerAddress",
  "personal_sign": {
    "message": "Sign in to dApp"
  }
}
```

Message length is limited (default: 1024 characters, configurable via `max_message_length`).

### Sign Typed Data (EIP-712)

```
POST /api/v1/evm/sign
Content-Type: application/json

{
  "sign_type": "typed_data",
  "chain_id": "1",
  "signer": "0xYourAgentSignerAddress",
  "typed_data": {
    "primaryType": "Permit",
    "domain": {
      "name": "USD Coin",
      "chainId": "1",
      "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    },
    "message": {
      "owner": "0xYourAgentSignerAddress",
      "spender": "0xSpenderAddress",
      "value": "1000000",
      "nonce": "0",
      "deadline": "1700000000"
    }
  }
}
```

Permit signatures are tracked in budget as `<verifyingContract>:permit`.

### Check Remaining Budget

```
GET /api/v1/evm/rules/<rule-id>/budgets
```

Returns budget records per unit:

```json
[
  {
    "unit": "1:native",
    "max_total": "1000000000000000000",
    "max_per_tx": "100000000000000000",
    "spent": "50000000000000000",
    "tx_count": 3,
    "max_tx_count": 0
  },
  {
    "unit": "1:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "max_total": "1000000000",
    "max_per_tx": "100000000",
    "spent": "500000",
    "tx_count": 1,
    "max_tx_count": 50
  }
]
```

### List Available Rules

```
GET /api/v1/evm/rules
```

### Handle Rejections

When a sign request is rejected, the response includes the reason:

```json
{
  "error": "blocked by rule: budget exceeded (unit: 1:native, spent: 1000000000000000000, max: 1000000000000000000)"
}
```

Common rejection reasons:
- `budget exceeded`: The spending limit for this token/unit has been reached
- `per-tx limit exceeded`: Single transaction exceeds the per-transaction cap
- `tx_count exceeded`: Too many transactions for this budget unit
- `message too long`: Personal sign message exceeds `max_message_length`
- `setApprovalForAll(true) is blocked`: Safety rule blocked a dangerous operation
- `transferOwnership is blocked`: Safety rule blocked ownership transfer

## Budget

### How Dynamic Budget Works

The `validateBudget` function in the agent-tx rule inspects each transaction and returns `{amount, unit}`:

| Transaction Type | Unit | Amount |
|-----------------|------|--------|
| ERC20 transfer(to, amount) | Token contract address | Transfer amount |
| ERC20 approve(spender, amount) | `<contract>:approve` | Approval amount |
| ERC20 transferFrom(from, to, amount) | Token contract address | Transfer amount |
| ERC721 safeTransferFrom | `<contract>:nft` | 1 |
| ERC1155 safeTransferFrom | `<contract>:1155` | Transfer amount |
| Native ETH transfer | `native` | ETH value in wei |
| Other contract calls | `tx_count` | 1 |

### Budget Configuration

From the preset:

```yaml
budget:
  dynamic: true
  unit_decimal: true
  known_units:
    native:
      max_total: "1"        # 1 ETH per period
      max_per_tx: "0.1"     # 0.1 ETH per transaction
      decimals: 18
    tx_count:
      max_total: "1000"     # 1000 calls per period
      max_per_tx: "1"
      decimals: 0
    sign_count:
      max_total: "500"      # 500 signatures per period
      max_per_tx: "1"
      decimals: 0
  unknown_default:
    max_total: "1000"        # 1000 tokens per period (auto-query decimals)
    max_per_tx: "100"        # 100 tokens per transaction
    max_tx_count: 50         # Max 50 transactions for unknown tokens
  period: "24h"
  alert_pct: 80
```

- **known_units**: Pre-configured limits for well-known budget categories
- **unknown_default**: Limits applied when the agent interacts with a token not in `known_units`
- **unit_decimal**: When true, limits are in human-readable units (e.g., "1" = 1 ETH, not 1 wei)
- **period**: Budget resets every 24 hours
- **alert_pct**: Alert when 80% of budget is consumed

## Security

### What the Safety Rule Blocks

The `agent-safety` blocklist rule prevents:
- `setApprovalForAll(address, true)`: NFT drainer pattern (revoking with `false` is allowed)
- `transferOwnership(address)`: Prevent ownership transfer of contracts
- `renounceOwnership()`: Prevent irreversible ownership renouncement
- `upgradeTo(address)`: Prevent proxy upgrades
- `upgradeToAndCall(address, bytes)`: Prevent proxy upgrades with calls

### Budget as Safety Net

Even if an agent is compromised (e.g., via prompt injection):
- Spending is capped per token per period
- Unknown tokens have conservative limits (`max_tx_count: 50`)
- Per-transaction limits prevent draining in a single call
- Budget is tracked per chain, per token -- one token's budget does not affect others

### API Key Restrictions

Agent API keys:
- Can only sign with signers listed in `allowed_signers`
- Cannot modify rules, templates, or API keys
- Cannot apply presets
- Can read rules and budgets to understand their constraints
- Are rate-limited (configurable, default 300 req/min)

## SDK Examples

### Python

```python
import requests
import time
import hashlib
import hmac
from nacl.signing import SigningKey

class RemoteSignerAgent:
    def __init__(self, base_url, api_key_id, private_key_hex):
        self.base_url = base_url
        self.api_key_id = api_key_id
        self.signing_key = SigningKey(bytes.fromhex(private_key_hex)[:32])

    def _sign_request(self, method, path, body=""):
        timestamp = str(int(time.time()))
        nonce = hashlib.sha256(f"{timestamp}{path}".encode()).hexdigest()[:16]
        message = f"{method}\n{path}\n{timestamp}\n{nonce}\n{body}"
        signature = self.signing_key.sign(message.encode()).signature.hex()
        return {
            "X-API-Key": self.api_key_id,
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Signature": signature,
            "Content-Type": "application/json",
        }

    def sign_transaction(self, chain_id, signer, tx):
        path = "/api/v1/evm/sign"
        body = {
            "sign_type": "transaction",
            "chain_id": chain_id,
            "signer": signer,
            "transaction": tx,
        }
        import json
        body_str = json.dumps(body)
        headers = self._sign_request("POST", path, body_str)
        resp = requests.post(f"{self.base_url}{path}", headers=headers, data=body_str)
        return resp.json()

    def get_budgets(self, rule_id):
        path = f"/api/v1/evm/rules/{rule_id}/budgets"
        headers = self._sign_request("GET", path)
        resp = requests.get(f"{self.base_url}{path}", headers=headers)
        return resp.json()

    def list_rules(self):
        path = "/api/v1/evm/rules"
        headers = self._sign_request("GET", path)
        resp = requests.get(f"{self.base_url}{path}", headers=headers)
        return resp.json()
```

### Go

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/ivanzzeth/remote-signer/pkg/client"
    "github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

func main() {
    c, err := client.NewClient(client.Config{
        BaseURL:       "https://signer.example.com",
        APIKeyID:      "trading-bot",
        PrivateKeyHex: "<ed25519-private-key-hex>",
    })
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // List rules to find your agent rules
    rules, err := c.EVM.Rules.List(ctx, nil)
    if err != nil {
        log.Fatal(err)
    }
    for _, r := range rules.Rules {
        fmt.Printf("Rule: %s (chain=%v, enabled=%t)\n", r.Name, r.ChainID, r.Enabled)
    }

    // Check budget before signing
    if len(rules.Rules) > 0 {
        budgets, err := c.EVM.Rules.ListBudgets(ctx, rules.Rules[0].ID)
        if err != nil {
            log.Fatal(err)
        }
        for _, b := range budgets {
            fmt.Printf("Budget unit=%s spent=%s/%s tx_count=%d\n",
                b.Unit, b.Spent, b.MaxTotal, b.TxCount)
        }
    }

    // Sign a transaction
    signer := evm.NewRemoteSigner(c.EVM.Sign,
        common.HexToAddress("0xYourAgentSigner"), "1")
    sig, err := signer.SignTransaction(ctx, tx)
    if err != nil {
        // Check if budget exceeded
        log.Printf("Sign failed: %v", err)
    }
}
```

---

## dApp Frontend Automation (Playwright + EIP-1193)

For agents that need to interact with dApp frontends (Uniswap, Aave, etc.), Remote Signer provides an EIP-1193 provider that bridges browser wallet interactions to the signing service.

### Architecture

```
┌─────────────────────┐     EIP-1193      ┌──────────────────┐     mTLS/Ed25519     ┌─────────────────┐
│  Playwright Browser  │ ◄──────────────► │ EIP-1193 Provider │ ◄────────────────► │  Remote Signer  │
│  (Uniswap, Aave...) │   inject wallet   │ (in-browser shim) │   sign + broadcast  │  (rules+budget) │
└─────────────────────┘                   └──────────────────┘                     └─────────────────┘
                                                                                          │
                                                                                   ┌──────┴──────┐
                                                                                   │ Admin (MCP) │
                                                                                   │ approve txs │
                                                                                   └─────────────┘
```

### Roles

| Role | Tooling | Responsibilities |
|------|---------|-----------------|
| **Agent** | Playwright + EIP-1193 Provider | Navigate dApp UI, select tokens/amounts, confirm swaps |
| **Admin** | CLI / MCP / TUI | Monitor authorizing requests, approve security-sensitive operations (approve, permit) |

### E2E Flow: Uniswap Swap (Polygon USDC.e → USDC)

#### Phase 0: Prerequisites

```bash
# 1. Remote-signer running with simulation + budget
docker compose up -d remote-signer

# 2. Signer unlocked
remote-signer-cli evm signer unlock 0x764602... --api-key-id admin ...

# 3. Agent rules deployed (agent-sign + agent-safety + simulation budget)
remote-signer-cli preset create-from agent.preset.js.yaml \
  --set allowed_spenders="0x3b86917369b83a6892f553609f3c2f439c184e31" \
  --config config.yaml --write

# 4. RPC gateway available (for simulation + nonce + broadcast)
curl http://localhost:8545/evm/137 -X POST -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'
```

#### Phase 1: Agent opens dApp

```
Agent (Playwright):
  1. Launch Chromium with EIP-1193 provider injected
     → Provider configured with: remote-signer URL, agent API key, signer address, chain ID
  2. Navigate to app.uniswap.org
  3. Wallet auto-connects (EIP-6963 announcement)
  4. Switch to Polygon network (chain ID 137)
  5. Select swap: USDC.e → USDC, amount: 1
  6. Click "Swap"
```

#### Phase 2: Approve flow (security-sensitive → manual approval)

```
Uniswap → eth_sendTransaction(approve USDC.e for router)
  │
  ▼
EIP-1193 Provider → POST /api/v1/evm/sign (agent API key)
  │
  ▼
Remote Signer:
  ├─ Blocklist: approve() selector not blocked (only setApprovalForAll(true) is)
  ├─ Whitelist: no match (no tx whitelist rule)
  ├─ Simulation fallback:
  │   ├─ eth_simulateV1: success, Approval event detected (owner=managed signer, value>0)
  │   ├─ Budget: no outflow (approve doesn't move tokens) → passes
  │   └─ Approval detected → return no_match → manual approval required
  └─ Status: authorizing (waiting for signer owner)

Admin (MCP/CLI):
  ├─ evm_list_requests(status=authorizing) → sees approve request
  ├─ Reviews: approve USDC.e to known DEX router ✓
  └─ evm_approve_request(id, approved=true) → signed

EIP-1193 Provider:
  ├─ Polls GET /api/v1/evm/requests/{id} until status=completed
  ├─ Gets signed_data → broadcasts via eth_sendRawTransaction
  └─ Returns tx_hash to Uniswap

Uniswap: shows "Approve confirmed" ✓
```

#### Phase 3: Swap flow (budget-gated → auto-approve)

```
Uniswap → eth_sendTransaction(swap via router)
  │
  ▼
EIP-1193 Provider → POST /api/v1/evm/sign (agent API key)
  │
  ▼
Remote Signer:
  ├─ Blocklist: swap selector not blocked ✓
  ├─ Whitelist: no match
  ├─ Simulation fallback:
  │   ├─ eth_simulateV1: success
  │   ├─ Events: Approval(value=0) for signer → skipped (transferFrom side effect)
  │   ├─ Balance changes: -1 USDC.e, +0.999 USDC
  │   ├─ Gas cost: ~366k gas × gasFeeCap → added to native outflow
  │   ├─ Budget: 1 USDC.e ≤ 100 max, 0.005 MATIC ≤ 0.01 max → passes
  │   ├─ No dangerous state changes → passes
  │   └─ Decision: allow → auto-sign (no admin needed)
  └─ Status: completed (immediate)

EIP-1193 Provider:
  ├─ Gets signed_data immediately
  ├─ Broadcasts via eth_sendRawTransaction
  └─ Returns tx_hash to Uniswap

Uniswap: shows "Swap confirmed" ✓
```

#### Phase 4: Verification

```bash
# Budget deducted
docker compose exec postgres psql -U signer -d remote_signer \
  -c "SELECT unit, spent, max_total FROM rule_budgets WHERE rule_id LIKE 'sim:%';"
# → 137:0x2791bca1... spent=1000000 (1 USDC.e)

# On-chain confirmed
cast receipt <approve_tx_hash> --rpc-url http://localhost:8545/evm/137
cast receipt <swap_tx_hash> --rpc-url http://localhost:8545/evm/137
```

### Security Model in dApp Automation

| Operation | Detection Method | Action | Admin Needed |
|-----------|-----------------|--------|-------------|
| ERC20 approve | Simulation: Approval event, owner=managed signer, value>0 | Manual approval | **Yes** |
| ERC20 transfer / swap | Simulation: balance change outflow | Budget check → auto-allow | No |
| Permit / Permit2 sign | Rule: `allowed_spenders` whitelist | Allow if spender known | No |
| transferOwnership | Blocklist: selector match | **Block** | No (hard reject) |
| OwnershipTransferred (via multicall) | Simulation: dangerous event | Manual approval | **Yes** |
| Proxy upgrade | Simulation: Upgraded event | Manual approval | **Yes** |
| Native transfer (gas) | Simulation: gasUsed × gasPrice | Native budget check | No |

### Key Design Principles

1. **Agent is autonomous within budget** — normal swaps, transfers auto-sign without admin
2. **Security-sensitive ops need human review** — approve, ownership changes, proxy upgrades
3. **Simulation is the security boundary** — not calldata selectors, not blocklist alone
4. **Budget is verified, not self-reported** — server simulates and checks actual balance changes
5. **Admin can be async** — agent's EIP-1193 provider polls; admin approves when available

### File Locations

| Component | Location |
|-----------|----------|
| Playwright POC | `projects/tech-research/playwright-poc/` |
| EIP-1193 Provider | `pkg/js-client/` (`EIP1193Provider` class) |
| Web3 context helper | `playwright-poc/src/web3-context.mjs` |
| Remote signer bridge | `playwright-poc/src/remote-signer-bridge.mjs` |
| EIP-1193 browser shim | `playwright-poc/src/eip1193-shim.mjs` |
