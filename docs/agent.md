# Agent Integration Guide

This guide covers how AI agents interact with the remote-signer service. The agent feature provides a controlled environment where bots can sign transactions and messages across multiple chains, with per-token budget tracking and safety guardrails.

## Overview

The agent feature consists of:

- **Agent Template** (`rules/templates/agent.template.js.yaml`): Three sub-rules that define what an agent can do
  - `agent-tx` (whitelist): Allows any transaction; dynamically tracks budget by token/native/count
  - `agent-sign` (whitelist): Allows `personal_sign` (with length limit) and `typed_data` (Permit budget tracked)
  - `agent-safety` (blocklist): Blocks dangerous admin functions (transferOwnership, upgradeTo, setApprovalForAll(true), etc.)
- **Agent Preset** (`rules/presets/agent.preset.js.yaml`): Deploys the template across 5 chains (Ethereum, Polygon, Arbitrum, Optimism, Base)
- **Agent API Key**: A role between `admin` and `dev` that can sign + read rules/budgets but cannot modify rules
- **Dynamic Budget**: Automatically tracks spending per token without pre-declaring every token

## Setup

### 1. Deploy Agent Preset

Apply the agent preset to create rules for all supported chains:

```bash
remote-signer-cli preset create-from agent.preset.js.yaml \
  --config config.yaml \
  --write
```

Or via API (admin key required):

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
    admin: false
    agent: true
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
