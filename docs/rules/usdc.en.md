# USDC (Circle) Signing Rules

Circle USDC stablecoin multi-chain rules. USDC is Circle's native stablecoin deployed across major EVM chains. Rules cover ERC20 transfer, transferFrom, and approve methods with parameter-level validation, amount caps, and budget metering.

**Template file**: `erc20.template.js.yaml`
**Preset file**: `usdc.preset.js.yaml`

---

## 1. Overview

USDC is issued natively by Circle on each supported chain (native USDC). This is distinct from bridged USDC (USDC.e) which is a wrapped version bridged from Ethereum. The addresses below are for Circle-issued native USDC only.

All amounts use USDC's 6 decimal precision: 1 USDC = 1000000, 1000 USDC = 1000000000.

---

## 2. Official Contract Addresses

Addresses sourced from [Circle's official documentation](https://developers.circle.com/stablecoins/docs/usdc-on-main-networks).

| Chain | Chain ID | USDC Address |
| --- | --- | --- |
| Ethereum | 1 | 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 |
| Polygon PoS | 137 | 0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359 |
| Arbitrum One | 42161 | 0xaf88d065e77c8cC2239327C5EDb3A432268e5831 |
| Optimism | 10 | 0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85 |
| Avalanche C-Chain | 43114 | 0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E |
| Base | 8453 | 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 |

---

## 3. Rules

### 3.1 transfer / transferFrom

Rule `erc20-transfer-limit`: validates transfer and transferFrom on the configured token contract.

| Rule | Contract | Method | Selector | Params | Notes |
| --- | --- | --- | --- | --- | --- |
| transfer | token_address | transfer(address,uint256) | 0xa9059cbb | to in allowed_recipients<br>amount <= max_transfer_amount | Direct token transfer |
| transferFrom | token_address | transferFrom(address,address,uint256) | 0x23b872dd | from in allowed_transfer_from<br>to in allowed_recipients<br>amount <= max_transfer_amount | Third-party transfer |

### 3.2 approve

Rule `erc20-approve-limit`: validates approve on the configured token contract.

| Rule | Contract | Method | Selector | Params | Notes |
| --- | --- | --- | --- | --- | --- |
| approve | token_address | approve(address,uint256) | 0x095ea7b3 | spender in allowed_spenders<br>amount <= max_approve_amount | Token spending approval |

---

## 4. Budget Metering

The ERC20 template includes a `validateBudget` function that extracts transfer/approve amounts for budget tracking.

- **transfer**: extracts `amount` (2nd parameter) from `transfer(address,uint256)`
- **transferFrom**: extracts `amount` (3rd parameter) from `transferFrom(address,address,uint256)`
- **approve**: extracts `amount` (2nd parameter) from `approve(address,uint256)`

Budget unit is `${chain_id}:${token_address}`, allowing per-chain per-token budget tracking. The preset configures:

| Budget Field | Value | Description |
| --- | --- | --- |
| unit | `${chain_id}:${token_address}` | Per-chain per-token budget scope |
| max_total | `${max_transfer_amount}` | Total budget cap per period |
| max_per_tx | `${max_transfer_amount}` | Per-transaction cap |
| max_tx_count | 0 (unlimited) | No transaction count limit |
| alert_pct | 80 | Alert at 80% budget usage |

Budget resets according to `budget_period` (default: 24h).

---

## 5. Configuration Variables

| Variable | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| token_address | address | Yes | - | USDC contract address (set per chain by preset matrix) |
| max_transfer_amount | string | Yes | "" (must set) | Max amount per transfer/transferFrom, in smallest unit (6 decimals). E.g. 1000000000 = 1000 USDC |
| max_approve_amount | string | No | "-1" (no cap) | Max amount per approve. -1 = no cap, 0 = block all |
| budget_period | string | No | "24h" | Budget reset period (e.g. 24h, 168h) |
| allowed_recipients | address_list | **Yes** | - | Comma-separated addresses allowed as transfer(to) or transferFrom(..., to). REQUIRED: must explicitly list allowed recipient addresses |
| allowed_spenders | address_list | **Yes** | - | Comma-separated addresses allowed as approve(spender). REQUIRED: must explicitly list allowed spender addresses |
| allowed_transfer_from | address_list | No | "" (any) | Comma-separated addresses allowed as transferFrom(from, ...) |

---

## 6. Preset Usage Examples

### Deploy USDC rules for all chains with transfer cap

`allowed_recipients` and `allowed_spenders` are **required** -- you must explicitly specify them.

```bash
remote-signer-cli preset create-from usdc.preset.js.yaml \
  --set max_transfer_amount=1000000000 \
  --set allowed_recipients=0x5B38Da6a701c568545dCfcB03FcB875f56beddC4 \
  --set allowed_spenders=0xE592427A0AEce92De3Edee1F18E0157C05861564 \
  --config config.yaml --write
```

### Deploy with custom budget period

```bash
remote-signer-cli preset create-from usdc.preset.js.yaml \
  --set max_transfer_amount=10000000000 \
  --set max_approve_amount=100000000000 \
  --set allowed_recipients=0x5B38Da6a701c568545dCfcB03FcB875f56beddC4 \
  --set allowed_spenders=0xE592427A0AEce92De3Edee1F18E0157C05861564 \
  --set budget_period=168h \
  --config config.yaml --write
```

### Deploy single-chain with ERC20 template directly

```bash
remote-signer-cli preset create-from erc20.preset.js.yaml \
  --set chain_id=1 \
  --set token_address=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
  --set max_transfer_amount=1000000000 \
  --config config.yaml --write
```

---

## Function Selector Reference

Selector = first 4 bytes of keccak256(function_signature). Verify with `cast sig "transfer(address,uint256)"`.

| Function Signature | Selector |
| --- | --- |
| transfer(address,uint256) | 0xa9059cbb |
| transferFrom(address,address,uint256) | 0x23b872dd |
| approve(address,uint256) | 0x095ea7b3 |
