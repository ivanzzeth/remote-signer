# Uniswap DEX Signing Rules

Uniswap decentralized exchange protocol, supporting V2, V3, and V4 across major EVM chains in a **single unified template + preset**. The unified rule dispatches by transaction recipient address: if the `tx.to` matches any of the V2/V3/V4 router addresses, it validates the swap; if it matches WETH, it validates wrap/unwrap; if it matches a known Uniswap router and the selector is `approve(address,uint256)`, it validates the ERC20 approval. Permit2 interactions are also whitelisted.

**Template**: `evm/uniswap` (single `evm_js` rule)  
**Preset**: `evm/uniswap` (one rule, per-chain Matrix overrides)

---

## 1. Key Concept: Rule-Level Matrix

Instead of one rule per chain (old multi-preset approach), the unified template uses **rule-level Variables + Matrix**:

- **Variables** hold base defaults (e.g. Ethereum mainnet addresses)
- **Matrix** is a per-chain override table: each row has a `chain_id` and chain-specific values (router addresses, WETH address)
- At evaluation time, `resolveRuleConfig()` merges Variables with the Matrix row matching the request's `chain_id`

This means **one rule covers all chains**. Adding a new chain means adding one row to the Matrix — no new rule needed.

**Supported chains** (7): Ethereum (1), Polygon PoS (137), BNB Chain (56), Arbitrum One (42161), Optimism (10), Base (8453), Avalanche C-Chain (43114)

---

## 2. Rule Coverage

The unified rule handles these interactions:

### Swap (V2/V3/V4)

| Router | Methods Validated |
|--------|-------------------|
| V2 Router02 | 6 swap methods (5-param and 4-param), full parameter validation: recipient=signer, token path allowlists, amount cap |
| V3 SwapRouter | `exactInputSingle`, `exactOutputSingle` — tuple-decoded token/amount validation |
| V4 Universal Router | `execute`, `multicall`, `multicall(uint256,bytes[])`, `sweep`, `unwrapWETH9`, `unwrapWETH9WithFee`, `pay`, `payPortion` — method selector whitelist only |

### ERC20 Approve

- `approve(address,uint256)` — spender must be a known Uniswap router, amount checked against `max_amount_in`

### WETH

- `deposit()` — value checked against `max_amount_in`
- `withdraw(uint256)` — amount checked against `max_amount_in`

### Permit2

- `permit(address,address,uint160,uint48,uint48)` — whitelisted
- `permitTransferFrom(...)` — whitelisted

---

## 3. Configuration Variables

| Variable | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| v2_router_address | address | Yes | - | Uniswap V2 Router address |
| v3_router_address | address | Yes | - | Uniswap V3 SwapRouter address |
| universal_router_address | address | Yes | - | Uniswap V4 Universal Router address |
| weth_address | address | Yes | - | Wrapped native token address |
| permit2_address | address | No | `0x000000000022D473030F116dDEE9F6B43aC78BA3` | Permit2 contract |
| allowed_token_in | address_list | No | "" (any) | Comma-separated allowed input token addresses |
| allowed_token_out | address_list | No | "" (any) | Comma-separated allowed output token addresses |
| max_amount_in | string | No | "-1" (no cap) | Max input amount per operation |

---

## 4. Usage

### Apply via API (recommended)

```bash
remote-signer evm preset apply evm/uniswap --url http://127.0.0.1:8548 --api-key-id admin
```

### Apply via CLI (config-file workflow)

```bash
remote-signer preset create-from uniswap --config config.yaml --write
```

### Update Matrix via PATCH API (add a new chain)

```bash
curl -X PATCH http://127.0.0.1:8548/api/v1/evm/rules/<rule-id> \
  -H "Content-Type: application/json" \
  -d '{
    "matrix": [
      {"chain_id": "1", "v2_router_address": "0x7a25...", ...},
      {"chain_id": "137", "v2_router_address": "0xa5E0...", ...},
      {"chain_id": "8453", "v2_router_address": "0x4752...", ...}
    ]
  }'
```

### Update Variables via PATCH API

```bash
curl -X PATCH http://127.0.0.1:8548/api/v1/evm/rules/<rule-id> \
  -H "Content-Type: application/json" \
  -d '{"variables": {"max_amount_in": "5000000000000000000"}}'
```

---

## 5. Official Contract Addresses

See the preset file at `rules/presets/evm/uniswap.yaml` for the complete per-chain address matrix.

---

## Function Selector Reference

Selector = first 4 bytes of keccak256(function_signature). Verify with `cast sig "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"`.

| Function Signature | Selector |
| --- | --- |
| swapExactTokensForTokens(uint256,uint256,address[],address,uint256) | 0x38ed1739 |
| swapExactETHForTokens(uint256,address[],address,uint256) | 0x7ff36ab5 |
| swapExactTokensForETH(uint256,uint256,address[],address,uint256) | 0x18cbafe5 |
| swapTokensForExactTokens(uint256,uint256,address[],address,uint256) | 0x8803dbee |
| swapETHForExactTokens(uint256,address[],address,uint256) | 0xfb3bdb41 |
| swapTokensForExactETH(uint256,uint256,address[],address,uint256) | 0x4a25d94a |
| exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160)) | 0x414bf389 |
| exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160)) | 0xdb3e2198 |
| execute(bytes,bytes[],uint256) | 0x3593564c |
| multicall(uint256,bytes[]) | 0x5ae401dc |
| multicall(bytes[]) | 0xac9650d8 |
| approve(address,uint256) | 0x095ea7b3 |
| deposit() | 0xd0e30db0 |
| withdraw(uint256) | 0x2e1a7d4d |
