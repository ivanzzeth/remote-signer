# Uniswap DEX Signing Rules

Uniswap decentralized exchange protocol, supporting V2, V3, and V4 across major EVM chains. V2 uses a simple Router with 6 swap methods; V3 introduces concentrated liquidity with tuple-encoded parameters and per-token/amount validation; V4 uses a Universal Router that combines V2+V3+V4 swaps into a single entry point.

**Template files**: `dex_swap.template.js.yaml` (V2), `dex_swap_v3.template.js.yaml` (V3/V4)

---

## 1. Overview

| Version | Router Type | Key Difference |
| --- | --- | --- |
| V2 | Router02 | 6 swap methods, full parameter validation: recipient=signer, token path allowlists, amount cap |
| V3 | SwapRouter | Tuple-encoded params (exactInputSingle/exactOutputSingle), token/amount validation |
| V4 | Universal Router | Single entry point for V2+V3+V4, method selector whitelist only (no deep calldata validation) |

---

## 2. Official Contract Addresses

### V2 Router Addresses

| Chain | Chain ID | Router Address |
| --- | --- | --- |
| Ethereum | 1 | 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D |
| Polygon PoS | 137 | 0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff |
| BNB Chain | 56 | 0x10ED43C718714eb63d5aA57B78B54704E256024E |
| Arbitrum One | 42161 | 0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506 |
| Avalanche | 43114 | 0x60aE616a2155Ee3d9A68541Ba4544862310933d4 |
| Optimism | 10 | 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D |

### V3 SwapRouter Addresses

| Chain | Chain ID | SwapRouter Address |
| --- | --- | --- |
| Ethereum | 1 | 0xE592427A0AEce92De3Edee1F18E0157C05861564 |
| Polygon PoS | 137 | 0xE592427A0AEce92De3Edee1F18E0157C05861564 |
| Arbitrum One | 42161 | 0xE592427A0AEce92De3Edee1F18E0157C05861564 |
| Optimism | 10 | 0xE592427A0AEce92De3Edee1F18E0157C05861564 |
| Base | 8453 | 0x2626664c2603336E57B271c5C0b26F421741e481 |
| BNB Chain | 56 | 0xB971eF87ede563556b2ED4b1C0b0019111Dd85d2 |
| Avalanche | 43114 | 0xbb00FF08d01D300023C629E8fFfFcb65A5a578cE |

### V4 Universal Router Addresses

| Chain | Chain ID | Universal Router Address |
| --- | --- | --- |
| Ethereum | 1 | 0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD |
| Polygon PoS | 137 | 0xec7BE89e9d109e7e3Fec59c222CF297125FEFda2 |
| Arbitrum One | 42161 | 0x5E325eDA8064b456f4781070C0738d849c824258 |
| Optimism | 10 | 0xCb1355ff08Ab38bBCE60111F1bb2B784bE25D7e8 |
| Base | 8453 | 0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD |
| BNB Chain | 56 | 0x4Dae2f939ACf50408e13d58534Ff8c2776d45265 |
| Avalanche | 43114 | 0x4Dae2f939ACf50408e13d58534Ff8c2776d45265 |

---

## 3. V2 Rules: Swap with Full Parameter Validation

V2 validation: router address + method selector whitelist + **full parameter-level validation**. All fund-related parameters are decoded and checked:
- **recipient (`to`)** MUST equal the signer address (prevents output theft)
- **amountIn / amountInMax** capped by `max_amount_in`
- **path[0]** (tokenIn) and **path[last]** (tokenOut) checked against allowlists

Methods with 5 ABI params (swapExactTokensForTokens, swapTokensForExactTokens, swapExactTokensForETH, swapTokensForExactETH) decode `(uint256, uint256, address[], address, uint256)`. Methods with 4 ABI params (swapExactETHForTokens, swapETHForExactTokens) decode `(uint256, address[], address, uint256)`. In both cases the `to` (recipient) address is validated against the signer.

| Rule | Contract | Method | Selector | Params | Notes |
| --- | --- | --- | --- | --- | --- |
| swapExactTokensForTokens | router_address | swapExactTokensForTokens(uint256,uint256,address[],address,uint256) | 0x38ed1739 | recipient=signer<br>amountIn <= max_amount_in<br>path[0] in allowed_token_in<br>path[last] in allowed_token_out | Exact input, variable output |
| swapExactETHForTokens | router_address | swapExactETHForTokens(uint256,address[],address,uint256) | 0x7ff36ab5 | recipient=signer<br>path[0] in allowed_token_in<br>path[last] in allowed_token_out | ETH in, token out |
| swapExactTokensForETH | router_address | swapExactTokensForETH(uint256,uint256,address[],address,uint256) | 0x18cbafe5 | recipient=signer<br>amountIn <= max_amount_in<br>path[0] in allowed_token_in<br>path[last] in allowed_token_out | Token in, ETH out |
| swapTokensForExactTokens | router_address | swapTokensForExactTokens(uint256,uint256,address[],address,uint256) | 0x8803dbee | recipient=signer<br>amountIn <= max_amount_in<br>path[0] in allowed_token_in<br>path[last] in allowed_token_out | Variable input, exact output |
| swapETHForExactTokens | router_address | swapETHForExactTokens(uint256,address[],address,uint256) | 0xfb3bdb41 | recipient=signer<br>path[0] in allowed_token_in<br>path[last] in allowed_token_out | ETH in, exact token out |
| swapTokensForExactETH | router_address | swapTokensForExactETH(uint256,uint256,address[],address,uint256) | 0x4a25d94a | recipient=signer<br>amountIn <= max_amount_in<br>path[0] in allowed_token_in<br>path[last] in allowed_token_out | Token in, exact ETH out |

**Configuration variables**:

| Variable | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| router_address | address | Yes | - | V2 Router contract address |
| allowed_token_in | address_list | No | "" (any) | Comma-separated allowed input token addresses (path[0]) |
| allowed_token_out | address_list | No | "" (any) | Comma-separated allowed output token addresses (path[last]) |
| max_amount_in | string | No | "-1" (no cap) | Max input amount per swap, in token smallest unit |

---

## 4. V3 Rules: SwapRouter with Tuple Validation

V3 validation: router address + method selector whitelist + tuple-decoded token/amount checks for single-hop swaps. **recipient MUST equal the signer** (prevents output theft).

### exactInputSingle

```solidity
struct ExactInputSingleParams {
    address tokenIn;
    address tokenOut;
    uint24 fee;
    address recipient;
    uint256 deadline;
    uint256 amountIn;
    uint256 amountOutMinimum;
    uint160 sqrtPriceLimitX96;
}
```

| Rule | Contract | Method | Selector | Params | Notes |
| --- | --- | --- | --- | --- | --- |
| exactInputSingle | router_address | exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160)) | 0x414bf389 | recipient=signer<br>tokenIn in allowed_token_in<br>tokenOut in allowed_token_out<br>amountIn <= max_amount_in | Tuple decoded; recipient + per-token + per-amount validation |

### exactOutputSingle

```solidity
struct ExactOutputSingleParams {
    address tokenIn;
    address tokenOut;
    uint24 fee;
    address recipient;
    uint256 deadline;
    uint256 amountOut;
    uint256 amountInMaximum;
    uint160 sqrtPriceLimitX96;
}
```

| Rule | Contract | Method | Selector | Params | Notes |
| --- | --- | --- | --- | --- | --- |
| exactOutputSingle | router_address | exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160)) | 0xdb3e2198 | recipient=signer<br>tokenIn in allowed_token_in<br>tokenOut in allowed_token_out<br>amountInMaximum <= max_amount_in | Tuple decoded; recipient + per-token + per-amount validation |

### Recognized but NOT Fully Validated

These methods are recognized by selector but rejected with "method not fully validated" because multi-hop path encoding cannot be safely decoded:

| Method | Selector | Notes |
| --- | --- | --- |
| exactInput((bytes,address,uint256,uint256,uint256)) | 0xc04b8d59 | Multi-hop, path bytes not decoded |
| exactOutput((bytes,address,uint256,uint256,uint256)) | 0xf28c0498 | Multi-hop, path bytes not decoded |
| multicall(uint256,bytes[]) | 0x5ae401dc | Batched calls, inner data not decoded |
| multicall(bytes[]) | 0xac9650d8 | Batched calls, inner data not decoded |
| execute(bytes,bytes[],uint256) | 0x3593564c | V4 Universal Router, inner commands not decoded |

**Configuration variables**:

| Variable | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| router_address | address | Yes | - | V3 SwapRouter contract address |
| allowed_token_in | address_list | No | "" (any) | Comma-separated allowed input token addresses |
| allowed_token_out | address_list | No | "" (any) | Comma-separated allowed output token addresses |
| max_amount_in | string | No | "-1" (no cap) | Max input amount per swap, in token smallest unit |

---

## 5. V4 Rules: Universal Router

V4 uses the same `dex_swap_v3.template.js.yaml` template. The Universal Router's `execute(bytes,bytes[],uint256)` method is recognized by selector but NOT deeply validated -- inner command bytes are not decoded. Only the router address + method selector whitelist is enforced.

For production use with the Universal Router, only `exactInputSingle` and `exactOutputSingle` calls receive full tuple-level validation. Other methods (execute, multicall) are rejected by default.

---

## 6. Preset Usage Examples

### Deploy V2 rules for all chains

```bash
remote-signer-cli preset create-from uniswap_v2.preset.js.yaml --config config.yaml --write
```

### Deploy V3 rules for all chains with token restrictions

```bash
remote-signer-cli preset create-from uniswap_v3.preset.js.yaml \
  --set allowed_token_in=0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 \
  --set max_amount_in=10000000000000000000 \
  --config config.yaml --write
```

### Deploy V4 Universal Router rules for all chains

```bash
remote-signer-cli preset create-from uniswap_v4.preset.js.yaml --config config.yaml --write
```

### Deploy single-chain V2 with custom router

```bash
remote-signer-cli preset create-from dex_swap.preset.js.yaml \
  --set chain_id=1 \
  --set router_address=0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D \
  --config config.yaml --write
```

### Deploy single-chain V3 with token and amount restrictions

```bash
remote-signer-cli preset create-from dex_swap_v3.preset.js.yaml \
  --set chain_id=1 \
  --set router_address=0xE592427A0AEce92De3Edee1F18E0157C05861564 \
  --set allowed_token_in=0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 \
  --set allowed_token_out=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
  --set max_amount_in=1000000000000000000 \
  --config config.yaml --write
```

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
| exactInput((bytes,address,uint256,uint256,uint256)) | 0xc04b8d59 |
| exactOutput((bytes,address,uint256,uint256,uint256)) | 0xf28c0498 |
| multicall(uint256,bytes[]) | 0x5ae401dc |
| multicall(bytes[]) | 0xac9650d8 |
| execute(bytes,bytes[],uint256) | 0x3593564c |
