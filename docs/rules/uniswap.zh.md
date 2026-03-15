# Uniswap DEX 签名规则

Uniswap 去中心化交易所协议，支持 V2、V3 和 V4，覆盖主流 EVM 链。V2 使用简单 Router，包含 6 个 swap 方法；V3 引入集中流动性，使用 tuple 编码参数，支持逐 token/金额验证；V4 使用 Universal Router，将 V2+V3+V4 swap 合并为单一入口。

**模板文件**：`dex_swap.template.js.yaml`（V2）、`dex_swap_v3.template.js.yaml`（V3/V4）

---

## 1. 概述

| 版本 | Router 类型 | 关键区别 |
| --- | --- | --- |
| V2 | Router02 | 6 个 swap 方法，动态数组 path 路由，不做深层 calldata 验证 |
| V3 | SwapRouter | Tuple 编码参数（exactInputSingle/exactOutputSingle），支持 token/金额验证 |
| V4 | Universal Router | V2+V3+V4 统一入口，仅做方法选择器白名单校验（不做深层 calldata 验证） |

---

## 2. 官方合约地址

### V2 Router 地址

| 链 | Chain ID | Router 地址 |
| --- | --- | --- |
| Ethereum | 1 | 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D |
| Polygon PoS | 137 | 0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff |
| BNB Chain | 56 | 0x10ED43C718714eb63d5aA57B78B54704E256024E |
| Arbitrum One | 42161 | 0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506 |
| Avalanche | 43114 | 0x60aE616a2155Ee3d9A68541Ba4544862310933d4 |
| Optimism | 10 | 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D |

### V3 SwapRouter 地址

| 链 | Chain ID | SwapRouter 地址 |
| --- | --- | --- |
| Ethereum | 1 | 0xE592427A0AEce92De3Edee1F18E0157C05861564 |
| Polygon PoS | 137 | 0xE592427A0AEce92De3Edee1F18E0157C05861564 |
| Arbitrum One | 42161 | 0xE592427A0AEce92De3Edee1F18E0157C05861564 |
| Optimism | 10 | 0xE592427A0AEce92De3Edee1F18E0157C05861564 |
| Base | 8453 | 0x2626664c2603336E57B271c5C0b26F421741e481 |
| BNB Chain | 56 | 0xB971eF87ede563556b2ED4b1C0b0019111Dd85d2 |
| Avalanche | 43114 | 0xbb00FF08d01D300023C629E8fFfFcb65A5a578cE |

### V4 Universal Router 地址

| 链 | Chain ID | Universal Router 地址 |
| --- | --- | --- |
| Ethereum | 1 | 0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD |
| Polygon PoS | 137 | 0xec7BE89e9d109e7e3Fec59c222CF297125FEFda2 |
| Arbitrum One | 42161 | 0x5E325eDA8064b456f4781070C0738d849c824258 |
| Optimism | 10 | 0xCb1355ff08Ab38bBCE60111F1bb2B784bE25D7e8 |
| Base | 8453 | 0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD |
| BNB Chain | 56 | 0x4Dae2f939ACf50408e13d58534Ff8c2776d45265 |
| Avalanche | 43114 | 0x4Dae2f939ACf50408e13d58534Ff8c2776d45265 |

---

## 3. V2 规则：Swap 方法白名单

V2 验证：仅做 router 地址白名单 + 方法选择器白名单校验。动态数组参数（path、amounts）不做解码验证。

| 规则 | 合约 | 方法 | 选择器 | 参数 | 备注 |
| --- | --- | --- | --- | --- | --- |
| swapExactTokensForTokens | router_address | swapExactTokensForTokens(uint256,uint256,address[],address,uint256) | 0x38ed1739 | Router 必须匹配配置 | 精确输入，可变输出 |
| swapExactETHForTokens | router_address | swapExactETHForTokens(uint256,address[],address,uint256) | 0x7ff36ab5 | Router 必须匹配配置 | ETH 输入，token 输出 |
| swapExactTokensForETH | router_address | swapExactTokensForETH(uint256,uint256,address[],address,uint256) | 0x18cbafe5 | Router 必须匹配配置 | Token 输入，ETH 输出 |
| swapTokensForExactTokens | router_address | swapTokensForExactTokens(uint256,uint256,address[],address,uint256) | 0x8803dbee | Router 必须匹配配置 | 可变输入，精确输出 |
| swapETHForExactTokens | router_address | swapETHForExactTokens(uint256,address[],address,uint256) | 0xfb3bdb41 | Router 必须匹配配置 | ETH 输入，精确 token 输出 |
| swapTokensForExactETH | router_address | swapTokensForExactETH(uint256,uint256,address[],address,uint256) | 0x4a25d94a | Router 必须匹配配置 | Token 输入，精确 ETH 输出 |

**配置变量**：

| 变量 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| router_address | address | 是 | V2 Router 合约地址 |

---

## 4. V3 规则：SwapRouter 与 Tuple 验证

V3 验证：router 地址 + 方法选择器白名单 + 单跳 swap 的 tuple 解码 token/金额校验。

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

| 规则 | 合约 | 方法 | 选择器 | 参数 | 备注 |
| --- | --- | --- | --- | --- | --- |
| exactInputSingle | router_address | exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160)) | 0x414bf389 | tokenIn 在 allowed_token_in 中<br>tokenOut 在 allowed_token_out 中<br>amountIn <= max_amount_in | Tuple 解码；逐 token + 金额验证 |

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

| 规则 | 合约 | 方法 | 选择器 | 参数 | 备注 |
| --- | --- | --- | --- | --- | --- |
| exactOutputSingle | router_address | exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160)) | 0xdb3e2198 | tokenIn 在 allowed_token_in 中<br>tokenOut 在 allowed_token_out 中<br>amountInMaximum <= max_amount_in | Tuple 解码；逐 token + 金额验证 |

### 可识别但未完全验证的方法

这些方法可通过选择器识别，但会被拒绝并提示 "method not fully validated"，因为多跳路径编码无法安全解码：

| 方法 | 选择器 | 备注 |
| --- | --- | --- |
| exactInput((bytes,address,uint256,uint256,uint256)) | 0xc04b8d59 | 多跳，path 字节未解码 |
| exactOutput((bytes,address,uint256,uint256,uint256)) | 0xf28c0498 | 多跳，path 字节未解码 |
| multicall(uint256,bytes[]) | 0x5ae401dc | 批量调用，内部数据未解码 |
| multicall(bytes[]) | 0xac9650d8 | 批量调用，内部数据未解码 |
| execute(bytes,bytes[],uint256) | 0x3593564c | V4 Universal Router，内部命令未解码 |

**配置变量**：

| 变量 | 类型 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- | --- |
| router_address | address | 是 | - | V3 SwapRouter 合约地址 |
| allowed_token_in | address_list | 否 | ""（任意） | 逗号分隔的允许输入 token 地址 |
| allowed_token_out | address_list | 否 | ""（任意） | 逗号分隔的允许输出 token 地址 |
| max_amount_in | string | 否 | "-1"（无上限） | 每笔 swap 最大输入金额，以 token 最小单位计 |

---

## 5. V4 规则：Universal Router

V4 使用与 V3 相同的 `dex_swap_v3.template.js.yaml` 模板。Universal Router 的 `execute(bytes,bytes[],uint256)` 方法可通过选择器识别，但内部命令字节不做深层验证，仅做 router 地址 + 方法选择器白名单校验。

生产环境中使用 Universal Router 时，仅 `exactInputSingle` 和 `exactOutputSingle` 调用会获得完整的 tuple 级别验证。其他方法（execute、multicall）默认被拒绝。

---

## 6. 预设使用示例

### 部署 V2 规则到所有链

```bash
remote-signer-cli preset create-from uniswap_v2.preset.js.yaml --config config.yaml --write
```

### 部署 V3 规则到所有链（含 token 限制）

```bash
remote-signer-cli preset create-from uniswap_v3.preset.js.yaml \
  --set allowed_token_in=0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 \
  --set max_amount_in=10000000000000000000 \
  --config config.yaml --write
```

### 部署 V4 Universal Router 规则到所有链

```bash
remote-signer-cli preset create-from uniswap_v4.preset.js.yaml --config config.yaml --write
```

### 部署单链 V2（自定义 router）

```bash
remote-signer-cli preset create-from dex_swap.preset.js.yaml \
  --set chain_id=1 \
  --set router_address=0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D \
  --config config.yaml --write
```

### 部署单链 V3（含 token 和金额限制）

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

## 函数选择器速查

选择器 = keccak256(函数签名) 前 4 字节。可用 `cast sig "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"` 验证。

| 函数签名 | 选择器 |
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
