# Uniswap DEX 签名规则

Uniswap 去中心化交易所协议，使用**单一统一模板 + 预设**支持 V2、V3、V4，覆盖主流 EVM 链。统一规则根据交易接收地址分发：若 `tx.to` 匹配任意 V2/V3/V4 router 地址则校验 swap；若匹配 WETH 则校验 wrap/unwrap；若匹配已知 Uniswap router 且选择器为 `approve(address,uint256)` 则校验 ERC20 授权。Permit2 交互也已列入白名单。

**模板**：`evm/uniswap`（单个 `evm_js` 规则）  
**预设**：`evm/uniswap`（一条规则，含各链 Matrix 覆盖）

---

## 1. 核心概念：规则级 Matrix

替代旧的多预设方式（每链一条规则），统一模板使用**规则级 Variables + Matrix**：

- **Variables** 存放基础默认值（如以太坊主网地址）
- **Matrix** 是每条链的覆盖表：每行包含 `chain_id` 和该链特定的值（router 地址、WETH 地址）
- 评估时，`resolveRuleConfig()` 将 Variables 与请求 `chain_id` 匹配的 Matrix 行合并

这意味着**一条规则覆盖所有链**。新增一条链只需在 Matrix 中添加一行——无需新建规则。

**支持的链**（7 条）：Ethereum (1)、Polygon PoS (137)、BNB Chain (56)、Arbitrum One (42161)、Optimism (10)、Base (8453)、Avalanche C-Chain (43114)

---

## 2. 规则覆盖范围

统一规则处理以下交互：

### Swap（V2/V3/V4）

| Router | 校验方法 |
|--------|---------|
| V2 Router02 | 6 个 swap 方法（5 参数和 4 参数），完整参数级验证：recipient=signer、token path 白名单、金额上限 |
| V3 SwapRouter | `exactInputSingle`、`exactOutputSingle` — tuple 解码 token/金额验证 |
| V4 Universal Router | `execute`、`multicall`、`multicall(uint256,bytes[])`、`sweep`、`unwrapWETH9`、`unwrapWETH9WithFee`、`pay`、`payPortion` — 仅方法选择器白名单 |

### ERC20 Approve

- `approve(address,uint256)` — spender 必须是已知 Uniswap router，金额受 `max_amount_in` 约束

### WETH

- `deposit()` — value 受 `max_amount_in` 约束
- `withdraw(uint256)` — amount 受 `max_amount_in` 约束

### Permit2

- `permit(address,address,uint160,uint48,uint48)` — 已列入白名单
- `permitTransferFrom(...)` — 已列入白名单

---

## 3. 配置变量

| 变量 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| v2_router_address | address | 是 | - | Uniswap V2 Router 地址 |
| v3_router_address | address | 是 | - | Uniswap V3 SwapRouter 地址 |
| universal_router_address | address | 是 | - | Uniswap V4 Universal Router 地址 |
| weth_address | address | 是 | - | Wrapped 原生代币地址 |
| permit2_address | address | 否 | `0x000000000022D473030F116dDEE9F6B43aC78BA3` | Permit2 合约 |
| allowed_token_in | address_list | 否 | ""（任意） | 逗号分隔的允许输入 token 地址 |
| allowed_token_out | address_list | 否 | ""（任意） | 逗号分隔的允许输出 token 地址 |
| max_amount_in | string | 否 | "-1"（无上限） | 每笔操作最大输入金额 |

---

## 4. 使用方法

### 通过 API 应用（推荐）

```bash
remote-signer evm preset apply evm/uniswap --url http://127.0.0.1:8548 --api-key-id admin
```

### 通过 CLI 应用（配置文件方式）

```bash
remote-signer preset create-from uniswap --config config.yaml --write
```

### 通过 PATCH API 更新 Matrix（新增链）

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

### 通过 PATCH API 更新 Variables

```bash
curl -X PATCH http://127.0.0.1:8548/api/v1/evm/rules/<rule-id> \
  -H "Content-Type: application/json" \
  -d '{"variables": {"max_amount_in": "5000000000000000000"}}'
```

---

## 5. 官方合约地址

完整各链地址矩阵请参见预设文件 `rules/presets/evm/uniswap.yaml`。

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
| execute(bytes,bytes[],uint256) | 0x3593564c |
| multicall(uint256,bytes[]) | 0x5ae401dc |
| multicall(bytes[]) | 0xac9650d8 |
| approve(address,uint256) | 0x095ea7b3 |
| deposit() | 0xd0e30db0 |
| withdraw(uint256) | 0x2e1a7d4d |
