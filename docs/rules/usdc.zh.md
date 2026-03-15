# USDC (Circle) 签名规则

Circle USDC 稳定币多链规则。USDC 是 Circle 发行的原生稳定币，部署于主流 EVM 链。规则覆盖 ERC20 transfer、transferFrom 和 approve 方法，支持参数级验证、金额上限和预算计量。

**模板文件**：`erc20.template.js.yaml`
**预设文件**：`usdc.preset.js.yaml`

---

## 1. 概述

USDC 由 Circle 在各支持链上原生发行（native USDC），区别于桥接版 USDC（USDC.e，从 Ethereum 桥接的封装版本）。以下地址均为 Circle 原生发行的 USDC。

所有金额使用 USDC 的 6 位小数精度：1 USDC = 1000000，1000 USDC = 1000000000。

---

## 2. 官方合约地址

地址来源：[Circle 官方文档](https://developers.circle.com/stablecoins/docs/usdc-on-main-networks)。

| 链 | Chain ID | USDC 地址 |
| --- | --- | --- |
| Ethereum | 1 | 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 |
| Polygon PoS | 137 | 0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359 |
| Arbitrum One | 42161 | 0xaf88d065e77c8cC2239327C5EDb3A432268e5831 |
| Optimism | 10 | 0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85 |
| Avalanche C-Chain | 43114 | 0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E |
| Base | 8453 | 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 |

---

## 3. 规则

### 3.1 transfer / transferFrom

规则 `erc20-transfer-limit`：验证配置 token 合约上的 transfer 和 transferFrom。

| 规则 | 合约 | 方法 | 选择器 | 参数 | 备注 |
| --- | --- | --- | --- | --- | --- |
| transfer | token_address | transfer(address,uint256) | 0xa9059cbb | to 在 allowed_recipients 中<br>amount <= max_transfer_amount | 直接 token 转账 |
| transferFrom | token_address | transferFrom(address,address,uint256) | 0x23b872dd | from 在 allowed_transfer_from 中<br>to 在 allowed_recipients 中<br>amount <= max_transfer_amount | 第三方转账 |

### 3.2 approve

规则 `erc20-approve-limit`：验证配置 token 合约上的 approve。

| 规则 | 合约 | 方法 | 选择器 | 参数 | 备注 |
| --- | --- | --- | --- | --- | --- |
| approve | token_address | approve(address,uint256) | 0x095ea7b3 | spender 在 allowed_spenders 中<br>amount <= max_approve_amount | Token 支出授权 |

---

## 4. 预算计量

ERC20 模板包含 `validateBudget` 函数，用于提取 transfer/approve 金额以进行预算跟踪。

- **transfer**：从 `transfer(address,uint256)` 提取 `amount`（第 2 个参数）
- **transferFrom**：从 `transferFrom(address,address,uint256)` 提取 `amount`（第 3 个参数）
- **approve**：从 `approve(address,uint256)` 提取 `amount`（第 2 个参数）

预算单位为 `${chain_id}:${token_address}`，支持按链按 token 的预算跟踪。预设配置：

| 预算字段 | 值 | 说明 |
| --- | --- | --- |
| unit | `${chain_id}:${token_address}` | 按链按 token 的预算范围 |
| max_total | `${max_transfer_amount}` | 每周期总预算上限 |
| max_per_tx | `${max_transfer_amount}` | 单笔交易上限 |
| max_tx_count | 0（无限制） | 不限交易次数 |
| alert_pct | 80 | 预算使用 80% 时告警 |

预算按 `budget_period` 周期重置（默认：24h）。

---

## 5. 配置变量

| 变量 | 类型 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- | --- |
| token_address | address | 是 | - | USDC 合约地址（由预设 matrix 按链设置） |
| max_transfer_amount | string | 是 | ""（必须设置） | 每笔 transfer/transferFrom 最大金额，以最小单位计（6 位小数）。如 1000000000 = 1000 USDC |
| max_approve_amount | string | 否 | "-1"（无上限） | 每笔 approve 最大金额。-1 = 无上限，0 = 全部禁止 |
| budget_period | string | 否 | "24h" | 预算重置周期（如 24h、168h） |
| allowed_recipients | address_list | **是** | - | 逗号分隔的允许 transfer(to) 或 transferFrom(..., to) 地址。必填：必须显式列出允许的收款地址 |
| allowed_spenders | address_list | **是** | - | 逗号分隔的允许 approve(spender) 地址。必填：必须显式列出允许的授权地址 |
| allowed_transfer_from | address_list | 否 | ""（任意） | 逗号分隔的允许 transferFrom(from, ...) 地址 |

---

## 6. 预设使用示例

### 部署 USDC 规则到所有链（含转账上限）

`allowed_recipients` 和 `allowed_spenders` 为**必填项** -- 必须显式指定。

```bash
remote-signer-cli preset create-from usdc.preset.js.yaml \
  --set max_transfer_amount=1000000000 \
  --set allowed_recipients=0x5B38Da6a701c568545dCfcB03FcB875f56beddC4 \
  --set allowed_spenders=0xE592427A0AEce92De3Edee1F18E0157C05861564 \
  --config config.yaml --write
```

### 部署含自定义预算周期

```bash
remote-signer-cli preset create-from usdc.preset.js.yaml \
  --set max_transfer_amount=10000000000 \
  --set max_approve_amount=100000000000 \
  --set allowed_recipients=0x5B38Da6a701c568545dCfcB03FcB875f56beddC4 \
  --set allowed_spenders=0xE592427A0AEce92De3Edee1F18E0157C05861564 \
  --set budget_period=168h \
  --config config.yaml --write
```

### 使用 ERC20 模板直接部署单链

```bash
remote-signer-cli preset create-from erc20.preset.js.yaml \
  --set chain_id=1 \
  --set token_address=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
  --set max_transfer_amount=1000000000 \
  --config config.yaml --write
```

---

## 函数选择器速查

选择器 = keccak256(函数签名) 前 4 字节。可用 `cast sig "transfer(address,uint256)"` 验证。

| 函数签名 | 选择器 |
| --- | --- |
| transfer(address,uint256) | 0xa9059cbb |
| transferFrom(address,address,uint256) | 0x23b872dd |
| approve(address,uint256) | 0x095ea7b3 |
