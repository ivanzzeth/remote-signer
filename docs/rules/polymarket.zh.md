# Polymarket 签名规则

Polymarket 预测市场协议，部署于 Polygon (chainId=137)。支持 EOA 与 Safe 钱包。规则按模板模块拆分：auth、create_safe、enable_trading、trading。预设 `polymarket_eoa_polygon` 组合 auth + enable_trading + trading；`polymarket_safe_init_polygon` 组合 auth + create_safe + enable_trading；`polymarket_safe_polygon` 为全量。

**模板文件**：`polymarket_auth.template.yaml`、`polymarket_create_safe.template.yaml`、`polymarket_enable_trading.template.yaml`、`polymarket_trading.template.yaml`

---

## 1. EIP712 ClobAuth 登录签名

ClobAuth 用于 Polymarket API 鉴权。

```solidity
struct ClobAuth {
    address address_;
    string timestamp;
    uint256 nonce;
    string message;
}
```

| 规则 | EIP712 主类型 | 参数 | 备注 |
| --- | --- | --- | --- |
| ClobAuth 登录 | ClobAuth | EIP712Domain.name=ClobAuthDomain<br>EIP712Domain.version=1<br>EIP712Domain.chainId=137<br>clobAuth.message="This message attests that I control the given wallet" | 固定 attestation 消息 |

---

## 2. EIP712 订单签名

订单结构体（与 Predict 相同）：

```solidity
struct Order {
    uint256 salt;
    address maker;
    address signer;
    address taker;
    uint256 tokenId;
    uint256 makerAmount;
    uint256 takerAmount;
    uint256 expiration;
    uint256 nonce;
    uint256 feeRateBps;
    uint8 side;
    uint8 signatureType;
}
```

EIP712 Domain：

- **name**：Polymarket CTF Exchange
- **version**：1
- **chainId**：137
- **verifyingContract**：CTF_EXCHANGE_ADDRESS

| 规则 | EIP712 主类型 | 参数 | 备注 |
| --- | --- | --- | --- |
| 订单签名 | Order | EIP712Domain.name=Polymarket CTF Exchange<br>EIP712Domain.version=1<br>eip712_domainContract=CTF_EXCHANGE_ADDRESS<br>order.taker=零地址<br>order.signer=ctx_signer<br>order.feeRateBps≤1000 | 中心化订单簿，链上执行 |

---

## 3. EIP712 SafeTx 签名

Safe 钱包交易签名，verifyingContract 必须为允许的 Safe 地址之一。

```solidity
struct SafeTx {
    address to;
    uint256 value;
    bytes data;
    uint8 operation;
    uint256 safeTxGas;
    uint256 baseGas;
    uint256 gasPrice;
    address gasToken;
    address refundReceiver;
    uint256 nonce;
}
```

| 规则 | EIP712 主类型 | 参数 | 备注 |
| --- | --- | --- | --- |
| SafeTx 签名 | SafeTx | EIP712Domain.chainId=137<br>eip712_domainContract=allowed_safe_addresses 之一<br>safeTx.value=0<br>safeTx.operation=0 (CALL)<br>safeTx.gasPrice=0<br>safeTx.gasToken=0<br>safeTx.refundReceiver=0 | 仅 CALL，禁止 DELEGATECALL；禁止 gas 操纵 |

---

## 4. Safe 钱包创建

### 4.1 CreateProxy EIP712 签名

```solidity
struct CreateProxy {
    address paymentToken;
    uint256 payment;
    address paymentReceiver;
}
```

| 规则 | EIP712 主类型 | 参数 | 备注 |
| --- | --- | --- | --- |
| Safe 创建签名 | CreateProxy | EIP712Domain.name=Polymarket Contract Proxy Factory<br>eip712_domainContract=Safe Factory<br>createProxy.paymentToken=0<br>createProxy.payment=0<br>createProxy.paymentReceiver=0 | 零费用创建 |

### 4.2 createProxy 直连交易

| 规则 | 合约 | 方法 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| Safe 钱包创建 | SAFE_PROXY_FACTORY_ADDRESS | createProxy(address,uint256,address,Signature) - 0xa1884d2c | paymentToken=0<br>payment=0<br>paymentReceiver=0 | 通过 Safe Factory 创建钱包 |

---

## 5. Safe 钱包交易 (execTransaction)

通过 Safe 合约的 execTransaction 执行内部调用。调用 Safe 时 txTo = Safe 地址，data 以 selector 0x6a761202 开头。

- **execTransaction**：execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) - 0x6a761202
- **约束**：txTo 为 allowed_safe_addresses 之一；value=0；operation=CALL(0)

### 5.1 开通交易 (仅 approve + setApprovalForAll)

enable_trading 模板：仅允许 USDC.e approve 与 CTF setApprovalForAll。

| 规则 | 内部 to | 方法 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| USDC.e 授权 | USDC_BRIDGED_ADDRESS | approve(address,uint256) - 0x095ea7b3 | spender=CTF Exchange / NegRiskAdapter / NegRiskExchange | 授权协议使用 USDC.e |
| CTF 授权 | CONDITIONAL_TOKENS_ADDRESS | setApprovalForAll(address,bool) - 0xa22cb465 | operator=CTF Exchange / NegRiskAdapter / NegRiskExchange<br>approved=true | 授权协议使用 ConditionalTokens |

### 5.2 完整交易 (split/merge/redeem + NegRiskAdapter)

trading 模板在 enable_trading 基础上增加 CTF split/merge/redeem 与 NegRiskAdapter 操作。

| 规则 | 内部 to | 方法 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| CTF splitPosition | CONDITIONAL_TOKENS_ADDRESS | splitPosition(address,bytes32,bytes32,uint256[],uint256) - 0x72ce4275 | collateralToken=USDC.e<br>parentCollectionId=bytes32(0) | 拆分头寸 |
| CTF mergePositions | CONDITIONAL_TOKENS_ADDRESS | mergePositions(address,bytes32,bytes32,uint256[],uint256) - 0x9e7212ad | collateralToken=USDC.e<br>parentCollectionId=bytes32(0) | 合并头寸 |
| CTF redeemPositions | CONDITIONAL_TOKENS_ADDRESS | redeemPositions(address,bytes32,bytes32,uint256[]) - 0x01b7037c | collateralToken=USDC.e<br>parentCollectionId=bytes32(0) | 赎回条件代币 |
| NegRisk 2-param split | NEG_RISK_ADAPTER_ADDRESS | splitPosition(bytes32,uint256) - 0xa3d7da1d | 无额外约束 | 简化版拆分 |
| NegRisk 2-param merge | NEG_RISK_ADAPTER_ADDRESS | mergePositions(bytes32,uint256) - 0xb10c5c17 | 无额外约束 | 简化版合并 |
| NegRisk 2-param redeem | NEG_RISK_ADAPTER_ADDRESS | redeemPositions(bytes32,uint256[]) - 0xdbeccb23 | 无额外约束 | 简化版赎回 |
| NegRisk 5-param split/merge | NEG_RISK_ADAPTER_ADDRESS | 0x72ce4275 / 0x9e7212ad | collateralToken=USDC.e<br>parentCollectionId=bytes32(0) | CTF 兼容 |

---

## 默认地址 (Polygon)

| 占位符 | 地址 |
| --- | --- |
| USDC_BRIDGED_ADDRESS | 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 |
| CONDITIONAL_TOKENS_ADDRESS | 0x4D97DCd97eC945f40cF65F87097ACe5EA0476045 |
| CTF_EXCHANGE_ADDRESS | 0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E |
| NEG_RISK_ADAPTER_ADDRESS | 0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296 |
| NEG_RISK_EXCHANGE_ADDRESS | 0xC5d563A36AE78145C45a50134d48A1215220f80a |
| SAFE_PROXY_FACTORY_ADDRESS | 0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b |

---

## 函数选择器速查

选择器 = keccak256(函数签名) 前 4 字节。可用 `cast sig "approve(address,uint256)"` 验证。

| 函数签名 | 选择器 |
| --- | --- |
| approve(address,uint256) | 0x095ea7b3 |
| setApprovalForAll(address,bool) | 0xa22cb465 |
| splitPosition(address,bytes32,bytes32,uint256[],uint256) | 0x72ce4275 |
| mergePositions(address,bytes32,bytes32,uint256[],uint256) | 0x9e7212ad |
| redeemPositions(address,bytes32,bytes32,uint256[]) | 0x01b7037c |
| splitPosition(bytes32,uint256) | 0xa3d7da1d |
| mergePositions(bytes32,uint256) | 0xb10c5c17 |
| redeemPositions(bytes32,uint256[]) | 0xdbeccb23 |
| createProxy(address,uint256,address,Signature) | 0xa1884d2c |
| execTransaction(...) | 0x6a761202 |
