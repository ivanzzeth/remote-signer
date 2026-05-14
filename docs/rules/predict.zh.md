# Predict.fun 签名规则

Predict.fun 预测市场协议，部署于 BNB Chain (chainId=56)。规则按模板模块拆分：auth、enable_trading、trading。预设 `predict_eoa_bnb` 组合 auth + enable_trading + trading。

**模板文件**：`predict_auth.template.yaml`、`predict_enable_trading.template.yaml`、`predict_trading.template.yaml`

---

## 1. EIP191 登录签名

PersonalSign 登录，消息由 API 动态下发，规则仅校验长度与格式。

- **sign_types**：`personal`、`eip191`
- **pattern**：`(?s)^.{1,1000}$`（非空、最长 1000 字符）

示例消息格式：

```
Sign in to predict.fun
Timestamp: 1704067200
Nonce: abc123
```

---

## 2. EIP712 订单签名

订单结构体：

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

- **name**：predict.fun CTF Exchange
- **version**：1
- **chainId**：56
- **verifyingContract**：4 个 Exchange 之一（CTF_EXCHANGE_NYB、CTF_EXCHANGE_YB、NEG_RISK_EXCHANGE_NYB、NEG_RISK_EXCHANGE_YB）

| 规则 | EIP712 主类型 | 参数 | 备注 |
| --- | --- | --- | --- |
| 订单签名 | Order | EIP712Domain.name=predict.fun CTF Exchange<br>EIP712Domain.version=1<br>EIP712Domain.chainId=56<br>eip712_domainContract 为 4 个 Exchange 之一<br>order.taker=零地址<br>order.signer=ctx_signer<br>order.feeRateBps≤1000<br>order.signatureType=0 (EOA) | 中心化订单簿，链上执行；taker 为零地址表示公开订单 |

---

## 3. 开通交易 (Enable Trading)

| 规则 | 合约 | 方法 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| USDT 授权 | USDT_ADDRESS | approve(address,uint256) - 0x095ea7b3 | spender 为 8 个协议合约之一：CT NYB/YB、CTFExchange NYB/YB、NegRiskExchange NYB/YB、NegRiskAdapter NYB/YB | 授权协议使用 USDT |
| CT 授权 | CT_NYB / CT_YB / NEG_RISK_CTF_YB | setApprovalForAll(address,bool) - 0xa22cb465 | operator 为 6 个协议合约之一（CTFExchange、NegRiskExchange、NegRiskAdapter，各 NYB+YB）；approved=true | 授权协议使用 ConditionalTokens |

---

## 4. 交易 (Trading)

### 4.1 ConditionalTokens split/merge/redeem

| 规则 | 合约 | 方法 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| splitPosition | CT_NYB / CT_YB | splitPosition(address,bytes32,bytes32,uint256[],uint256) - 0x72ce4275 | collateralToken=USDT<br>parentCollectionId=bytes32(0) | 拆分头寸 |
| mergePositions | CT_NYB / CT_YB | mergePositions(address,bytes32,bytes32,uint256[],uint256) - 0x9e7212ad | collateralToken=USDT<br>parentCollectionId=bytes32(0) | 合并头寸 |
| redeemPositions | CT_NYB / CT_YB | redeemPositions(address,bytes32,bytes32,uint256[]) - 0x01b7037c | collateralToken=USDT<br>parentCollectionId=bytes32(0) | 赎回条件代币换回 USDT |

### 4.2 NegRiskAdapter 操作

| 规则 | 合约 | 方法 | 参数 | 备注 |
| --- | --- | --- | --- | --- |
| 2-param splitPosition | NEG_RISK_ADAPTER_NYB / NEG_RISK_ADAPTER_YB | splitPosition(bytes32,uint256) - 0xa3d7da1d | 无额外约束 | 简化版拆分 |
| 2-param mergePositions | NEG_RISK_ADAPTER_NYB / NEG_RISK_ADAPTER_YB | mergePositions(bytes32,uint256) - 0xb10c5c17 | 无额外约束 | 简化版合并 |
| 2-param redeemPositions | NEG_RISK_ADAPTER_NYB / NEG_RISK_ADAPTER_YB | redeemPositions(bytes32,uint256[]) - 0xdbeccb23 | 无额外约束 | 简化版赎回 |
| 5-param splitPosition | NEG_RISK_ADAPTER_NYB / NEG_RISK_ADAPTER_YB | splitPosition(address,bytes32,bytes32,uint256[],uint256) - 0x72ce4275 | collateralToken=USDT<br>parentCollectionId=bytes32(0) | CTF 兼容拆分 |
| 5-param mergePositions | NEG_RISK_ADAPTER_NYB / NEG_RISK_ADAPTER_YB | mergePositions(address,bytes32,bytes32,uint256[],uint256) - 0x9e7212ad | collateralToken=USDT<br>parentCollectionId=bytes32(0) | CTF 兼容合并 |
| convertPositions | NEG_RISK_ADAPTER_NYB / NEG_RISK_ADAPTER_YB | convertPositions(bytes32,uint256,uint256) - 0xc64748c4 | 无额外约束 | 头寸转换 |

---

## 默认地址 (BNB Chain)

| 占位符 | 地址 |
| --- | --- |
| USDT_ADDRESS | 0x55d398326f99059fF775485246999027B3197955 |
| CT_NYB | 0x22DA1810B194ca018378464a58f6Ac2B10C9d244 |
| CT_YB | 0x9400F8Ad57e9e0F352345935d6D3175975eb1d9F |
| NEG_RISK_CTF_YB | 0xF64b0b318AAf83BD9071110af24D24445719A07F |
| CTF_EXCHANGE_NYB | 0x8BC070BEdAB741406F4B1Eb65A72bee27894B689 |
| NEG_RISK_EXCHANGE_NYB | 0x365fb81bd4A24D6303cd2F19c349dE6894D8d58A |
| NEG_RISK_ADAPTER_NYB | 0xc3Cf7c252f65E0d8D88537dF96569AE94a7F1A6E |
| CTF_EXCHANGE_YB | 0x6bEb5a40C032AFc305961162d8204CDA16DECFa5 |
| NEG_RISK_EXCHANGE_YB | 0x8A289d458f5a134bA40015085A8F50Ffb681B41d |
| NEG_RISK_ADAPTER_YB | 0x41dCe1A4B8FB5e6327701750aF6231B7CD0B2A40 |

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
| convertPositions(bytes32,uint256,uint256) | 0xc64748c4 |
