# Predict.fun Signing Rules

Predict.fun prediction market protocol, deployed on BNB Chain (chainId=56). Rules are split by template modules: auth, enable_trading, trading. Preset `predict_eoa_bnb` composes auth + enable_trading + trading.

**Template files**: `predict_auth.template.yaml`, `predict_enable_trading.template.yaml`, `predict_trading.template.yaml`

---

## 1. EIP191 Login Signature

PersonalSign login; message content is dynamic from API. Rules only validate length and format.

- **sign_types**: `personal`, `eip191`
- **pattern**: `(?s)^.{1,1000}$` (non-empty, max 1000 chars)

Example message format:

```
Sign in to predict.fun
Timestamp: 1704067200
Nonce: abc123
```

---

## 2. EIP712 Order Signature

Order struct:

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

EIP712 Domain:

- **name**: predict.fun CTF Exchange
- **version**: 1
- **chainId**: 56
- **verifyingContract**: one of 4 Exchanges (CTF_EXCHANGE_NYB, CTF_EXCHANGE_YB, NEG_RISK_EXCHANGE_NYB, NEG_RISK_EXCHANGE_YB)

| Rule | EIP712 Primary Type | Params | Notes |
| --- | --- | --- | --- |
| Order signature | Order | EIP712Domain.name=predict.fun CTF Exchange<br>EIP712Domain.version=1<br>EIP712Domain.chainId=56<br>eip712_domainContract is one of 4 Exchanges<br>order.taker=zero address<br>order.signer=ctx_signer<br>order.feeRateBps≤1000<br>order.signatureType=0 (EOA) | Centralized order book, on-chain execution; zero taker = public order |

---

## 3. Enable Trading

| Rule | Contract | Method | Params | Notes |
| --- | --- | --- | --- | --- |
| USDT approve | USDT_ADDRESS | approve(address,uint256) - 0x095ea7b3 | spender is one of 8 protocol contracts: CT NYB/YB, CTFExchange NYB/YB, NegRiskExchange NYB/YB, NegRiskAdapter NYB/YB | Allow protocol to spend USDT |
| CT setApprovalForAll | CT_NYB / CT_YB / NEG_RISK_CTF_YB | setApprovalForAll(address,bool) - 0xa22cb465 | operator is one of 6 protocol contracts (CTFExchange, NegRiskExchange, NegRiskAdapter, each NYB+YB); approved=true | Allow protocol to use ConditionalTokens |

---

## 4. Trading

### 4.1 ConditionalTokens split/merge/redeem

| Rule | Contract | Method | Params | Notes |
| --- | --- | --- | --- | --- |
| splitPosition | CT_NYB / CT_YB | splitPosition(address,bytes32,bytes32,uint256[],uint256) - 0x72ce4275 | collateralToken=USDT<br>parentCollectionId=bytes32(0) | Split positions |
| mergePositions | CT_NYB / CT_YB | mergePositions(address,bytes32,bytes32,uint256[],uint256) - 0x9e7212ad | collateralToken=USDT<br>parentCollectionId=bytes32(0) | Merge positions |
| redeemPositions | CT_NYB / CT_YB | redeemPositions(address,bytes32,bytes32,uint256[]) - 0x01b7037c | collateralToken=USDT<br>parentCollectionId=bytes32(0) | Redeem conditional tokens for USDT |

### 4.2 NegRiskAdapter Operations

| Rule | Contract | Method | Params | Notes |
| --- | --- | --- | --- | --- |
| 2-param splitPosition | NEG_RISK_ADAPTER_NYB / NEG_RISK_ADAPTER_YB | splitPosition(bytes32,uint256) - 0xa3d7da1d | No extra constraints | Simplified split |
| 2-param mergePositions | NEG_RISK_ADAPTER_NYB / NEG_RISK_ADAPTER_YB | mergePositions(bytes32,uint256) - 0xb10c5c17 | No extra constraints | Simplified merge |
| 2-param redeemPositions | NEG_RISK_ADAPTER_NYB / NEG_RISK_ADAPTER_YB | redeemPositions(bytes32,uint256[]) - 0xdbeccb23 | No extra constraints | Simplified redeem |
| 5-param splitPosition | NEG_RISK_ADAPTER_NYB / NEG_RISK_ADAPTER_YB | splitPosition(address,bytes32,bytes32,uint256[],uint256) - 0x72ce4275 | collateralToken=USDT<br>parentCollectionId=bytes32(0) | CTF-compatible split |
| 5-param mergePositions | NEG_RISK_ADAPTER_NYB / NEG_RISK_ADAPTER_YB | mergePositions(address,bytes32,bytes32,uint256[],uint256) - 0x9e7212ad | collateralToken=USDT<br>parentCollectionId=bytes32(0) | CTF-compatible merge |
| convertPositions | NEG_RISK_ADAPTER_NYB / NEG_RISK_ADAPTER_YB | convertPositions(bytes32,uint256,uint256) - 0xc64748c4 | No extra constraints | Position conversion |

---

## Default Addresses (BNB Chain)

| Placeholder | Address |
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

## Function Selector Reference

Selector = first 4 bytes of keccak256(function_signature). Verify with `cast sig "approve(address,uint256)"`.

| Function Signature | Selector |
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
