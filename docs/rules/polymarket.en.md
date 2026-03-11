# Polymarket Signing Rules

Polymarket prediction market protocol, deployed on Polygon (chainId=137). Supports EOA and Safe wallets. Rules are split by template modules: auth, create_safe, enable_trading, trading. Preset `polymarket_eoa_polygon` composes auth + enable_trading + trading; `polymarket_safe_init_polygon` composes auth + create_safe + enable_trading; `polymarket_safe_polygon` is full.

**Template files**: `polymarket_auth.template.yaml`, `polymarket_create_safe.template.yaml`, `polymarket_enable_trading.template.yaml`, `polymarket_trading.template.yaml`

---

## 1. EIP712 ClobAuth Login Signature

ClobAuth for Polymarket API authentication.

```solidity
struct ClobAuth {
    address address_;
    string timestamp;
    uint256 nonce;
    string message;
}
```

| Rule | EIP712 Primary Type | Params | Notes |
| --- | --- | --- | --- |
| ClobAuth login | ClobAuth | EIP712Domain.name=ClobAuthDomain<br>EIP712Domain.version=1<br>EIP712Domain.chainId=137<br>clobAuth.message="This message attests that I control the given wallet" | Fixed attestation message |

---

## 2. EIP712 Order Signature

Order struct (same as Predict):

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

- **name**: Polymarket CTF Exchange
- **version**: 1
- **chainId**: 137
- **verifyingContract**: CTF_EXCHANGE_ADDRESS

| Rule | EIP712 Primary Type | Params | Notes |
| --- | --- | --- | --- |
| Order signature | Order | EIP712Domain.name=Polymarket CTF Exchange<br>EIP712Domain.version=1<br>eip712_domainContract=CTF_EXCHANGE_ADDRESS<br>order.taker=zero address<br>order.signer=ctx_signer<br>order.feeRateBps≤1000 | Centralized order book, on-chain execution |

---

## 3. EIP712 SafeTx Signature

Safe wallet transaction signature. verifyingContract must be one of allowed Safe addresses.

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

| Rule | EIP712 Primary Type | Params | Notes |
| --- | --- | --- | --- |
| SafeTx signature | SafeTx | EIP712Domain.chainId=137<br>eip712_domainContract=one of allowed_safe_addresses<br>safeTx.value=0<br>safeTx.operation=0 (CALL)<br>safeTx.gasPrice=0<br>safeTx.gasToken=0<br>safeTx.refundReceiver=0 | CALL only, no DELEGATECALL; gas manipulation blocked |

---

## 4. Safe Wallet Creation

### 4.1 CreateProxy EIP712 Signature

```solidity
struct CreateProxy {
    address paymentToken;
    uint256 payment;
    address paymentReceiver;
}
```

| Rule | EIP712 Primary Type | Params | Notes |
| --- | --- | --- | --- |
| Safe creation signature | CreateProxy | EIP712Domain.name=Polymarket Contract Proxy Factory<br>eip712_domainContract=Safe Factory<br>createProxy.paymentToken=0<br>createProxy.payment=0<br>createProxy.paymentReceiver=0 | Zero-fee creation |

### 4.2 createProxy Direct Transaction

| Rule | Contract | Method | Params | Notes |
| --- | --- | --- | --- | --- |
| Safe wallet creation | SAFE_PROXY_FACTORY_ADDRESS | createProxy(address,uint256,address,(uint8,bytes32,bytes32)) - 0xa1884d2c | paymentToken=0<br>payment=0<br>paymentReceiver=0 | Create wallet via Safe Factory |

---

## 5. Safe Wallet Transactions (execTransaction)

Internal calls via Safe execTransaction. When calling the Safe, txTo = Safe address; data starts with selector 0x6a761202.

- **execTransaction**: execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) - 0x6a761202
- **Constraints**: txTo must be one of allowed_safe_addresses; value=0; operation=CALL(0)

### 5.1 Enable Trading (approve + setApprovalForAll only)

enable_trading template: USDC.e approve and CTF setApprovalForAll only.

| Rule | Internal to | Method | Params | Notes |
| --- | --- | --- | --- | --- |
| USDC.e approve | USDC_BRIDGED_ADDRESS | approve(address,uint256) - 0x095ea7b3 | spender=CTF Exchange / NegRiskAdapter / NegRiskExchange | Allow protocol to spend USDC.e |
| CTF setApprovalForAll | CONDITIONAL_TOKENS_ADDRESS | setApprovalForAll(address,bool) - 0xa22cb465 | operator=CTF Exchange / NegRiskAdapter / NegRiskExchange<br>approved=true | Allow protocol to use ConditionalTokens |

### 5.2 Full Trading (split/merge/redeem + NegRiskAdapter)

trading template adds CTF split/merge/redeem and NegRiskAdapter operations.

| Rule | Internal to | Method | Params | Notes |
| --- | --- | --- | --- | --- |
| CTF splitPosition | CONDITIONAL_TOKENS_ADDRESS | splitPosition(address,bytes32,bytes32,uint256[],uint256) - 0x72ce4275 | collateralToken=USDC.e<br>parentCollectionId=bytes32(0) | Split positions |
| CTF mergePositions | CONDITIONAL_TOKENS_ADDRESS | mergePositions(address,bytes32,bytes32,uint256[],uint256) - 0x9e7212ad | collateralToken=USDC.e<br>parentCollectionId=bytes32(0) | Merge positions |
| CTF redeemPositions | CONDITIONAL_TOKENS_ADDRESS | redeemPositions(address,bytes32,bytes32,uint256[]) - 0x01b7037c | collateralToken=USDC.e<br>parentCollectionId=bytes32(0) | Redeem conditional tokens |
| NegRisk 2-param split | NEG_RISK_ADAPTER_ADDRESS | splitPosition(bytes32,uint256) - 0xa3d7da1d | No extra constraints | Simplified split |
| NegRisk 2-param merge | NEG_RISK_ADAPTER_ADDRESS | mergePositions(bytes32,uint256) - 0xb10c5c17 | No extra constraints | Simplified merge |
| NegRisk 2-param redeem | NEG_RISK_ADAPTER_ADDRESS | redeemPositions(bytes32,uint256[]) - 0xdbeccb23 | No extra constraints | Simplified redeem |
| NegRisk 5-param split/merge | NEG_RISK_ADAPTER_ADDRESS | 0x72ce4275 / 0x9e7212ad | collateralToken=USDC.e<br>parentCollectionId=bytes32(0) | CTF-compatible |

---

## Default Addresses (Polygon)

| Placeholder | Address |
| --- | --- |
| USDC_BRIDGED_ADDRESS | 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 |
| CONDITIONAL_TOKENS_ADDRESS | 0x4D97DCd97eC945f40cF65F87097ACe5EA0476045 |
| CTF_EXCHANGE_ADDRESS | 0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E |
| NEG_RISK_ADAPTER_ADDRESS | 0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296 |
| NEG_RISK_EXCHANGE_ADDRESS | 0xC5d563A36AE78145C45a50134d48A1215220f80a |
| SAFE_PROXY_FACTORY_ADDRESS | 0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b |

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
| createProxy(address,uint256,address,(uint8,bytes32,bytes32)) | 0xa1884d2c |
| execTransaction(...) | 0x6a761202 |
