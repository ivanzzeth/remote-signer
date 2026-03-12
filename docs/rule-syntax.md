# Rule Syntax Reference

This document describes the Solidity expression syntax for writing rules in the remote-signer.

**Sign type filter (`sign_type_filter`)**: Only **evm_js** rules support a comma-separated value (e.g. `"typed_data,transaction"`). All other rule types (evm_solidity_expression, message_pattern, etc.) accept a **single** sign type only.

## Overview

Rules use Solidity expressions to validate signing requests. The evaluator generates Solidity code from your rules and executes them using Forge to validate conditions.

## Budget metering (templates)

When you create **rule instances from templates**, you can optionally enable **budget enforcement**.

- A **template** may define `budget_metering` to describe **how to measure spend amount** for each matched request.
- A **rule instance** stores the **limits and usage** (e.g. `max_total`, `max_per_tx`, `spent`, `tx_count`) keyed by `(rule_id, unit)`.

### `budget_metering` schema

`budget_metering` is an object with:

- `method`: how to extract the spend amount
- `unit`: budget identity string (recommended to include chain + asset identity, e.g. `${chain_id}:${token_address}`)

Supported `method` values:

- `none`: disable budgeting
- `count_only`: spend amount is always `1` per matched request (counts requests/txs)
- `tx_value`: use EVM transaction `value` as amount
- `calldata_param`: extract a `uint` amount from calldata by parameter index (ABI word index after selector)
- `typed_data_field`: extract amount from an EIP-712 typed data field path (e.g. `message.amount`)
- `js`: for `evm_js` rules only, compute amount via `validateBudget(input)` in the rule script

### `method: js` contract (`evm_js`)

If `budget_metering.method` is `js`, the `evm_js` rule script may implement:

- `validateBudget(input) -> bigint | decimal-string`

Contract:

- Return `0n` to indicate "no spend" (e.g. method not applicable / no match).
- Return a non-negative integer amount.
- Any error, negative amount, or unsupported return type is treated as **budget evaluation failure** (fail-closed).

## Rule Types

### 1. Transaction Rules (`functions`)

Validate direct Ethereum transactions by defining allowed function signatures:

```yaml
config:
  functions: |
    function transfer(address recipient, uint256 amount) external {
        require(recipient == 0x1234..., "invalid recipient");
    }
```

### 2. Typed Data Rules (`typed_data_expression`)

Validate EIP-712 typed data signing requests:

```yaml
config:
  typed_data_expression: |
    require(eip712_domainName == "MyDomain", "invalid domain");
    require(value > 0, "value must be positive");
```

## Context Variables

Context variables are automatically injected into your Solidity expressions. They use prefixes to avoid conflicts with user-defined EIP-712 message fields.

### EIP-712 Domain Context (`eip712_*` prefix)

These variables provide access to the EIP-712 domain separator fields:

| Variable | Type | Description |
|----------|------|-------------|
| `eip712_primaryType` | `string` | The primary type name of the EIP-712 message (e.g., "Order", "SafeTx") |
| `eip712_domainName` | `string` | The `name` field from the EIP-712 domain separator |
| `eip712_domainVersion` | `string` | The `version` field from the EIP-712 domain separator |
| `eip712_domainChainId` | `uint256` | The `chainId` field from the EIP-712 domain separator |
| `eip712_domainContract` | `address` | The `verifyingContract` field from the EIP-712 domain separator |

**Example:**
```solidity
// Validate that the message is for the correct domain
require(
    keccak256(bytes(eip712_domainName)) == keccak256(bytes("Polymarket CTF Exchange")),
    "invalid domain name"
);
require(eip712_domainChainId == 137, "must be on Polygon");
```

### Signing Context (`ctx_*` prefix)

These variables provide information about the signing request itself:

| Variable | Type | Description |
|----------|------|-------------|
| `ctx_signer` | `address` | The address of the signing key that will produce the signature |
| `ctx_chainId` | `uint256` | The chain ID from the signing request context |

**Example:**
```solidity
// Ensure the signer is the expected address
require(ctx_signer == 0x1234567890123456789012345678901234567890, "unauthorized signer");
```

### Transaction Context (`tx_*` prefix)

These variables are available for direct transaction rules (not typed data):

| Variable | Type | Description |
|----------|------|-------------|
| `tx_to` | `address` | The target address of the transaction |
| `tx_value` | `uint256` | The ETH value being sent with the transaction |
| `tx_selector` | `bytes4` | The function selector (first 4 bytes of calldata) |
| `tx_data` | `bytes` | The complete transaction calldata |

**Example:**
```solidity
// In a functions block, you can access tx context
require(tx_value == 0, "no ETH should be sent");
```

### Message Fields (No Prefix)

The actual message fields from the EIP-712 typed data are accessible directly by their names. For example, if you have an Order type with fields `maker`, `taker`, `amount`, you can access them directly:

```solidity
// Access message fields directly
require(taker == address(0), "taker must be zero address");
require(amount > 0, "amount must be positive");
require(feeRateBps <= 1000, "fee exceeds 10%");
```

## Reserved Keywords

The following keywords are reserved and cannot be used as message field names in your rules.

### Solidity Reserved Keywords

These are reserved by the Solidity language:

**Types:** `address`, `bool`, `string`, `bytes`, `uint`, `int`, `mapping`, `struct`, `enum`

**Integer Types:** `uint8`-`uint256`, `int8`-`int256`, `bytes1`-`bytes32`

**Control Flow:** `if`, `else`, `for`, `while`, `do`, `break`, `continue`, `return`

**Functions:** `function`, `returns`, `modifier`, `constructor`, `fallback`, `receive`

**Visibility:** `public`, `private`, `internal`, `external`, `view`, `pure`, `payable`

**Data Location:** `memory`, `storage`, `calldata`

**Contract:** `contract`, `interface`, `library`, `abstract`, `is`, `using`

**Error Handling:** `require`, `assert`, `revert`, `try`, `catch`

**Other:** `event`, `emit`, `indexed`, `anonymous`, `new`, `delete`, `this`, `super`, `selfdestruct`, `type`, `import`, `pragma`, `constant`, `immutable`, `override`, `virtual`

**Literals:** `true`, `false`, `wei`, `gwei`, `ether`, `seconds`, `minutes`, `hours`, `days`, `weeks`

**Global:** `msg`, `block`, `tx`, `abi`, `now`

## Examples

### Validating a CTF Exchange Order

```yaml
- name: "Polymarket Order Signature"
  type: "evm_solidity_expression"
  mode: "whitelist"
  enabled: true
  config:
    typed_data_expression: |
      // Validate domain
      require(
        keccak256(bytes(eip712_domainName)) == keccak256(bytes("Polymarket CTF Exchange")),
        "invalid domain name"
      );
      require(
        keccak256(bytes(eip712_domainVersion)) == keccak256(bytes("1")),
        "invalid domain version"
      );

      // Validate message fields
      require(taker == address(0), "taker must be zero address");
      require(feeRateBps <= 1000, "fee exceeds 10%");
    sign_type_filter: "typed_data"
```

### Validating a Safe Transaction

```yaml
- name: "Polymarket SafeTx Signature"
  type: "evm_solidity_expression"
  mode: "whitelist"
  enabled: true
  config:
    typed_data_expression: |
      // Validate domain chain
      require(eip712_domainChainId == 137, "SafeTx must be on Polygon");

      // Validate message fields (value comes from SafeTx message)
      require(value == 0, "ETH value must be zero");
    sign_type_filter: "typed_data"
```

### Validating a Token Transfer Transaction

```yaml
- name: "USDC Transfer to Treasury"
  type: "evm_solidity_expression"
  mode: "whitelist"
  enabled: true
  config:
    functions: |
      function transfer(address recipient, uint256 amount) external {
          require(
              recipient == 0x9Ce3316B865e940227EA724AFdeAAA2759f1AA7C,
              "recipient must be Treasury"
          );
      }
```

## Rule Type: `message_pattern`

Validate personal sign / EIP-191 messages against regex patterns.

### Config Schema

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `pattern` | string | Yes (if `patterns` empty) | — | Regex pattern (Go `regexp` syntax) |
| `patterns` | string[] | No | — | Multiple patterns (any match = rule fires). If both `pattern` and `patterns` set, `pattern` is prepended |
| `sign_types` | string[] | No | `["personal", "eip191"]` | Which sign types this rule applies to |
| `description` | string | No | — | Human-readable description |
| `test_cases` | TestCase[] | Yes (for validation) | — | At least 2: 1 positive + 1 negative |

### TestCase Schema (for `message_pattern`)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Test case description |
| `input.raw_message` | string | Yes | The message text to test against the pattern |
| `input.sign_type` | string | No | Sign type (default: "personal") |
| `expect_pass` | bool | Yes | true = message should match pattern (whitelist) / should be blocked (blocklist) |
| `expect_reason` | string | No | Expected reason substring (for negative cases) |

### Behavior by Mode

- **whitelist**: returns true (allow) if message matches ANY pattern
- **blocklist**: returns true (block) if message matches ANY pattern

### Example

```yaml
- name: "Predict Login PersonalSign"
  type: "message_pattern"
  mode: "whitelist"
  enabled: true
  config:
    pattern: "^.{1,1024}$"
    sign_types: ["personal", "eip191"]
    description: "Accept any non-empty message up to 1024 chars"
    test_cases:
      - name: "should match normal login message"
        input:
          raw_message: "Sign in to predict.fun\nTimestamp: 1704067200"
        expect_pass: true
      - name: "should reject empty message"
        input:
          raw_message: ""
        expect_pass: false
```

### SIWE Example (Strict Regex)

```yaml
- name: "Opinion Login Signature"
  type: "message_pattern"
  mode: "whitelist"
  enabled: true
  config:
    pattern: |
      ^app\.opinion\.trade wants you to sign in with your Ethereum account:\n0x[a-fA-F0-9]{40}\n\nWelcome.*$
    sign_types: ["personal", "eip191"]
    test_cases:
      - name: "should match valid SIWE message"
        input:
          raw_message: "app.opinion.trade wants you to sign in with your Ethereum account:\n0x88eD75e9eCE373997221E3c0229e74007C1AD718\n\nWelcome to opinion.trade!..."
        expect_pass: true
      - name: "should reject non-SIWE message"
        input:
          raw_message: "Please sign this random message"
        expect_pass: false
```

---

## Rule Type: `evm_address_list` (alias: `evm_address_whitelist`)

Validate that the transaction recipient (`tx.To`) is in an address list.

### Config Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `addresses` | string[] | Yes | List of 0x-prefixed Ethereum addresses |

### Config Go Struct

File: `internal/chain/evm/types.go`
```go
type AddressListConfig struct {
    Addresses []string `json:"addresses"` // 0x prefixed
}
```

### Behavior by Mode

- **whitelist**: allow if `tx.To` is in the list
- **blocklist**: block if `tx.To` is in the list

### Example

```yaml
- name: "Allow transfers to treasury"
  type: "evm_address_list"   # or "evm_address_whitelist" (legacy alias)
  mode: "whitelist"
  enabled: true
  config:
    addresses:
      - "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
      - "0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2"
```

---

## Rule Type: `evm_contract_method`

Validate that the contract address and method selector match allowed combinations.

### Config Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `contract` | string | No | 0x-prefixed contract address (if empty, matches any contract) |
| `method_sigs` | string[] | Yes | 4-byte hex method selectors, 0x-prefixed |

### Config Go Struct

File: `internal/chain/evm/types.go`
```go
type ContractMethodConfig struct {
    Contract   string   `json:"contract"`    // 0x prefixed
    MethodSigs []string `json:"method_sigs"` // 4-byte hex, 0x prefixed
}
```

### Example

```yaml
- name: "ERC20 transfer/approve only"
  type: "evm_contract_method"
  mode: "whitelist"
  enabled: true
  config:
    method_sigs:
      - "0xa9059cbb"  # transfer(address,uint256)
      - "0x095ea7b3"  # approve(address,uint256)
```

---

## Rule Type: `evm_value_limit`

Check transaction value against a limit.

### Config Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `max_value` | string | Yes | Maximum value in wei (decimal string) |

### Config Go Struct

File: `internal/chain/evm/types.go`
```go
type ValueLimitConfig struct {
    MaxValue string `json:"max_value"` // wei as decimal string
}
```

### Behavior by Mode

- **whitelist**: allow if `value <= max_value`
- **blocklist**: block if `value > max_value`

### Example

```yaml
- name: "Transfer limit 100 ETH"
  type: "evm_value_limit"
  mode: "whitelist"
  enabled: true
  config:
    max_value: "100000000000000000000"  # 100 ETH in wei
```

---

## Rule Type: `sign_type_restriction`

Restrict which signing types are allowed.

### Config Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `allowed_sign_types` | string[] | Yes | Allowed sign types |

Valid sign types: `hash`, `raw_message`, `eip191`, `personal`, `typed_data`, `transaction`

### Config Go Struct

File: `internal/chain/evm/rule_evaluator.go`
```go
type SignTypeRestrictionConfig struct {
    AllowedSignTypes []string `json:"allowed_sign_types"`
}
```

### Example

```yaml
- name: "Allowed signing methods"
  type: "sign_type_restriction"
  mode: "whitelist"
  enabled: true
  config:
    allowed_sign_types:
      - "personal"
      - "typed_data"
      - "transaction"
```

---

## Rule Type: `signer_restriction`

Restrict which signer addresses are allowed.

### Config Schema

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `allowed_signers` | string[] | Yes | List of 0x-prefixed allowed signer addresses |

### Config Go Struct

File: `internal/chain/evm/rule_evaluator.go`
```go
type SignerRestrictionConfig struct {
    AllowedSigners []string `json:"allowed_signers"`
}
```

### Example

```yaml
- name: "Authorized signers"
  type: "signer_restriction"
  mode: "whitelist"
  enabled: true
  config:
    allowed_signers:
      - "0x53c68c954f85a29d2098e90addaf41baf2ff0a50"
```

---

## Rule Type: `chain_restriction`

**NOTE:** This type is defined as a constant (`RuleTypeChainRestriction = "chain_restriction"`) but has NO evaluator implementation. Include in rule files for forward compatibility but no config validation is performed beyond basic JSON parsing.

---

## Migration Guide

If you have existing rules using the old variable names, update them as follows:

| Old Variable | New Variable |
|--------------|--------------|
| `primaryType` | `eip712_primaryType` |
| `domainName` | `eip712_domainName` |
| `domainVersion` | `eip712_domainVersion` |
| `domainChainId` | `eip712_domainChainId` |
| `domainContract` | `eip712_domainContract` |
| `signer` | `ctx_signer` |
| `chainId` | `ctx_chainId` |
| `to` | `tx_to` |
| `value` (tx context) | `tx_value` |
| `selector` | `tx_selector` |
| `data` | `tx_data` |
| `_value` (escaped) | `value` (no escape needed) |

**Note:** Message fields named `value`, `to`, `data`, etc. no longer need escaping with `_` prefix. They can now be accessed directly by their names since context variables use prefixes.
