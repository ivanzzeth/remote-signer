# Rule Syntax Reference

This document describes the Solidity expression syntax for writing rules in the remote-signer.

## Overview

Rules use Solidity expressions to validate signing requests. The evaluator generates Solidity code from your rules and executes them using Forge to validate conditions.

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
