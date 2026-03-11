# evm_js rs Module API Reference

The **rs** (remote-signer) module provides a composable, safe API for evm_js rules. It is injected into the rule sandbox; the name `rs` is reserved — do not use it as a variable.

## Overview

| Sub-module   | Purpose                                      |
|-------------|-----------------------------------------------|
| **rs.tx**   | Transaction validation and calldata parsing   |
| **rs.addr** | Address checks (allowlist, zero)              |
| **rs.int**  | Strict small-integer parsing (parseUint, requireLte, requireEq) |
| **rs.bigint** | BigInt parsing and comparison (uint256/int256, requireLte, requireEq, requireZero) |
| **rs.typedData** | EIP-712 typed data validation             |
| **rs.multisend** | Gnosis MultiSend batch parsing             |
| **rs.delegate** | Resolve rule ID by target address          |
| **rs.config** | Config requireNonEmpty(key, reason); config strings are trimmed when injected |
| **rs.hex**  | Hex value checks (e.g. zero32)                |

Most `rs.*.require*` helpers are **fail-fast**: on failure they **throw** (panic) with the provided `reason`, and the engine converts it into `{ valid: false, reason }`.  
Soft-check helpers (like `rs.addr.inList`) return `boolean` instead of throwing.

---

## Global primitives: revert / require

These are **global** (same level as `fail` and `ok`), not under `rs`.

### revert(reason)

Throws so the engine treats the rule as failed with `reason`. Use when you want to fail without returning `fail(reason)` and checking every call site. The Go layer catches the exception and returns `{ valid: false, reason }`.

### require(cond, reason)

If `cond` is falsy, calls `revert(reason)`. Shorthand for one-line guards: `require(amount <= cap, "exceeds cap");` instead of `if (amount > cap) return fail("exceeds cap");`.

**Example:**
```javascript
function validate(i) {
  var ctx = rs.tx.require(i);
  require(rs.addr.inList(ctx.tx.to, config.allowed), "contract not allowed");
  require(amount <= config.max, "exceeds cap");
  return ok();
}
```

---

## rs.tx

### rs.tx.require(input)

Validates `sign_type === 'transaction'`, presence of `transaction`, `to`, `data`, and calldata length ≥ 8.

**Returns:**
- Success: `{ tx, selector, payloadHex }`
- Failure: throws with `reason`

**Example:**
```javascript
var ctx = rs.tx.require(input);
// ctx.tx = transaction object, ctx.selector = '0x...', ctx.payloadHex = '0x...'
```

### rs.tx.getCalldata(tx)

Extracts selector and payload from `tx.data`.

**Returns:**
- Success: `{ selector, payloadHex }`
- Failure: throws with `reason` (e.g. calldata too short)

---

## rs.addr

### rs.addr.inList(addr, list)

Returns `true` if `addr` (checksummed) is in `list`. `list` accepts:
- Array of addresses
- Comma-separated string

Empty list → `false`.

### rs.addr.notInList(addr, list)

Returns `true` if `addr` is **not** in `list` (or addr is invalid). Empty list → `true`.

### rs.addr.requireInList(addr, list, reason)

Returns `ok()` if addr in list; otherwise throws with `reason`.

### rs.addr.requireNotInList(addr, list, reason)

Returns `ok()` if addr is **not** in list (or addr is invalid); otherwise throws with `reason`.

### rs.addr.requireInListIfNonEmpty(addr, list, reason)

When `list` is empty (array length 0 or string trim empty), returns `ok()` (allow any).  
Otherwise same as `requireInList`. Use for optional allowlists where empty = no restriction.

### rs.addr.isZero(addr)

Returns `true` if addr is the zero address.

### rs.addr.requireZero(addr, reason)

Returns `ok()` if addr is zero; otherwise throws with `reason`.

---

## rs.int

Strict integer parsing helpers. Invalid input never silently becomes 0.

### rs.int.parseUint(value)

Parses an unsigned integer from a decimal string/number.

**Returns:** `{ n }` or throws `"invalid value"`.

### rs.int.requireLte(value, max, reason)

Throws with `reason` when value/max are invalid or value > max.

### rs.int.requireEq(value, want, reason)

Throws with `reason` when value/want are invalid or value != want.

---

## rs.bigint

### rs.bigint.parse(value)

Parses `value` into a real JavaScript `BigInt` using `BigInt(...)`.

- **Input**: decimal string (`"42"`), hex string (`"0x2a"`), or integer-like number.
- **Returns**: `{ n: <BigInt> }` or throws with `reason`.

### rs.bigint.uint256(value)

Parses `value` as a **uint256** (range \(0 \le x \le 2^{256}-1\)) and returns a JavaScript `BigInt`.

**Returns**: `{ n: <BigInt> }` or throws `"invalid uint256"`.

### rs.bigint.int256(value)

Parses `value` as an **int256** (range \(-2^{255} \le x \le 2^{255}-1\)) and returns a JavaScript `BigInt`.

**Returns**: `{ n: <BigInt> }` or throws `"invalid int256"`.

### rs.bigint.requireLte(a, b, reason)

Strict BigInt compare. When `b` is empty or `"0"`, no limit → returns `ok()`. Otherwise fails with `reason` when inputs are invalid or \(a > b\).

### rs.bigint.requireEq(a, b, reason)

Strict BigInt compare. Throws with `reason` when inputs are invalid or \(a \ne b\).

### rs.bigint.requireZero(amount, reason)

Throws with `reason` when amount is invalid or not zero. Use for "value must be zero" checks.

---

## rs.typedData

### rs.typedData.match(input, primaryType)

Soft match for typed-data rules: checks `sign_type === 'typed_data'` and `typed_data.primaryType === primaryType`.

**Returns:**
- Matched: `{ matched: true, domain, message }`
- Not matched: `{ matched: false }`

This function does **not** validate domain fields (name/version/chainId/verifyingContract) — use `requireDomain` for that.

### rs.typedData.require(input, primaryType)

Validates `sign_type === 'typed_data'`, presence of `typed_data`, and `primaryType` match.

**Returns:**
- Success: `{ domain, message }`
- Failure: throws with `reason`

### rs.typedData.requireDomain(domain, opts)

Validates domain. `opts`:
- `name`: optional; when present, required domain name
- `version`: optional; when present, required domain version
- `chainId`: required chain ID (number or string)
- `allowedContracts`: optional array of allowed `verifyingContract` addresses
- `requireVerifyingContract`: optional boolean (default: true). When false and `allowedContracts` is not set, verifyingContract is not required/validated.

**Returns:** `ok()` or `fail(reason)`.

### rs.typedData.requireSignerMatch(msgSigner, inputSigner, reason)

Returns `ok()` if both signers (checksummed) match; otherwise throws with `reason`.

---

## rs.multisend

### rs.multisend.parseBatch(raw, chainId, signer)

Parses Gnosis MultiSend(bytes) calldata. `raw` = hex without 0x prefix.

**Returns:** `{ items: [...], err?: string }`. Each item: `{ sign_type, chain_id, signer, transaction }`.

---

## rs.delegate

### rs.delegate.resolveByTarget(innerTo, byTarget, defaultRule)

Resolves delegate rule ID by inner target address. `byTarget` = `"addr:rule_id,addr:rule_id"`, `defaultRule` = fallback when no match.

**Returns:** rule ID string.

---

## rs.config

Config string values are **trimmed when injected** (in Go), so rules can use `config.xxx` directly without `(config.xxx || '').trim()`.

### rs.config.requireNonEmpty(key, reason)

Reads `config[key]` and **panics** with `reason` if missing or empty (after trim). Use for required config:  
`rs.config.requireNonEmpty('allowed_safe_addresses', 'missing or invalid allowed_safe_addresses');`

---

## rs.hex

### rs.hex.requireZero32(hexValue, reason)

Checks 32-byte hex value equals zero. Returns `ok()` or throws with `reason`.

---

## rs.gnosis.safe

### rs.gnosis.safe.parseExecTransactionData(calldataHex)

Parses Safe `execTransaction(...)` calldata (hex string with or without `0x`) and extracts:
- `innerTo`: `address to`
- `innerHex`: the dynamic `bytes data` payload (as `0x...`)
- `valueZero`: whether `value` is zero
- `operationCALL`: whether `operation` is `CALL` (`0`)

**Returns:** `{ valid: true, innerTo, innerHex, valueZero, operationCALL }` or `{ valid: false, reason }`.

---

## Examples

**ERC20 transfer with allowlist and cap:**
```javascript
function validate(input) {
  var ctx = rs.tx.require(input);
  if (!rs.addr.inList(ctx.tx.to, [config.token_address])) return fail('wrong contract');
  if (!eq(ctx.selector, selector('transfer(address,uint256)'))) return fail('not transfer');
  var dec = abi.decode(ctx.payloadHex, ['address', 'uint256']);
  rs.addr.requireInList(dec[0], config.allowed_recipients, 'to not allowed');
  if (config.max_amount) rs.bigint.requireLte(dec[1], config.max_amount, 'exceeds cap');
  return ok();
}
```

**EIP-712 Order validation:**
```javascript
function validate(input) {
  var ctx = rs.typedData.require(input, 'Order');
  rs.typedData.requireDomain(ctx.domain, {
    name: config.domain_name,
    version: config.domain_version,
    chainId: parseInt(config.chain_id, 10),
    allowedContracts: [config.exchange_address]
  });
  rs.addr.requireZero(ctx.message.taker, 'taker must be zero');
  rs.typedData.requireSignerMatch(ctx.message.signer, input.signer, 'signer mismatch');
  return ok();
}
```
