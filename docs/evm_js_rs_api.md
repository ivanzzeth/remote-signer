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

All methods guard against null/undefined; invalid input returns `fail` or `false` instead of throwing.  
Exceptions thrown (e.g. `revert()`, `require()` failure, or `throw`) are caught by the engine and turned into **fail** with that message, so rules cannot be bypassed by triggering errors.

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
  if (!ctx.valid) return ctx;
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
- Success: `{ valid: true, tx, selector, payloadHex }`
- Failure: `{ valid: false, reason }`

**Example:**
```javascript
var ctx = rs.tx.require(input);
if (!ctx.valid) return ctx;
// ctx.tx = transaction object, ctx.selector = '0x...', ctx.payloadHex = '0x...'
```

### rs.tx.getCalldata(tx)

Extracts selector and payload from `tx.data`.

**Returns:**
- Success: `{ valid: true, selector, payloadHex }`
- Failure: `{ valid: false, reason }` (e.g. calldata too short)

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

Returns `ok()` if addr in list, else `fail(reason)`.

### rs.addr.requireNotInList(addr, list, reason)

Returns `ok()` if addr is **not** in list (or addr is invalid), else `fail(reason)`.

### rs.addr.requireInListIfNonEmpty(addr, list, reason)

When `list` is empty (array length 0 or string trim empty), returns `ok()` (allow any).  
Otherwise same as `requireInList`. Use for optional allowlists where empty = no restriction.

### rs.addr.isZero(addr)

Returns `true` if addr is the zero address.

### rs.addr.requireZero(addr, reason)

Returns `ok()` if addr is zero, else `fail(reason)`.

---

## rs.int

Strict integer parsing helpers. Invalid input never silently becomes 0.

### rs.int.parseUint(value)

Parses an unsigned integer from a decimal string/number.

**Returns:** `{ valid: true, n }` or `fail("invalid value")`.

### rs.int.requireLte(value, max, reason)

Fails with `reason` when value/max are invalid or value > max.

### rs.int.requireEq(value, want, reason)

Fails with `reason` when value/want are invalid or value != want.

---

## rs.bigint

### rs.bigint.parse(value)

Parses `value` into a real JavaScript `BigInt` using `BigInt(...)`.

- **Input**: decimal string (`"42"`), hex string (`"0x2a"`), or integer-like number.
- **Returns**: `{ valid: true, n: <BigInt> }` or `{ valid: false, reason }`.

### rs.bigint.uint256(value)

Parses `value` as a **uint256** (range \(0 \le x \le 2^{256}-1\)) and returns a JavaScript `BigInt`.

**Returns**: `{ valid: true, n: <BigInt> }` or `fail("invalid uint256")`.

### rs.bigint.int256(value)

Parses `value` as an **int256** (range \(-2^{255} \le x \le 2^{255}-1\)) and returns a JavaScript `BigInt`.

**Returns**: `{ valid: true, n: <BigInt> }` or `fail("invalid int256")`.

### rs.bigint.requireLte(a, b, reason)

Strict BigInt compare. When `b` is empty or `"0"`, no limit → returns `ok()`. Otherwise fails with `reason` when inputs are invalid or \(a > b\).

### rs.bigint.requireEq(a, b, reason)

Strict BigInt compare. Fails with `reason` when inputs are invalid or \(a \ne b\).

### rs.bigint.requireZero(amount, reason)

Fails with `reason` when amount is invalid or not zero. Use for "value must be zero" checks.

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
- Success: `{ valid: true, domain, message }`
- Failure: `{ valid: false, reason }`

### rs.typedData.requireDomain(domain, opts)

Validates domain. `opts`:
- `name`: optional; when present, required domain name
- `version`: optional; when present, required domain version
- `chainId`: required chain ID (number or string)
- `allowedContracts`: optional array of allowed `verifyingContract` addresses
- `requireVerifyingContract`: optional boolean (default: true). When false and `allowedContracts` is not set, verifyingContract is not required/validated.

**Returns:** `ok()` or `fail(reason)`.

### rs.typedData.requireSignerMatch(msgSigner, inputSigner, reason)

Returns `ok()` if both signers (checksummed) match, else `fail(reason)`.

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

Checks 32-byte hex value equals zero. Returns `ok()` or `fail(reason)`.

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
  if (!ctx.valid) return ctx;
  if (!rs.addr.inList(ctx.tx.to, [config.token_address])) return fail('wrong contract');
  if (!eq(ctx.selector, selector('transfer(address,uint256)'))) return fail('not transfer');
  var dec = abi.decode(ctx.payloadHex, ['address', 'uint256']);
  var r = rs.addr.requireInList(dec[0], config.allowed_recipients, 'to not allowed');
  if (!r.valid) return r;
  if (config.max_amount) { var r = rs.bigint.requireLte(dec[1], config.max_amount, 'exceeds cap'); if (!r.valid) return r; }
  return ok();
}
```

**EIP-712 Order validation:**
```javascript
function validate(input) {
  var ctx = rs.typedData.require(input, 'Order');
  if (!ctx.valid) return ctx;
  var r = rs.typedData.requireDomain(ctx.domain, {
    name: config.domain_name,
    version: config.domain_version,
    chainId: parseInt(config.chain_id, 10),
    allowedContracts: [config.exchange_address]
  });
  if (!r.valid) return r;
  r = rs.addr.requireZero(ctx.message.taker, 'taker must be zero');
  if (!r.valid) return r;
  r = rs.typedData.requireSignerMatch(ctx.message.signer, input.signer, 'signer mismatch');
  if (!r.valid) return r;
  return ok();
}
```
