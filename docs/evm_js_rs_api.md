# evm_js rs Module API Reference

The **rs** (remote-signer) module provides a composable, safe API for evm_js rules. It is injected into the rule sandbox; the name `rs` is reserved — do not use it as a variable.

## Overview

| Sub-module   | Purpose                                      |
|-------------|-----------------------------------------------|
| **rs.tx**   | Transaction validation and calldata parsing   |
| **rs.addr** | Address checks (allowlist, zero)              |
| **rs.uint256** | Uint256 string comparison                  |
| **rs.typedData** | EIP-712 typed data validation             |
| **rs.multisend** | Gnosis MultiSend batch parsing             |
| **rs.delegate** | Resolve rule ID by target address          |
| **rs.hex**  | Hex value checks (e.g. zero32)                |

All methods guard against null/undefined; invalid input returns `fail` or `false` instead of throwing.

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

### rs.addr.requireInList(addr, list, reason)

Returns `ok()` if addr in list, else `fail(reason)`.

### rs.addr.requireInListIfNonEmpty(addr, list, reason)

When `list` is empty (array length 0 or string trim empty), returns `ok()` (allow any).  
Otherwise same as `requireInList`. Use for optional allowlists where empty = no restriction.

### rs.addr.isZero(addr)

Returns `true` if addr is the zero address.

### rs.addr.requireZero(addr, reason)

Returns `ok()` if addr is zero, else `fail(reason)`.

---

## rs.uint256

String-only comparison; no Number coercion. Invalid (non-decimal) input → `false` or `null`.

### rs.uint256.cmp(a, b)

Returns `-1` (a < b), `0` (a == b), `1` (a > b), or `null` (invalid).

### rs.uint256.lt(a, b), lte, gt, gte

Returns boolean. Invalid input → `false`.

### rs.uint256.requireLte(amount, max, label)

Amount cap check. When `max` is empty or `"0"`, no limit → returns `ok()`.

**Returns:** `ok()` or `fail(reason)`:
- `label + " cap invalid"` when max is not a decimal string
- `label + " amount invalid"` when amount is not a decimal string
- `label + " exceeds cap"` when amount > max

**Example:** `rs.uint256.requireLte(dec[1], config.max_transfer_amount, 'transfer')`

---

## rs.typedData

### rs.typedData.require(input, primaryType)

Validates `sign_type === 'typed_data'`, presence of `typed_data`, and `primaryType` match.

**Returns:**
- Success: `{ valid: true, domain, message }`
- Failure: `{ valid: false, reason }`

### rs.typedData.requireDomain(domain, opts)

Validates domain. `opts`:
- `name`: required domain name
- `version`: required domain version
- `chainId`: required chain ID (number or string)
- `allowedContracts`: optional array of allowed `verifyingContract` addresses

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

## rs.hex

### rs.hex.requireZero32(hexValue, reason)

Checks 32-byte hex value equals zero. Returns `ok()` or `fail(reason)`.

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
  if (config.max_amount && rs.uint256.gt(dec[1], config.max_amount)) return fail('exceeds cap');
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
