---
name: remote-signer-rule-development
description: Remote Signer rule development guide. Covers evm_js rules, solidity expression rules, templates, presets, delegate_to mechanism, and rs.* helper functions.
---

# Rule Development (remote-signer)

Guide for developing authorization rules for the remote-signer service.

## Rule Types

| Type | Engine | Use Case |
|------|--------|----------|
| `evm_js` | JavaScript (Goja) | Complex validation, delegate chains, address lists |
| `evm_solidity_expression` | Solidity (Forge) | On-chain equivalent validation |
| `evm_address_list` | Built-in | Simple address whitelist/blocklist |
| `evm_contract_method` | Built-in | Contract + method selector matching |
| `evm_value_limit` | Built-in | Max value per transaction |
| `signer_restriction` | Built-in | Restrict which signers can be used |
| `sign_type_restriction` | Built-in | Restrict sign types (transaction, typed_data, personal) |
| `message_pattern` | Built-in | Regex match on personal_sign messages |

## Rule Modes

- **blocklist** — Evaluated first. Match = immediate reject. Error = reject (fail-closed).
- **whitelist** — Evaluated second. Match = auto-approve. Error = skip rule (fail-open).

## evm_js Rule Structure

```yaml
rules:
  - name: "My Rule"
    type: "evm_js"
    mode: "whitelist"
    enabled: true
    config:
      sign_type_filter: "transaction"    # or: typed_data, personal, ""
      script: |
        function validate(input) {
          // input.sign_type, input.chain_id, input.signer
          // input.transaction: { from, to, value, data, gas }
          // input.typed_data: { domain, message, primaryType }
          // input.message: string (for personal_sign)

          var ctx = rs.tx.require(input);
          if (!rs.addr.inList(ctx.tx.to, [config.allowed_recipient])) {
            return fail('recipient not allowed');
          }
          return ok();
        }
```

## The config Object

Template variables are injected into the JS sandbox as `config.*`. For example, if a template declares:

```yaml
variables:
  - name: allowed_recipient
    type: address
    required: true
```

Then in the JS script: `config.allowed_recipient` is available.

### test_variables

Used during `remote-signer validate` to seed `config.*` for isolated template validation:

```yaml
test_variables:
  allowed_recipient: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
```

## Test Cases

Templates can include test cases for CI validation:

```yaml
test_cases:
  - name: "allow transfer to whitelisted address"
    input:
      sign_type: "transaction"
      chain_id: 137
      signer: "0x..."
      transaction:
        from: "0x..."
        to: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
        value: "0x0"
        data: "0xa9059cbb0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc4"
    expect_pass: true

  - name: "block transfer to unknown address"
    input:
      sign_type: "transaction"
      chain_id: 137
      signer: "0x..."
      transaction:
        from: "0x..."
        to: "0x0000000000000000000000000000000000000001"
        value: "0x0"
        data: "0xa9059cbb0000000000000000000000000000000000000000000000000000000000000001"
    expect_pass: false
```

## rs.* Helper Functions

38 functions across 10 modules:

| Module | Functions | Purpose |
|--------|-----------|---------|
| `rs.addr` | `requireInList`, `inList`, `requireZero`, `isZeroAddr`, `checksum`, `eq` | Address validation |
| `rs.bigint` | `requireLte`, `requireGte`, `requireGt`, `requireZero`, `isZero`, `cmp` | Big integer comparisons |
| `rs.int` | `requireInRange`, `requirePositive`, `requireLte` | Integer bounds checking |
| `rs.tx` | `require`, `isCreate` | Transaction structure validation |
| `rs.typedData` | `require`, `requireDomain`, `requireStruct` | EIP-712 typed data validation |
| `rs.config` | `get`, `getBool`, `getInt`, `require` | Config value access |
| `rs.delegate` | `resolve`, `resolveByTarget` | Delegate target resolution |
| `rs.multisend` | `unpack`, `mapToTxs`, `toTxLike` | MultiSend batch parsing |
| `rs.gnosis.safe` | `unpackExecTransaction` | Safe execTransaction unpacking |
| `rs.hex` | `toBytes`, `fromBytes` | Hex encoding/decoding |

### Common rs patterns

```javascript
// Transaction validation
var ctx = rs.tx.require(input);
if (!rs.addr.inList(ctx.tx.to, [config.allowed_recipient])) return fail('wrong contract');
rs.bigint.requireLte(ctx.tx.value, config.max_value, 'value');

// Typed data validation
var ctx = rs.typedData.require(input, 'Order');
rs.typedData.requireDomain(ctx.domain, {
  name: config.domain_name,
  version: config.domain_version,
  chainId: parseInt(config.chain_id, 10),
  allowedContracts: [config.exchange_address]
});

// Delegate resolution
var delegateTo = rs.delegate.resolveByTarget(
  innerToChecksum,
  config.delegate_to_by_target,
  config.delegate_to
);
if (delegateTo) return { valid: true, payload: payload, delegate_to: delegateTo };
```

## Delegate Mechanism

A whitelist rule can delegate inner call validation to another rule:

```
Outer rule (Safe wrapper) → unpacks payload → delegates to → Inner rule (calldata validation)
```

**Two delegation modes:**

| Mode | Behavior |
|------|----------|
| `single` (default) | Forward one payload. Try each target rule; any one passing = allowed. |
| `per_item` | Extract array from payload (keyed by `items_key`). Each item must pass at least one target. |

**Two ways to set target rule ID:**

| Source | Mechanism | Precedence |
|--------|-----------|-----------|
| Script return value | `validate()` returns `{ valid: true, delegate_to: "inst_abc..." }` | Higher |
| Config / template variable | `config.delegate_to` (set via Variables) | Lower (fallback) |

**Security constraints:**
- Depth limit: `DelegationMaxDepth = 6`
- Cycle detection: same rule cannot appear twice in delegation path
- Blocklist re-evaluation: inner payloads always run through blocklist first
- Item limit: `DelegationMaxItems = 256` for `per_item` mode

## Templates

Templates are parameterized rules with `${variable}` placeholders:

```yaml
# rules/templates/evm/my_template.yaml
variables:
  - name: chain_id
    type: string
    required: true
  - name: allowed_recipient
    type: address
    required: true

test_variables:
  chain_id: "137"
  allowed_recipient: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"

rules:
  - id: "my-rule"
    name: "My Parameterized Rule"
    type: "evm_js"
    mode: "whitelist"
    config:
      sign_type_filter: "transaction"
      chain_id: "${chain_id}"
      script: |
        function validate(input) {
          var ctx = rs.tx.require(input);
          if (!rs.addr.inList(ctx.tx.to, [config.allowed_recipient])) return fail('not allowed');
          return ok();
        }
```

## Presets

Presets bundle template references with default variable values. See `rules/presets/` for examples.

### Preset Variables & Default Danger Levels

When a template function receives empty string for allowlists, the validation **passes** (no restriction).
When it receives "-1" for amount caps, the validation **passes** (no limit).

| Default | Meaning | Danger |
|---------|---------|--------|
| `""` (empty string) | `requireInListIfNonEmpty()` → **any value allowed** | HIGH — no restriction |
| `"-1"` | `requireLte(-1)` → **no cap** | HIGH — unlimited |
| `"0"` | Block all | SAFE |
| Specific address/value | Restricted to that value | SAFE |

### Using CLI to Inspect Presets & Templates (Do NOT Hardcode Variable Tables)

Presets and templates change over time. NEVER hardcode variable tables in prompts or skills. Always use the CLI to query live data:

```bash
# Step 1: List available presets
./remote-signer preset remote-list --api-key-id admin

# Step 2: Get full preset details (variables, defaults, descriptions)
./remote-signer preset remote-get <preset-id> --api-key-id admin

# Step 3: Get the linked template to see validation logic
# Find template_id from preset remote-get output, then:
./remote-signer template get <template-id> --api-key-id admin
```

The `preset remote-get` output includes a variables table with NAME, TYPE, REQUIRED, DEFAULT, and DESCRIPTION. The `template get` output shows the full template YAML including JS validation code with `requireInListIfNonEmpty()`, `requireLte()`, etc.

### Preset Apply Protocol (Least-Privilege)

Before applying a preset that creates rules on the daemon, follow this protocol:

1. **Query preset details**: `preset remote-get <preset-id>` — see all variables, types, descriptions, defaults
2. **Query template**: `template get <template-id>` — see full validation logic, especially `requireInListIfNonEmpty` and `requireLte` behavior
3. **Assess each variable's default danger** (universal rule, does not depend on specific presets):
   - `""` (empty string) with `requireInListIfNonEmpty()` → **any value allowed** (no restriction)
   - `"-1"` with `requireLte()` → **no cap** (unlimited)
   - Non-empty value → restricted to that value (safe)
4. **Fill EVERY variable** that controls scope — do NOT leave optional variables at permissive defaults
5. **Ask the user** before deciding final values. Present each variable's default, its risk, and what values make sense.
6. Only after user confirms, run: `preset apply <preset-id> --set key=value --set key=value ...`

### Server API apply format

```yaml
name: "My Preset"
chain_type: "evm"
chain_id: "137"
variables:
  allowed_recipient: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
template_ids:
  - evm/my_template
```

## Chain ID Resolution

When a preset applies via daemon API (`preset apply <id> --set chain_id=56`):

1. Preset's `chain_id` field sets the rule scope (which chains the rule matches)
2. `--set chain_id=X` overrides preset's `chain_id` for the rule scope
3. `chain_id` is also injected as a **reserved variable** — available as `${chain_id}` in template substitution
4. If the preset has no `chain_id`, the rule matches **all chains** (nil scope)

Fix for hardcoded chain_id: if a preset was shipped with `chain_id: "1"` and you want to override, use `--set chain_id=<target>`. The variable value wins over the preset field.

## Validation

```bash
# Validate a single template
remote-signer validate rules/templates/evm/my_template.yaml

# Validate all templates
remote-signer validate rules/

# Validate full config
remote-signer validate
```
