---
name: remote-signer-rule-development
description: Remote Signer rule development guide. Covers evm_js templates, presets, variables lifecycle, rs.* helpers, validation, and protocol authoring workflow. Single source of truth for agent-driven rule development.
---

# Rule Development (remote-signer)

> **Single source of truth for agents.** All rule files live under the operator home `~/.remote-signer/rules/`. Do not duplicate variable tables here — query live presets/templates via CLI.

## Concepts

| Artifact | Purpose | Example |
|----------|---------|---------|
| **Template** | Protocol validation logic (reusable) | `~/.remote-signer/rules/templates/evm/aori.yaml` |
| **Preset** | dApp scenario: addresses + `template_ids` composition | `~/.remote-signer/rules/presets/evm/stargate.yaml` |
| **Instance** | Runtime rule expanded from template + variables | Created by `preset apply` |

**Naming:** template = protocol/engine (`aori`); preset = dApp/scenario (`stargate`). Do not combine names (`stargate-aori`).

## Authoring workflow

```
1. Observe real sign requests (approve, typed_data, tx)
2. Write template(s) under ~/.remote-signer/rules/templates/
3. remote-signer validate -v ~/.remote-signer/rules/templates/evm/<protocol>.yaml
4. Write preset under ~/.remote-signer/rules/presets/
5. preset remote-get → assess default danger → ask user → preset apply
6. UI Reload from disk (or restart if config changed)
```

**Upstream contribution (optional, when stable):** clone the [remote-signer](https://github.com/ivanzzeth/remote-signer) project, add templates/presets there, open a PR. Operators without that repo never need this step.

### Case study: Stargate Fast Swaps (Aori)

Stargate UI (`stargate.finance/transfer`) uses **Aori** as execution engine — not the same protocol.

| Step | Sign type | What |
|------|-----------|------|
| 1 | `transaction` | ERC20 `approve` → Aori contract (`0xffe691...` on BSC) |
| 2 | `typed_data` | Aori `Order` EIP-712 (`domain.name: Aori`, `version: 0.3.1`) |

**On-disk artifacts:**

- `~/.remote-signer/rules/templates/evm/aori.yaml` — Order typed_data validation
- `~/.remote-signer/rules/presets/evm/stargate.yaml` — composes `evm/erc20` + `evm/aori` (multi-chain via **matrix**, same pattern as `uniswap.yaml`)

**Order fields** (from `GET https://api.aori.io/domain`):

```
Order(uint128 inputAmount, uint128 outputAmount, address inputToken, address outputToken,
      uint32 startTime, uint32 endTime, uint32 srcEid, uint32 dstEid,
      address offerer, address recipient)
```

**Security (required in `aori` template):**

- `offerer` must match `input.signer` (payer on source chain)
- `recipient` must match `input.signer` (destination output must land on the signing key — blocks draining to arbitrary addresses)

**Multi-chain preset (Stargate):** Do **not** put `chain_id: "56"` on the preset. Stargate is cross-chain; one preset covers all Aori source chains:

```yaml
name: "Stargate"
chain_type: "evm"
# no chain_id — one rule instance per template, matrix resolves per request chain
defaults:
  domain_name: "Aori"
  allowed_dst_eids: "..."      # all LayerZero eids from GET https://api.aori.io/chains
  allowed_output_tokens: "..." # all routable tokens from GET https://api.aori.io/tokens
matrix:
  - chain_id: "56"
    aori_contract_address: "0xffe691..."   # from /chains
    allowed_spenders: "0xffe691..."        # erc20 approve spender
    allowed_src_eids: "30102"
    allowed_input_tokens: "..."            # that chain's tokens from /tokens
template_ids: [evm/erc20, evm/aori]
```

Reference: `~/.remote-signer/rules/presets/evm/uniswap.yaml` (`defaults` + `matrix`, no preset `chain_id`).

**Anti-pattern:** Do not whitelist Aori `Order` via generic `evm/agent` `trusted_contracts`. Use a dedicated `aori` template like Polymarket uses `polymarket_v2`. Do not split Stargate into per-chain presets.

## File layout

All agent/user rule development happens here:

```
~/.remote-signer/rules/
├── templates/evm/<protocol>.yaml
└── presets/evm/<dapp>.yaml
```

`~/.remote-signer/config.yaml` must set:

```yaml
templates_dir: /home/<user>/.remote-signer/rules/templates
presets:
  dir: /home/<user>/.remote-signer/rules/presets
```

**First-time setup:** if `templates_dir` is set, the daemon reads the **entire** catalogue from disk (embedded catalogue is bypassed). Seed `~/.remote-signer/rules/` by copying the shipped `rules/templates` and `rules/presets` trees from a [remote-signer](https://github.com/ivanzzeth/remote-signer) clone, then add your own files.

**Reload semantics:**

- Config change or first enable of `templates_dir` → **restart** server
- Subsequent YAML edits → UI **Reload from disk** (`POST /api/v1/registry/refresh`)

Each rule in a template **must** have explicit `id` (required by `remote-signer validate`). Optional template variables **must** declare `default`.

## Rule modes

- **blocklist** — first. Match = reject. Error = reject (fail-closed).
- **whitelist** — second. Match = auto-approve. Error = skip (fail-open).

## evm_js rule structure

```yaml
rules:
  - id: "my-rule"          # required
    name: "My Rule"
    type: "evm_js"
    mode: "whitelist"
    enabled: true
    chain_id: "${chain_id}" # optional scope
    config:
      sign_type_filter: "typed_data"   # transaction | typed_data | personal | ""
      script: |
        function validate(input) {
          var ctx = rs.typedData.require(input, 'Order');
          return ok();
        }
      test_cases:
        - name: "should pass"
          input: { sign_type: "typed_data", ... }
          expect_pass: true
```

`test_variables` seeds `config.*` during offline validation. Use `${var}` substitution in test_cases.

## Variables lifecycle (critical)

Template variables flow through four stages:

1. **Template `variables[].default`** — schema defaults
2. **Preset `variables`** — deployment values
3. **Agent `propose` / `update`** — **merge** patch onto existing (partial update safe)
4. **Eval time** — missing keys filled from template defaults (`ApplyVariableDefaults`)

**Known pitfall:** proposing only `{ trusted_contracts: "0x..." }` must not drop other keys like `max_approve_amount: "-1"` → eval fails with `approve exceeds cap`. Partial patches merge; never send a variables object that omits existing caps.

## Danger defaults (per helper)

| Value | `requireInListIfNonEmpty` | `requireLte` |
|-------|---------------------------|--------------|
| `""` empty | allow any | **FAIL** (invalid) |
| `"-1"` | N/A | no cap |
| `"0"` | N/A | cap zero (block) |
| specific value | restricted | restricted |

At eval, a **missing** key may inherit template `default` (e.g. `max_approve_amount: "-1"`). An **empty string value** does not.

**Never hardcode preset variable tables in this skill.** Query live data:

```bash
RS="remote-signer --url http://127.0.0.1:8548 \
  --api-key-id admin \
  --api-key-keystore ~/.remote-signer/apikeys/admin.keystore.json \
  --tls-skip-verify"

$RS preset remote-list
$RS preset remote-get <preset-id>
$RS template get evm/aori
```

## Preset format

```yaml
name: "Stargate (BSC source)"
chain_type: "evm"
chain_id: "56"
enabled: true
variables:
  token_address: "0x55d3..."
  aori_contract_address: "0xffe691..."
  allowed_src_eids: "30102"
  allowed_dst_eids: "30110"
template_ids:
  - evm/erc20
  - evm/aori
operator_overrides:
  - name: max_approve_amount
    required: false
budget:
  unit: "${chain_id}:${token_address}"
  max_per_tx: "${max_approve_amount}"
schedule:
  period: "${budget_period}"
```

Apply after user confirms variable values:

```bash
$RS preset apply stargate --set max_input_amount=1000000000000000000
```

`--set chain_id=X` overrides preset chain scope. Reserved variable `chain_id` is also injected for `${chain_id}` substitution.

## Global JS primitives

Injected into every evm_js sandbox (do not redefine):

`fail(reason)`, `ok()`, `revert(reason)`, `require(cond, reason)`, `eq`, `keccak256`, `selector`, `toChecksum`, `isAddress`, `toWei`, `fromWei`, `abi.encode`, `abi.decode`

## rs.* module (current API)

When unsure about a helper, read `js_helpers*.go` in the remote-signer source. Do not trust stale function lists.

| Module | Functions |
|--------|-----------|
| `rs.tx` | `require`, `getCalldata` |
| `rs.addr` | `inList`, `eq`, `notInList`, `requireInList`, `requireNotInList`, `requireInListIfNonEmpty`, `isZero`, `requireZero`, `toChecksumList` |
| `rs.int` | `parseUint`, `requireLte`, `requireEq` |
| `rs.bigint` | `parse`, `uint256`, `int256`, `requireLte`, `requireEq`, `requireZero` |
| `rs.typedData` | `match`, `require`, `requireDomain`, `requireSignerMatch` |
| `rs.config` | `requireNonEmpty` |
| `rs.delegate` | `resolveByTarget` |
| `rs.multisend` | `parseBatch` |
| `rs.gnosis.safe` | `parseExecTransactionData` |
| `rs.hex` | `requireZero32` |

### Common patterns

```javascript
// Transaction
var ctx = rs.tx.require(input);
if (!rs.addr.inList(ctx.tx.to, [config.token_address])) return fail('wrong contract');
rs.bigint.requireLte(amount, config.max_approve_amount, 'approve exceeds cap');

// Typed data (Aori / Polymarket style)
var ctx = rs.typedData.require(input, 'Order');
rs.typedData.requireDomain(ctx.domain, {
  name: config.domain_name,
  version: config.domain_version,
  chainId: parseInt(config.chain_id, 10),
  allowedContracts: [config.aori_contract_address]
});
rs.typedData.requireSignerMatch(msg.offerer, input.signer, 'offerer must match signing key');
rs.typedData.requireSignerMatch(msg.recipient, input.signer, 'recipient must match signing key');
rs.addr.requireInListIfNonEmpty(msg.inputToken, config.allowed_input_tokens, 'inputToken not allowed');
```

`rs.*` helpers throw on failure; uncaught exceptions become `valid: false`.

## Delegate mechanism

Outer rule unpacks wrapper (Safe, MultiSend) → delegates inner validation.

| Config key | Purpose |
|------------|---------|
| `delegate_to` | Target rule ID(s), comma-separated |
| `delegate_mode` | `single` (default) or `per_item` |
| `items_key` | Array field in payload for `per_item` (default `items`) |

Script can return `{ valid: true, payload, delegate_to: "inst_..." }` (higher precedence than config).

Limits: depth ≤ 6, items ≤ 256, cycle detection, blocklist re-run on inner payloads.

## Validation

```bash
remote-signer validate -v ~/.remote-signer/rules/templates/evm/aori.yaml
remote-signer validate ~/.remote-signer/rules/templates/evm/
$RS preset validate stargate
```

Flag order: `remote-signer validate -v <file>` (not `validate <file> -v`).

Test cases support `expect_pass`, `expect_reason`, `expect_budget_amount` (for `validateBudget()`).

## Preset apply protocol (least-privilege)

1. `preset remote-get <id>` — variables, defaults, descriptions
2. `template get <template-id>` — read validation logic
3. Assess each variable's default danger (`""` / `"-1"` = high risk)
4. Fill every scope-limiting variable; do not leave permissive defaults
5. **Ask user** before final values
6. `preset apply <id> --set key=value ...`

## Chain ID resolution

- Preset `chain_id` → rule scope (which chains match)
- `--set chain_id=X` overrides scope
- `${chain_id}` available in template substitution
- No `chain_id` on preset → matches all chains; use **`matrix`** rows with `chain_id` to override per-chain variables at eval time (see `uniswap.yaml`, `stargate.yaml`)

### Matrix (multi-chain presets)

One rule instance + `matrix: [{ chain_id, ...vars }]`. At evaluation, `effectiveVarMap` overlays the row matching the request `chain_id` onto `Variables` before `${var}` substitution. String values only in matrix rows.

## Rule types (built-in + evm_js)

| Type | Use |
|------|-----|
| `evm_js` | Complex validation, delegates, protocol templates |
| `evm_solidity_expression` | Solidity/Forge equivalent |
| `evm_address_list` | Address whitelist/blocklist |
| `evm_contract_method` | Contract + selector |
| `evm_value_limit` | Max tx value |
| `signer_restriction` | Signer allowlist |
| `sign_type_restriction` | Sign type filter |
| `message_pattern` | personal_sign regex |

## Checklist before going live

- [ ] Observed real sign requests captured (types, domain, calldata)
- [ ] Template with explicit rule `id`s and ≥1 negative `test_cases`
- [ ] `remote-signer validate -v` passes on `~/.remote-signer/rules/...`
- [ ] Preset composes only needed `template_ids` (no generic agent-sign hack)
- [ ] All scope variables filled in preset (tokens, contracts, eids, caps)
- [ ] User confirmed variable values before `preset apply`
- [ ] Reload from disk (or restart) picked up files; tested against authorizing re-eval
