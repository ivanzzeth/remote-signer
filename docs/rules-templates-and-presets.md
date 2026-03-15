# Rules, Templates, and Presets

This document explains how rules are defined, how **templates** parameterize them, and how **presets** simplify adding ready-made rule configurations (e.g. Polymarket, Predict) with minimal variable overrides.

For rule *syntax* (Solidity expressions, EIP-712, evm_js), see [rule-syntax.md](rule-syntax.md). For config structure reference, see [configuration.md](configuration.md).

---

## 1. Concepts

| Term | Meaning |
|------|--------|
| **Rule** | A single policy entry: name, type (e.g. `evm_js`, `evm_solidity_expression`), mode (whitelist/blocklist), and config. Rules are evaluated in order; blocklist first, then whitelist. |
| **Template** | A parameterized rule (or set of rules) defined in a YAML file. It declares **variables** (e.g. `chain_id`, contract addresses) and **rules** that use `${variable}` placeholders. The server does not run the template as-is; it is expanded only when an **instance** supplies concrete variable values. |
| **Instance** | A config entry of type `instance` that references a template by name and provides **variables**. The server expands it into concrete rules by substituting those variables into the template. |
| **Preset** | A convenience layer: a YAML file that stores one (or more) instance-style rule(s) with **default variables** already filled in. You override only a few values (e.g. your Safe address) and optionally merge the result into `config.yaml` via CLI or setup. |

Flow in short: **Template file** (variables + rules with `${var}`) → loaded in config under **templates** → **Instance** in **rules** (template name + variables) → server **expands** to concrete rules. **Presets** are just pre-filled instance data so you don’t copy-paste long variable blocks.

---

## 2. Naming convention

File and artifact names use a single pattern so that **type** (template vs instance vs preset) and **protocol + capability** are clear at a glance.

| Pattern | Meaning | Example |
|--------|---------|--------|
| `xxx_yyy.template.yaml` | Rule **template**: parameterized rules, `xxx` = protocol, `yyy` = capability | `polymarket_auth.template.yaml`, `polymarket_create_safe.template.yaml` |
| `xxx_yyy.template.js.yaml` | Rule template implemented in **JavaScript** (same idea, JS engine) | `polymarket_some_capability.template.js.yaml` |
| `xxx_yyy.yaml` (no `template`/`preset`) | **Instance**: concrete rule config (references a template and supplies variables) | `polymarket_safe.yaml`, `polymarket_eoa.yaml` |
| `xxx_yyy.preset.yaml` | **Preset**: pre-filled instance(s) for quick add (replace `template` with `preset`) | `polymarket_eoa_polygon.preset.yaml`, `polymarket_safe_init_polygon.preset.js.yaml` |

- **Segments**: use **underscores** (`_`) for readability (e.g. `create_safe`, `eoa_polygon`). No mixing of kebab-case and underscores in the same naming scheme.
- **Protocol** (`xxx`): e.g. `polymarket`, `predict`.
- **Capability / scenario** (`yyy`): e.g. `auth`, `create_safe`, `enable_trading`, `trading`, `eoa_polygon`, `safe_init_polygon`, `safe_polygon`.
- **Suffix**: `.template.yaml` or `.template.js.yaml` = template; `.preset.yaml` = preset; no suffix (only `.yaml`) = instance. So the **presence or replacement of the word `template`** (or `preset`) in the filename identifies the kind of file.

---

## 3. Rule templates

### 3.1 What a template is

A **template** is a YAML file that defines:

- **variables**: list of `{ name, type, description, required }` (e.g. `chain_id`, `ctf_exchange_address`, `allowed_safe_addresses`).
- **test_variables**: (optional) default values used when validating the template in isolation (e.g. `remote-signer-validate-rules rules/templates/polymarket_safe.template.yaml` or `remote-signer-cli validate rules/...`).
- **rules**: the same structure as config rules, but with **placeholders** like `${chain_id}` or `${allowed_safe_addresses}` in expressions and config.

The server does not evaluate the template file directly. It loads templates listed in `config.templates` (type `file` with a `path`). When a **rule** of type `instance` references that template and supplies `config.variables`, the server substitutes those values into the template’s rules and expands them into concrete rules.

### 3.2 Where templates are defined

In `config.yaml`:

```yaml
templates:
  - name: "Polymarket Safe Template"
    type: "file"
    enabled: true
    config:
      path: "rules/templates/polymarket_safe.template.yaml"
```

- **name**: used by instance rules in `config.rules` via `config.template`.
- **type: "file"**: load from the given path (relative to config file or project root).
- **path**: path to the template YAML.

Template files live under `rules/templates/` (e.g. `polymarket_safe.template.yaml`, `predict_auth.template.yaml`, `predict_enable_trading.template.yaml`, `predict_trading.template.yaml`). Each file contains `variables`, optional `test_variables`, and `rules` with `${var}` placeholders.

### 3.3 Template file format (example)

```yaml
# rules/templates/polymarket_safe.template.yaml
variables:
  - name: chain_id
    type: string
    description: "Chain ID (e.g. 137 for Polygon)"
    required: true
  - name: allowed_safe_addresses
    type: string
    description: "Comma-separated allowed Safe addresses"
    required: true

test_variables:   # used by remote-signer-validate-rules / remote-signer-cli validate when validating this file alone
  chain_id: "137"
  allowed_safe_addresses: "0x..."

rules:
  - name: "Polymarket CTF check"
    type: "evm_js"
    mode: "whitelist"
    config:
      expression: "in(verifyingContract, allowed_safe_addresses)"
      # ...; allowed_safe_addresses is filled from instance variables
```

Variables can be scalars (string, number) or, in config/instance, represented as comma-separated strings or arrays for list-like values (e.g. multiple addresses). The engine uses comma-separated values for constructs like `in(expr, varName)`.

### 3.4 rs helpers (evm_js templates)

evm_js templates can use the **rs** module for composable validation. See [evm_js_rs_api.md](evm_js_rs_api.md) for the full API.

**Transaction validation:**
```javascript
var ctx = rs.tx.require(input);
if (!rs.addr.inList(ctx.tx.to, [config.token_address])) return fail('wrong contract');
```

**Typed-data validation:**
```javascript
var ctx = rs.typedData.require(input, 'Order');
rs.typedData.requireDomain(ctx.domain, { name: config.domain_name, version: config.domain_version, chainId: parseInt(config.chain_id, 10), allowedContracts: [config.exchange_address] });
```

**Address and amount checks:**
```javascript
rs.addr.requireInList(spender, config.allowed_spenders, 'spender not allowed');
rs.addr.requireInListIfNonEmpty(to, config.allowed_recipients, 'to not allowed');  // empty list = any
rs.addr.requireZero(msg.taker, 'taker must be zero');
rs.bigint.requireLte(amount, config.max_amount, 'transfer');  // empty/0 max = no limit
```

---

## 4. Rule examples in config

Rules in `config.rules` can be defined in three ways.

### 4.1 Inline rules

The rule is fully defined under `rules` in config:

```yaml
rules:
  - name: "Allow treasury"
    type: "evm_address_list"
    mode: "whitelist"
    enabled: true
    config:
      addresses: ["0x5B38Da..."]
```

No template or file reference; good for small, static policies.

### 4.2 File rules

Load a list of rules from an external YAML file:

```yaml
rules:
  - name: "Treasury rules"
    type: "file"
    config:
      path: "rules/treasury.yaml"
```

The file must contain a top-level `rules:` list (same shape as config rules). No variable substitution; the file is used as-is.

### 4.3 Instance rules (from template)

Reference a template by name and supply variables. The server expands this into concrete rules by substituting the variables into the template:

```yaml
rules:
  - name: "Polymarket Safe rules (Polygon)"
    type: "instance"
    chain_type: "evm"
    chain_id: "137"
    enabled: true
    config:
      template: "Polymarket Safe Template"
      variables:
        chain_id: "137"
        ctf_exchange_address: "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"
        # ... all variables the template expects ...
        allowed_safe_addresses: "0xYourSafe1,0xYourSafe2"
        allowed_safe_address_for_testing: "0xYourSafe1"
```

- **template**: must match a `name` in `config.templates`.
- **variables**: map of variable names to values. Values can be strings or (in YAML) arrays; for list-like use (e.g. `in(expr, varName)`), comma-separated strings or arrays are normalized as needed by the engine.

Instance rules are the main way to use shared templates (Polymarket, Predict, Opinion, etc.) without duplicating long rule definitions; you only maintain the variable set.

---

## 5. Presets

### 5.1 What a preset is

A **preset** is a YAML file that stores one or more **instance-style rule(s)** with default variables already filled in. It does not add a new rule type: it is a convenience format so you can:

- Avoid copying long variable blocks from `config.example.yaml`.
- Override only a few values (e.g. your Safe address) and optionally merge the result into your `config.yaml` via **remote-signer-cli** or **setup.sh**.

Presets live under `rules/presets/` (e.g. `polymarket_safe_polygon.preset.js.yaml`). The **CLI** uses them for list/vars/create-from and setup; when `presets.dir` is set in config, the **server** can also read the same directory and expose a preset API (list, vars, apply) for admin keys.

### 5.2 Single-rule preset format

One rule per file, flat structure:

```yaml
# rules/presets/polymarket_safe_polygon.preset.js.yaml
name: "Polymarket Safe rules (Polygon)"
template: "Polymarket Safe Template"
chain_type: "evm"
chain_id: "137"
enabled: true
variables:
  chain_id: "137"
  ctf_exchange_address: "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"
  # ... all required template variables with defaults ...
  allowed_safe_addresses: "0x1111111111111111111111111111111111111111"
  allowed_safe_address_for_testing: "0x1111111111111111111111111111111111111111"

# Optional: keys users typically override (for CLI prompts / docs)
override_hints:
  - allowed_safe_addresses
  - allowed_safe_address_for_testing
```

This is equivalent to one entry in `config.rules` with `type: "instance"` and the same `name`, `config.template`, and `config.variables`.

### 5.3 Multi-rule preset format

One file can define multiple rules with a top-level `rules:` list:

```yaml
# rules/presets/polygon-and-bnb.yaml
rules:
  - name: "Polymarket Safe rules (Polygon)"
    type: "instance"
    config:
      template: "Polymarket Safe Template"
      variables: { chain_id: "137", ... }
    chain_type: "evm"
    chain_id: "137"
    enabled: true
  - name: "Predict.fun EOA (BNB) (Predict Auth Template)"
    type: "instance"
    config:
      template: "Predict Auth Template"
      variables: {}
    chain_type: "evm"
    chain_id: "56"
    enabled: true
  - name: "Predict.fun EOA (BNB) (Predict Enable Trading Template)"
    type: "instance"
    config:
      template: "Predict Enable Trading Template"
      variables: { chain_id: "56", usdt_address: "0x55d3...", ... }
    chain_type: "evm"
    chain_id: "56"
    enabled: true
  - name: "Predict.fun EOA (BNB) (Predict Trading Template)"
    type: "instance"
    config:
      template: "Predict Trading Template"
      variables: { chain_id: "56", order_domain_name: "predict.fun CTF Exchange", ... }
    chain_type: "evm"
    chain_id: "56"
    enabled: true
```

The CLI can apply overrides to all entries or target one by index.

### 5.4 Variables in presets: scalars and arrays

- **Scalars**: string or number, same as in config (e.g. `chain_id: "137"`, `clob_auth_domain_name: "ClobAuthDomain"`).
- **Lists / arrays**: template variables that represent multiple values (e.g. allowed Safe addresses) can be:
  - A **comma-separated string**: `allowed_safe_addresses: "0xa,0xb"`.
  - A **YAML array**: `allowed_safe_addresses: ["0xa", "0xb"]`. When merged into config or expanded by the server, these are normalized so the engine sees the same behavior (e.g. comma-separated for `in(expr, varName)`).

When using the CLI to override variables, array-like values can be passed as:

- `--set key=val1,val2` (stored as a single string), or
- `--set key='["val1","val2"]'` (parsed as JSON array and normalized when writing config).

### 5.5 Preset format: template_path and override_hints

- **template_path** (optional): Path to the template file (e.g. `rules/templates/polymarket_safe.template.yaml`). When you run `preset create-from ... --write`, the CLI injects this template into `config.templates` if it is not already present, so the preset is self-contained and config does not need to define the template beforehand.
- **override_hints** (optional): List of variable names to prompt for in setup (e.g. `allowed_safe_addresses`, `allowed_safe_address_for_testing`). The **preset vars** subcommand reads the template file (via `template_path`) and outputs each variable with its **description** from the template, so setup can show “variable (description)” when prompting.

Template files define variables with a **description** field; that description is shown during interactive setup when the user is asked to fill in override values.

### 5.6 Using presets with the CLI

(When **remote-signer-cli** is available.)

- **List presets**:  
  `remote-signer-cli preset list`  
  Scans `rules/presets/` and shows preset name(s) and template name(s).

- **Variables to prompt (for scripts)**:  
  `remote-signer-cli preset vars <preset-name> --presets-dir rules/presets --project-dir .`  
  Outputs one line per override variable: `name<TAB>description`. Used by setup to show descriptions when prompting.

- **Generate a rule from a preset (no config change)**:  
  `remote-signer-cli preset create-from polymarket_safe_polygon --set allowed_safe_addresses=0xYourSafe`  
  Outputs the rule YAML so you can paste it into `config.yaml`.

- **Append the rule to config (and inject template if missing)**:  
  `remote-signer-cli preset create-from polymarket_safe_polygon --config config.yaml --write --set allowed_safe_addresses=0xYourSafe`  
  If the preset has `template_path` and the config does not yet define that template, the CLI adds the template entry from the preset.

- **Composite presets (multiple templates)**  
  Use `template_paths` and `template_names` in the preset. The CLI generates one rule per template; each rule gets a **copy** of the preset’s `variables` (see below). Example: `polymarket_safe_polygon.preset.js.yaml` with four templates produces four instance rules, all sharing the same variable values.

### 5.7 How variables work: one fill, no interference

- **Preset = one variable set**  
  A preset has a single `variables` block (and optional `--set` overrides). You fill variables **once** for the whole preset.

- **Composite preset → one set copied to every rule**  
  When a preset uses `template_paths` / `template_names`, the CLI generates one config rule per template. Each of those rules gets a **copy** of the same preset variables. So you do **not** fill each template separately; the same values are used for every instance.

- **Repeated variable names across templates**  
  Templates (e.g. auth, create_safe, trading) often declare the same names (`chain_id`, `allowed_safe_addresses`, etc.). In the preset you still define each name only once. That single value is copied into every generated rule.

- **No interference between rule instances**  
  In the final config, each rule is a separate entry with its own `config.variables` map. When the server expands an instance rule, it uses **only that rule’s** `config.variables` to substitute into that rule’s template. So multiple rules with the same variable names do not affect each other; each instance is evaluated in isolation.

- **Templates use a subset of the preset variables**  
  A preset usually contains the **union** of variables needed by all its templates (e.g. auth needs `chain_id`, trading needs `allowed_safe_addresses`). When a template is expanded, only the placeholders it actually uses (e.g. `${chain_id}`) are replaced; extra keys in the variable map are simply unused for that template and cause no problem.

### 5.8 Budget and schedule in presets (templates with budget_metering)

Presets can include **`budget`** and **`schedule`** so that instance rules get budget enforcement and period reset when config is synced (or when instantiating via API with the same structure).

- **`budget`** (optional block): when present, **`unit`** is **required**. It identifies what is being consumed (e.g. per chain+token) so budgets do not get mixed up. Also: `max_total`, `max_per_tx`, `max_tx_count`, `alert_pct`. **All** of these fields support template variables (`${var}`).
- **`schedule`** (optional): `period` (e.g. `"24h"`, `"168h"`), optional `start_at` (RFC3339).

**Template variables** are supported in **every** budget and schedule field: any string value can use `${var}` (e.g. `unit: "${chain_id}:${token_address}"`, `max_total: "${max_transfer_amount}"`, `period: "${budget_period}"`). The CLI substitutes them from the preset’s `variables` (and `--set` overrides) when generating the rule config; the server also substitutes at sync time so config-sourced rules get the same behaviour. **Optional fields** (`max_total`, `max_per_tx`, `max_tx_count`, `alert_pct`): if a variable is instantiated to **empty**, that is accepted and treated as no limit or default (empty → `-1` for `max_total`/`max_per_tx`, 0 for `max_tx_count`, 80 for `alert_pct`). **Cap semantics**: **`-1` = no cap** (unlimited); **`0` = cap of zero** (block all). So you can temporarily disable the budget by setting `max_total`/`max_per_tx` to `-1` without confusing with a real zero limit. Only `unit` must resolve to a non-empty value.

### 5.9 Loading multiple presets (e.g. Polymarket + Opinion)

You can load several presets into the same config (e.g. Polymarket and Opinion). Rules and variables are isolated per rule, so they do not interfere. **One thing can go wrong: template name collision.**

- **Template names are global in config**  
  The server resolves instance rules by **template name** (e.g. `"Polymarket Auth Template"`). Config has a single list of templates; each name must refer to exactly one template (one path).

- **What happens if two presets use the same template name**  
  Suppose you load the Polymarket preset first (it injects `"Polymarket Auth Template"` → `polymarket_auth.template.yaml`). Then you load an Opinion preset that also uses the name `"Polymarket Auth Template"` but points to `opinion_safe.template.yaml`. On the second run, the CLI sees that a template named `"Polymarket Auth Template"` already exists, so it **does not inject again**. The Opinion rules are appended, but they reference `"Polymarket Auth Template"` and therefore expand using the **Polymarket** template, not the Opinion one. That is wrong and can cause mis-evaluation (e.g. wrong chain or contract logic).

- **Best practice**  
  Use a **protocol/ecosystem prefix** in every template name so that names never clash across presets: e.g. `"Polymarket Auth Template"`, `"Opinion Safe Template"`, `"Predict Auth Template"`, `"Predict Enable Trading Template"`, `"Predict Trading Template"`. Then loading both Polymarket and Opinion presets is safe: each injects its own templates under distinct names, and each preset’s rules reference only those names.

- **Multiple overrides**:  
  `--set key1=val1 --set key2=val2`

For multi-rule presets, the CLI may support something like `--rule-index 0` to target the first rule. See the CLI help and [remote-signer-cli design](features/remote-signer-cli-design.md) for details.

### 5.10 Server preset API (admin-only)

When `presets.dir` is set in the server config, the following endpoints are registered under `/api/v1/presets`. All require **admin** API key authentication. Apply is also disabled when `security.rules_api_readonly` is true (403).

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/presets` | GET | List preset IDs and template names (from files in `presets.dir`). |
| `/api/v1/presets/:id/vars` | GET | Return override hints (and variable metadata) for preset `:id`. `:id` is the preset filename (e.g. `polymarket_safe_polygon.preset.yaml`). |
| `/api/v1/presets/:id/apply` | POST | Parse the preset with optional body `{ "variables": { "key": "value", ... } }`, create one template instance per rule in **one transaction** (all success or all rollback), and return `{ "results": [ { "rule", "budget?" }, ... ] }` (201). Templates must exist in the template library (DB); config-only templates must be added via API or config first. |

Apply uses the same preset format and variable substitution as the CLI; the server resolves templates by **name** from the database. See [api.md](api.md#presets) for request/response details and [security.md](security.md) for access control.

### 5.11 Using presets in setup (CLI)

**setup.sh** runs an optional step (Step 4b) after generating config: “Add rules from preset?”. If the user agrees, it:

1. Ensures **remote-signer-cli** is available (download from release or build from repo).
2. Lists presets via `remote-signer-cli preset list`.
3. Lets the user choose a preset by number.
4. Runs `remote-signer-cli preset vars <name>` to get variables and their **descriptions** from the template (using the preset’s `template_path`).
5. Prompts for each variable, showing the description (e.g. “allowed_safe_addresses (Comma-separated list of allowed Safe addresses…):”).
6. Runs `remote-signer-cli preset create-from <name> --config config.yaml --write --set ...`, which injects the template into config if needed and appends the rule.
7. Optionally repeats for another preset.

New users get a working rule set by picking a preset and filling in a few values with clear descriptions, without editing long YAML by hand.

---

## 6. Template and Preset Reference

### 6.1 Templates by category

All templates live under `rules/templates/`.

#### Token Standards

| File | Engine | Description |
|------|--------|-------------|
| `erc20.template.js.yaml` | evm_js | ERC-20 transfer, transferFrom, approve with parameter-level validation |
| `erc721.template.js.yaml` | evm_js | ERC-721 transferFrom, safeTransferFrom, approve, setApprovalForAll |
| `erc1155.template.js.yaml` | evm_js | ERC-1155 safeTransferFrom, safeBatchTransferFrom, setApprovalForAll |
| `native_transfer.template.js.yaml` | evm_js | Plain native token transfers (ETH/BNB/MATIC etc.) |
| `weth.template.js.yaml` | evm_js | WETH deposit() and withdraw(uint256) |

#### Gasless / Meta-TX

| File | Engine | Description |
|------|--------|-------------|
| `erc20_permit.template.js.yaml` | evm_js | EIP-2612 Permit typed_data validation for gasless token approvals |
| `erc721_permit.template.js.yaml` | evm_js | EIP-4494 Permit typed_data validation for gasless NFT approvals |
| `eip3009_transfer_auth.template.js.yaml` | evm_js | EIP-3009 TransferWithAuthorization / ReceiveWithAuthorization (USDC, EURC) |
| `meta_transaction.template.js.yaml` | evm_js | EIP-2771 ForwardRequest typed_data validation for gasless meta-transactions |

#### DeFi

| File | Engine | Description |
|------|--------|-------------|
| `dex_swap.template.js.yaml` | evm_js | Uniswap V2 router swap method whitelist |
| `dex_swap_v3.template.js.yaml` | evm_js | Uniswap V3 SwapRouter + V4 Universal Router |
| `staking.template.js.yaml` | evm_js | Common staking operations (stake, unstake, withdraw, claimRewards, exit) |

#### Account Abstraction

| File | Engine | Description |
|------|--------|-------------|
| `eip4337_userop.template.js.yaml` | evm_js | EIP-4337 UserOperation typed_data validation |

#### Smart Wallets (Safe / Gnosis)

| File | Engine | Description |
|------|--------|-------------|
| `safe.template.js.yaml` | evm_js | Generic composable Safe template (SafeTx typed_data + execTransaction) |
| `multisend.template.js.yaml` | evm_js | Gnosis MultiSend packed format batch transaction validation |

#### Polymarket

| File | Engine | Description |
|------|--------|-------------|
| `polymarket_auth.template.yaml` | solidity | CLOB login (auth only) |
| `polymarket_create_safe.template.yaml` | solidity | createProxy (Safe creation) |
| `polymarket_enable_trading.template.yaml` | solidity | SafeTx + execTransaction for approve/setApprovalForAll |
| `polymarket_trading.template.yaml` | solidity | Order signing + SafeTx + execTransaction |
| `polymarket_safe.template.yaml` | solidity | Combined Polymarket Safe rules (all capabilities) |
| `polymarket_safe_init.template.js.yaml` | evm_js | Auth + CreateProxy only (no Safe address required) |
| `polymarket.template.js.yaml` | evm_js | Polymarket protocol rules for composing with Safe template |

#### Opinion Protocol

| File | Engine | Description |
|------|--------|-------------|
| `opinion_safe.template.yaml` | solidity | Opinion Protocol Safe operations on BSC (based on Polymarket Safe) |

#### Predict.fun

| File | Engine | Description |
|------|--------|-------------|
| `predict_auth.template.yaml` | solidity | PersonalSign login (auth only) |
| `predict_enable_trading.template.yaml` | solidity | Approve + setApprovalForAll for trading setup |
| `predict_enable_trading.template.js.yaml` | evm_js | Same as above, evm_js engine (no Forge required) |
| `predict_trading.template.yaml` | solidity | Order + split/merge/redeem + NegRiskAdapter |
| `predict_trading.template.js.yaml` | evm_js | Same as above, evm_js engine (no Forge required) |
| `predict_eoa.template.yaml` | solidity | Combined Predict.fun EOA rules (all capabilities) |

#### Security

| File | Engine | Description |
|------|--------|-------------|
| `global_blocklist.template.js.yaml` | evm_js | Blocklist mode: blocks transactions to known-bad addresses |
| `contract_call_guard.template.js.yaml` | evm_js | Whitelist specific contracts + method selectors |
| `max_gas_cap.template.js.yaml` | evm_js | Blocklist mode: caps gas limit per transaction |
| `eip1559_fee_guard.template.js.yaml` | evm_js | Blocklist mode: caps gas limit and transaction value |

### 6.2 Presets

All presets live under `rules/presets/`.

#### Protocol-Specific Presets

| File | Description |
|------|-------------|
| `polymarket_eoa_polygon.preset.yaml` | Polymarket EOA rules on Polygon |
| `polymarket_safe_init_polygon.preset.js.yaml` | Polymarket Safe initialization on Polygon (auth + createProxy) |
| `polymarket_safe_polygon.preset.js.yaml` | Polymarket Safe full rules on Polygon |
| `predict_eoa_bnb.preset.yaml` | Predict.fun EOA rules on BNB Chain (solidity engine) |
| `predict_eoa_bnb.preset.js.yaml` | Predict.fun EOA rules on BNB Chain (evm_js engine) |

#### Token Presets

| File | Description |
|------|-------------|
| `erc20.preset.js.yaml` | ERC-20 transfer/approve limits |
| `erc721.preset.js.yaml` | ERC-721 NFT transfer rules |
| `erc721_permit.preset.js.yaml` | ERC-721 gasless permit rules |
| `erc1155.preset.js.yaml` | ERC-1155 multi-token rules |
| `erc20_permit.preset.js.yaml` | ERC-20 gasless permit rules |
| `native_transfer.preset.js.yaml` | Native token transfer limits |
| `weth.preset.js.yaml` | WETH deposit/withdraw rules |
| `usdc.preset.js.yaml` | USDC transfer/approve limits across major EVM chains (**matrix format**) |

#### DeFi Presets

| File | Description |
|------|-------------|
| `dex_swap.preset.js.yaml` | DEX swap V2 rules |
| `dex_swap_v3.preset.js.yaml` | DEX swap V3/V4 rules |
| `staking.preset.js.yaml` | Staking contract rules |
| `uniswap_v2.preset.js.yaml` | Uniswap V2 Router across major EVM chains (**matrix format**) |
| `uniswap_v3.preset.js.yaml` | Uniswap V3 SwapRouter across major EVM chains (**matrix format**) |
| `uniswap_v4.preset.js.yaml` | Uniswap V4 Universal Router across major EVM chains (**matrix format**) |

#### Gasless / Meta-TX Presets

| File | Description |
|------|-------------|
| `eip3009_transfer_auth.preset.js.yaml` | EIP-3009 transfer authorization rules |
| `eip4337_userop.preset.js.yaml` | EIP-4337 UserOperation rules |
| `meta_transaction.preset.js.yaml` | EIP-2771 meta-transaction rules |

#### Security Presets

| File | Description |
|------|-------------|
| `global_blocklist.preset.js.yaml` | Global address blocklist |
| `contract_call_guard.preset.js.yaml` | Contract call guard (address + selector whitelist) |
| `max_gas_cap.preset.js.yaml` | Max gas cap per transaction |
| `eip1559_fee_guard.preset.js.yaml` | EIP-1559 fee guard (gas + value cap) |

**Matrix format presets** (`uniswap_v2`, `uniswap_v3`, `uniswap_v4`, `usdc`) create one rule per chain with chain-specific contract addresses. They deploy across multiple EVM chains in a single apply.

---

## 7. Summary

| Concept | Where it lives | Purpose |
|--------|----------------|--------|
| **Template** | `config.templates` (type `file`) + `rules/templates/*.template.yaml` | Parameterized rules with `${var}`; loaded once, expanded per instance. See section 6.1 for the full list. |
| **Instance** | `config.rules` (type `instance`) | Binds a template name + variables; server expands to concrete rules. |
| **Preset** | `rules/presets/*.yaml` | Pre-filled instance(s); used by CLI/setup to generate or merge rule(s) with minimal overrides. See section 6.2 for the full list. |
| **Inline / file rules** | `config.rules` (type other than `instance` / `file`) or external YAML | Static or file-loaded rules without template expansion. |

For validation of template files (with `test_variables`) or full config (with templates + instance + file rules), use **remote-signer-validate-rules** or `remote-signer-cli validate`. See [testing.md](testing.md) and [configuration.md](configuration.md).
