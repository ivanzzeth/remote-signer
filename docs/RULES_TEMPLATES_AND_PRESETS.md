# Rules, Templates, and Presets

This document explains how rules are defined, how **templates** parameterize them, and how **presets** simplify adding ready-made rule configurations (e.g. Polymarket, Predict) with minimal variable overrides.

For rule *syntax* (Solidity expressions, EIP-712, evm_js), see [RULE_SYNTAX.md](RULE_SYNTAX.md). For config structure reference, see [CONFIGURATION.md](CONFIGURATION.md).

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

## 2. Rule templates

### 2.1 What a template is

A **template** is a YAML file that defines:

- **variables**: list of `{ name, type, description, required }` (e.g. `chain_id`, `ctf_exchange_address`, `allowed_safe_addresses`).
- **test_variables**: (optional) default values used when validating the template in isolation (e.g. `remote-signer-validate-rules rules/templates/polymarket.safe.template.yaml` or `remote-signer-cli validate rules/...`).
- **rules**: the same structure as config rules, but with **placeholders** like `${chain_id}` or `${allowed_safe_addresses}` in expressions and config.

The server does not evaluate the template file directly. It loads templates listed in `config.templates` (type `file` with a `path`). When a **rule** of type `instance` references that template and supplies `config.variables`, the server substitutes those values into the template’s rules and expands them into concrete rules.

### 2.2 Where templates are defined

In `config.yaml`:

```yaml
templates:
  - name: "Polymarket Safe Template"
    type: "file"
    enabled: true
    config:
      path: "rules/templates/polymarket.safe.template.yaml"
```

- **name**: used by instance rules in `config.rules` via `config.template`.
- **type: "file"**: load from the given path (relative to config file or project root).
- **path**: path to the template YAML.

Template files live under `rules/templates/` (e.g. `polymarket.safe.template.yaml`, `predict.eoa.template.yaml`). Each file contains `variables`, optional `test_variables`, and `rules` with `${var}` placeholders.

### 2.3 Template file format (example)

```yaml
# rules/templates/polymarket.safe.template.yaml
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

---

## 3. Rule examples in config

Rules in `config.rules` can be defined in three ways.

### 3.1 Inline rules

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

### 3.2 File rules

Load a list of rules from an external YAML file:

```yaml
rules:
  - name: "Treasury rules"
    type: "file"
    config:
      path: "rules/treasury.yaml"
```

The file must contain a top-level `rules:` list (same shape as config rules). No variable substitution; the file is used as-is.

### 3.3 Instance rules (from template)

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

## 4. Presets

### 4.1 What a preset is

A **preset** is a YAML file that stores one or more **instance-style rule(s)** with default variables already filled in. It does not add a new rule type: it is a convenience format so you can:

- Avoid copying long variable blocks from `config.example.yaml`.
- Override only a few values (e.g. your Safe address) and optionally merge the result into your `config.yaml` via **remote-signer-cli** or **setup.sh**.

Presets live under `rules/presets/` (e.g. `polymarket-safe-polygon.yaml`). They are used only by the CLI (and optionally by setup); the server does not read preset files.

### 4.2 Single-rule preset format

One rule per file, flat structure:

```yaml
# rules/presets/polymarket-safe-polygon.yaml
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

### 4.3 Multi-rule preset format

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
  - name: "Predict EOA (BNB)"
    type: "instance"
    config:
      template: "Predict EOA Template"
      variables: { chain_id: "56", ... }
    chain_type: "evm"
    chain_id: "56"
    enabled: true
```

The CLI can apply overrides to all entries or target one by index.

### 4.4 Variables in presets: scalars and arrays

- **Scalars**: string or number, same as in config (e.g. `chain_id: "137"`, `clob_auth_domain_name: "ClobAuthDomain"`).
- **Lists / arrays**: template variables that represent multiple values (e.g. allowed Safe addresses) can be:
  - A **comma-separated string**: `allowed_safe_addresses: "0xa,0xb"`.
  - A **YAML array**: `allowed_safe_addresses: ["0xa", "0xb"]`. When merged into config or expanded by the server, these are normalized so the engine sees the same behavior (e.g. comma-separated for `in(expr, varName)`).

When using the CLI to override variables, array-like values can be passed as:

- `--set key=val1,val2` (stored as a single string), or
- `--set key='["val1","val2"]'` (parsed as JSON array and normalized when writing config).

### 4.5 Preset format: template_path and override_hints

- **template_path** (optional): Path to the template file (e.g. `rules/templates/polymarket.safe.template.yaml`). When you run `preset create-from ... --write`, the CLI injects this template into `config.templates` if it is not already present, so the preset is self-contained and config does not need to define the template beforehand.
- **override_hints** (optional): List of variable names to prompt for in setup (e.g. `allowed_safe_addresses`, `allowed_safe_address_for_testing`). The **preset vars** subcommand reads the template file (via `template_path`) and outputs each variable with its **description** from the template, so setup can show “variable (description)” when prompting.

Template files define variables with a **description** field; that description is shown during interactive setup when the user is asked to fill in override values.

### 4.6 Using presets with the CLI

(When **remote-signer-cli** is available.)

- **List presets**:  
  `remote-signer-cli preset list`  
  Scans `rules/presets/` and shows preset name(s) and template name(s).

- **Variables to prompt (for scripts)**:  
  `remote-signer-cli preset vars <preset-name> --presets-dir rules/presets --project-dir .`  
  Outputs one line per override variable: `name<TAB>description`. Used by setup to show descriptions when prompting.

- **Generate a rule from a preset (no config change)**:  
  `remote-signer-cli preset create-from polymarket-safe-polygon --set allowed_safe_addresses=0xYourSafe`  
  Outputs the rule YAML so you can paste it into `config.yaml`.

- **Append the rule to config (and inject template if missing)**:  
  `remote-signer-cli preset create-from polymarket-safe-polygon --config config.yaml --write --set allowed_safe_addresses=0xYourSafe`  
  If the preset has `template_path` and the config does not yet define that template, the CLI adds the template entry from the preset.

- **Multiple overrides**:  
  `--set key1=val1 --set key2=val2`

For multi-rule presets, the CLI may support something like `--rule-index 0` to target the first rule. See the CLI help and [remote-signer-cli design](features/remote-signer-cli-design.md) for details.

### 4.7 Using presets in setup

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

## 5. Summary

| Concept | Where it lives | Purpose |
|--------|----------------|--------|
| **Template** | `config.templates` (type `file`) + `rules/templates/*.template.yaml` | Parameterized rules with `${var}`; loaded once, expanded per instance. |
| **Instance** | `config.rules` (type `instance`) | Binds a template name + variables; server expands to concrete rules. |
| **Preset** | `rules/presets/*.yaml` | Pre-filled instance(s); used by CLI/setup to generate or merge rule(s) with minimal overrides. |
| **Inline / file rules** | `config.rules` (type other than `instance` / `file`) or external YAML | Static or file-loaded rules without template expansion. |

For validation of template files (with `test_variables`) or full config (with templates + instance + file rules), use **remote-signer-validate-rules** or `remote-signer-cli validate`. See [TESTING.md](TESTING.md) and [CONFIGURATION.md](CONFIGURATION.md).
