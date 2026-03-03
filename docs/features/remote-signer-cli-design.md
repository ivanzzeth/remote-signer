# remote-signer-cli: Design and Implementation Plan

## 0. Plan items (to implement)

- **CLI framework**: Use **Cobra** (`github.com/spf13/cobra`) for remote-signer-cli instead of hand-rolled flag/arg parsing. Cobra is the de facto standard in the Go ecosystem (used by Kubernetes, Hugo, GitHub CLI); it handles subcommands, POSIX flags, and argument order correctly.
- **Validate binary name**: Ship the rules-validator binary as **`remote-signer-validate-rules`** (not `validate-rules`) to avoid clashing with other tools in the user’s global PATH. All references (release assets, setup.sh, CLI exec lookup) use this name.

---

## 1. Goal

- **CLI tool** `remote-signer-cli` with subcommands to improve UX: create/update rule config from templates and presets, validate rules, and launch TUI.
- **Presets / “final template”**: Today config combines a template (e.g. `Polymarket Safe Template`) with a long `variables` block. We want a way to work from a **preset** (template + default variables) so users only override a few values (e.g. `allowed_safe_addresses`) and optionally write directly to `config.yaml`.
- **Integration**: Expose existing **validate-rules** and **TUI** via this CLI (as subcommands); **release** the CLI binary in GitHub Actions alongside the TUI.

### 1.1 Reuse-only (no duplicate logic)

- **Do not reimplement** expansion, validation, or TUI. Reuse existing code only.
- **Config / rules / templates**: Use only `internal/config`: `Load`, `ExpandTemplatesFromFiles`, `ExpandInstanceRules`, `ExpandFileRules`, `RuleConfig`, `TemplateConfig`. No new expansion or rule logic.
- **Validate**: Reuse the existing validate-rules flow. **Option A (preferred)**: `remote-signer-cli validate` **exec**’s the **`remote-signer-validate-rules`** binary (see plan §0) with the same flags (zero code change, single code path). **Option B**: Extract the validator’s `run()` into a callable and have both the binary and CLI call it.
- **TUI**: `remote-signer-cli tui` **exec**’s the existing `remote-signer-tui` binary with forwarded args. No second TUI implementation, no refactor of TUI code.
- **Presets**: Preset files are **data only** (YAML). Parsing produces the same `RuleConfig` shape the server already uses (type `instance`, `config.template`, `config.variables`). Output or merge is just emitting/updating that structure; expansion stays in existing `ExpandInstanceRules` when the server or validate runs.

---

## 2. Current Code Flow (Relevant Parts)

### 2.1 Config and expansion

- **`config.yaml`** has:
  - **`templates`**: list of template entries. Type `file` → path to a YAML that defines `variables`, `test_variables`, and `rules` (with `${var}` placeholders).
  - **`rules`**: list of rule entries. Types:
    - **`file`**: load rules from an external YAML path.
    - **`instance`**: reference a template by name + provide `config.template` and `config.variables`; server expands to concrete rules via variable substitution.

- **Expansion order** (same in server and validate-rules):
  1. **ExpandTemplatesFromFiles**(`cfg.Templates`, configDir)  
     Loads file-type templates from disk, parses variables + rules, stores serialized rules in template config as `rules_json`.
  2. **ExpandInstanceRules**(`cfg.Rules`, loadedTemplates)  
     Replaces each `type: instance` rule with concrete rules by substituting `config.variables` into the template’s `rules_json`.
  3. **ExpandFileRules**(expandedRules, configDir)  
     Expands `type: file` rules by loading rules from their `config.path`.

- **Key types**: `internal/config/config.go` — `TemplateConfig`, `RuleConfig`; expansion in `internal/config/template_init.go` and `rule_init.go`; rules validator in `cmd/validate-rules/` (binary name: `remote-signer-validate-rules`).

### 2.2 Templates today

- One template = one YAML file (e.g. `rules/templates/polymarket.safe.template.yaml`) with many variables.
- Config then has one **instance** rule that references that template and fills all variables (long block). No “composed” or “meta” template in the engine.

### 2.3 Rules validator and TUI

- **Rules validator**: Built as **`remote-signer-validate-rules`** (see plan §0); source in `cmd/validate-rules/` (or `cmd/remote-signer-validate-rules/` after rename). Supports `-config config.yaml` (expand templates + instance + file rules, then validate) and direct rule/template file paths.
- **TUI**: `cmd/tui/main.go` — binary `remote-signer-tui`; connects to server, manages signers/rules/requests etc.

---

## 3. Design

### 3.1 Presets as “final template” (no engine change)

- **Preset** = one YAML file that describes **one or more** instance rules: template name(s) + full default variables (and optional metadata). No new rule/template type in the server; CLI only **generates** the same `rules[]` entries that config already supports.
- **Composed template** in the user’s sense = **preset**: e.g. “Polymarket Safe (Polygon)” = template “Polymarket Safe Template” + a fixed set of variables; user overrides only a few (e.g. `allowed_safe_addresses`).

**Preset file format**

- **Single-rule preset** (one rule per file, e.g. `rules/presets/polymarket-safe-polygon.yaml`):

```yaml
# Preset: Polymarket Safe (Polygon). Override allowed_safe_addresses / allowed_safe_address_for_testing.
name: "Polymarket Safe rules (Polygon)"
template: "Polymarket Safe Template"
chain_type: "evm"
chain_id: "137"
enabled: true
variables:
  chain_id: "137"
  ctf_exchange_address: "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E"
  allowed_safe_address_for_testing: "0x1111111111111111111111111111111111111111"
  allowed_safe_addresses: "0x1111111111111111111111111111111111111111"   # or YAML array, see below
override_hints:
  - allowed_safe_addresses
  - allowed_safe_address_for_testing
```

- **Multi-rule preset** (multiple rules in one file): use top-level `rules:` list. Same shape as config’s `rules` (each entry: name, type instance, config.template, config.variables). CLI can apply `--set` to all entries or use `--rule-index N` to target one.

```yaml
# Preset: multiple instance rules (e.g. Polymarket + Predict in one file)
rules:
  - name: "Polymarket Safe rules (Polygon)"
    type: "instance"
    config:
      template: "Polymarket Safe Template"
      variables: { ... }
    chain_type: "evm"
    chain_id: "137"
    enabled: true
  - name: "Predict EOA (BNB)"
    type: "instance"
    config:
      template: "Predict EOA Template"
      variables: { ... }
    chain_type: "evm"
    chain_id: "56"
    enabled: true
```

**Variables: scalars and arrays**

- In config and in expansion, `variables` are `map[string]interface{}`; the server stringifies with `fmt.Sprintf("%v", v)` for substitution. For `in(expr, varName)` the engine expects **comma-separated** values (see `fillInMappingArrays`).
- In preset YAML, **variables may be scalars (string/number) or arrays** (YAML list). Examples:
  - `allowed_safe_addresses: "0xa,0xb"` (single string, comma-separated).
  - `allowed_safe_addresses: ["0xa", "0xb"]` (YAML array). When merging into config or when the server expands, arrays should be normalized to comma-separated strings for in-mapping use so the engine behaves the same.
- CLI **`--set`**:
  - Scalar: `--set key=value` (value is string).
  - Array: `--set key=val1,val2` (stored as string `"val1,val2"`) or `--set key='["val1","val2"]'` (parse as JSON array and store as `[]interface{}`; when writing config, serialize to comma-separated string for consistency with template substitution).
- Implementation: when building `RuleConfig` from preset + overrides, normalize variable values so that (1) config YAML round-trips correctly, and (2) server’s `expandInstanceRule` and `fillInMappingArrays` see the same behavior (comma-separated string for list-like vars).

- CLI **rule create-from-preset** loads preset(s), applies `--set` overrides (and optional `--rule-index` for multi-rule files), and outputs rule block(s) or patches config.

### 3.2 remote-signer-cli layout

Single binary: **remote-signer-cli** (or **rscli** as shorthand in docs).

**Subcommands:**

| Subcommand | Purpose |
|------------|--------|
| **rule** | Rule and template/preset operations |
| **validate** | Validate rules (current validate-rules behavior) |
| **tui** | Launch TUI (same as current `cmd/tui`) |

**`rule` subcommands:**

| Command | Description |
|---------|-------------|
| `rule list-templates` | List templates (from `-config` or default config path). Shows name, path, variable names. |
| `rule list-presets` | List presets (scan `rules/presets/*.yaml` or path from flag). Shows preset name and template. |
| `rule create-from-preset <preset>` | Load preset, apply `--set key=value`, output rule YAML block. With `--config path` and `--write`: append or update rule in config. |
| `rule create-from-template <template-name>` | Load template from config, gather variables (prompt or `--set` / file), output rule YAML. Optional `--config` + `--write`. |
| `rule validate` | Run rule validation (same as current validate-rules: `-config` or rule files). Can be implemented by calling existing validate-rules logic in-process or by exec. |

**`validate`** (top-level): same as `rule validate` (alias or delegate).

**`tui`**: run the TUI (same as current TUI binary; can be same package `cmd/tui` invoked from CLI, or exec of `remote-signer-tui` if we keep releasing TUI separately). Prefer in-process (single CLI binary that embeds TUI) so one download gives both CLI and TUI.

### 3.3 Config patching (--config and --write)

- **Read** existing `config.yaml` (or path from `--config`).
- **Append** new rule to `rules` (e.g. at end), or **update** existing rule by matching `name` (if `--update` or similar).
- **Write** back: use a YAML library that supports round-trip with comments if possible; otherwise at least preserve structure and only modify `rules`. Prefer a small, focused patch (e.g. only inject one rule) to avoid wiping comments.

### 3.4 Preset discovery and template discovery

- **Presets**: default directory `rules/presets/` (relative to CWD or `--project-root`). Each file is one preset (name + template + variables + optional override_hints).
- **Templates**: from loaded config only (config’s `templates` section). So `rule list-templates` requires `-config` (or default `config.yaml`). Templates are expanded from file-type entries (path to template YAML).

### 3.5 Composed template (optional future)

- If we later want “one YAML that composes multiple templates”: we could add a preset format that references **multiple** template names and merges variables (e.g. `templates: [A, B]`, `variables: { ... }`). The CLI would expand each and concatenate rules. Not required for MVP; presets as “single template + full defaults” already give the “final template” UX.

---

## 4. Implementation Outline

### 4.1 New directory and files

- **`cmd/remote-signer-cli/`**
  - Use **Cobra** for all commands and flags (see plan §0). Root command and subcommands: `rule`, `validate`, `tui`.
  - `main.go` — Cobra root; no expansion or validation logic; only delegation.
  - `rule.go` — Cobra `rule` command and children: list-templates, list-presets, create-from-preset (same behavior; flags via Cobra).
  - `validate_cmd.go` — `validate` subcommand: **exec** **`remote-signer-validate-rules`** binary with forwarded flags.
  - `tui_cmd.go` — `tui` subcommand: **exec** `remote-signer-tui` binary with forwarded args.
- **`rules/presets/`**
  - Preset YAML files (data only). Example: `polymarket-safe-polygon.yaml` — same structure as one `rules` entry in config (name, type instance, config.template, config.variables). Extracted from current config.example; no new format.
  - Optional: `predict-eoa-bnb.yaml`, `opinion-safe-bsc.yaml`.

### 4.2 Reuse only (no new validation/TUI logic)

- **Validate**: **Exec** the **`remote-signer-validate-rules`** binary (same flags forwarded). One code path, no refactor. Release both `remote-signer-cli` and `remote-signer-validate-rules`; CLI’s `validate` subcommand finds `remote-signer-validate-rules` in same directory or PATH and runs it.
- **TUI**: **Exec** the existing `remote-signer-tui` binary with forwarded args. No change to TUI code. Release both binaries; CLI’s `tui` subcommand finds the TUI binary and runs it.
- **Rule list-templates**: Use `config.Load` + `config.ExpandTemplatesFromFiles` only; print template names and variable names. No new logic.
- **Rule list-presets**: Read `rules/presets/*.yaml`; parse minimal fields (name, template) for listing. Presets are data.
- **Rule create-from-preset**: Read preset YAML into a struct that maps 1:1 to one `RuleConfig` (type `instance`, name, chain_*, config.template, config.variables). Apply `--set k=v` to variables. Output as YAML or, with `--config` + `--write`, load config (config.Load), append this rule to `cfg.Rules`, write back. Expansion is **not** done by the CLI; it only produces the same rule entry the server would have. No duplicate expansion.

### 4.3 rule create-from-preset flow (reuse types only)

1. Resolve preset path: `rules/presets/<name>.yaml` (or `--presets-dir`).
2. Parse preset YAML into a struct that matches **one** `config.RuleConfig` (type `instance`, name, chain_type, chain_id, enabled, config.template, config.variables). Use the same `RuleConfig` type from `internal/config` so the produced rule is identical to what config today has.
3. Apply `--set k=v` overrides to `config.variables`.
4. If `--config` + `--write`: load config via `config.Load`, append this rule to `cfg.Rules`, write back (YAML). If not: print this single rule as YAML (so user can paste into config). No expansion or validation in CLI; server or validate-rules do that when they run.

### 4.4 rule list-templates / list-presets

- **list-templates**: Load config (default or `-config`), run `ExpandTemplatesFromFiles(cfg.Templates, configDir, log)`, print table: template name, path (if file), variable names.
- **list-presets**: Glob `rules/presets/*.yaml`, parse each enough to get name and template, print table.

### 4.5 Release workflow

- In **`.github/workflows/release.yml`**:
  - Add a build step for **remote-signer-cli** (same multi-arch: linux amd64/arm64, darwin amd64/arm64).
  - Output: `remote-signer-cli-<os>-<arch>`.
  - Upload as additional release assets (alongside existing TUI assets).
- Build and upload **remote-signer-tui**, **remote-signer-validate-rules**, and **remote-signer-cli** (binary names per plan §0). Document that validate is available via `remote-signer-cli validate` and TUI via `remote-signer-cli tui`.

---

## 5. Test Plan

### 5.1 Unit tests

| Area | What to test | Location / notes |
|------|----------------|------------------|
| **Preset parsing** | Single-rule preset: parse YAML into struct matching one `RuleConfig` (name, type instance, config.template, config.variables). | `cmd/remote-signer-cli/` or `internal/preset/` (if extracted). |
| **Preset parsing** | Multi-rule preset: parse top-level `rules:` into `[]RuleConfig`; preserve order and all fields. | Same. |
| **Variables** | Scalar variables: string and number round-trip; `--set key=value` overwrites. | Unit test preset with mixed scalar types. |
| **Variables** | Array variables: YAML list `["a","b"]` parses; `--set key=val1,val2` produces string `"val1,val2"`; `--set key='["v1","v2"]'` parses as JSON array and normalizes to comma-separated when writing config (or store as slice for config). | Test that merged config passes server expansion and `fillInMappingArrays` (e.g. in_mapping var). |
| **Override application** | `--set` overrides preset variables; multiple `--set A=x --set B=y`; override does not add new keys if we restrict to preset keys (or allow extra keys). | Unit test with preset + set flags. |
| **Config merge** | Load existing config (YAML), append one rule to `cfg.Rules`, write back; no duplicate rule when appending same preset twice (by name?) or document as append-only. | Use temp config file; assert `rules` length and content. |
| **Config merge** | Update existing rule by name when `--update` (if implemented): replace rule with same name instead of appending. | Same. |
| **Binary discovery** | Resolve `remote-signer-validate-rules` / `remote-signer-tui`: same dir vs PATH; return clear error when not found. | Test with mock FS or temp dir with/without binaries. |
| **list-templates** | With `-config`: load config, expand templates, output table (name, path, variable names); no config → clear error. | Use fixture config + template file. |
| **list-presets** | List presets from `rules/presets/` or `--presets-dir`: single-rule and multi-rule files; output preset name and template name(s). | Fixture presets dir. |

### 5.2 Integration tests

| Scenario | Steps | Assertions |
|----------|--------|------------|
| **create-from-preset → validate** | Create rule from preset (single-rule) with `--set`, write to temp config that has required `templates` section; run `remote-signer-validate-rules -config` (or `remote-signer-cli validate -config`) on that config. | Validation passes; no “template not found” or “variable missing”. |
| **create-from-preset (array var)** | Preset with `allowed_safe_addresses: ["0xa", "0xb"]`; create-from-preset, merge into config; run server or validate so `ExpandInstanceRules` + `ExpandFileRules` run. | Expanded rules contain correct in_mapping or substituted values. |
| **create-from-preset (multi-rule)** | Preset file with `rules:` and 2 entries; create-from-preset with `--set` (applies to all or first); merge into config. | Config has 2 new rules; validate passes. |
| **validate exec** | `remote-signer-cli validate -config <path>` exec’s `remote-signer-validate-rules` with same flags; exit code and stdout/stderr forwarded. | Exit code 0 when rules valid; non-zero when invalid; output matches running `remote-signer-validate-rules` directly. |
| **tui exec** | `remote-signer-cli tui -url ... -api-key-id admin` exec’s `remote-signer-tui` with same args. | Process starts (integration can assert exec succeeded; full TUI is manual). |

### 5.3 setup.sh integration

| Step | Behavior | Verification |
|------|----------|---------------|
| **Optional step: add rules from preset** | After generating config (Step 4), prompt: “Add rules from preset? (y/N)”. If yes, run `remote-signer-cli rule list-presets` (or read presets dir), show numbered list; user picks preset name (or index). Then prompt for override variables (e.g. `allowed_safe_addresses`, `allowed_safe_address_for_testing`) if preset has `override_hints`; or accept one line “key=value” repeats. Call `remote-signer-cli rule create-from-preset <name> --config config.yaml --write --set ...`. | Config file contains new rule(s); server starts and validate passes. |
| **Presets dir** | If using presets, ensure `rules/presets/` exists (e.g. from repo or created by setup). If CLI is from release, presets may be in repo only — document “run from repo” or ship presets with release. | setup.sh runs without error; generated config includes selected preset rule(s). |
| **Array variables in setup** | When prompting for e.g. `allowed_safe_addresses`, accept comma-separated input and pass as `--set allowed_safe_addresses=0xa,0xb`. | Merged rule has correct variables; validation passes. |

### 5.4 Manual test TODOs

- [ ] **Full flow (local)**: Run `./scripts/setup.sh` → choose local → complete steps → when offered “Add rules from preset”, pick Polymarket preset → enter Safe address(es) → start server → run `remote-signer-cli validate -config config.yaml` → open TUI, confirm rules visible.
- [ ] **Full flow (Docker)**: Same with Docker mode; confirm config and preset rule(s) work in container.
- [ ] **Multi-rule preset**: Use a preset file with `rules:` and 2+ entries; run create-from-preset with `--write`; open config, confirm all entries; run validate.
- [ ] **Array variable in TUI/server**: Preset with array variable (e.g. multiple Safe addresses); create-from-preset, start server, send a request that hits the rule; confirm behavior matches single-address case.
- [ ] **Binary discovery**: Install only `remote-signer-cli` in PATH; run `remote-signer-cli validate` and `remote-signer-cli tui` — confirm clear error when `remote-signer-validate-rules` / `remote-signer-tui` not in same dir or PATH. Then place binaries in same dir, re-run — should succeed.
- [ ] **Release assets**: After release, download CLI + TUI + remote-signer-validate-rules for one platform; run CLI validate and CLI tui from same directory; confirm no path errors.

---

## 6. Summary

| Item | Approach |
|------|----------|
| **Preset / “final template”** | Preset = one YAML (template name + full variables). No new server type. CLI uses presets to generate config rule entries. |
| **remote-signer-cli** | One binary; subcommands: `rule` (list-templates, list-presets, create-from-preset, create-from-template, validate), `validate`, `tui`. |
| **rule create-from-preset** | Load preset, apply `--set`, output rule block or patch config with `--config` + `--write`. |
| **validate** | **Exec** existing **`remote-signer-validate-rules`** binary (same flags). No duplicate validation logic. |
| **TUI** | **Exec** existing `remote-signer-tui` binary (forward args). No duplicate TUI logic. |
| **Release** | Build and upload `remote-signer-cli-<os>-<arch>` in the same release workflow. |

This gives a single CLI that improves UX (presets + config patching), keeps templates as they are, and unifies rule validation and TUI under one tool while still allowing separate TUI/remote-signer-validate-rules binaries in the release if desired.
