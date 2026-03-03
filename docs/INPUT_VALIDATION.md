# Input validation

All inputs (API, config, CLI) are strictly validated so invalid or unknown values fail fast with 400 / config load error instead of being ignored or causing silent misbehavior.

## Shared validation (single source of truth)

- **`internal/validate`** — Request/query/body and config **non–rule-config** validation:
  - **Address / sign / wei**: `IsValidEthereumAddress(s)`, `ValidSignTypes`, `IsValidWeiDecimal(s)` — used by sign handler, request/rule list filters, chain adapter `ValidateBasicRequest`, and approval `max_value`.
  - **Enums**: `ValidateRuleMode`, `NormalizeRuleType`, `IsValidChainType`, `IsValidRuleType`, `IsValidRuleSource`, `IsValidAuditEventType`, `IsValidSignerType` — used by API and config load.

- **`internal/ruleconfig`** — **Rule config only**: `ValidateRuleConfig(ruleType, config)` — used by API create/update rule, config rule load (`rule_init`), and `validate-rules` CLI. Enforces config shape per rule type (e.g. `allowed_sign_types` array, `sign_type_filter` string, address list, value limit). Uses `validate` internally for address/sign-type/wei checks.

- **`internal/chain/evm/adapter.go`**
  - `ValidateBasicRequest(chainID, signerAddress, signType, payload)` — uses `validate.IsValidEthereumAddress` and `validate.ValidSignTypes`.

## By entry point

### Config (YAML)

- **`internal/config/config.go`**  
  Port, DSN, chains enabled, TLS paths, API keys (id, duplicate id, public key / env).

- **`internal/config/rule_init.go`**  
  Per rule: `ValidateRuleMode(mode)`; for non-file rules with config, `ValidateRuleConfig(type, config)`.

- **`internal/config/template_init.go`**  
  Per template: `ValidateRuleMode(mode)`; type must be known or `file`. Template config may contain variable placeholders; validated when an instance is created.

### API – EVM sign

- **POST /api/v1/evm/sign**  
  Body: `chain_id` (decimal), `signer_address` (0x40 hex via `ruleconfig.IsValidEthereumAddress`), `sign_type` (via `ruleconfig.ValidSignTypes`), `payload` (required, max 2MB).  
  Service layer also runs adapter `ValidateBasicRequest` (same sign_type/address + payload shape/size).

### API – EVM rules

- **Create/Update rule**  
  Body: `type` (known rule type), `mode` (whitelist/blocklist), `config` via `ValidateRuleConfig`. Solidity rules additionally validated with Foundry when validator is present.

- **List rules**  
  Query: `chain_type`, `signer_address` (0x40 hex), `type` (known rule type), `source` (known source). Invalid values return 400.

### API – EVM requests

- **List requests**  
  Query: `signer_address` (0x40 hex), `chain_id` (decimal), `status` (comma-separated, each must be valid status), `limit` (1–100), `cursor` (RFC3339Nano).

### API – Approval / preview-rule

- **POST approve, POST preview-rule**  
  Body: `rule_type` (known type), `rule_mode` (whitelist/blocklist), `rule_name` (max 255 chars), `max_value` (if set: non-empty decimal string via `IsValidWeiDecimal`).

### API – Templates

- **Create template**  
  Body: `name`, `type` (known rule type), `mode` (whitelist/blocklist). Config is not validated here (may contain placeholders).

- **Update template**  
  Body: optional fields; config, when provided, is not validated (template config may contain placeholders).

### API – Signers

- **List signers**  
  Query: `type` (must be `private_key` or `keystore`). `offset` / `limit` validated.

- **Create signer**  
  Body: validated by `types.CreateSignerRequest.Validate()`.

### API – Audit

- **List audit**  
  Query: `event_type` (known audit event type), `chain_type` (known), `start_time` / `end_time` (RFC3339), `limit` (1–100), `cursor` (RFC3339Nano). Invalid values return 400.

### CLI

- **validate-rules**  
  Uses `ruleconfig.ValidateRuleConfig` for declarative rule config (same as API and config load). Solidity and JS rules have their own validators.

## Not validated here

- **Template config** (create/update and template_init): may contain variable placeholders (e.g. `${target}`). Resolved and validated when an instance is created.
- **Request ID / rule ID / cursor_id** in paths or query: treated as opaque identifiers; 404 if not found.
