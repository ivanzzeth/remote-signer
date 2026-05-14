# Configuration Reference

This document covers the `config.yaml` structure used at startup.

**Configuration templates:**
- [`config.example.yaml`](../config.example.yaml) — Minimal production-ready configuration
- [`config.full.yaml`](../config.full.yaml) — Complete examples of all features and protocols

Use `config.example.yaml` as the starting point for most deployments. Reference `config.full.yaml` when you need specific protocol examples (Polymarket, Predict.fun, DEX, etc.).

## What lives in config.yaml vs the database

As of v0.3.0, config.yaml only holds the **bootstrap** settings the daemon
needs before the database is reachable (listen address, TLS files, DSN,
logger). Every other knob — API keys, rules, templates, notify providers
and recipients, security limits, IP whitelist, audit thresholds, dynamic
blocklist sources, simulation/foundry/RPC-gateway settings — lives in the
database and is managed at runtime via the admin HTTP API or
`remote-signer settings ...` / `remote-signer api-key ...` /
`remote-signer rule ...` etc.

| Concern | Where it lives | How to edit |
|---|---|---|
| `server` (port, TLS), `database.dsn`, `logger` | `config.yaml` | Restart required |
| `chains.evm.enabled`, signer directories | `config.yaml` | Restart required |
| API keys, rules, templates | `api_keys`/`rules`/`rule_templates` tables | `remote-signer api-key/rule/template ...`, or HTTP API |
| Security, IP whitelist, rate limits, approval guard | `system_settings.security` (JSON) | `remote-signer settings set security …`, or `PUT /api/v1/admin/settings/security` |
| Notify providers + recipient channels | `system_settings.notify` (JSON) | `remote-signer settings set notify …` |
| Audit monitor thresholds | `system_settings.audit_monitor` | same |
| Dynamic blocklist sources | `system_settings.evm.dynamic_blocklist` | same |
| EVM simulation / foundry / RPC gateway / material check | `system_settings.evm.*` | same |

YAML files that still contain `api_keys:`, `templates:`, or `rules:`
sections fail to load — the error message points at the replacement
command. The retired settings are seeded into the database from YAML the
first time a Phase-3 build sees them; any subsequent edits go through the
admin surface.

## Config File Precedence

| File | Database | Used By |
|------|----------|---------|
| `config.local.yaml` | SQLite (local file) | `deploy.sh local-run` (preferred) |
| `config.yaml` | PostgreSQL | `deploy.sh local-run` (fallback), Docker |
| `config.example.yaml` | -- | Minimal template (recommended) |
| `config.full.yaml` | -- | Complete examples (reference) |

`setup.sh` generates the appropriate file based on your chosen deployment mode.

## Server

```yaml
server:
  host: "0.0.0.0"         # Bind address
  port: 8548               # Listening port
  read_timeout: 30s       # Optional; HTTP read timeout (default 30s)
  write_timeout: 30s       # Optional; HTTP write timeout (default 30s)
  tls:
    enabled: false
    cert_file: "./certs/server.crt"
    key_file: "./certs/server.key"
    ca_file: "./certs/ca.crt"        # CA for verifying client certs
    client_auth: false               # true = require client certs (mTLS)
```

For TLS certificate generation and trust model details, see [tls.md](tls.md).

## Database

```yaml
database:
  # PostgreSQL (production)
  dsn: "postgres://user:password@localhost:5432/remote_signer?sslmode=disable"

  # SQLite (development)
  dsn: "file:./data/remote-signer.db?_journal_mode=WAL&_busy_timeout=5000"
```

Environment variable substitution is supported: `dsn: "${DATABASE_DSN:-fallback}"`.

## Chains (EVM)

```yaml
chains:
  evm:
    enabled: true
    signers:
      # Option 1: Private keys from env vars
      private_keys:
        - address: "0x..."
          key_env: "EVM_SIGNER_KEY_1"   # Env var with hex private key (no 0x)
          enabled: true

      # Option 2: Encrypted keystores
      keystores:
        - address: "0x..."
          path: "/etc/signer/keystores/"
          password_env: "EVM_KEYSTORE_PASSWORD_1"
          enabled: true

      # Option 3: HD wallets (derive multiple addresses)
      hd_wallets:
        - path: "./data/hd-wallets/wallet1.json"
          password_env: "HD_WALLET_PASSWORD_1"
          derive_indices: [0, 1, 2]
          enabled: true

    # Directories for dynamically created signers (via API/TUI)
    keystore_dir: "./data/keystores"
    hd_wallet_dir: "./data/hd-wallets"
```

Keystores and HD wallets can also be created dynamically after server startup via the admin API or TUI. See [api.md](api.md) for endpoints.

## Foundry

Required for `evm_solidity_expression` rules.

```yaml
chains:
  evm:
    foundry:
      enabled: true
      forge_path: ""                       # Empty = auto-detect from PATH
      cache_dir: "./data/forge-cache"      # Compiled script cache
      temp_dir: "./data/forge-workspace"   # Workspace with forge-std
      timeout: "30s"                       # Max execution time per rule
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable Solidity expression rules |
| `forge_path` | string | `""` | Path to forge binary. Empty = auto-detect |
| `cache_dir` | string | `/tmp/...` | Cache for compiled Solidity scripts |
| `temp_dir` | string | -- | Workspace directory with forge-std |
| `timeout` | duration | `30s` | Max execution time per rule evaluation |

## Simulation

Transaction simulation uses `eth_simulateV1` through `rpc_gateway` to predict balance changes, gas usage, and approval detection.

```yaml
chains:
  evm:
    simulation:
      enabled: false
      timeout: "60s"                       # per-simulation timeout
      batch_window: "1s"                   # accumulation window for batch sign fallback
      batch_max_size: 20                   # max txs per batch
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable simulation engine |
| `timeout` | duration | `"60s"` | Per-simulation timeout |
| `batch_window` | duration | `"1s"` | Accumulation window for single sign batch fallback |
| `batch_max_size` | int | `20` | Max transactions per batch |

API endpoints: `POST /api/v1/evm/simulate`, `POST /api/v1/evm/simulate/batch`, `GET /api/v1/evm/simulate/status`. See [tx-simulation-budget.md](features/tx-simulation-budget.md) for details.

## API Keys

API keys authenticate clients using Ed25519 key pairs. As of v0.3.0 keys are
**not configured in config.yaml** — the daemon rejects a non-empty `api_keys`
block at startup. Manage them via the admin CLI / HTTP API instead.

### Bootstrap admin key

On the very first launch (no API keys in the database yet) the daemon
generates an Ed25519 admin keypair, writes it to
`~/.remote-signer/apikeys/admin.key.priv` (0600) and `~/.remote-signer/apikeys/admin.key.pub`
(0644), and inserts the row into `api_keys` with `source=bootstrap`. The
private key is never logged. Subsequent launches are no-ops.

### Generate a new API key

```bash
# Mint locally — no daemon contact needed.
remote-signer api-key keygen --out ./alice
# Writes alice.priv and alice.pub; prints the hex public key.

# Register with the service as an admin.
remote-signer api-key create \
  --id alice \
  --name "Alice" \
  --role dev \
  --public-key <hex-from-keygen> \
  --rate-limit 100 \
  --api-key-id admin \
  --api-key-file ~/.remote-signer/apikeys/admin.key.priv \
  --url http://localhost:8548
```

### List / update / delete

```bash
remote-signer api-key list
remote-signer api-key update alice --rate-limit 500
remote-signer api-key delete alice
```

All operations are admin-only. The full set of fields (including scope
restrictions like `allowed_signers`, `allowed_hd_wallets`,
`allowed_chain_types`) is documented at
`/api/v1/api-keys` — see [docs/api.md](api.md).

### Permission model

| Field | `role: admin` | `role: dev` |
|-------|---------------|----------------|
| Submit sign requests | Yes | Yes |
| View request status | Yes | Own requests only |
| Approve/reject requests | Yes | No |
| Manage rules | Yes | No |
| Create signers (keystore/HD) | Yes | No |
| `allowed_signers: []` | All signers | All signers |
| `allowed_signers: [addr]` | Only listed | Only listed |
| `allowed_hd_wallets: []` | All HD wallets | **No** HD wallet access |
| `allowed_hd_wallets: [addr]` | Only listed | Only listed |

## Notifications

```yaml
notify:
  slack:
    enabled: false
    bot_token: "${SLACK_BOT_TOKEN}"
  pushover:
    enabled: false
    app_token: "${PUSHOVER_APP_TOKEN}"
    retry: 30          # Seconds between retries
    expire: 300        # Notification expiry
    max_retries: 3
    retry_delay: 1
  webhook:
    enabled: false
    headers:
      Authorization: "Bearer ${WEBHOOK_AUTH_TOKEN}"
    timeout: "10s"

notify_channels:
  slack: ["C1234567890"]
  pushover: ["user_key"]
  webhook: ["https://example.com/webhook"]
```

## Security

```yaml
security:
  max_request_age: "60s"          # Replay attack window (30-120s recommended)
  rate_limit_default: 100         # Default rate limit per API key (req/min)
  ip_rate_limit: 200              # Pre-auth per-IP rate limit (req/min)
  nonce_required: true            # Require X-Nonce header for replay protection
  manual_approval_enabled: false  # true = unmatched requests go to pending approval
  allow_sighup_rules_reload: false # Reload rules from config on SIGHUP (default: false)

  # API lockdown (security hardening). Recommended for production:
  # - rules_api_readonly: true (default)  — block rule/template mutations via API
  # - api_keys_api_readonly: true (default) — block API key CRUD via API
  # - signers_api_readonly: true/false depending on whether you want runtime signer creation
  rules_api_readonly: true         # Default: true (secure by default)
  api_keys_api_readonly: true      # Default: true (secure by default)
  signers_api_readonly: false      # Default: false (low risk; API never returns private keys)

  # Timeouts
  auto_lock_timeout: "0s"          # Default: 0s (disabled). Auto-lock signers after unlock.
  sign_timeout: "30s"              # Default: 30s. Context timeout for signing operations.

  # Approval guard: detect API key abuse (pause signing when rejection rate exceeds threshold)
  approval_guard:
    enabled: true                        # Default: true. Enabled for better security.
    window: "1h"                         # Default: 1h. Sliding time window for rate calculation.
    rejection_threshold_pct: 50          # Default: 50. Rejection rate % that triggers pause.
    min_samples: 10                      # Default: 10. Minimum events in window before rate check applies.
    resume_after: "2h"                   # Default: 2h. Pause duration before auto-resume.

  # IP whitelist
  ip_whitelist:
    enabled: false
    allowed_ips:
      - "127.0.0.1"
      - "::1"
    trust_proxy: false            # Trust X-Forwarded-For (only behind trusted proxy!)
    # trusted_proxies: ["10.0.0.1"] # Required when trust_proxy=true; empty => ignore proxy headers (fail-closed)
```

Notes:
- For security design rationale and recommended production baseline, see [security.md](security.md).
- `security.ip_rate_limit <= 0` disables pre-auth IP rate limiting.
- `security.nonce_required` defaults to **true** when omitted (recommended).

## Dynamic Blocklist

### dynamic_blocklist

Runtime address blocklist synced from external URLs.

```yaml
dynamic_blocklist:
  enabled: false
  sync_interval: "1h"
  fail_mode: "open"
  cache_file: "data/blocklist_cache.json"
  sources:
    - name: "OFAC SDN List"
      type: "url_text"
      url: "https://example.com/ofac-addresses.txt"
    - name: "Scam Database"
      type: "url_json"
      url: "https://example.com/scam-addresses.json"
      json_path: "data.addresses"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable dynamic blocklist |
| `sync_interval` | string | `"1h"` | How often to refresh from sources (min: 1m) |
| `fail_mode` | string | `"open"` | `"open"` = use stale cache on failure, `"close"` = reject all |
| `cache_file` | string | `""` | Local file for persisting fetched addresses |
| `sources` | array | `[]` | List of address list sources |

Source config:

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Human-readable source name |
| `type` | string | `"url_text"` (one address per line) or `"url_json"` (JSON with path) |
| `url` | string | URL to fetch (http:// or https:// only) |
| `json_path` | string | For `url_json`: dot-path to address array (e.g. `"data.addresses"`) |

Notes:
- On startup, the cache file is loaded first (no network required). Background sync starts asynchronously.
- On partial source failure, successfully fetched addresses are merged into the existing cache.
- On total sync failure with `fail_mode: "close"` and no cached addresses, all requests matching `evm_dynamic_blocklist` rules are rejected.
- To use dynamic blocklist rules, define `evm_dynamic_blocklist` rules under `rules` (see [rule-syntax.md](rule-syntax.md#rule-type-evm_dynamic_blocklist)).

## Audit Monitor

```yaml
audit_monitor:
  enabled: false
  interval: "1h"
  lookback_hours: 1
  auth_failure_threshold: 5
  blocklist_reject_threshold: 3
  high_freq_threshold: 100
```

## Logger

```yaml
logger:
  level: "info"    # debug, info, warn, error
  pretty: true     # Pretty-print for development
```

## Rules

Rules define the policy engine. They can be defined **inline**, loaded from **files**, or expanded from **templates** (via **instance** rules). For concepts (templates, instances, presets) and examples, see [rules-templates-and-presets.md](rules-templates-and-presets.md). For rule type syntax (Solidity, evm_js, etc.), see [rule-syntax.md](rule-syntax.md).

**Rule sources in config:**

| Type | Meaning |
|------|--------|
| **inline** | Rule fully defined under `rules` (no `type: "file"` or `type: "instance"`). |
| **file** | Load rules from an external YAML file (`config.path`). |
| **instance** | Expand from a **template**: reference by name and supply `config.template` + `config.variables`; server substitutes variables into the template to produce concrete rules. |

```yaml
rules:
  # Inline rule
  - name: "Allow treasury"
    type: "evm_address_list"
    mode: "whitelist"            # whitelist | blocklist
    enabled: true
    config:
      addresses: ["0x5B38Da..."]

  # From file
  - name: "Treasury rules"
    type: "file"
    config:
      path: "rules/treasury.yaml"

  # From template instance (template name + variables)
  - name: "Polymarket Safe rules"
    type: "instance"
    config:
      template: "Polymarket Safe Template"
      variables:
        chain_id: "137"
        ctf_exchange_address: "0x..."
        allowed_safe_addresses: "0xYourSafe"
```

**Presets** (optional): Pre-filled instance data in `rules/presets/*.yaml`; use **remote-signer** or **setup.sh** to generate or merge rules from a preset with minimal overrides. See [rules-templates-and-presets.md](rules-templates-and-presets.md#5-presets).

### Rule evaluation order

1. **Blocklist** rules checked first — any match = reject immediately
2. **Whitelist** rules checked second — any match = auto-approve
3. No match = reject (or pending manual approval if `manual_approval_enabled: true`)

## Templates

**Templates** are parameterized rule files (variables + rules with `${var}` placeholders). They are loaded from paths listed under `templates` and expanded only when a **rule** of type **instance** references them and supplies variables. See [rules-templates-and-presets.md](rules-templates-and-presets.md#3-rule-templates).

```yaml
templates:
  - name: "Polymarket Safe Template"
    type: "file"
    enabled: true
    config:
      path: "rules/templates/polymarket_safe.template.yaml"
```

### Budget metering and enforcement (optional)

Templates can define `budget_metering` so that **instance** rules get per-request spend amounts for budget enforcement. **Enforcement (卡上限)** only runs when the rule has a **template ID** and a **budget record**:

- **API-created instances**: When you call the instantiate API with `budget` (e.g. `max_total`, `max_per_tx`) and optionally `schedule` (e.g. `period: "24h"`), the server creates a budget record and sets the rule’s template ID. Every matching request then goes through `CheckAndDeductBudget`: single-tx cap (`max_per_tx`) and total cap (`max_total`) are enforced; over limit → request blocked. Use **`-1` for no cap** (temporarily disable limit); **`0` = cap of zero** (block all).
- **Config-sourced instance rules**: If your config is produced from a **preset** that includes `budget` and `schedule`, the rule sync creates budget records and sets the rule’s template ID so the same enforcement applies. Presets that use templates with `budget_metering` should set `budget` and optionally `schedule` so limits and period reset are applied.

**Session / period (周期重置)**:

- `schedule.period` (e.g. `24h`, `168h`) plus optional `schedule.start_at` enable **periodic budget renewal**: spent/tx_count reset at the start of each period so limits are “per period” (e.g. daily cap).
- Without `schedule`, the budget is lifetime (no automatic reset).

Supported `method` values: `count_only`, `tx_value`, `calldata_param`, `typed_data_field`, and **`js`** (for `evm_js` rules: the script implements `validateBudget(input)` and returns the amount). For multi-chain assets, use a unit that identifies chain and asset, e.g. **`"${chain_id}:${token_address}"`** so the same token on different chains has separate budgets.

## Environment Variables

| Variable | Used By | Description |
|----------|---------|-------------|
| `EVM_SIGNER_KEY_1` | `chains.evm.signers.private_keys[].key_env` | EVM private key (hex, no 0x) |
| `EVM_KEYSTORE_PASSWORD_1` | `chains.evm.signers.keystores[].password_env` | Keystore password |
| `HD_WALLET_PASSWORD_1` | `chains.evm.signers.hd_wallets[].password_env` | HD wallet password |
| `DATABASE_DSN` | `database.dsn` | Database connection string |
| `SLACK_BOT_TOKEN` | `notify.slack.bot_token` | Slack bot token |
| `PUSHOVER_APP_TOKEN` | `notify.pushover.app_token` | Pushover app token |
| `WEBHOOK_AUTH_TOKEN` | `notify.webhook.headers` | Webhook auth token |
| `POSTGRES_USER` | Docker only | PostgreSQL username |
| `POSTGRES_PASSWORD` | Docker only | PostgreSQL password |
| `POSTGRES_DB` | Docker only | PostgreSQL database name |
