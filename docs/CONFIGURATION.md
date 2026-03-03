# Configuration Reference

This document covers the full `config.yaml` structure. For a quick, annotated template see [`config.example.yaml`](../config.example.yaml).

## Config File Precedence

| File | Database | Used By |
|------|----------|---------|
| `config.local.yaml` | SQLite (local file) | `deploy.sh local-run` (preferred) |
| `config.yaml` | PostgreSQL | `deploy.sh local-run` (fallback), Docker |
| `config.example.yaml` | -- | Template for both |

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

For TLS certificate generation and trust model details, see [TLS.md](TLS.md).

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

Keystores and HD wallets can also be created dynamically after server startup via the admin API or TUI. See [API.md](API.md) for endpoints.

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

## API Keys

API keys authenticate clients to the signing service using Ed25519 key pairs.

```yaml
api_keys:
  - id: "admin"                            # Unique identifier (X-API-Key-ID header)
    name: "Admin"                          # Human-readable name
    public_key: "MCowBQYDK2VwAyEA..."     # Base64 or hex (auto-detected)
    # public_key_env: "ADMIN_PUBLIC_KEY"   # Or read from env var
    admin: true                            # Can manage rules, approve requests, create signers
    enabled: true
    rate_limit: 1000                       # Requests per minute

  - id: "dev"
    name: "Dev"
    public_key: "MCowBQYDK2VwAyEA..."
    admin: false                           # Can only submit sign requests
    enabled: true
    rate_limit: 100
    # Optional scope restrictions:
    # allowed_chain_types: ["evm"]         # Empty = all chains
    # allowed_signers:                     # Empty = all signers
    #   - "0x1234..."
    # allowed_hd_wallets:                  # Empty = no HD wallet access
    #   - "0xPrimaryAddress..."            # Grants access to all derived addresses
```

### Key generation

```bash
# Generate a key pair
./scripts/generate-api-key.sh -n admin

# Or manually:
openssl genpkey -algorithm ed25519 -out data/admin_private.pem
openssl pkey -in data/admin_private.pem -pubout -out data/admin_public.pem

# Extract base64 for config:
openssl pkey -in data/admin_public.pem -pubin -outform DER | base64
```

### Permission model

| Field | `admin: true` | `admin: false` |
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

Keys defined in the config file are synced to the database on startup.

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

  # Approval guard: detect API key abuse
  approval_guard:
    enabled: false
    window: "5m"
    threshold: 10                 # Consecutive non-approvals before pause
    resume_after: "2h"

  # IP whitelist
  ip_whitelist:
    enabled: false
    allowed_ips:
      - "127.0.0.1"
      - "::1"
    trust_proxy: false            # Trust X-Forwarded-For (only behind trusted proxy!)
    # trusted_proxies: ["10.0.0.1"]
```

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

Rules define the policy engine. They can be defined **inline**, loaded from **files**, or expanded from **templates** (via **instance** rules). For concepts (templates, instances, presets) and examples, see [RULES_TEMPLATES_AND_PRESETS.md](RULES_TEMPLATES_AND_PRESETS.md). For rule type syntax (Solidity, evm_js, etc.), see [RULE_SYNTAX.md](RULE_SYNTAX.md).

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

**Presets** (optional): Pre-filled instance data in `rules/presets/*.yaml`; use **remote-signer-cli** or **setup.sh** to generate or merge rules from a preset with minimal overrides. See [RULES_TEMPLATES_AND_PRESETS.md](RULES_TEMPLATES_AND_PRESETS.md#4-presets).

### Rule evaluation order

1. **Blocklist** rules checked first — any match = reject immediately
2. **Whitelist** rules checked second — any match = auto-approve
3. No match = reject (or pending manual approval if `manual_approval_enabled: true`)

## Templates

**Templates** are parameterized rule files (variables + rules with `${var}` placeholders). They are loaded from paths listed under `templates` and expanded only when a **rule** of type **instance** references them and supplies variables. See [RULES_TEMPLATES_AND_PRESETS.md](RULES_TEMPLATES_AND_PRESETS.md#2-rule-templates).

```yaml
templates:
  - name: "Polymarket Safe Template"
    type: "file"
    enabled: true
    config:
      path: "rules/templates/polymarket_safe.template.yaml"
```

## Environment Variables

| Variable | Used By | Description |
|----------|---------|-------------|
| `EVM_SIGNER_KEY_1` | `chains.evm.signers.private_keys[].key_env` | EVM private key (hex, no 0x) |
| `EVM_KEYSTORE_PASSWORD_1` | `chains.evm.signers.keystores[].password_env` | Keystore password |
| `HD_WALLET_PASSWORD_1` | `chains.evm.signers.hd_wallets[].password_env` | HD wallet password |
| `ADMIN_PUBLIC_KEY` | `api_keys[].public_key_env` | Admin API public key |
| `DATABASE_DSN` | `database.dsn` | Database connection string |
| `SLACK_BOT_TOKEN` | `notify.slack.bot_token` | Slack bot token |
| `PUSHOVER_APP_TOKEN` | `notify.pushover.app_token` | Pushover app token |
| `WEBHOOK_AUTH_TOKEN` | `notify.webhook.headers` | Webhook auth token |
| `POSTGRES_USER` | Docker only | PostgreSQL username |
| `POSTGRES_PASSWORD` | Docker only | PostgreSQL password |
| `POSTGRES_DB` | Docker only | PostgreSQL database name |
