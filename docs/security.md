# Security

Remote Signer applies defense in depth from the network layer to the application layer. All security controls are explicit and configurable; there are no silent fallbacks.

## Configuration reference (source of truth)

- **Full config schema**: see [`configuration.md`](configuration.md) and [`config.example.yaml`](../config.example.yaml).
- This document focuses on **threat model, guardrails, and recommended baselines**. For exact defaults and all keys, prefer `configuration.md` (kept in sync with code).

## Recommended production baseline (minimum)

- **Transport**: enable TLS (`server.tls.enabled: true`); consider mTLS for internal-only deployments (`server.tls.client_auth: true`).
- **Replay protection**: keep `security.nonce_required: true` (default) and `security.max_request_age` short (e.g. 30–60s).
- **Rate limiting**: keep `security.ip_rate_limit` enabled; set per-key `api_keys[].rate_limit` as needed (falls back to `security.rate_limit_default`).
- **API lockdown** (recommended): `security.rules_api_readonly: true` (default), `security.api_keys_api_readonly: true` (default); set `security.signers_api_readonly` based on whether you allow runtime signer/HD-wallet creation.
- **Access control**: enable `security.ip_whitelist` for admin/internal deployments; if behind proxy, set `trust_proxy: true` and populate `trusted_proxies` (otherwise proxy headers are ignored, fail-closed).
- **Operational guardrails**: configure `security.approval_guard` for leaked-key detection; consider `security.auto_lock_timeout` for hot signers.

---

## 1. Network / Transport

### TLS (HTTPS)

- All server traffic can be served over TLS. Configure `server.tls.enabled`, `cert_file`, and `key_file`.
- Protects confidentiality and integrity of API traffic in transit.

### mTLS (Mutual TLS)

- Optional client certificate authentication: set `server.tls.client_auth: true` and `ca_file` to the CA that signs client certificates.
- Only clients that present a valid certificate issued by that CA can establish a connection.
- Adds a strong identity layer at the transport level before any API logic runs.

---

## 2. Network / Access Control

### IP whitelist

- Optional: `security.ip_whitelist.enabled: true` and `security.ip_whitelist.allowed_ips` (list of IPs or CIDR ranges, e.g. `10.0.0.0/8`).
- Requests from other IPs are rejected before authentication.
- Supports both IPv4 and IPv6, including IPv4-mapped IPv6 address normalization.
- When behind a reverse proxy, `security.ip_whitelist.trust_proxy: true` uses the real client IP from `X-Forwarded-For` / `X-Real-IP` (only from trusted proxies listed in `trusted_proxies`; fail-closed if proxy is not trusted).

---

## 3. API Layer

### API key (Ed25519)

- Every request (except `/health` and `/metrics`) must be signed with an API key.
- Keys are Ed25519 key pairs: the server stores the public key; the client signs a request payload with the private key.
- Signature covers: timestamp, nonce, method, path, and SHA-256 of the body. Format: `{timestamp}|{nonce}|{method}|{path}|{sha256(body)}`. Invalid or missing signature → 401.
- **Header length validation** (DoS prevention): `X-API-Key-ID` ≤ 128, `X-Timestamp` ≤ 24, `X-Signature` ≤ 256, `X-Nonce` ≤ 256 chars.

### Replay protection

- **Max request age** (`security.max_request_age`, e.g. 60s): signed timestamp must be within the window. Old requests are rejected.
- **Nonce** (`security.nonce_required: true`): client sends `X-Nonce`; the server stores used nonces and rejects duplicates. Prevents replay even within the timestamp window.

Together, timestamp + nonce ensure that each request is fresh and used at most once.

### Authorization scopes

- **`allowed_signers`** (empty = all): restricts which signer addresses the key can use for signing. Empty means unrestricted access to all signers.
- **`allowed_hd_wallets`** (empty = none): grants access to all derived addresses of specified HD wallet primary addresses. Empty means no HD wallet access. This is intentionally different from `allowed_signers` — HD wallet authorization must be explicit.
- **`allowed_chain_types`** (empty = all): restricts which chain types (e.g. `evm`, `solana`, `cosmos`) the key can use.
- **Admin vs Non-Admin**: Admin keys can approve requests, create/modify rules, manage signers, and use the preset API (when `presets.dir` is set). Non-admin keys can only submit sign requests and view status. Preset apply is also disabled when `security.rules_api_readonly` is true.
- **Key enable/disable**: Keys can be disabled (`enabled: false`) without deletion — disabled keys are rejected with a security alert.
- Permission hierarchy: admin > `allowed_hd_wallets` (derived addresses) > `allowed_signers` (individual addresses).
- Defense-in-depth: sign requests check both `allowed_signers` and `allowed_hd_wallets` derived addresses.

### Rate limit (two-layer)

Two independent rate-limiting layers protect against different attack vectors:

1. **IP-level rate limit (pre-auth)**: runs before authentication. Per-source-IP sliding window (default 200 req/min, configurable via `security.ip_rate_limit`). Protects against unauthenticated flood attacks and credential brute-force.

2. **API key rate limit (post-auth)**: runs after authentication. Per-key sliding window (default 100 req/min, configurable per key via `rate_limit` field). Limits abuse from a single compromised key.

Both layers trigger security alerts and audit logging when exceeded. Stale rate-limit windows are cleaned up every 5 minutes.

---

## 4. Signer key custody

Private keys used to sign transactions (EVM and others) are the most sensitive asset. Custody options:

### Current: keystore + password

- **Keystore**: signer private keys can be stored in encrypted keystore files (e.g. Ethereum JSON keystore). Keys are encrypted at rest.
- **Password**: decryption password is supplied at runtime (e.g. via environment variable or secret manager). The server never logs or persists the password. Password memory is securely zeroed (`keystore.SecureZeroize()`) after use.
- **Password strength and management**: use a **truly random** passphrase of **25+ characters** (avoid common words and predictable patterns). Store it in an **encrypted password manager** (e.g. 1Password); do not keep keystore passwords in plaintext configs or docs.
- Recommended for production when HSM is not yet available: keeps keys off disk in plaintext and allows separation of key material from password.

### HD wallet (multi-key custody)

- Encrypted mnemonic (BIP-39) stored in `chains.evm.hd_wallet_dir`.
- Derives multiple addresses from a single seed using BIP-44 path: `m/44'/60'/0'/0/{index}`.
- Password-protected encryption at rest.
- **Locking/unlocking**: signers can be locked after creation; locked signers cannot sign. Must be unlocked with password before signing. Prevents accidental signing while signer is unused.
- API supports derive single (`index`) or range (`start`, `count`).
- File permissions: `0700` (owner-only) for new files.

### Test only: plaintext private key

- For **local or test environments only**, a signer can be configured with a raw private key (e.g. in config or env). This is **not for production**.
- Use only in isolated testnets or CI; never use plaintext keys for mainnet or any environment where compromise would have real impact.

### Future: HSM

- **HSM (Hardware Security Module)** support is planned. Signing would be delegated to an HSM; private keys never leave the device, and the server would only request signatures via PKCS#11 or similar.
- This will provide higher-assurance custody for production and regulated use cases.

---

## 5. Application Layer — Authorization Rules

Authorization is **parameter-level**: rules evaluate the concrete request (chain, signer, sign type, payload fields such as `to`, `value`, calldata, EIP-712 fields, etc.).

### Two-tier evaluation

1. **Blocklist** (evaluated first): any rule that matches in blocklist mode → request is **rejected immediately**. No manual approval. Fail-closed: blocklist evaluation errors also lead to rejection.
2. **Whitelist**: if no blocklist hit, whitelist rules are evaluated. Any match → request is **auto-approved**. No match → request goes to **manual approval** (or is rejected if manual approval is disabled).

### Rule types

| Type | Description | Security Impact |
|------|-------------|-----------------|
| **signer_restriction** | Limit which signer addresses can be used | Restrict signing authority |
| **chain_restriction** | Limit which chains/chain IDs are allowed | Prevent cross-chain abuse |
| **sign_type_restriction** | Limit sign types (personal, typed_data, transaction, hash, raw_message, eip191) | Control what can be signed |
| **message_pattern** | Regex on personal/EIP-191 message content | Content-based filtering |
| **evm_address_list** | Whitelist/blocklist by recipient address | Prevent sending to unauthorized addresses |
| **evm_contract_method** | Allow/block by contract address + method selector | Restrict contract interactions to known safe methods |
| **evm_value_limit** | Cap transaction value per tx or in aggregate | Prevent large unintended transfers |
| **evm_solidity_expression** | Custom Solidity logic via Foundry scripts | Most flexible; arbitrary conditions (sandboxed) |
| **evm_js** | JavaScript rule evaluation via Sobek sandbox | Simpler logic, faster execution, lower risk |

### Scope fields

Rules can be scoped by `chain_type`, `chain_id`, `api_key_id`, `signer_address`. Unscoped rules (nil) apply to all matching requests. They are stored in config or created/updated via API (with admin key).

---

## 6. Application Layer — Budget and Expiry

### Per-rule budgets (template instances)

- Template instances can define a **budget** (e.g. max total spend per unit such as USDT/ETH, or max tx count).
- **Metering** is configurable: by tx value, by calldata param, by EIP-712 field, or count-only.
- Budget is enforced before a whitelist-matched request is approved; if exceeded, that rule is skipped (other rules can still match).

### Period and automatic renewal

- A rule can have a **budget period** (e.g. 24h, 7d) and a **period start**. At each period boundary, the budget for that rule+unit is **reset** (spent/tx count zeroed for the new period).
- This gives time-bounded quotas (e.g. "X per day") with automatic renewal without manual intervention.

### Expiry

- Rules (and template instances) can have an **expires_at**. After expiry, the rule is not used. This supports time-limited grants.

### Alert threshold

- When usage reaches a configured percentage of the budget (e.g. 80%), an alert can be sent (integrated with the notify system where implemented).

---

## 7. Application Layer — Abuse and Guardrails

### Approval guard

- Detects bursts of "rejected" outcomes: requests that are **blocked by a rule** or that **require manual approval** (no whitelist match).
- Use case: **API key leaked** — attacker uses a valid key and repeatedly hits blocklist or pending-approval; guard treats this as abuse.
- When, within a configurable **window**, the number of consecutive such outcomes reaches a **threshold**, the service **pauses** all new sign requests and sends an alert (Telegram/Slack/Pushover/webhook).
- **Resume**: after a configurable **resume_after** duration, the service auto-resumes; or an admin can call `POST /api/v1/evm/guard/resume` immediately.

Configuration:
```yaml
security:
  approval_guard:
    enabled: true
    window: "5m"         # Time window for counting rejections
    threshold: 10        # Consecutive rejections before pause
    resume_after: "2h"   # Auto-resume duration (0 = manual only)
```

---

## 8. Real-Time Security Alerts

The `SecurityAlertService` sends instant notifications (Telegram, webhook, Slack, Pushover) when unauthorized access is detected. Alerts are rate-limited per (type, source) with a 5-minute cooldown to prevent notification flooding.

### Alert Types

| Alert Type | Trigger | Severity |
|------------|---------|----------|
| `ip_blocked` | Request from non-whitelisted IP | Critical |
| `auth_failure` | Invalid API key, bad signature | Critical |
| `nonce_replay` | Duplicate nonce (replay attack) | Critical |
| `disabled_key` | Request with disabled API key | Critical |
| `expired_key` | Request with expired API key | Warning |
| `admin_denied` | Non-admin key accessing admin endpoint | Warning |
| `rate_limit_ip` | IP-level rate limit exceeded | Warning |
| `rate_limit_key` | API key rate limit exceeded | Warning |
| `chain_denied` | API key lacks chain permission | Warning |
| `signer_denied` | API key lacks signer permission | Warning |

### Alert Points in Request Pipeline

```
Request → IP Whitelist (ip_blocked)
        → IP Rate Limit (rate_limit_ip)
        → Auth Verification (auth_failure / nonce_replay / disabled_key / expired_key)
        → Admin Check (admin_denied)
        → API Key Rate Limit (rate_limit_key)
        → Handler: Chain Permission (chain_denied)
        → Handler: Signer Permission (signer_denied)
```

### Configuration

Alerts are delivered through the `notify` channels configured in `config.yaml`. Setup via `scripts/setup.sh` step 5 (interactive Telegram/webhook wizard).

```yaml
notify:
  telegram:
    enabled: true
    bot_token: "${TELEGRAM_BOT_TOKEN}"  # from setup.sh
notify_channels:
  telegram: ["-123456789"]
```

### Admin Operation Alerts (High-Risk Write Operations)

Every privileged write operation triggers an immediate notification. This enables a simple security model: **if you didn't initiate the operation, it may be a breach — investigate immediately.**

| Alert Type | Trigger | Category |
|------------|---------|----------|
| `signer_created` | Signer created via API | Signer Mgmt |
| `signer_unlocked` | Signer unlocked via API | Signer Mgmt |
| `signer_locked` | Signer locked via API | Signer Mgmt |
| `signer_auto_locked` | Signer auto-locked by timeout | Signer Mgmt |
| `hdwallet_created` | HD wallet created/imported | Signer Mgmt |
| `hdwallet_derived` | HD wallet addresses derived | Signer Mgmt |
| `rule_created` | Rule created via API | Rule Mgmt |
| `rule_updated` | Rule updated via API | Rule Mgmt |
| `rule_deleted` | Rule deleted via API | Rule Mgmt |
| `preset_applied` | Preset applied via API | Rule Mgmt |
| `config_reloaded` | Config reloaded via SIGHUP | Config Sync |
| `template_synced` | Template created/updated/deleted from config | Config Sync |
| `apikey_synced` | API key created/updated from config | Config Sync |

Config sync alerts (template_synced, apikey_synced) only fire on **actual changes**, not on every startup.

Alert format includes: operation type, API key ID, source IP, detail, and timestamp.

### OFAC Dynamic Blocklist

Runtime address blocklist synced periodically from external sources (default: OFAC SDN list). Blocks signing requests to sanctioned/malicious addresses.

- **Startup**: loads from local cache file (instant, no network dependency)
- **Background sync**: fetches from configured URLs every hour (configurable)
- **Persistence**: writes to local cache file after each successful sync
- **Fail mode**: "open" (use stale cache on failure) or "close" (reject all)
- **Security**: URL scheme validation (http/https only), 10MB body limit, minimum 1-minute sync interval

```yaml
dynamic_blocklist:
  enabled: true
  sync_interval: "1h"
  fail_mode: "open"
  cache_file: "data/blocklist_cache.json"
  sources:
    - name: "OFAC SDN ETH"
      type: "url_text"
      url: "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/main/sanctioned_addresses_ETH.txt"
```

### Docker Proxy

When running in Docker, outbound HTTPS (e.g. Telegram API) may require a proxy. The `docker-compose.yml` passes `HTTP_PROXY` / `HTTPS_PROXY` from the host environment. If unset, no proxy is used.

---

## 9. Audit and Monitoring

### Full API request audit

Every API request is recorded in the audit log for **complete attack timeline reconstruction**. The `LoggingMiddleware` captures method, path, status code, duration, and user-agent for every request, regardless of whether it succeeds or fails. This enables post-incident forensics to reconstruct the full sequence of attacker actions.

### Audit event types (15 types)

| Event Type | Description | Severity |
|------------|-------------|----------|
| `auth_success` | API key authenticated successfully | Info |
| `auth_failure` | Authentication rejected | **Critical** |
| `sign_request` | Sign request created | Info |
| `sign_complete` | Successfully signed | Info |
| `sign_failed` | Signing error occurred | **Critical** |
| `sign_rejected` | Blocklist rule violation | **Critical** |
| `rule_matched` | Rule evaluation matched | Info |
| `approval_request` | Manual approval required | Warning |
| `approval_granted` | Approved by admin | Info |
| `approval_denied` | Denied by admin | Warning |
| `rule_created` | Rule created via API | Info |
| `rule_updated` | Rule modified via API | Info |
| `rule_deleted` | Rule deleted via API | Info |
| `rate_limit_hit` | Rate limit exceeded | Warning |
| `api_request` | Every API request (method, path, status, duration, user-agent) | Status-based |

**Severity mapping**: `auth_failure`, `sign_rejected`, `sign_failed` → Critical. `approval_denied`, `rate_limit_hit` → Warning. `api_request` severity derived from HTTP status: 4xx → Warning, 5xx → Critical, else → Info. All others → Info.

### Audit record fields

Each record stores: `id` (UUID), `timestamp`, `event_type`, `severity`, `api_key_id`, `actor_address` (client IP), `sign_request_id`, `signer_address`, `chain_type`, `chain_id`, `rule_id`, `request_method`, `request_path`, `details` (JSON with extra info like status code, duration, user agent), `error_message`.

### Query API

- `GET /api/v1/audit` with filters: `event_type`, `api_key_id`, `chain_type`, `signer_address`, `severity`, `sign_request_id`, `start_time`, `end_time`.
- `GET /api/v1/audit/requests/{requestID}` — all audit records for a specific sign request.
- Cursor-based pagination for large result sets.
- TUI provides interactive audit log viewer with filtering, detail view, and navigation.

### Anomaly monitor (background)

- Background job scans audit records periodically for anomaly patterns:
  - **AUTH_FAILURE_BURST**: auth failures per source exceeding threshold
  - **SIGN_REJECTION_BURST**: sign rejections per key exceeding threshold
  - **RATE_LIMIT_HIT**: any rate limit events
  - **HIGH_FREQUENCY_REQUESTS**: request rate per source exceeding threshold
- When thresholds are exceeded, notifications are sent via configured notify channels (Telegram, Slack, Pushover, webhook).
- Configurable via `audit_monitor` section: interval, lookback window, per-category thresholds.

### Metrics

- Prometheus metrics (e.g. rule evaluation duration and counts by outcome) are exposed on the same port as the API (`/metrics`). No auth; suitable for internal monitoring only.

---

## 10. Rule Engine Security — Sandbox and Static Analysis

Both Solidity and JavaScript rule engines are sandboxed with defense-in-depth: static analysis before execution, runtime restrictions during execution.

### Solidity Rules (Foundry-based)

#### Static analysis (pre-execution)

`ValidateSolidityCodeSecurity()` scans rule code against a regex blocklist of **24 dangerous patterns**:

- **Foundry cheatcodes — command execution** (1): `vm.ffi()` (arbitrary shell command execution)
- **Foundry cheatcodes — file system** (8): `vm.readFile`, `vm.writeFile`, `vm.removeFile`, `vm.readDir`, `vm.closeFile`, `vm.writeLine`, `vm.readLine`, `vm.fsMetadata`
- **Foundry cheatcodes — environment** (9): `vm.envOr`, `vm.envString`, `vm.envUint`, `vm.envBool`, `vm.envAddress`, `vm.envBytes`, `vm.envBytes32`, `vm.envInt`, `vm.setEnv`
- **Foundry cheatcodes — path disclosure** (1): `vm.projectRoot()`
- **Foundry cheatcodes — network** (3): `vm.rpc()`, `vm.createFork()`, `vm.selectFork()`
- **Foundry cheatcodes — transaction** (2): `vm.broadcast()`, `vm.startBroadcast()`
- **Foundry cheatcodes — signing** (1): `vm.sign()` (would allow signing with test keys)
- **Solidity language** (3): `selfdestruct()`, `delegatecall()`, `staticcall()` (defense-in-depth)

Rules containing any of these patterns are **rejected at creation time** — they never execute.

#### Runtime protections (defense-in-depth)

Even if a pattern somehow bypasses static analysis, runtime protections are enforced:

```
FOUNDRY_FFI=false            # Disable FFI cheatcode at runtime
FOUNDRY_FS_PERMISSIONS=[]    # Empty filesystem permission list
```

- **Timeout**: 30-second timeout per rule execution (configurable).
- **Temp file cleanup**: all temporary files created during validation are removed.
- **Script hash caching**: syntax validation results cached by script hash to avoid redundant forge invocations.

#### Validation pipeline

1. Static security check (24 regex patterns) — rejects at rule creation
2. Syntax validation via `forge build`
3. Test case execution (rules must include test cases that validate behavior)
4. Batch compilation for performance (rules grouped by mode)

### JavaScript Rules (Sobek-based)

#### Static analysis (pre-execution)

`ValidateJSCodeSecurity()` scans JS rule code against a regex blocklist:

- **Prototype pollution / sandbox escape** (5): `__proto__`, `constructor.constructor`, `Object.getPrototypeOf`, `Object.setPrototypeOf`, `Object.defineProperty`
- **Dynamic code execution** (2): `Function()`, dynamic `import()`
- **Node.js dangerous modules** (1): `child_process`

Rules containing any of these patterns are **rejected at creation time**.

#### Runtime sandbox

The JS evaluator uses **Sobek** (a Go-native JavaScript runtime, not Node.js) with comprehensive sandboxing:

**Blocked global APIs** (removed via `removeGlobals()`):
| Category | Blocked APIs |
|----------|-------------|
| Code execution | `eval`, `Function()` |
| Network exfiltration | `fetch`, `XMLHttpRequest`, `WebSocket` |
| Timer abuse | `setTimeout`, `setInterval`, `clearTimeout`, `clearInterval` |
| Reflection | `Reflect`, `Proxy` |
| Runtime introspection | `console`, `require`, `global`, `globalThis` |
| Date construction | `Date` (constructor disabled) |
| Randomness | `Math.random()` (partially disabled) |

**Resource limits**:
- **Timeout**: 20ms per rule evaluation (`jsRuleTimeout`)
- **Memory**: 32MB max allocation growth per evaluation (`jsRuleMaxAllocBytes`)
- Memory monitoring runs every 5ms during execution
- VM interrupted on timeout or memory limit; graceful cleanup with `vm.ClearInterrupt()`
- **Reason length**: 120 chars max for rule rejection reasons

**Input/Output isolation**:
- Only `input` (parsed request), `config` (variables), and injected helper functions are exposed
- Script must define `validate(input)` function returning `{valid, reason?, payload?, delegate_to?}`
- All returned data is sanitized and type-checked
- Supports delegation to other rules via `delegate_to` field

---

## 11. Request Lifecycle (State Machine)

Sign requests follow a strict state machine with audit logging at each transition:

```
Pending → Authorizing (rule engine evaluates)
  │
  ├→ Rejected (blocklist rule matched) [FINAL - no appeal]
  ├→ Pending Manual Approval (no whitelist match + manual_approval_enabled)
  │    ├→ Approved → Signing
  │    └→ Denied [FINAL]
  └→ Signing (whitelist matched or approved)
       ├→ Completed (signature created) [FINAL]
       └→ Failed (signing error) [FINAL]
```

**Timeline fields**: `created_at`, `updated_at` (last status change), `completed_at` (final state reached).

**Audit trail**: each state transition is logged with the event type, rule matches are tracked in `rule_evaluation_result`, approval info stored in `approved_by` / `approved_at`.

---

## 12. Middleware Security Chain

Request processing follows a strict middleware order (outermost to innermost):

```
1. IPWhitelistMiddleware     → Reject non-whitelisted IPs (if enabled)
2. ClientIPMiddleware        → Resolve client IP (X-Forwarded-For aware)
3. LoggingMiddleware         → Log + audit ALL requests (timing, status, user-agent)
4. SecurityHeadersMiddleware → Set response headers
5. IPRateLimitMiddleware     → Pre-auth IP rate limit (if enabled)
6. AuthMiddleware            → Verify Ed25519 signature + nonce + audit auth events
7. AdminMiddleware           → Admin role check (for admin-only routes)
8. RateLimitMiddleware       → Per-API-key rate limit + audit rate limit events
9. Route Handler             → Process request
```

**Security headers set on every response**:
- `X-Content-Type-Options: nosniff` — Prevent MIME type sniffing
- `X-Frame-Options: DENY` — Prevent clickjacking
- `Cache-Control: no-store` — No caching of sensitive responses
- `Content-Security-Policy: default-src 'none'` — API-only server, restrict resource loading

---

## 13. Template System

### Parameterized rules

- Templates define rules with `${variable}` placeholders.
- Variables have type, description, required flag, and default value.
- Template instantiation creates concrete rules by substituting values.
- Instance-level budget/period overrides allowed.

### Template sources

1. **File-based**: YAML file with `variables`, `test_variables`, `rules` sections. Format: `rules/templates/template_name.template.yaml`.
2. **Inline**: Rules directly in config.

### Instance lifecycle

- **Expiration**: `expires_at` (optional) — instance auto-disables after expiry.
- **Budget period**: `budget_period` + `budget_period_start` — automatic renewal at period boundaries.
- **Override**: Instance-level settings override template defaults for budget/period.

---

## 14. Configuration Security

### Secrets management

- **Environment variables**: `${VAR_NAME:-fallback}` syntax supported in config files.
- **No hardcoding**: production secrets must use env vars or secret managers.
- **Immutable config options**:
  - `security.rules_api_readonly: true` — blocks rule CRUD via API (default: true)
  - `security.signers_api_readonly: false` — blocks signer creation via API
  - `security.allow_sighup_rules_reload: false` — prevents unexpected config reload

### Sensitive fields (never logged)

- Database DSN
- Keystore/HD wallet passwords (cleared after use via `SecureZeroize()`)
- API key private keys (client-side, never sent to server)
- Notification tokens (Telegram, Slack, etc.)

---

## 15. Container Hardening (Docker)

Production Docker deployment includes multiple hardening layers:

| Control | Purpose |
|---------|---------|
| `read_only: true` | Immutable root filesystem; writes only via explicit volumes/tmpfs |
| `tmpfs: /tmp, /run` | Ephemeral writable areas with `noexec,nosuid` |
| `no-new-privileges` | Prevent privilege escalation via setuid/setgid |
| `seccomp=deploy/seccomp.json` | Block dangerous syscalls (ptrace, mount, kexec, kernel modules, etc.) |
| `cap_drop: ALL` + minimal `cap_add` | Only NET_BIND_SERVICE and IPC_LOCK capabilities |
| Resource limits | CPU/memory limits to prevent DoS |
| `mem_swappiness: 0` | Prevent private keys from being swapped to disk |
| Named volumes | `svm_data` for solc compiler cache persistence |

### Seccomp Profile

The seccomp profile (`deploy/seccomp.json`) uses a default-allow policy with explicit denials for:
- Process debugging (`ptrace`, `process_vm_readv/writev`)
- Filesystem manipulation (`mount`, `umount2`, `pivot_root`, `chroot`)
- Kernel operations (`kexec_load`, `init_module`, `reboot`)
- Namespace escape (`unshare`, `setns`)
- Kernel keyring (`keyctl`, `add_key`, `request_key`)

### Image Scanning

Use `scripts/scan-image.sh` to scan the Docker image for HIGH/CRITICAL vulnerabilities with Trivy.

---

## 16. Development Security Pipeline

Pre-commit hooks enforce security checks before any code reaches the repository. Install with `bash scripts/install-hooks.sh`.

### Go Security

| Tool | Purpose | Install |
|------|---------|---------|
| **gosec** | Static analysis for Go security issues (OWASP, CWE) | `go install github.com/securego/gosec/v2/cmd/gosec@latest` |
| **govulncheck** | Checks Go dependencies against the Go vulnerability database | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| **go vet** | Built-in Go static analysis | Included with Go |

- `gosec` scans all Go source (excluding `vendor/`, `pkg/js-client/`). Use `// #nosec GXXX -- reason` to suppress false positives.
- `govulncheck` reports only vulnerabilities that are actually reachable from the call graph. Stdlib-only vulnerabilities are downgraded to WARN (non-blocking).

### Secret Detection (multi-layer)

| Tool | Purpose | Install |
|------|---------|---------|
| **gitleaks** | Fast regex-based secret scanner, scans staged git diffs | `go install github.com/zricethezav/gitleaks/v8@latest` |
| **detect-secrets** | Entropy + pattern-based detector (complements gitleaks) | `pip install detect-secrets` |
| **Plaintext grep** | Heuristic grep for `private_key`, `password`, `secret`, `token` patterns | Built-in |

- **gitleaks** uses `.gitleaks.toml` for configuration and allowlists.
- **detect-secrets** uses `.secrets.baseline` to track known false positives. Regenerate baseline: `detect-secrets scan --exclude-files 'vendor/.*' --exclude-files 'node_modules/.*' --exclude-files 'go\.sum' > .secrets.baseline`.
- Three layers ensure different secret patterns are caught (regex rules, entropy analysis, heuristic grep).

### JS/TS Security

| Tool | Purpose | Install |
|------|---------|---------|
| **semgrep** | SAST for JS/TS — XSS, prototype pollution, command injection, etc. | `pip install semgrep` |
| **eslint-plugin-security** | ESLint rules for common JS security antipatterns (eval, innerHTML, etc.) | `cd pkg/js-client && npm install` |
| **npm audit** | Dependency vulnerability scanner for npm packages | Included with npm |

- **semgrep** runs with `--config=auto` (community security rules) on any staged `.js`/`.ts` files.
- **eslint-plugin-security** is configured in `pkg/js-client/.eslintrc.json` and runs only when `pkg/js-client/src/` files are staged.
- **npm audit** runs at `--audit-level=high` only when `package.json` or `package-lock.json` changes.

### Pre-commit Check Order

1. Error suppression check (`_ = xxx` forbidden)
2. gosec (Go SAST)
3. govulncheck (Go dependency vulnerabilities)
4. go vet (Go static analysis)
5. Plaintext secret grep
6. gitleaks (staged diff secret scan)
7. detect-secrets (entropy-based secret scan)
8. semgrep (JS/TS SAST, only when JS/TS files staged)
9. eslint-plugin-security (JS/TS lint, only when js-client files staged)
10. npm audit (JS deps, only when package files staged)
11. Rule YAML validation (only when rule files staged)
12. E2E tests

### `#nosec` / Suppression Policy

Suppressions require a justification comment:
```go
// #nosec G115 -- bounds checked above
// #nosec G118 -- intentional: audit logging must outlive request context
// #nosec G204 -- foundryPath is admin-configured
// #nosec G304 -- path is admin-configured via config file
// #nosec G104 -- HTTP response write error cannot be meaningfully handled
```

Suppressions without justification are not accepted. Review all `#nosec` annotations during code review.

---

## Summary

| Layer | Control | Purpose |
|-------|---------|---------|
| Transport | TLS / mTLS | Confidentiality, integrity, client identity |
| Network | IP whitelist (CIDR + proxy trust) | Restrict which hosts can reach the API |
| API | Ed25519 API key | Authenticate clients |
| API | Timestamp + nonce | Replay protection |
| API | Rate limit (pre-auth IP + post-auth key) | Throttle abuse per source and per key |
| API | Header length validation | DoS prevention |
| Key custody | Keystore + password (SecureZeroize) | Encrypted signer keys at rest |
| Key custody | HD wallet (BIP-44, lockable) | Multi-key from single seed |
| Key custody | HSM (planned) | Signing in HSM; keys never leave device |
| Application | Blocklist rules (fail-closed) | Hard reject by parameter |
| Application | Whitelist rules | Allow only by parameter; else manual/reject |
| Application | Budget + period/renew | Time- and amount-bounded quotas |
| Application | Rule/instance expiry | Time-limited authorization |
| Application | Approval guard | Pause + alert on abuse burst |
| Rule engine | JS sandbox (Sobek) | 20ms timeout, 32MB memory, 13+ blocked globals |
| Rule engine | Solidity static check | 24 dangerous patterns blocked before execution |
| Rule engine | Solidity runtime | FFI disabled, FS permissions empty |
| Alerting | Real-time security alerts | 10 alert types, rate-limited 5min/source |
| Audit | Complete API request audit | Every request logged for timeline reconstruction |
| Audit | 15 event types with severity | Auth, signing, rules, approvals, rate limits |
| Audit | Anomaly monitor | Background pattern detection + alerts |
| Container | read_only + seccomp | Immutable filesystem + syscall restrictions |
| Container | tmpfs + named volumes | Controlled writable paths only |
| Container | no-new-privileges + cap_drop ALL | Minimal container capabilities |
| Dev pipeline | gosec + govulncheck | Go SAST and dependency vulnerability checks |
| Dev pipeline | gitleaks + detect-secrets | Multi-layer secret detection in commits |
| Dev pipeline | semgrep + eslint-security | JS/TS SAST and security linting |
| Dev pipeline | npm audit | JS dependency vulnerability scanning |

Together, these provide layered protection from the network through to application-level authorization, operational visibility, and development-time security enforcement.

---

## Future improvements and roadmap

Planned security upgrades, recorded for prioritisation and roadmap planning.

### Backlog (no fixed order)

1. **Monitoring upgrade**
   Use Falco or eBPF rules to detect abnormal process memory read/write (e.g. scraping or injection).

2. **Signing process isolation**
   Run keystore decrypt and signing in a dedicated container: read-only filesystem, seccomp, no ptrace, drop root immediately after startup. Significantly raises the bar for memory dump and process inspection.

3. **Backup and key rotation**
   Encrypted keystore backups to offsite (encrypted USB + cloud). Quarterly: generate new signer key, migrate funds (batch transfer driven by rules / automation).

4. **HSM**
   Consider YubiHSM 2 for signer key custody; keys never leave the device.

5. **Rule engine security (Solidity / Foundry)**
   Run Foundry/Solidity rules in isolated container with hard timeout, no network access, and resource limits beyond current static analysis.

6. **Supply chain and lifecycle**
   Binary signing for releases; dependency scanning (e.g. Dependabot, Snyk); periodic penetration testing and code audits, especially for the rule engine.

7. **Infrastructure**
   WAF and DDoS protection (e.g. Cloudflare, AWS Shield); zero-trust network design; infrastructure as code with automated vulnerability scanning.

8. **Manual approval flow**
   Approval channel must use 2FA/MFA; multi-signer approval where required; tamper-evident approval records; timeout with automatic reject.

---

### ROI-oriented prioritisation

| Item                      | Impact (risk reduction / compliance) | Effort | ROI   | Notes |
|---------------------------|---------------------------------------|--------|-------|--------|
| Rule engine sandbox (5)   | **Critical** – prevents RCE           | Medium | **High** | Single point of failure; do first. |
| Signing isolation (2)     | **High** – limits key extraction      | Medium | **High** | Directly protects private keys. |
| Approval 2FA/MFA + audit (8) | **High** – approval abuse / repudiation | Medium | **High** | Core to "who approved what". |
| Backup & rotation (3)     | **High** – recovery and key hygiene   | Medium | **High** | Enables safe key rotation. |
| HSM / YubiHSM 2 (4)       | **High** – key never in app memory    | High   | Medium | After isolation/sandbox. |
| Supply chain (6)          | **Medium** – dependency/artifact trust | Low–Med | **High** | Quick wins: Dependabot, signed binaries. |
| Infra WAF/DDoS (7)        | **Medium** – availability, abuse      | Low    | **High** | Often config-only. |
| Monitoring Falco/eBPF (1) | **Medium** – detect runtime abuse     | Medium | Medium | Improves detection, not prevention. |

**Suggested roadmap phases**

- **Phase 1 (highest ROI, foundational)**
  - Rule engine sandbox (5): container + timeout + no network for Foundry/Solidity execution.
  - Supply chain (6): dependency scanning + signed binaries.
  - Approval hardening (8): 2FA/MFA, multi-sig where needed, tamper-evident log, timeout auto-reject.

- **Phase 2 (key and process protection)**
  - Signing process isolation (2): dedicated container, read-only fs, seccomp, drop root.
  - Backup and rotation (3): encrypted offsite backup, quarterly key rotation + rule-driven migration.

- **Phase 3 (hardening and detection)**
  - HSM (4): evaluate and integrate YubiHSM 2.
  - Infra (7): WAF, DDoS, zero-trust, IaC + vuln scan.
  - Monitoring (1): Falco or eBPF rules for process/memory anomalies.

This order addresses RCE and approval integrity first, then key custody and isolation, then infrastructure and detection.

---

## Appendix: Breach Impact Analysis (Zero-Trust Framework)

Each defense point is assumed to be independently compromisable. This analysis maps: **what is breached → what the attacker gains → what still holds → worst-case blast radius**. Use this as a zero-trust architecture checklist: every row should have meaningful "remaining defenses".

### Layer-by-Layer Breach Analysis

#### L1. TLS / mTLS Compromised

| Aspect | Detail |
|--------|--------|
| **Attack vector** | MITM via compromised CA, stolen server cert, or TLS downgrade |
| **Attacker gains** | Read/modify API traffic in transit; intercept Ed25519 signatures and request bodies |
| **Cannot do** | Forge new requests — Ed25519 signatures bind to (timestamp, nonce, method, path, body hash); replaying captured requests is blocked by nonce |
| **Remaining defenses** | Ed25519 auth, nonce replay protection, IP whitelist, all application-layer rules |
| **Blast radius** | **Low** — confidentiality loss (request/response content visible), but integrity and authorization intact |
| **Mitigation** | Certificate pinning; mTLS with client certs; short-lived certs (e.g. Let's Encrypt + auto-renewal) |

#### L2. IP Whitelist Bypassed

| Aspect | Detail |
|--------|--------|
| **Attack vector** | IP spoofing, proxy header forgery (`X-Forwarded-For` from untrusted proxy), or compromised host within allowed CIDR |
| **Attacker gains** | Can reach the API from an unauthorized network location |
| **Cannot do** | Authenticate — still needs valid Ed25519 API key; cannot bypass auth, rules, or rate limits |
| **Remaining defenses** | Ed25519 auth, rate limiting (IP + key), all application-layer rules, audit |
| **Blast radius** | **Low** — expands attack surface but no privilege gain without API key |
| **Mitigation** | Restrict `trusted_proxies` to known reverse proxy IPs; use mTLS instead of IP-only filtering |

#### L3. API Key (Ed25519) Compromised

| Aspect | Detail |
|--------|--------|
| **Attack vector** | Client-side key theft (disk, memory, log leak), social engineering, or insider threat |
| **Attacker gains** | Submit sign requests as the key holder; access to whatever `allowed_signers`, `allowed_chain_types`, `allowed_hd_wallets` the key permits |
| **Cannot do** | Bypass blocklist rules; exceed budget limits; access signers outside key scope; gain admin privileges (if non-admin key) |
| **Remaining defenses** | Blocklist/whitelist rules, budget limits, approval guard (detects burst abuse), rate limiting, audit trail, real-time alerts (`rate_limit_key`) |
| **Blast radius** | **Medium** — can submit valid requests within key scope, but rules still gate actual signing. If whitelist rules are tight (e.g. address list + value limit), damage is bounded. If rules are loose, damage is proportional to key scope |
| **Mitigation** | Narrow key scopes (`allowed_signers`, `allowed_chain_types`); per-key rate limits; budget limits on whitelist rules; approval guard to detect burst; key rotation policy; disable compromised key immediately (`enabled: false`) |

#### L4. Admin API Key Compromised

| Aspect | Detail |
|--------|--------|
| **Attack vector** | Same as L3, but targeting an admin key |
| **Attacker gains** | Everything in L3, plus: create/modify/delete rules, approve pending requests, manage signers, view audit logs, resume approval guard |
| **Cannot do** | Extract signer private keys via API (no endpoint exposes keys); bypass container/OS-level protections; modify config file rules if `rules_api_readonly: true` |
| **Remaining defenses** | `rules_api_readonly` (blocks rule mutation via API), signer key custody (keystore encryption), container hardening, audit trail (all admin actions logged), rule CRUD audit events |
| **Blast radius** | **High** — can weaken authorization by modifying rules, then submit and self-approve requests. With `rules_api_readonly: true`, attacker is limited to existing rules |
| **Mitigation** | Enable `rules_api_readonly: true` in production; minimize admin keys; separate admin key from signing key; monitor `rule_created/updated/deleted` audit events; 2FA for admin actions (roadmap) |

#### L5. Replay / Nonce Protection Bypassed

| Aspect | Detail |
|--------|--------|
| **Attack vector** | Nonce storage failure (database unavailable), clock skew exploitation, or nonce generation collision |
| **Attacker gains** | Re-submit previously captured valid requests within the timestamp window |
| **Cannot do** | Create new requests — still needs the private key to sign new payloads; bypass rules or budget checks on replayed requests |
| **Remaining defenses** | Ed25519 signature (cannot forge new requests), timestamp window (60s default), application-layer rules, budget deduction (replayed request may exceed budget) |
| **Blast radius** | **Low–Medium** — can repeat a specific past action (e.g. re-sign same tx), but budget/rules still apply. Most damaging if the original request was a high-value transaction |
| **Mitigation** | Ensure nonce storage is HA (replicated database); strict timestamp window; idempotency in downstream systems |

#### L6. Rate Limiting Bypassed

| Aspect | Detail |
|--------|--------|
| **Attack vector** | Distributed attack from many IPs, in-memory rate limiter crash/restart, or clock manipulation |
| **Attacker gains** | Flood the API with requests; brute-force API key signatures; DoS legitimate users |
| **Cannot do** | Authenticate without a valid key; bypass authorization rules |
| **Remaining defenses** | Ed25519 auth (brute-forcing Ed25519 is computationally infeasible), application-layer rules, approval guard (detects burst), container resource limits |
| **Blast radius** | **Low** — availability impact (DoS), but no authorization bypass. Ed25519 brute-force is not practical |
| **Mitigation** | External WAF/DDoS protection (Cloudflare, AWS Shield); distributed rate limiting (Redis-backed); approval guard as secondary burst detector |

#### L7. Blocklist Rules Bypassed

| Aspect | Detail |
|--------|--------|
| **Attack vector** | Rule misconfiguration, rule deletion by compromised admin key, or rule evaluation bug |
| **Attacker gains** | Transactions to blocked addresses or with blocked parameters are no longer rejected |
| **Cannot do** | Bypass whitelist requirement — if no whitelist matches, request still goes to manual approval or rejection |
| **Remaining defenses** | Whitelist rules (must still match to auto-approve), budget limits, manual approval workflow, approval guard, signer key scoping |
| **Blast radius** | **Medium** — loses the "hard reject" layer, but whitelist still gates approval. Impact depends on how much the blocklist was relied upon vs. whitelist coverage |
| **Mitigation** | `rules_api_readonly: true` to prevent API-based rule deletion; monitor `rule_deleted` audit events; rule backup in config files (source of truth); test rules with `validate-rules` CLI |

#### L8. Whitelist Rules Too Permissive

| Aspect | Detail |
|--------|--------|
| **Attack vector** | Overly broad rules (e.g. address list with `*`, no value limit, no chain restriction), or attacker creates permissive rules via compromised admin key |
| **Attacker gains** | Auto-approval for requests that should require scrutiny; bypass manual approval workflow |
| **Cannot do** | Bypass blocklist (evaluated first); exceed budget limits on the rule; use signers outside API key scope |
| **Remaining defenses** | Blocklist rules (checked first), budget/period limits, API key scope restrictions, signer custody |
| **Blast radius** | **Medium–High** — depends on rule scope. A permissive whitelist + compromised API key = auto-approved transactions up to budget limit |
| **Mitigation** | Principle of least privilege for rules; mandatory budget limits on whitelist rules; regular rule audit; `rules_api_readonly: true`; template system for standardized rule patterns |

#### L9. JS Sandbox Escaped (Sobek)

| Aspect | Detail |
|--------|--------|
| **Attack vector** | Sobek VM vulnerability, prototype pollution via unknown vector, or memory corruption |
| **Attacker gains** | Arbitrary Go code execution within the remote-signer process; read process memory (including decrypted signer keys if in memory) |
| **Cannot do** | Escape container (seccomp, no-new-privileges, cap_drop ALL); access host filesystem (read_only + tmpfs); survive process restart (no persistence) |
| **Remaining defenses** | Container hardening (seccomp, read-only fs, no-new-privileges), static analysis pre-check (blocks known dangerous patterns), process-level isolation |
| **Blast radius** | **Critical** — RCE within the process. If signer keys are decrypted in memory, attacker can extract them. This is the highest-impact application-layer breach |
| **Mitigation** | Run JS evaluation in a separate subprocess or container (roadmap); HSM so keys never enter process memory; keep Sobek updated; fuzz testing of JS evaluator; 20ms timeout limits exploitation window |

#### L10. Solidity/Foundry Sandbox Escaped

| Aspect | Detail |
|--------|--------|
| **Attack vector** | Bypass of 24-pattern static check (new cheatcode not in blocklist), `FOUNDRY_FFI=false` override, or Foundry zero-day |
| **Attacker gains** | `vm.ffi()` → arbitrary command execution on the host/container; file system access; environment variable reading (secrets) |
| **Cannot do** | Escape container (if properly hardened); execute network calls (if network restricted); survive container restart |
| **Remaining defenses** | Container hardening (seccomp blocks dangerous syscalls), `FOUNDRY_FS_PERMISSIONS=[]`, `FOUNDRY_FFI=false` (runtime defense-in-depth), 30s timeout, static analysis as first gate |
| **Blast radius** | **Critical** — RCE via `forge` subprocess. Unlike JS sandbox escape, this runs as a separate process with file system access. Can potentially read keystore files, environment variables, or database credentials |
| **Mitigation** | Run Foundry in isolated container with no network, no volume mounts to keystore (roadmap item #5); update pattern blocklist when new Foundry cheatcodes are released; signing process isolation (roadmap item #2) so keystores are not accessible from rule evaluation context |

#### L11. Signer Key Extracted

| Aspect | Detail |
|--------|--------|
| **Attack vector** | Memory dump (via L9/L10 RCE), keystore file theft + password brute-force, or backup compromise |
| **Attacker gains** | Sign arbitrary transactions on-chain without going through remote-signer; bypass all application-layer controls |
| **Cannot do** | Nothing within remote-signer scope — this is a total compromise of that signer's on-chain authority |
| **Remaining defenses** | On-chain controls only (multisig, timelocks, contract-level guards); other signers not compromised; audit trail shows the breach timeline (but cannot prevent on-chain damage) |
| **Blast radius** | **Critical** — full control over the compromised signer's on-chain assets. Damage = total value accessible by that signer address |
| **Mitigation** | HSM (keys never in memory); signing process isolation (separate container); `mem_swappiness: 0`; keystore password strength (25+ chars); on-chain multisig so single key compromise is insufficient; key rotation policy; minimize per-signer asset exposure |

#### L12. Audit / Monitoring Compromised

| Aspect | Detail |
|--------|--------|
| **Attack vector** | Database compromise (audit records deleted/modified), log injection, or anomaly monitor disabled |
| **Attacker gains** | Erase attack traces; prevent anomaly detection; disable alert-based response |
| **Cannot do** | Bypass prevention controls — authentication, authorization, rules, rate limits all still function independently |
| **Remaining defenses** | All prevention controls intact; real-time alerts (separate from audit); external log shipping (if configured) |
| **Blast radius** | **Medium** — loses forensic capability and anomaly detection, but prevention unaffected. Attacker operates "invisibly" but still constrained by rules |
| **Mitigation** | Append-only audit storage (immutable log); ship audit records to external SIEM in real-time; separate database credentials for audit writes vs. deletes; database backup with integrity verification |

#### L13. Real-Time Alerts Compromised

| Aspect | Detail |
|--------|--------|
| **Attack vector** | Notification channel failure (Telegram bot blocked, webhook endpoint down), alert rate-limit exploitation (flood one alert type to suppress others), or notification token compromise |
| **Attacker gains** | Security team not notified of ongoing attack; delayed incident response |
| **Cannot do** | Bypass any prevention control; modify audit records (separate system) |
| **Remaining defenses** | All prevention controls; audit log (records events even if alerts fail); anomaly monitor (background, independent of real-time alerts) |
| **Blast radius** | **Low–Medium** — detection delay only. If anomaly monitor is also compromised (L12), attacker operates undetected until manual audit review |
| **Mitigation** | Multiple notification channels (Telegram + webhook + Slack); alert delivery health check; monitoring of alert system itself (meta-monitoring); out-of-band alerting for critical events |

#### L14. Container Escape

| Aspect | Detail |
|--------|--------|
| **Attack vector** | Kernel vulnerability, container runtime exploit, or misconfigured seccomp/capabilities |
| **Attacker gains** | Host-level access; read all containers' filesystems; access host network; potentially compromise other services |
| **Cannot do** | Retroactively erase audit records already shipped to external SIEM |
| **Remaining defenses** | Host-level security (SELinux/AppArmor, firewall); HSM (if used — keys on hardware device); external audit log copies; on-chain multisig |
| **Blast radius** | **Critical** — full host compromise. Access to all keystore files, database credentials, environment variables. Equivalent to L11 for all signers on that host |
| **Mitigation** | Keep kernel and container runtime updated; minimal base image (distroless); VM-level isolation for high-value signers; separate hosts for rule evaluation vs. signing |

#### L15. Database Compromised

| Aspect | Detail |
|--------|--------|
| **Attack vector** | SQL injection (mitigated by GORM parameterized queries), credential theft, or network-level database access |
| **Attacker gains** | Read API key public keys (not private), nonce history, audit records, rule definitions, sign request history; modify/delete rules and audit records |
| **Cannot do** | Forge API key signatures (private keys are client-side); extract signer private keys (stored in keystore files, not database); bypass in-memory rate limits |
| **Remaining defenses** | Ed25519 auth (private keys not in database), signer key custody (keystore files separate from database), container hardening |
| **Blast radius** | **High** — rule deletion removes authorization controls; nonce deletion enables replay; audit deletion removes forensic trail. But signing keys are safe |
| **Mitigation** | Parameterized queries (GORM); principle of least privilege for DB user; separate DB users for read vs. write; network-level DB access control; encrypted backups; audit log shipping to separate storage |

### Breach Cascade Analysis

The most dangerous attack chains combine multiple breaches. This matrix shows which combinations lead to catastrophic outcomes:

| Combination | Result | Severity |
|-------------|--------|----------|
| L3 (API key) alone | Constrained by rules + budget | Medium |
| L3 + L7 (API key + blocklist bypass) | Constrained by whitelist + budget | Medium |
| L3 + L8 (API key + permissive whitelist) | Auto-approved up to budget limit | **High** |
| L4 (admin key) + `rules_api_readonly: false` | Can weaken rules then exploit | **High** |
| L4 + L12 (admin key + audit compromised) | Invisible rule tampering + exploitation | **Critical** |
| L9 or L10 (sandbox escape) | RCE → potential key extraction | **Critical** |
| L9/L10 + L14 (sandbox escape + container escape) | Full host compromise | **Critical** |
| L11 (signer key extracted) | Total on-chain control for that signer | **Critical** |
| L15 + L5 (database + replay bypass) | Nonce deletion enables replay attacks | **High** |
| L15 + L7 (database + rule deletion) | All rules removed, requests auto-rejected or manual-only | **High** |

### Zero-Trust Design Principles (Current Status)

| Principle | Status | Gap |
|-----------|--------|-----|
| **Never trust the network** | IP whitelist + TLS + Ed25519 auth | mTLS not enforced by default |
| **Never trust the client** | Signature verification on every request | No client cert binding |
| **Never trust the rule engine** | Static analysis + runtime sandbox + timeout | Solidity rules share container with signer keys (roadmap #2, #5) |
| **Never trust a single control** | Blocklist + whitelist + budget + approval guard | Budget not mandatory on whitelist rules |
| **Assume breach, detect fast** | 15 audit event types + anomaly monitor + real-time alerts | No external SIEM integration yet |
| **Minimize blast radius** | Key scoping + chain restriction + per-rule budget | No per-signer process isolation yet (roadmap #2) |
| **Immutable evidence** | Audit log in PostgreSQL | Not append-only; no external log shipping |
| **Least privilege** | cap_drop ALL, seccomp, read-only fs | DB user has full table access |

### Priority Actions from This Analysis

Based on the breach impact analysis, the highest-leverage improvements are:

1. **Separate rule evaluation from signing** (addresses L9, L10 → L11 cascade): rule engine sandbox escape should not grant access to signer keys. Run Foundry/JS evaluation in a separate container with no access to keystore volumes.

2. **HSM integration** (addresses L11, L14): signer keys never in process memory = sandbox escape and container escape cannot extract keys.

3. **Append-only audit + external SIEM** (addresses L12, L15): audit records shipped in real-time to external immutable storage; database compromise cannot erase forensic trail.

4. **Mandatory budget on whitelist rules** (addresses L3 + L8): even with a compromised key and permissive whitelist, budget limits cap total damage.

5. **Admin action 2FA** (addresses L4): compromised admin key alone is insufficient to modify rules or approve requests without second factor.
