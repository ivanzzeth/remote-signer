# Security

Remote Signer applies defense in depth from the network layer to the application layer. All security controls are explicit and configurable; there are no silent fallbacks.

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
- When behind a reverse proxy, `security.ip_whitelist.trust_proxy: true` uses the real client IP from `X-Forwarded-For` / `X-Real-IP` (only enable if the proxy is trusted).

---

## 3. API Layer

### API key (Ed25519)

- Every request (except `/health` and `/metrics`) must be signed with an API key.
- Keys are Ed25519 key pairs: the server stores the public key; the client signs a request payload with the private key.
- Signature covers: timestamp, method, path, and SHA-256 of the body (and optionally nonce). Invalid or missing signature → 401.

### Replay protection

- **Max request age** (`security.max_request_age`, e.g. 60s): signed timestamp must be within the window. Old requests are rejected.
- **Nonce** (`security.nonce_required: true`): client sends `X-Nonce`; the server stores used nonces and rejects duplicates. Prevents replay even within the timestamp window.

Together, timestamp + nonce ensure that each request is fresh and used at most once.

### Rate limit

- Per-API-key rate limit (requests per minute), configurable per key and with a default (`security.rate_limit_default`).
- Limits abuse and brute-force from a single key.

---

## 4. Signer key custody

Private keys used to sign transactions (EVM and others) are the most sensitive asset. Custody options:

### Current: keystore + password

- **Keystore**: signer private keys can be stored in encrypted keystore files (e.g. Ethereum JSON keystore). Keys are encrypted at rest.
- **Password**: decryption password is supplied at runtime (e.g. via environment variable or secret manager). The server never logs or persists the password.
- **Password strength and management**: use a **truly random** passphrase of **25+ characters** (avoid common words and predictable patterns). Store it in an **encrypted password manager** (e.g. 1Password); do not keep keystore passwords in plaintext configs or docs.
- Recommended for production when HSM is not yet available: keeps keys off disk in plaintext and allows separation of key material from password.

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
2. **Whitelist**: if no blocklist hit, whitelist rules are evaluated. Any match → request is **auto-approved**. No match → request goes to **manual approval** (or is rejected if you never approve it).

### Rule types (examples)

- **Signer / chain / sign-type restrictions**: limit which signers, chains, or sign types a key can use.
- **Address lists** (whitelist/blocklist): allow or block by `to` (and optionally other addresses).
- **Contract method**: allow or block by contract and method selector.
- **Value limit**: cap value per tx or in aggregate.
- **Solidity expression**: custom logic via Foundry scripts; can express arbitrary conditions on `to`, `value`, `data`, etc.
- **Message pattern**: regex on personal/EIP-191 message content.

Rules can be scoped by `chain_type`, `chain_id`, `api_key_id`, `signer_address`. They are stored in config or created/updated via API (with admin key).

---

## 6. Application Layer — Budget and Expiry

### Per-rule budgets (template instances)

- Template instances can define a **budget** (e.g. max total spend per unit such as USDT/ETH, or max tx count).
- **Metering** is configurable: by tx value, by calldata param, by EIP-712 field, or count-only.
- Budget is enforced before a whitelist-matched request is approved; if exceeded, that rule is skipped (other rules can still match).

### Period and automatic renewal

- A rule can have a **budget period** (e.g. 24h, 7d) and a **period start**. At each period boundary, the budget for that rule+unit is **reset** (spent/tx count zeroed for the new period).
- This gives time-bounded quotas (e.g. “X per day”) with automatic renewal without manual intervention.

### Expiry

- Rules (and template instances) can have an **expires_at**. After expiry, the rule is not used. This supports time-limited grants.

### Alert threshold

- When usage reaches a configured percentage of the budget (e.g. 80%), an alert can be sent (integrated with the notify system where implemented).

---

## 7. Application Layer — Abuse and Guardrails

### Approval guard

- Detects bursts of “rejected” outcomes: requests that are **blocked by a rule** or that **require manual approval** (no whitelist match).
- Use case: **API key leaked** — attacker uses a valid key and repeatedly hits blocklist or pending-approval; guard treats this as abuse.
- When, within a configurable **window**, the number of consecutive such outcomes reaches a **threshold**, the service **pauses** all new sign requests and sends an alert (Slack/Pushover/webhook).
- **Resume**: after a configurable **resume_after** duration, the service auto-resumes; or an admin can call the resume API immediately.
- Ensures that abuse does not keep the pipeline flooded and gives operators time to react (rotate key, adjust rules, etc.).

---

## 8. Audit and Monitoring

### Audit log

- Sign requests, approvals, rejections, rule matches, and other security-relevant events are written to the audit store.
- Supports forensics and compliance.

### Anomaly monitor (optional)

- Background job scans audit records for patterns such as:
  - Auth failures per source
  - Blocklist rejections per key
  - High request frequency per key
- When thresholds are exceeded, notifications are sent via the same notify channels (Slack, Pushover, webhook).

### Metrics

- Prometheus metrics (e.g. rule evaluation duration and counts by outcome) are exposed on the same port as the API (`/metrics`). No auth; suitable for internal monitoring only.

---

## Summary

| Layer        | Control                | Purpose                                      |
|-------------|------------------------|----------------------------------------------|
| Transport   | TLS                    | Confidentiality and integrity in transit    |
| Transport   | mTLS                   | Client identity at TLS                       |
| Network     | IP whitelist           | Restrict which hosts can reach the API      |
| API         | Ed25519 API key        | Authenticate clients                         |
| API         | Timestamp + nonce      | Replay protection                           |
| API         | Rate limit (per key)   | Throttle abuse per key                       |
| Key custody | Keystore + password    | Encrypted signer keys at rest; test-only plaintext |
| Key custody | HSM (planned)          | Signing in HSM; keys never leave device     |
| Application | Blocklist rules        | Hard reject by parameter (e.g. address)     |
| Application | Whitelist rules        | Allow only by parameter; else manual approval|
| Application | Budget + period/renew  | Time- and amount-bounded quotas             |
| Application | Rule/instance expiry   | Time-limited authorization                   |
| Application | Approval guard         | Pause + alert on abuse burst, then resume    |
| Operations  | Audit log + monitor    | Forensics and anomaly alerts                 |

Together, these provide layered protection from the network through to application-level authorization and operational visibility.

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
   “Solidity expression via Foundry scripts” is powerful but risky: arbitrary script execution can lead to RCE. Enforce strict sandbox: run in isolated container, hard timeout, no network access.

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
| Approval 2FA/MFA + audit (8) | **High** – approval abuse / repudiation | Medium | **High** | Core to “who approved what”. |
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
