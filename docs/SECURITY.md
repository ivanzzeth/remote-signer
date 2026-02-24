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

- Optional: `security.ip_whitelist.enabled` with a list of allowed IPs or CIDR ranges.
- Requests from other IPs are rejected before authentication.
- When behind a reverse proxy, `trust_proxy` can be enabled so the real client IP is taken from `X-Forwarded-For` / `X-Real-IP` (only enable if the proxy is trusted).

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

## 4. Application Layer — Authorization Rules

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

## 5. Application Layer — Budget and Expiry

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

## 6. Application Layer — Abuse and Guardrails

### Approval guard

- Detects bursts of “rejected” outcomes: requests that are **blocked by a rule** or that **require manual approval** (no whitelist match).
- Use case: **API key leaked** — attacker uses a valid key and repeatedly hits blocklist or pending-approval; guard treats this as abuse.
- When, within a configurable **window**, the number of consecutive such outcomes reaches a **threshold**, the service **pauses** all new sign requests and sends an alert (Slack/Pushover/webhook).
- **Resume**: after a configurable **resume_after** duration, the service auto-resumes; or an admin can call the resume API immediately.
- Ensures that abuse does not keep the pipeline flooded and gives operators time to react (rotate key, adjust rules, etc.).

---

## 7. Audit and Monitoring

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
| Application | Blocklist rules        | Hard reject by parameter (e.g. address)     |
| Application | Whitelist rules        | Allow only by parameter; else manual approval|
| Application | Budget + period/renew  | Time- and amount-bounded quotas             |
| Application | Rule/instance expiry   | Time-limited authorization                   |
| Application | Approval guard         | Pause + alert on abuse burst, then resume    |
| Operations  | Audit log + monitor    | Forensics and anomaly alerts                 |

Together, these provide layered protection from the network through to application-level authorization and operational visibility.
