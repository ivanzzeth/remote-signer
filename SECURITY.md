# Remote Signer Security Model

## Overview

Remote Signer applies defense in depth from transport to application layer. Every control is explicit and configurable — there are no silent fallbacks.

This document describes the **threat model, security boundaries, and recommended baselines**. For exact configuration defaults, see [docs/configuration.md](docs/configuration.md) and [config.example.yaml](config.example.yaml).

---

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| API key theft | Per-key scoping, rate limiting, budget enforcement, approval guard |
| Admin key compromise | `rules_api_readonly` blocks API-based rule mutation; audit trail detects all admin actions |
| Network eavesdropping | TLS/mTLS for transport encryption |
| Replay attacks | Timestamp window + nonce uniqueness per key |
| Brute-force / DoS | IP-level rate limit (pre-auth) + per-key rate limit (post-auth) |
| Rule engine escape | JS sandbox (Sobek, 20ms timeout, 32MB memory, blocked globals); Solidity static analysis (24 blocked patterns) + runtime protections (FFI/FS disabled) |
| Signer key extraction | Encrypted keystores, memory hardening (mlockall, core dump disabled, password zeroization) |
| Insider / compromised signer | Budget caps, manual approval for out-of-policy requests, real-time admin alerts |
| Supply chain | Pre-commit hooks (gosec, govulncheck, gitleaks, detect-secrets), dependency scanning |

---

## Security Boundaries

### Transport Layer

- **TLS** — All API traffic can be served over TLS. Configure `server.tls.enabled` with cert and key paths.
- **mTLS** — Optional client certificate authentication via `server.tls.client_auth: true` and a CA file. Only clients with a valid certificate from that CA can connect.

### Network Access Control

- **IP whitelist** — Optional CIDR-based access restriction. Supports trusted proxy headers (X-Forwarded-For / X-Real-IP) when behind a reverse proxy with explicit `trusted_proxies` list (fail-closed if proxy is not trusted).

### API Authentication

Every request (except `/health` and `/metrics`) must be signed with an Ed25519 API key:

- **Signature** — `{timestamp}|{nonce}|{method}|{path}|{sha256(body)}` signed with the key's Ed25519 private key.
- **Replay protection** — Configurable max request age (default 60s) + per-key nonce uniqueness. Together ensures every request is fresh and used at most once.
- **Rate limiting** — Two independent layers: IP-level (pre-auth, default 200 req/min) and per-key (post-auth, per-key configurable). Both trigger alerts on excess.

### Authorization Scopes

API keys carry scoping fields that constrain what they can do:

| Field | Purpose |
|-------|---------|
| `allowed_signers` | Restrict which signer addresses the key can use (empty = all) |
| `allowed_hd_wallets` | Grant access to derived addresses of specific HD wallets (empty = none) |
| `allowed_chain_types` | Restrict which chain types (evm, solana, cosmos) the key can access |
| `is_admin` | Full management access vs. sign-only |
| `is_agent` | Agent role: sign + read rules/budgets, cannot modify policies |

### Policy Enforcement

The two-tier rule engine (blocklist → whitelist) is the core authorization boundary:

1. **Blocklist** — Evaluated first. Fail-closed: any match or evaluation error rejects immediately. No manual approval possible.
2. **Whitelist** — Evaluated second. Fail-open: evaluation errors skip the rule. If a rule matches, the request is auto-approved (subject to budget).
3. **Manual approval** — If no rule matches, the request enters manual approval. Only the signer's owner API key can approve or reject.

### Budget Enforcement

- **Static budgets** — Declared per-rule limits (max total per period, max per tx, max tx count). Reset automatically at period boundaries.
- **Dynamic budgets** — Auto-tracked from transaction simulation (`eth_simulateV1`). Budget is based on actual balance changes, not declared intent. Gas costs included in native token budget.
- **Approval guard** — Detects bursts of rejected/pending outcomes and pauses all new sign requests with alert (configurable window and threshold).

### Sandboxing

**JavaScript rules** (Sobek runtime):
- 20ms execution timeout, 32MB memory limit
- 13+ blocked global APIs (eval, Function, fetch, setTimeout, Reflect, Proxy, etc.)
- Only `input` (parsed request), `config` (variables), and helpers exposed

**Solidity rules** (Foundry):
- Static analysis blocks 24 dangerous patterns pre-execution (vm.ffi, vm.readFile, vm.envOr, etc.)
- Runtime: `FOUNDRY_FFI=false`, `FOUNDRY_FS_PERMISSIONS=[]`, 30s timeout
- Temporary file cleanup after execution

---

## Key Management

### Signer Private Keys

| Method | Security Level | Production Ready |
|--------|---------------|-----------------|
| Encrypted keystore (JSON) | Password-protected at rest, decrypted in memory for signing, password zeroized after use | Yes |
| HD Wallet (BIP-39) | Encrypted mnemonic on disk, derived addresses via BIP-44, lockable | Yes |
| Plaintext key (config/env) | Not encrypted | No (test only) |
| HSM | Keys never leave hardware device | Planned |

### API Keys

API keys use Ed25519 key pairs:
- Server stores only the **public key** — the private key is client-side only
- Keys are synced from config or created via API (admin-only)
- Keys can be disabled (without deletion) — disabled keys are rejected with a security alert
- Key rotation is supported via create/delete

### Memory Hardening

- `mlockall` prevents private keys from being swapped to disk
- `PR_SET_DUMPABLE=0` prevents core dumps (which could contain key material)
- Keystore passwords are zeroized via `keystore.SecureZeroize()` after use
- Container: `mem_swappiness: 0` prevents swap

---

## Recommended Production Baseline

```
Transport:        TLS enabled; mTLS preferred
Replay:           nonce_required: true, max_request_age: 30-60s
Rate limiting:    ip_rate_limit: enabled (default 200/min)
                  per-key rate_limit: configured as needed
API lockdown:     rules_api_readonly: true (default)
                  signers_api_readonly: based on deployment
Access control:   ip_whitelist for admin deployments
Budget:           mandatory on whitelist rules in production
Alerts:           approval_guard enabled
                  real-time alerts configured (Telegram/Slack/Pushover/Webhook)
Container:        read_only, seccomp, no-new-privileges, cap_drop ALL
```

---

## Breach Impact Analysis

The system assumes every defense layer can be independently compromised. The key insight:

| Compromised Layer | Blast Radius | Remaining Defenses |
|-------------------|-------------|-------------------|
| Transport (TLS) | Low | Ed25519 auth + nonce + IP whitelist survive |
| IP whitelist | Low | Still need valid API key + rules |
| API key (non-admin) | Medium | Rules + budgets + approval guard constrain |
| Admin key | High | `rules_api_readonly` blocks API rule mutation; audit logs everything |
| JS/Solidity sandbox | Critical (RCE) | Container hardening (seccomp, read-only fs, no-new-privileges) |
| Signer key extracted | Critical | On-chain controls only (multisig, timelocks) |

Container escape is the highest-severity scenario: full host compromise gives access to all keystore files, DB credentials, and environment variables. The roadmap priorities address this through signing process isolation and HSM integration.

See the full zero-trust breach cascade analysis in [ARCHITECTURE.md](ARCHITECTURE.md#security-boundary). For detailed breach scenarios (L1-L15), refer to the archived version of `docs/security.md`.
