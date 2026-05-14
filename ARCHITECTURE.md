# Remote Signer Architecture

## Overview

Remote Signer is a policy-controlled signing service. It enforces **what** gets signed through a configurable rule engine, not just **who** can sign. The architecture separates key custody from signing authority — signer private keys are held by the service, but every signing operation is gated by a chain of policy checks.

---

## Core Concepts

### Signer

A **Signer** is a cryptographic identity that can produce signatures. It represents a private key under the service's custody. Multiple signer types exist:

- **Keystore signer** — An encrypted private key file (e.g. Ethereum JSON keystore) stored on disk. Decrypted at runtime with a password for signing.
- **HD Wallet** — A BIP-39 mnemonic from which many addresses are derived deterministically (BIP-44 path). Each derived address is a distinct signer.
- **Plaintext key** — A directly configured private key. Only intended for local or test environments.

Signers belong to a **chain type** (e.g. EVM). Each signer has an **owner** — the API key that created it — which controls who can use it and who can approve pending requests.

### Wallet

A **Wallet** is an organizational concept that groups signers and provides higher-level operations. Wallets abstract away individual signer addresses:

- Wallets unify multiple signer types (keystore, HD wallet derived addresses) under a single interface.
- A wallet knows its signers and can sign on their behalf.
- Wallets support locking/unlocking, resource limits, and ownership transfer.

The Wallet domain is the boundary for multi-tenant isolation: different tenants (API keys) own different wallets, and a wallet's signers cannot be used by another tenant's API key.

### API Key

An **API Key** is the authentication credential for programmatic access. Every request to the signing API must be signed with an API key's Ed25519 private key.

API keys carry **authorization scope**:
- **Admin keys** — Full access: create/modify rules, manage signers, approve requests, manage API keys.
- **Agent keys** — Can sign and read rules/budgets, but cannot modify policies.
- **Non-admin keys** — Submit sign requests and view status only.

Scoping fields further limit a key's reach: `allowed_signers`, `allowed_hd_wallets`, `allowed_chain_types`, per-key rate limits.

### Rule

A **Rule** is a policy statement that constrains signing behavior. Rules are the core of the policy engine and operate in a two-tier model:

- **Blocklist rules** — Evaluated first. If a request matches a blocklist rule, it is **rejected immediately** (fail-closed). Any evaluation error also causes rejection.
- **Whitelist rules** — Evaluated second. If a request matches a whitelist rule, it is **auto-approved** (fail-open). Evaluation errors skip the rule.

If no whitelist rule matches and no blocklist rule triggers, the request enters **manual approval** — a human (the signer owner) must explicitly approve or reject it.

Rules can be parameterized (via Templates) or written inline. Rule types include address lists, value limits, contract method restrictions, Solidity expressions, JavaScript sandbox rules, and message pattern matching.

Rules support **delegation**: a whitelist rule can delegate inner call validation to other rules, forming recursive validation chains (e.g. a Safe transaction delegates to MultiSend, which delegates each inner transfer to an ERC20 rule). Delegation has depth limits and cycle detection.

### Template

A **Template** is a parameterized rule definition stored as a YAML file. Templates declare typed variables with descriptions and default values, and define rules using `${variable}` placeholders.

Templates are not evaluated directly — they are expanded into concrete rules when an **instance** supplies variable values. This enables reusable, auditable rule patterns: a single template (e.g. "ERC20 transfer validation") can produce rules for different tokens, chains, and parameters without duplicating logic.

Templates can include test cases that validate behavior during development.

### Preset

A **Preset** is a convenience layer: a pre-filled instance (or set of instances) stored as a YAML file. Presets bundle template references with default variable values so that common rule configurations (e.g. "Polymarket on Polygon", "USDC across all chains") can be deployed with minimal variable overrides.

Presets support single-rule and multi-rule formats, including **matrix presets** that create one rule per chain with chain-specific addresses. They are used by the CLI for interactive setup and by the API for programmatic deployment.

### Budget

A **Budget** enforces spending limits on signing operations. Budgets are tied to rules (via template instances) and define:

- **What is measured** — Transaction value, token amount, tx count, or custom units.
- **How much is allowed** — `max_total` (per period), `max_per_tx` caps.
- **When it resets** — Configurable period (e.g. 24h, 7d) with automatic renewal.
- **Alert threshold** — Notification when usage reaches a configurable percentage of the budget.

Budgets can be **static** (declared limits) or **dynamic** (auto-tracked from transaction simulation outcomes). Dynamic budgets inspect actual balance changes from `eth_simulateV1` rather than relying on the caller's declared intent. Gas costs are included in native token budgets.

Budget enforcement happens after a whitelist rule matches but before final approval. If the budget is exceeded, that rule is skipped (other rules may still match).

### Audit

**Audit** is the complete, immutable record of every operation in the service. Every API request, state transition, rule match, approval, rejection, and error is logged with metadata including:

- Event type, severity, and timestamp
- Actor identity (API key ID, client IP)
- Request and rule identifiers
- Detailed context (status codes, durations, error messages)

The audit trail enables full attack timeline reconstruction, compliance verification, and operational debugging. An anomaly monitor scans audit records in the background for suspicious patterns (auth failure bursts, rejection spikes, high-frequency requests).

---

## Relationships

```
Template ──parameterizes──► Instance ──produces──► Rule
                                                      │
Preset ──bundles──► Template + variables ──────► Instance
                                                      │
API Key ──authenticates──► Request
                             │
Request ──evaluated by──► Rule Engine (blocklist → whitelist → manual)
                             │
                  ┌──────────┴──────────┐
                  ▼                     ▼
              Budget check          Manual approval
                  │                     │
                  ▼                     ▼
              Signer ──produces──► Signature ──logged to──► Audit
```

## Data Flow

```
Client → API Key (Ed25519 sign) → Middleware Pipeline → Handler → SignService
                                                                        │
                                          ChainAdapter ◄── SignService ─┤
                                                                        │
                                          Rule Engine ◄── SignService ─┤
                                                                        │
                                          Budget Check ◄── SignService ─┤
                                                                        │
                                          Signer ──signs──► Signature ──┤
                                                                        │
                                          Audit Log ◄───── Every step ──┘
```

1. **Authentication** — The client signs the request with its Ed25519 API key. The server verifies the signature, checks nonce uniqueness (replay protection), and validates the timestamp window.
2. **Authorization** — The server checks whether the API key has permission to use the specified chain type and signer address.
3. **Rule evaluation** — The two-tier rule engine evaluates the request against blocklist rules first, then whitelist rules.
4. **Budget enforcement** — If a whitelist rule matched, its budget is checked before approval.
5. **Manual approval** — If no rule matched and manual approval is enabled, the request enters a pending state awaiting the signer owner's decision.
6. **Signing** — The chain adapter performs the cryptographic signing operation.
7. **Audit logging** — Every step produces audit records for the complete trail.

## Security Boundary

The security model follows defense-in-depth across these layers:

| Layer | Controls |
|-------|----------|
| Transport | TLS / mTLS |
| Network | IP whitelist (CIDR, proxy trust) |
| API | Ed25519 auth, nonce replay protection, rate limiting (IP + per-key) |
| Authorization | Admin/agent/non-admin roles, per-key scoping |
| Policy | Two-tier rule engine (blocklist → whitelist), delegation depth limits |
| Budget | Per-rule spending limits, dynamic budget from simulation |
| Sandbox | JS rules (20ms timeout, 32MB memory, blocked globals), Solidity rules (disabled cheatcodes) |
| Alerting | Real-time security alerts (10 alert types, rate-limited) |
| Audit | Complete request audit, anomaly monitor |
| Container | Read-only filesystem, seccomp, no-new-privileges, cap_drop ALL |

See [SECURITY.md](SECURITY.md) for the full security model including breach impact analysis.
