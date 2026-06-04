# Authentication & RBAC

## Ed25519 Request Signing

Every API request (except `/health` and `/metrics`) must be signed:

```
Signature payload: {timestamp}|{nonce}|{method}|{path}|{sha256(body)}
Signed with: API key's Ed25519 private key
Headers:
  X-API-Key-ID: <key-id>
  X-Timestamp: <unix-ms>
  X-Nonce: <random>
  X-Signature: <base64-signature>
```

- **Replay protection**: max request age (default 60s) + per-key nonce uniqueness
- **Rate limiting**: IP-level (pre-auth, 200 req/min) + per-key (configurable)

## RBAC Roles

**This table is the single source of truth.** Consult it before attempting any operation.

| Capability | `admin` | `dev` | `agent` | `strategy` |
|------------|:---:|:---:|:---:|:---:|
| Submit sign requests | Yes | Yes | Yes | Yes |
| View own request status + payload | Yes | Yes | Yes | Yes |
| View own request simulation | Yes | Yes | Yes | Yes |
| Preview rule for a request | Yes | Yes | Yes | Yes |
| Read rules | Yes | No | Yes | No |
| Read budgets | Yes | No | Yes | No |
| Create rules | Yes | No | Yes | No |
| Update own rules | Yes | No | Yes | No |
| List signers (scoped to key) | Yes | Yes | Yes | Yes |
| View all request status | Yes | No | No | No |
| Approve/reject requests | Yes | No | No | No |
| Create signers (keystore/HD) | Yes | No | No | No |
| Manage API keys | Yes | No | No | No |
| View audit logs | Yes | No | No | No |
| Manage templates | Yes | No | No | No |

### Critical RBAC rules for AI agents:

- **`agent` role**: Can submit sign requests, inspect stuck requests (get payload, check simulation), read rules/budgets, create and update whitelist rules. **Cannot approve requests, manage API keys, or create signers.** When a request enters `authorizing`, the agent should self-service by updating whitelist rules (see remote-signer SKILL.md "Unified Signing Workflow"). If unsafe or rule update requires approval (`require_approval`), the agent tells the user to approve with admin credentials.
- **`admin` role**: Full access. Use admin keystore (`~/.remote-signer/apikeys/admin.keystore.json`) for approve/reject/rule-approve operations.
- **Signer ownership**: Only the API key that created a signer (or someone granted access) can approve/reject requests for that signer.

## Scoping Fields

API keys can be further restricted:

| Field | Effect |
|-------|--------|
| `allowed_signers: []` | Can use all signers |
| `allowed_signers: [addr]` | Only listed signers |
| `allowed_hd_wallets: []` | `dev`: no HD wallet access. `admin`: all |
| `allowed_hd_wallets: [addr]` | Only listed HD wallets |
| `allowed_chain_types: []` | All chain types |
| `allowed_chain_types: ["evm"]` | EVM only |
| Per-key `rate_limit` | Override default rate limit |

## Signer Ownership Model

- The API key that **creates** a signer becomes its **owner**
- Only the owner can approve/reject pending requests for that signer
- The owner can grant/revoke access to other API keys
- The owner can transfer ownership to another API key (clears access list)

```bash
# Grant access
./remote-signer evm signer grant-access 0xSignerAddr --api-key-id agent-key

# Revoke access
./remote-signer evm signer revoke-access 0xSignerAddr agent-key

# Transfer ownership
./remote-signer evm signer transfer-ownership 0xSignerAddr --new-owner-id new-admin
```
