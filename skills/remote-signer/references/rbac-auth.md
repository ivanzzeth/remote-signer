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

This table is the **single source of truth** for what each role can do. Consult it before attempting any operation.

| Capability | `role: admin` | `role: dev` | `role: agent` | `role: strategy` |
|------------|:---:|:---:|:---:|:---:|
| Submit sign requests | Yes | Yes | Yes | Yes |
| View own request status | Yes | Yes | Yes | Yes |
| View all request status | Yes | No | No | No |
| Approve/reject requests (signer owner) | Yes | No | No | No |
| Manage rules (CRUD) | Yes | No | No | No |
| Read rules/budgets | Yes | No | Yes | No |
| Create signers (keystore/HD) | Yes | No | No | No |
| Manage API keys | Yes | No | No | No |
| View audit logs | Yes | No | No | No |
| Manage templates | Yes | No | No | No |

### Critical RBAC rules for AI agents:

- **`agent` role**: Can only SUBMIT sign requests and VIEW own request status. Cannot approve, cannot list all requests, cannot manage rules. If a request enters `authorizing` status, the agent MUST tell the user to approve it with admin credentials — the agent cannot do it itself.
- **`admin` role**: Full access. Use admin keystore (`~/.remote-signer/apikeys/admin.keystore.json`) for approve/reject/rule management operations.
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
