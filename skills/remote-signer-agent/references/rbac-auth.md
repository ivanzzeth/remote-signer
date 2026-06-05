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
| Create signers (keystore) | Yes | Yes | Yes | No |
| View all request status | Yes | No | No | No |
| Approve/reject sign requests | Yes | No | No | No |
| Approve pending signers | Yes | No | No | No |
| Manage API keys | Yes | No | No | No |
| View audit logs | Yes | No | No | No |
| Manage templates | Yes | No | No | No |

### Critical RBAC rules for AI agents:

- **`agent` role**: Can submit sign requests, create signers (**`pending_approval` until admin approves the signer**), inspect stuck requests, read rules/budgets, create/update whitelist rules. **Cannot approve sign requests or signers, or manage API keys.** When a request enters `authorizing`, self-service via whitelist rules first; if unsafe, tell the user to approve with admin credentials.
- **`admin` role**: Full access. Use admin keystore (`~/.remote-signer/apikeys/admin.keystore.json`) for approve/reject/rule-approve operations.
- **Signer ownership**: The API key that **creates** a signer is its **owner**. For **sign request** approve/reject and preview-rule during manual approval, **`admin` may act on any request** (typical when `agent` owns the signer). Non-admin roles may preview only requests they submitted.

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
- Only the owner can approve/reject pending requests for that signer **unless the caller is admin** (manual approval queue in the Web UI)
- The owner can grant/revoke access to other API keys
- The owner can transfer ownership to another API key (clears access list)

```bash
# Grant access (owner only)
./remote-signer evm signer access grant 0xSignerAddr --to agent-key-id \
  --url http://127.0.0.1:8548 --api-key-id owner --api-key-file ~/.remote-signer/apikeys/agent.key.priv

# Revoke access
./remote-signer evm signer access revoke 0xSignerAddr agent-key-id

# Approve a pending signer (admin only; required before non-admin-owned signers can sign)
./remote-signer evm signer approve 0xSignerAddr \
  --url http://127.0.0.1:8548 --api-key-id admin \
  --api-key-keystore ~/.remote-signer/apikeys/admin.keystore.json

# Transfer ownership
./remote-signer evm signer transfer 0xSignerAddr --to new-owner-id
```
