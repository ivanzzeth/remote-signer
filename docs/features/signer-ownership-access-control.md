# Signer Ownership & Access Control

## Status: Design

## Problem

Signer access is configured on the **API key** side (`AllowAllSigners`, `AllowedSigners`), not on the **signer** side:

1. Admin keys with `AllowAllSigners=true` can use **any** signer — a single leaked key compromises all funds
2. Permissions are static config, not dynamic API-managed
3. Signers have no owner — anyone with config access can grant themselves signer permissions

## Solution

Signer-centric ownership model:

- Each signer has an **owner** (API key ID) and an **access list** (granted API key IDs)
- Only owner + access list members can use the signer for signing
- Admin has no special override — must be owner or granted like everyone else
- Owner manages access exclusively via API

## Implementation Phases

```
Phase 1 (ownership) ──→ Phase 2 (access list) ──→ Phase 3 (lifecycle safety)

Phase 4a (API key keystore) ── independent
Phase 4b (internal transfer rule) ── depends on Phase 1 only
```

**Recommendation**: Ship Phase 1 + 2 together (ownership without sharing is too restrictive).

---

## Phase 1: Signer Ownership

### Data Model Changes

**Add to `signers` table:**

```sql
ALTER TABLE signers ADD COLUMN owner_id TEXT NOT NULL DEFAULT 'admin';
```

**Remove from `api_keys` table:**

```
AllowAllSigners, AllowedSigners, AllowAllHDWallets, AllowedHDWallets, AllowedChainTypes
```

### Discovery (startup)

```
For each discovered signer in keystore directory:
  DB has record → keep existing owner_id
  DB no record  → INSERT with owner_id = first admin key (ORDER BY created_at ASC)
  DB record but owner key deleted → reassign to first admin, log warning

"First admin" is deterministic: SELECT id FROM api_keys WHERE role='admin' AND enabled=true ORDER BY created_at ASC LIMIT 1
```

### Access Check (Phase 1 only: owner-only)

```
CheckSignerAccess(caller, signer_address):
  signer.owner_id == caller → ALLOW
  else → DENY (403)
```

### API Changes

| Endpoint | Change |
|----------|--------|
| `POST /api/v1/evm/signers` | Set `owner_id = caller`; admin → active, non-admin → pending_approval |
| `GET /api/v1/evm/signers` | Filter: `owner_id = caller` only |
| `POST /signers/{addr}/unlock` | Owner only (was: admin only) |
| `POST /signers/{addr}/lock` | Owner only |
| `POST /signers/{addr}/approve` | NEW: admin only, sets pending → active |
| `POST /api/v1/evm/sign` | Replace `CheckSignerPermissionWithHDWallets` → owner check |
| `POST /api/v1/api-keys` | Remove `allow_all_signers`, `allowed_signers`, etc. from request body |

### CLI/TUI Changes

```bash
# CLI: signer list shows owner column
remote-signer-cli evm signer list
# ADDRESS              TYPE       OWNER    STATUS
# 0x53c68c95...        keystore   admin    unlocked

# CLI: approve pending signer (admin)
remote-signer-cli evm signer approve <address>
```

TUI: Signer list adds Owner column. Non-owner cannot unlock/lock.

### Security Notes

- **Atomic migration**: Remove old fields + add owner_id + discovery must be in same release. Otherwise all sign requests fail between deploys.
- **Breaking change**: Existing agent configs with `AllowAllSigners=true` will lose signer access. Document in release notes.

### Files

| File | Change |
|------|--------|
| `internal/core/types/signer.go` | Add `OwnerID string` to Signer struct |
| `internal/core/types/auth.go` | Remove AllowAllSigners/AllowedSigners/AllowAllHDWallets/AllowedHDWallets/AllowedChainTypes |
| `internal/storage/gorm_signer_repo.go` | owner_id migration; filtered list |
| `internal/config/signer_init.go` | Discovery: orphan detection + owner assignment |
| `internal/config/apikey_init.go` | Remove AllowedSigners from config loading |
| `internal/config/config.go` | Remove signer permission fields from APIKeyConfig |
| `internal/api/handler/evm/signer.go` | Owner-only unlock/lock; approve endpoint; filtered list |
| `internal/api/handler/evm/sign.go` | Replace CheckSignerPermissionWithHDWallets → owner check |
| `internal/api/middleware/ratelimit.go` | Remove CheckSignerPermissionWithHDWallets |
| `internal/api/router.go` | Register approve endpoint |
| `pkg/client/evm/signer_types.go` | Remove AllowAll fields; add OwnerID |
| `cmd/remote-signer-cli/signer.go` | Owner column in list; approve command |
| `tui/views/signers.go` | Owner column |
| `config.example.yaml` | Remove signer permission fields from api_keys |
| `e2e/test_server.go` | Remove AllowAllSigners, use explicit ownership |

### Unit Tests

| Test | Expected |
|------|----------|
| SignCheck_OwnerAllowed | owner signs → allow |
| SignCheck_NonOwnerDenied | non-owner signs → 403 |
| SignerList_OnlyOwned | caller sees only own signers |
| Unlock_OwnerOnly | non-owner unlock → 403 |
| Create_AdminActive | admin creates → status=active |
| Create_NonAdminPending | agent creates → status=pending_approval |
| Approve_AdminOnly | agent approves → 403 |
| Discovery_NewSigner | no DB record → owner=first admin |
| Discovery_OrphanReassign | owner key deleted → reassign to admin |

### E2E Tests

| Test | Verification |
|------|-------------|
| OwnerCanSign | admin creates signer → admin signs → OK |
| NonOwnerBlocked | admin signer → agent signs → 403 |
| PendingSigner | agent creates → pending → sign 403 → admin approve → agent sign OK |
| SignerListScoped | admin + agent signers → each only sees own |

---

## Phase 2: Access List

### Data Model

```sql
CREATE TABLE signer_access (
    id              TEXT PRIMARY KEY,
    signer_address  TEXT NOT NULL,
    api_key_id      TEXT NOT NULL,
    granted_by      TEXT NOT NULL,
    created_at      TIMESTAMP NOT NULL,
    UNIQUE(signer_address, api_key_id)
);
CREATE INDEX idx_signer_access_signer ON signer_access(signer_address);
CREATE INDEX idx_signer_access_key ON signer_access(api_key_id);
```

### Access Check (extends Phase 1)

```
CheckSignerAccess(caller, signer_address):
  1. signer.owner_id == caller → ALLOW
  2. signer_access(signer_address, caller) exists → ALLOW
  3. If signer_address is HD wallet derived:
     a. parent = HDWalletManager.FindParent(signer_address)
     b. Repeat 1-2 with parent address
  4. → DENY (403)
```

### HD Wallet Inheritance

Access granted at **primary address level** covers all derived addresses:

```
Grant access to primary 0xABC → derived 0xABC/0, 0xABC/1, ... all accessible
Revoke access to 0xABC → all derived addresses lose access
```

`signer_access` table only stores primary addresses. Grant response includes warning for HD wallets: "access includes all current and future derived addresses."

### API Endpoints

```
POST   /api/v1/evm/signers/{address}/access        owner only
       Body: {"api_key_id": "agent-2"}
       Response: 201

DELETE /api/v1/evm/signers/{address}/access/{keyID} owner only
       Response: 204

GET    /api/v1/evm/signers/{address}/access         owner only
       Response: 200 [{api_key_id, granted_by, created_at}]
```

Signer list extends to: `owner_id = caller OR signer_access.api_key_id = caller`

### CLI/TUI Changes

```bash
remote-signer-cli evm signer access grant <address> --to <api-key-id>
remote-signer-cli evm signer access revoke <address> --from <api-key-id>
remote-signer-cli evm signer access list <address>
```

TUI: Signer detail view shows access list. Owner sees [g]rant / [r]evoke hotkeys. Non-owner sees read-only access list (if granted) or nothing.

### Security Notes

- Owner granting self is harmless (owner already has access via owner_id check) but wastes a DB row. Handler may reject with 400 "owner already has access."
- IDOR prevention: handler MUST verify `signer.owner_id == caller` before any grant/revoke/list-access operation.

### Files

| File | Change |
|------|--------|
| `internal/storage/signer_access_repo.go` | NEW: repository interface + GORM impl |
| `internal/core/service/signer_access.go` | NEW: HasAccess/Grant/Revoke |
| `internal/api/handler/evm/signer.go` | Grant/revoke/list-access endpoints |
| `internal/api/handler/evm/sign.go` | Extend access check: owner OR granted |
| `internal/api/router.go` | Register access endpoints |
| `pkg/client/evm/signers.go` | GrantAccess/RevokeAccess/ListAccess |
| `pkg/client/evm/signer_types.go` | SignerAccess type |
| `cmd/remote-signer-cli/signer.go` | `access grant/revoke/list` subcommands |
| `tui/views/signer_detail.go` | Access list display + grant/revoke UI |
| `e2e/e2e_signer_access_test.go` | NEW |

### Unit Tests

| Test | Expected |
|------|----------|
| HasAccess_GrantedAllowed | caller in access_list → allow |
| HasAccess_NeitherDenied | not owner, not granted → deny |
| HasAccess_HDWalletDerived | derived → parent granted → allow |
| HasAccess_PendingSigner | pending signer → deny regardless |
| Grant_OwnerSuccess | owner grants → 201 |
| Grant_NonOwnerForbidden | non-owner → 403 |
| Grant_NonExistentKey | grantee not found → 400 |
| Grant_Duplicate | idempotent 200 or 409 |
| Revoke_OwnerSuccess | owner revokes → 204 |
| Revoke_NonOwnerForbidden | non-owner → 403 |

### E2E Tests

| Test | Verification |
|------|-------------|
| AccessGrantFlow | admin signer → grant agent → agent signs OK |
| AccessDenyFlow | admin signer → agent signs without grant → 403 |
| RevokeFlow | grant → sign OK → revoke → sign 403 |
| HDWalletAccess | grant HD wallet → sign with derived → OK |
| HDWalletRevoke | revoke HD wallet → sign with derived → 403 |

---

## Phase 3: Lifecycle Safety

### Transfer Ownership

```
POST /api/v1/evm/signers/{address}/transfer
     Body: {"new_owner_id": "agent-2"}
     Auth: owner only
     Side effects: clear entire access_list; old owner loses ALL access
```

### Delete Signer

```
DELETE /api/v1/evm/signers/{address}
     Auth: owner only
     Cascade: delete all signer_access records for this address
```

### API Key Delete (enhanced)

```
DELETE /api/v1/api-keys/{id}
  Precondition: key owns 0 signers (else 400 "delete or transfer signers first")
  Cascade:
    1. DELETE rules WHERE owner = key
    2. Remove key from all rules' applied_to (delete rule if applied_to becomes empty)
    3. DELETE signer_access WHERE api_key_id = key
  Admin self-protection:
    - Cannot delete self
    - Cannot change own role
    - Last admin cannot be deleted
```

### Signer Approval Gate

Non-admin created signers start as `pending_approval`. Cannot unlock, sign, or appear in internal transfer rule matching.

### Resource Limits

```yaml
security:
  max_keystores_per_key: 5
  max_hd_wallets_per_key: 3
```

### CLI/TUI Changes

```bash
remote-signer-cli evm signer transfer <address> --to <api-key-id>
remote-signer-cli evm signer delete <address>
```

TUI: Signer detail adds [t]ransfer / [d]elete. API key management tab shows cascade warnings on delete.

### Security Notes

- **Transfer + access race**: Transfer clears access atomically in a DB transaction. No window where old grantees retain access.
- **Delete signer but keystore file remains**: Re-discovery on restart inserts new record with owner=admin. If this is undesirable, operator must delete the keystore file.
- **API key delete cascade concurrency**: Entire cascade runs in one DB transaction. Sign requests using stale data during tx will fail after commit.

### Files

| File | Change |
|------|--------|
| `internal/core/service/signer_access.go` | Transfer/CleanupForDeletedKey |
| `internal/api/handler/evm/signer.go` | Transfer/delete endpoints; approve endpoint |
| `internal/api/handler/apikey.go` | Delete precondition + cascade + self-protection |
| `internal/config/config.go` | max_keystores_per_key, max_hd_wallets_per_key |
| `cmd/remote-signer-cli/signer.go` | transfer/delete subcommands |
| `tui/views/signer_detail.go` | Transfer/delete UI |

### Unit Tests

| Test | Expected |
|------|----------|
| Transfer_ClearsAccess | access list empty after transfer |
| Transfer_NonOwner | 403 |
| Transfer_ToSelf | 400 |
| DeleteSigner_CascadeAccess | signer_access records deleted |
| DeleteKey_BlockedBySigners | 400 |
| DeleteKey_CascadeRules | rules + applied_to cleaned |
| DeleteKey_AdminSelfBlock | 400 |
| DeleteKey_LastAdminBlock | 400 |
| ResourceLimit_Exceeded | agent over limit → 403 |

### E2E Tests

| Test | Verification |
|------|-------------|
| TransferFlow | transfer → old owner 403 → new owner OK |
| TransferClearsAccess | grant dev → transfer → dev 403 |
| DeleteKeyBlocked | owns signers → 400 |
| DeleteKeyCascade | rules + access cleaned |
| APIKeyLastAdmin | 400 |
| ResourceLimit | max keystores → next 403 |

---

## Phase 4a: API Key Encrypted Keystore

Independent of Phases 1-3.

### Design

API key private keys stored in encrypted keystore files (using `ethsig/cmd/keystore`, Ed25519 support). Same UX as EVM signer keystores — password-protected, private key never on disk in plaintext.

```bash
# Generate encrypted API key keystore
ethsig keystore create --algo ed25519 --out data/apikeys/agent-2.json
# Interactive: enter password

# Extract public key (no password needed)
ethsig keystore pubkey data/apikeys/agent-2.json

# Use with CLI
remote-signer-cli evm signer list \
  --api-key-id agent-2 --api-key-keystore data/apikeys/agent-2.json
# Interactive: "Enter API key password: ****"
```

### CLI/TUI Auth Flags

| Flag | Description |
|------|-------------|
| `--api-key-file` | Raw PEM (dev/CI, existing) |
| `--api-key-keystore` | Encrypted keystore (production, new) |
| `--api-key-password-env` | Env var with password (CI, non-interactive) |

### Security Notes

- `--api-key-password-env`: process env vars readable via `/proc/pid/environ`. Production should use interactive input, not env var.

### Files

| File | Change |
|------|--------|
| `cmd/remote-signer-cli/client.go` | Keystore loading + password prompt |
| `cmd/tui/main.go` | Keystore loading + password prompt |
| `scripts/setup.sh` | Generate encrypted keystores |

---

## Phase 4b: Internal Transfer Rule (same_owner scope)

Depends on Phase 1 (owner_id).

### Design

New rule evaluator for internal transfers between signers owned by the same API key:

```
Evaluation:
  1. Extract recipient from tx calldata
  2. Look up recipient in signers table
  3. recipient not a signer → neutral (rule does not match)
  4. recipient.owner_id != sender.owner_id → neutral (different trust domain)
  5. recipient.owner_id == sender.owner_id → match (same trust domain)
```

This enables multi-tenant custodial signing where each tenant's signers are isolated.

### Security Notes

- **Critical invariant**: Internal transfer rules MUST NOT match across ownership boundaries. This is the defense against signer self-registration attacks (see threat analysis below).

### Threat Analysis: Self-Registration Attack

Attacker (agent key) creates signer → pending_approval → not in active pool → internal transfer cannot target it. Even if admin approves, `same_owner` scope blocks cross-owner transfers. Two-layer defense.

### Files

| File | Change |
|------|--------|
| `internal/chain/evm/` | New `InternalTransferEvaluator` |
| `internal/storage/gorm_signer_repo.go` | `GetByAddress` for recipient lookup |

### Unit Tests

| Test | Expected |
|------|----------|
| SameOwner | rule matches |
| DifferentOwner | rule does not match |
| PendingRecipient | rule does not match |
| NonSignerRecipient | rule does not match |

---

## API Key Management

API key create/update/delete is admin-only. Server never sees private keys.

### Create

Client generates Ed25519 keypair locally, registers public key:

```
POST /api/v1/api-keys
  Body: {id, name, role, public_key, rate_limit}
  Response: 201 (metadata only, no private key)
  New key has ZERO permissions: no signer access, no rules
```

Two key storage options:
- **Raw PEM**: `openssl genpkey -algorithm ED25519` (dev/CI)
- **Encrypted keystore**: `ethsig keystore create --algo ed25519` (production, Phase 4a)

### Update

```
PATCH /api/v1/api-keys/{id}
  Body: {name?, role?, rate_limit?, enabled?}
  Constraints: cannot change own role; disable preserves ownership
```

### Delete

```
DELETE /api/v1/api-keys/{id}
  Precondition: 0 owned signers
  Cascade: owned rules + applied_to refs + signer_access entries
  Self-protection: cannot delete self; last admin blocked
```

---

## Security Invariants

1. **No signer without owner**: `owner_id NOT NULL` at DB level
2. **No implicit access**: Zero-permission start for new keys. Access always explicit.
3. **Owner-only management**: Unlock/lock/grant/revoke/transfer/delete — owner only, no admin override
4. **No delete with owned signers**: API key deletion blocked if signers remain
5. **Transfer clears access**: New owner starts with empty access list
6. **HD wallet inheritance**: Derived address access resolved through parent wallet
7. **Orphan recovery**: Signers with deleted owner auto-reassigned to admin on startup
8. **Resource limits**: Configurable max keystores/HD wallets per key
9. **Full audit trail**: Every operation logged with caller identity + signer address
10. **Signer approval gate**: Non-admin created signers require admin approval
11. **Same-owner transfer boundary**: Internal transfer rules scoped to same owner only

## Blast Radius Analysis

What happens when each component is compromised. This section is designed to be directly usable in security documentation and incident response runbooks.

### Scenario 1: Admin API Key Leaked

| Attacker Action | Result | Blast Radius |
|----------------|--------|-------------|
| Sign with admin's own signers | Succeeds | **Admin's funds only** |
| Sign with agent's signers | 403 — not owner, not in access list | None |
| Unlock agent's signers | 403 — owner only | None |
| Grant self access to agent's signers | 403 — owner only | None |
| Transfer agent's signers to self | 403 — owner only | None |
| Create new signer | Succeeds, owner=admin | Admin's funds only (new empty address) |
| Create new API key | Succeeds, zero permissions | None (no signer access, no rules) |
| Delete agent's API key | Blocked (agent owns signers) | None |
| Delete agent's rules | Blocked (rules owned by agent, not admin) | None |
| Modify agent's rules | Blocked (owner-only modify) | None |
| Read audit logs | Succeeds (admin permission) | Information disclosure only |

**Containment**: Revoke admin key, create new admin key, transfer admin-owned signers to new key. Agent/dev/strategy operations unaffected throughout.

### Scenario 2: Agent API Key Leaked

| Attacker Action | Result | Blast Radius |
|----------------|--------|-------------|
| Sign with agent's own signers | Succeeds (if unlocked) | **Agent's funds only** |
| Sign with admin's signers | 403 — not owner, not in access list | None |
| Sign with other agents' signers | 403 — isolated | None |
| Unlock agent's locked signers | Succeeds (owner) | Agent's signers exposed |
| Create signers | Pending approval — cannot use until admin approves | None |
| Create rules (self-scoped) | Succeeds, applied_to=["self"] | Agent's own scope only |
| Grant access to agent's signers | Succeeds (owner) | Agent decides who uses their signers |
| Access admin endpoints | 403 — role-based | None |

**Containment**: Disable agent key, lock all agent-owned signers. Other keys unaffected.

### Scenario 3: Database Compromised (read access)

| Exposed Data | Sensitivity | Mitigation |
|-------------|-------------|-----------|
| API key public keys | Low — public by design | None needed |
| API key private keys | **Not stored** — never reaches server | N/A |
| Signer keystore passwords | **Not stored** — entered interactively | N/A |
| Signer keystore files | Encrypted (scrypt/argon2) | Brute-force resistant |
| signer_access table | Medium — shows who has access to what | Useful for attacker recon but not directly exploitable |
| Rules + config | Low — policy data | No secrets |
| Audit logs | Medium — operation history | Information disclosure |

**Key point**: Even with full DB read access, attacker cannot sign transactions. They need: (1) an API key private key (not in DB) AND (2) the signer keystore to be unlocked (password not in DB).

### Scenario 4: Server Process Compromised (full memory access)

| Exposed Data | Impact |
|-------------|--------|
| Unlocked signer private keys (in memory) | **Critical** — can sign arbitrary transactions |
| API key auth tokens (in-flight) | Can impersonate any active session |
| DB connection | Full data access |

**Mitigation**: This is the worst-case scenario. Defenses:
- Memory protection: `mlockall` prevents swapping keys to disk (already implemented)
- Core dump disabled: `PR_SET_DUMPABLE=0` (already implemented)
- Auto-lock timeout: Signers auto-lock after configurable period (already implemented)
- Minimize unlocked signers: Only unlock when actively needed

**Blast radius**: All currently unlocked signers. Locked signers remain safe.

### Scenario 5: Keystore File Stolen (from disk)

| Condition | Impact |
|-----------|--------|
| Attacker has keystore file + password | Can reconstruct signer locally, steal funds via external tx |
| Attacker has keystore file, no password | Cannot decrypt — scrypt/argon2 brute-force resistant |
| Attacker has keystore file + API key | Still needs keystore password to unlock via API |

**Mitigation**: Encrypted filesystem, strict file permissions (0600), backup encryption.

### Scenario 6: Network MITM (TLS compromised)

| Exposed Data | Impact |
|-------------|--------|
| API key signatures (in-flight) | Replay attack possible within nonce window |
| Sign request/response | Can see signed transactions but cannot forge new ones |

**Mitigation**: mTLS (mutual TLS) with client certificates. Nonce-based replay protection with configurable window. Timestamp validation.

### Summary: Blast Radius Matrix

```
Component Compromised    → Funds at Risk
─────────────────────────────────────────
Admin API key            → Admin's signers only
Agent API key            → Agent's signers only
Strategy API key         → Zero (cannot sign)
Database (read)          → Zero (no keys stored)
Database (write)         → Can grant access, but still needs API key to sign
Server memory            → All UNLOCKED signers
Keystore file (no pass)  → Zero
Keystore file + password → That signer only
Network (no mTLS)        → Replay risk within nonce window
```

Each row is an **isolated failure domain**. No single compromise escalates to full system breach.

## Manual Verification (CLI)

Full walkthrough covering Phase 1-3:

```bash
AUTH_ADMIN="--api-key-id admin --api-key-file data/admin_private.pem ..."
AUTH_AGENT="--api-key-id agent --api-key-file data/agent_private.pem ..."

# --- API Key lifecycle ---
openssl genpkey -algorithm ED25519 -out /tmp/agent2.pem
PUB=$(openssl pkey -in /tmp/agent2.pem -pubout -text -noout | grep -A2 "pub:" | tail -2 | tr -d ' :\n')
remote-signer-cli apikey create --id agent-2 --name "Agent 2" --role agent --public-key $PUB $AUTH_ADMIN
# 201, zero permissions

# --- Phase 1: Ownership ---
remote-signer-cli evm signer create --password test123 $AUTH_ADMIN       # active, owner=admin
remote-signer-cli evm signer list $AUTH_ADMIN                            # sees signer
remote-signer-cli evm signer list $AUTH_AGENT                            # empty
remote-signer-cli evm sign personal "test" --signer <addr> $AUTH_AGENT   # 403

# --- Phase 2: Access ---
remote-signer-cli evm signer access grant <addr> --to agent $AUTH_ADMIN  # 201
remote-signer-cli evm sign personal "test" --signer <addr> $AUTH_AGENT   # OK
remote-signer-cli evm signer access revoke <addr> --from agent $AUTH_ADMIN
remote-signer-cli evm sign personal "test" --signer <addr> $AUTH_AGENT   # 403

# --- Phase 3: Transfer ---
remote-signer-cli evm signer transfer <addr> --to agent $AUTH_ADMIN
remote-signer-cli evm sign personal "test" --signer <addr> $AUTH_ADMIN   # 403 (not owner)
remote-signer-cli evm sign personal "test" --signer <addr> $AUTH_AGENT   # OK (now owner)
remote-signer-cli evm signer access list <addr> $AUTH_AGENT              # empty (cleared)

# --- Phase 3: Delete cascade ---
remote-signer-cli evm signer delete <addr> $AUTH_AGENT                   # owner deletes
remote-signer-cli apikey delete agent-2 $AUTH_ADMIN                      # cascade: rules + access
```

## Manual Verification (TUI)

```
1. Admin TUI → Signers: Owner column, only own signers visible
2. Signer detail: Owner, Status, Access List
3. [g]rant → enter key ID → access list updates
4. Agent TUI → Signers: only granted signers, grant/revoke disabled
5. Strategy TUI → Signers: empty
```
