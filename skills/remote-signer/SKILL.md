---
name: remote-signer
description: >
  Policy-driven EVM signing service. Use when the user mentions signing transactions,
  typed data, messages, or hashes through remote-signer. Covers pre-flight checks,
  signing flow, RBAC permissions, and troubleshooting auth/approval issues.
  For installation, CLI reference, TLS setup, or SDK integration, consult the
  corresponding reference file.
---

# Remote Signer

Policy-driven signing service for EVM chains. Controls **what** gets signed through a rule engine, not just **who** can sign.

## When to Activate

- User asks to sign anything (transaction, typed data, personal message, hash)
- Installing or configuring remote-signer → [references/installation.md](references/installation.md)
- Managing API keys or RBAC permissions → [references/rbac-auth.md](references/rbac-auth.md)
- Configuring TLS/mTLS or IP whitelist → [references/tls-security.md](references/tls-security.md)
- Integrating via MCP or SDKs → [references/sdk-integration.md](references/sdk-integration.md)
- CLI command reference → [references/cli-reference.md](references/cli-reference.md)

---

## RBAC Decision Table

**Stop and check this table before attempting any remote-signer operation.**

| Capability | `admin` | `dev` | `agent` | `strategy` |
|------------|:---:|:---:|:---:|:---:|
| Submit sign requests | Yes | Yes | Yes | Yes |
| View own request status | Yes | Yes | Yes | Yes |
| View all request status | Yes | No | No | No |
| Approve/reject requests | Yes | No | No | No |
| Manage rules (CRUD) | Yes | No | No | No |
| Read rules/budgets | Yes | No | Yes | No |
| Create signers | Yes | No | No | No |
| Manage API keys | Yes | No | No | No |

**`agent` role**: Can SUBMIT signing requests. Cannot list all requests, approve, or manage rules. When a request enters `authorizing`, tell the user — only `admin` can approve it.

---

## Pre-Flight Checklist

Run these checks **before** calling any signing tool.

### 1. Server is running

```bash
curl -fsS "http://127.0.0.1:8548/health" 2>/dev/null || \
  curl -fsS --cacert certs/ca.crt "https://127.0.0.1:8548/health" 2>/dev/null
```

If not running, start it: `./remote-signer &`

### 2. API key is configured

Check existence only — never print values:

```bash
test -n "$REMOTE_SIGNER_API_KEY_ID" || echo "REMOTE_SIGNER_API_KEY_ID missing"
test -n "$REMOTE_SIGNER_PRIVATE_KEY" -o -n "$REMOTE_SIGNER_PRIVATE_KEY_FILE" || \
  echo "Neither REMOTE_SIGNER_PRIVATE_KEY nor REMOTE_SIGNER_PRIVATE_KEY_FILE is set"
```

### 3. At least one signer exists and is unlocked

```bash
./remote-signer evm signer list --url http://localhost:8548 \
  --api-key-id "$REMOTE_SIGNER_API_KEY_ID" \
  --api-key-file ~/.remote-signer/apikeys/admin.key.priv
```

If locked, unlock: `./remote-signer evm signer unlock 0x<address> --password "<pw>"`

### 4. Understand what you're signing

| Question | Why |
|----------|-----|
| Which chain? | Chain ID (1=mainnet, 137=polygon, 56=bsc) |
| Which signer address? | Which key signs |
| What type? | `transaction`, `typed_data`, `personal`, or `hash` |
| What payload? | Review for safety |

---

## Signing Flow

```
Pre-flight checks (server, key, signer)
  │
  ▼
Determine sign type (tx / typed_data / personal / hash)
  │
  ▼
Call sign tool (MCP or CLI)
  │
  ├─ Auto-approved (whitelist rule matched) → signature returned
  │
  ├─ Auto-blocked (blocklist rule matched) → rejected
  │
  └─ No rule match
       ├─ manual_approval_enabled=true → "authorizing" → admin must approve
       └─ manual_approval_enabled=false → rejected
```

## Approving a Pending Request

When a signing request is stuck in `authorizing`:

1. **Confirm your role** — check the RBAC table. Only `admin` can approve.
2. If you are `agent`: tell the user. Do not try to approve — it will fail with "missing authentication headers" or permission errors.
3. If the user has admin access, guide them:

```bash
# List pending requests
./remote-signer --config ~/.remote-signer/config.yaml evm request list \
  --status authorizing \
  --url http://127.0.0.1:8548 \
  --api-key-id admin

# Approve a specific request
./remote-signer --config ~/.remote-signer/config.yaml evm request approve <request-id> \
  --url http://127.0.0.1:8548 \
  --api-key-id admin
```

Note: `--api-key-id admin` auto-discovers `~/.remote-signer/apikeys/admin.keystore.json` if `--api-key-file` is omitted. The `--config` flag is required when running from a directory without its own `config.yaml`.

## Architecture

```
Client → Ed25519 Auth → Middleware Pipeline → Handler → SignService
                                                            │
                              ChainAdapter ◄── SignService ─┤
                              Rule Engine  ◄── SignService ─┤
                              Budget Check ◄── SignService ─┤
                              Signer ──signs──► Signature ──┤
                              Audit Log ◄───── Every step ──┘
```

| Component | Description |
|-----------|-------------|
| Server | Daemon on `:8548`, REST API, SQLite or PostgreSQL |
| CLI | `remote-signer` — `server start`, `tui`, `validate`, `api-key`, `evm` |
| TUI | Terminal UI for interactive monitoring |
| Web UI | React dashboard served at `http://127.0.0.1:8548` |
| MCP Server | `remote-signer-mcp` (npm) — AI agent tools |

## References

| Reference | When to Read |
|-----------|-------------|
| [references/rbac-auth.md](references/rbac-auth.md) | Full RBAC table, Ed25519 signing, scoping, signer ownership |
| [references/installation.md](references/installation.md) | Install methods, bootstrap, first-time setup guide |
| [references/cli-reference.md](references/cli-reference.md) | Complete CLI command list, auth flags, preset protocol |
| [references/tls-security.md](references/tls-security.md) | TLS/mTLS, IP whitelist, security baseline, sandboxing |
| [references/sdk-integration.md](references/sdk-integration.md) | MCP server, TypeScript/Go/Rust SDKs |
