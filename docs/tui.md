# TUI (Terminal User Interface)

> ⛔ **Frozen legacy surface — frozen 2026-04-03 (`abc01e5`). No new features are
> accepted here.** Decision recorded as **D16** in [`prd.md`](prd.md) §7.

| | |
|---|---|
| Status | Kept in the repo, still builds, still runs; bug fixes and security fixes only |
| New features | **Not accepted.** Feature work happens in the **Web UI** |
| Why it is kept | It still works for the read-mostly operator flows it already covers |
| What it cannot do | ⛔ It is **not** at parity with the Web UI. The concrete missing-capability table is in [`product-forms.md`](product-forms.md) §3.3 |
| Rewrite | ⛔ Rejected — a single static binary ships with no Node runtime; see [`product-forms.md`](product-forms.md) §3.3 |

⭐ One capability runs the other way: the **Metrics** view (Prometheus `/metrics`,
p50/p95 latency histograms) exists **only** here. Closing that gap is tracked as
**F1** in [`product-forms.md`](product-forms.md) §5.

The remote-signer includes a terminal-based management interface for monitoring and managing the signing service.

## Build

```bash
# -o output path must come before the package path (go build -o <binary> <pkg>)
go build -o remote-signer tui ./cmd/remote-signer
```

## Run

```bash
# Recommended: use API key PEM file (no paste)
./remote-signer tui -api-key-id admin -api-key-file data/admin_private.pem -url http://localhost:8548

# Or environment variable
export REMOTE_SIGNER_URL=http://localhost:8548
export REMOTE_SIGNER_API_KEY_ID=admin
export REMOTE_SIGNER_PRIVATE_KEY=your-ed25519-private-key
./remote-signer tui

# Or inline env vars
REMOTE_SIGNER_PRIVATE_KEY=your-ed25519-private-key ./remote-signer tui -url http://localhost:8548 -api-key-id admin
```

If neither `-api-key-file` nor `REMOTE_SIGNER_PRIVATE_KEY` is set, the TUI will prompt for the key interactively.

### Parameters

| Flag | Env Variable | Default | Description |
|------|--------------|---------|-------------|
| `-url` | `REMOTE_SIGNER_URL` | `http://localhost:8548` | Server URL |
| `-api-key-id` | `REMOTE_SIGNER_API_KEY_ID` | (required) | API key ID registered on the server |
| `-api-key-file` | — | — | Path to API key PEM (e.g. `data/admin_private.pem`); avoids paste |
| — | `REMOTE_SIGNER_PRIVATE_KEY` | (interactive prompt) | Ed25519 private key (hex or base64) |

### TLS / mTLS

When connecting to a TLS-enabled server, see [tls.md](tls.md#client-usage) for the TUI TLS flags (`-tls-ca`, `-tls-cert`, `-tls-key`).

## Views

- **Dashboard** — Service health, request counts by status, rules summary
- **Requests** — View all sign requests, filter by status, approve/reject pending requests
  (⛔ one at a time — batch approve/reject is Web UI only)
- **Rules** — View/edit authorization rules, toggle enable/disable, delete rules
  (⛔ no propose/approve flow, no validation, budgets are read-only here)
- **Signers** — Create keystores, import/create HD wallets (mnemonic wallets), derive addresses
- **Audit Logs** — View all audit events, filter by event type or severity
- **Metrics** — ⭐ Prometheus `/metrics` scrape with p50/p95 latency histograms.
  **The only view with no Web UI equivalent**
- **API Keys · Templates · Presets · Security** — ⚠️ browse only; all writes are Web UI only

## Key Bindings

| Key | Action |
|-----|--------|
| `1-4` / `Tab` | Switch tabs (Dashboard, Requests, Rules, Audit) |
| `↑/↓` or `j/k` | Navigate lists |
| `Enter` | View details |
| `a` | Approve request (with optional rule generation) |
| `x` | Reject request |
| `t` | Toggle rule enabled/disabled |
| `d` | Delete rule |
| `f` | Filter lists |
| `r` | Refresh |
| `?` | Show help |
| `q` | Quit |
