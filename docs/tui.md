# TUI (Terminal User Interface)

The remote-signer includes a terminal-based management interface for monitoring and managing the signing service.

## Build

```bash
# -o output path must come before the package path (go build -o <binary> <pkg>)
go build -o remote-signer-tui ./cmd/remote-signer-tui
```

## Run

```bash
# Recommended: use API key PEM file (no paste)
./remote-signer-tui -api-key-id admin -api-key-file data/admin_private.pem -url http://localhost:8548

# Or environment variable
export REMOTE_SIGNER_URL=http://localhost:8548
export REMOTE_SIGNER_API_KEY_ID=admin
export REMOTE_SIGNER_PRIVATE_KEY=your-ed25519-private-key
./remote-signer-tui

# Or inline env vars
REMOTE_SIGNER_PRIVATE_KEY=your-ed25519-private-key ./remote-signer-tui -url http://localhost:8548 -api-key-id admin
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
- **Rules** — View/edit authorization rules, toggle enable/disable, delete rules
- **Signers** — Create keystores, import/create HD wallets (mnemonic wallets), derive addresses
- **Audit Logs** — View all audit events, filter by event type or severity

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
