# TUI (Terminal User Interface)

The remote-signer includes a terminal-based management interface for monitoring and managing the signing service.

## Build

```bash
go build -o remote-signer-tui ./cmd/tui
```

## Run

```bash
# Using command-line flags (hex or base64, auto-detected)
./remote-signer-tui \
  -url http://localhost:8548 \
  -api-key-id admin \
  -private-key your-ed25519-private-key

# Or using environment variables
export REMOTE_SIGNER_URL=http://localhost:8548
export REMOTE_SIGNER_API_KEY_ID=admin
export REMOTE_SIGNER_PRIVATE_KEY=your-ed25519-private-key
./remote-signer-tui
```

### Parameters

| Flag | Env Variable | Default | Description |
|------|--------------|---------|-------------|
| `-url` | `REMOTE_SIGNER_URL` | `http://localhost:8548` | Server URL |
| `-api-key-id` | `REMOTE_SIGNER_API_KEY_ID` | (required) | API key ID registered on the server |
| `-private-key` | `REMOTE_SIGNER_PRIVATE_KEY` | (required) | Ed25519 private key (hex or base64) |

### TLS / mTLS

When connecting to a TLS-enabled server, see [TLS.md](TLS.md#client-usage) for the TUI TLS flags (`-tls-ca`, `-tls-cert`, `-tls-key`).

## Views

- **Dashboard** — Service health, request counts by status, rules summary
- **Requests** — View all sign requests, filter by status, approve/reject pending requests
- **Rules** — View/edit authorization rules, toggle enable/disable, delete rules
- **Signers** — Create keystores, import/create HD wallets, derive addresses
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
