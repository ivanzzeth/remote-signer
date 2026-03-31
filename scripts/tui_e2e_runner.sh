#!/bin/bash
# Start server + TUI for interactive/E2E testing (e.g. from interactive terminal).
# Uses port 28548 so it does not conflict with E2E (18548) or other servers. Stops any existing server on this port first.
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_DIR/data"
PORT=28548
CONFIG="$PROJECT_DIR/config.tui_e2e.yaml"

cd "$PROJECT_DIR"
mkdir -p "$DATA_DIR"

# Stop existing server on PORT so we don't get "address already in use"
for _ in 1 2; do
	if command -v fuser &>/dev/null; then
		fuser -k "$PORT/tcp" 2>/dev/null || true
	fi
	if command -v lsof &>/dev/null; then
		lsof -ti ":$PORT" 2>/dev/null | xargs -r kill 2>/dev/null || true
	fi
	pkill -f "remote-signer.*config.tui_e2e" 2>/dev/null || true
	sleep 2
done

# Generate admin API key if missing
if [ ! -f "$DATA_DIR/admin_private.pem" ]; then
	"$SCRIPT_DIR/generate-api-key.sh" -n admin -o "$DATA_DIR" -f
fi
# Public key as 64-char hex (config accepts hex or base64)
ADMIN_PUBLIC_HEX=$(openssl pkey -in "$DATA_DIR/admin_public.pem" -pubin -outform DER 2>/dev/null | tail -c 32 | xxd -p -c 64 | tr -d '\n')

# Minimal config: in-memory SQLite, one admin key, EVM with HD wallet dir
cat > "$CONFIG" << EOF
server:
  host: "127.0.0.1"
  port: $PORT
database:
  dsn: "file::memory:?cache=shared&_journal_mode=WAL&_busy_timeout=5000"
chains:
  evm:
    enabled: true
    signers:
      private_keys: []
    keystore_dir: "$DATA_DIR/keystores-e2e"
    hd_wallet_dir: "$DATA_DIR/hd-wallets"
    foundry:
      enabled: false
api_keys:
  - id: admin
    role: admin
    enabled: true
    public_key: "$ADMIN_PUBLIC_HEX"
security:
  max_request_age: "60s"
  rate_limit_default: 1000
  nonce_required: true
  manual_approval_enabled: false
logger:
  level: "warn"
  pretty: false
rules: []
templates: []
EOF

# Start server in background
go run ./cmd/remote-signer -config "$CONFIG" &
SRV_PID=$!
trap "kill $SRV_PID 2>/dev/null || true" EXIT
sleep 3

# Run TUI (foreground)
exec go run ./cmd/remote-signer-tui -api-key-id admin -api-key-file "$DATA_DIR/admin_private.pem" -url "http://localhost:$PORT"
