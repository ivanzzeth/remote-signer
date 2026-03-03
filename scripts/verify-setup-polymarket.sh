#!/bin/bash
# Quick verification of Polymarket setup flow using verify-setup-polymarket and preset CLI.
# Prerequisites: server running with polymarket_safe_init preset, one signer created & unlocked via TUI.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SIGNER="${SIGNER_ADDRESS:-0x4F2fE52763B4E89afC5bB061644d60Cd3C488717}"
CONFIG="${CONFIG:-config.local.yaml}"

cd "$PROJECT_DIR"

echo "[1/4] createProxy sign (safe_init preset)..."
go run ./cmd/verify-setup-polymarket/ -step createproxy -signer "$SIGNER" -url "${URL:-http://localhost:8548}"

echo "[2/4] Add full preset (polymarket_safe_polygon) to config..."
# Use same placeholder Safe address as in setup for vars
if command -v remote-signer-cli &>/dev/null; then
  CLI=remote-signer-cli
else
  CLI="go run ./cmd/remote-signer-cli/"
fi
$CLI preset create-from polymarket_safe_polygon.preset.yaml \
  --config "$CONFIG" --write \
  --presets-dir rules/presets \
  --set "allowed_safe_addresses=$SIGNER" \
  --set "allowed_safe_address_for_testing=$SIGNER" \
  || { echo "preset create-from failed (maybe already added?)"; exit 1; }

echo "[3/4] Restart server to load new rules..."
# Stop existing server on 8548
if command -v lsof &>/dev/null; then
  pid=$(lsof -ti:8548 2>/dev/null) || true
  if [ -n "$pid" ]; then
    kill "$pid" 2>/dev/null || true
    sleep 2
  fi
fi
if [ -x "./build/remote-signer" ]; then
  nohup ./build/remote-signer -config "$CONFIG" > /tmp/remote-signer.log 2>&1 &
else
  nohup go run ./cmd/remote-signer/ -config "$CONFIG" > /tmp/remote-signer.log 2>&1 &
fi
sleep 3
curl -sf "${URL:-http://localhost:8548}/health" >/dev/null || { echo "server failed to start"; tail -20 /tmp/remote-signer.log; exit 1; }

echo "[4/4] Trade sign (full preset)..."
go run ./cmd/verify-setup-polymarket/ -step trade -signer "$SIGNER" -url "${URL:-http://localhost:8548}"

echo "Done. Full flow verified."
