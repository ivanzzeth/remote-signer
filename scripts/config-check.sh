#!/bin/bash
# =============================================================================
# Configuration Security Checker
# Validates config.yaml for production security requirements.
# Run before deployment to catch misconfigurations.
#
# Usage: ./scripts/config-check.sh [config-file]
#        Default config file: ./config.yaml
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${1:-$PROJECT_DIR/config.yaml}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

pass()    { echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail()    { echo -e "  ${RED}[FAIL]${NC} $1"; ERRORS=$((ERRORS + 1)); }
warn()    { echo -e "  ${YELLOW}[WARN]${NC} $1"; WARNINGS=$((WARNINGS + 1)); }

echo "=============================================="
echo " Configuration Security Check"
echo " File: $CONFIG_FILE"
echo "=============================================="
echo ""

if [ ! -f "$CONFIG_FILE" ]; then
    fail "Config file not found: $CONFIG_FILE"
    exit 1
fi

CONFIG_CONTENT=$(cat "$CONFIG_FILE")

# =============================================================================
# 1. Secret Management
# =============================================================================
echo "--- [1/6] Secret Management ---"

# Check for plaintext private keys (not using env var substitution)
if echo "$CONFIG_CONTENT" | grep -q 'key_env:.*"[0-9a-fA-F]\{64\}"'; then
    # key_env with a literal 64-char hex means a hardcoded private key
    fail "Plaintext private key found in key_env field (use environment variable name instead)"
else
    pass "No plaintext private keys in key_env"
fi

# Check for test private keys
if echo "$CONFIG_CONTENT" | grep -q 'ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; then
    warn "Test private key (anvil account 0) found - OK for dev, NEVER use in production"
else
    pass "No well-known test private keys"
fi

# Check DSN uses environment variable
if echo "$CONFIG_CONTENT" | grep -q 'dsn:.*\$' || echo "$CONFIG_CONTENT" | grep -q 'dsn:.*DATABASE_DSN'; then
    pass "Database DSN uses environment variable substitution"
else
    if echo "$CONFIG_CONTENT" | grep -q 'dsn:.*password'; then
        warn "Database DSN appears to contain hardcoded password"
    else
        pass "Database DSN looks acceptable"
    fi
fi

# Check for default passwords
if echo "$CONFIG_CONTENT" | grep -q 'change_me_in_production\|signer_password'; then
    warn "Default/example password found - change before production deployment"
else
    pass "No default passwords detected"
fi
echo ""

# =============================================================================
# 2. Authentication & Replay Protection
# =============================================================================
echo "--- [2/6] Authentication ---"

# Check nonce_required
if echo "$CONFIG_CONTENT" | grep -q 'nonce_required:\s*true'; then
    pass "Nonce required for replay protection"
elif echo "$CONFIG_CONTENT" | grep -q 'nonce_required:\s*false'; then
    fail "nonce_required is false - vulnerable to replay attacks"
else
    warn "nonce_required not explicitly set (defaults to true, but should be explicit)"
fi

# Check max_request_age
MAX_AGE=$(echo "$CONFIG_CONTENT" | grep 'max_request_age' | grep -oP '"?\K[0-9]+' | head -1 || echo "")
if [ -n "$MAX_AGE" ]; then
    if [ "$MAX_AGE" -le 120 ]; then
        pass "max_request_age is ${MAX_AGE}s (within recommended range)"
    else
        warn "max_request_age is ${MAX_AGE}s (recommended: 30-60s to minimize replay window)"
    fi
else
    pass "max_request_age not set (defaults to 60s)"
fi

# Check rate limiting
RATE_LIMIT=$(echo "$CONFIG_CONTENT" | grep 'rate_limit_default' | grep -oP '[0-9]+' | head -1 || echo "")
if [ -n "$RATE_LIMIT" ]; then
    if [ "$RATE_LIMIT" -eq 0 ]; then
        fail "Rate limit is 0 (disabled) - vulnerable to abuse"
    elif [ "$RATE_LIMIT" -gt 10000 ]; then
        warn "Rate limit is $RATE_LIMIT (very high - consider reducing)"
    else
        pass "Rate limit set to $RATE_LIMIT requests/min"
    fi
else
    pass "Rate limit not set (defaults to 100/min)"
fi
echo ""

# =============================================================================
# 3. Network Security
# =============================================================================
echo "--- [3/6] Network Security ---"

# Check if listening on all interfaces
if echo "$CONFIG_CONTENT" | grep -q 'host:.*"0\.0\.0\.0"'; then
    warn "Server listening on 0.0.0.0 (all interfaces) - ensure firewall/proxy is configured"
else
    pass "Server not binding to all interfaces"
fi

# Check IP whitelist
if echo "$CONFIG_CONTENT" | grep -q 'ip_whitelist:' && echo "$CONFIG_CONTENT" | grep -A2 'ip_whitelist:' | grep -q 'enabled:\s*true'; then
    pass "IP whitelist is enabled"
else
    warn "IP whitelist is disabled - any IP can access the API"
fi

# Check trust_proxy
if echo "$CONFIG_CONTENT" | grep -q 'trust_proxy:\s*true'; then
    warn "trust_proxy is enabled - ensure running behind a trusted reverse proxy only"
else
    pass "trust_proxy is disabled (safe default)"
fi
echo ""

# =============================================================================
# 4. API Key Configuration
# =============================================================================
echo "--- [4/6] API Key Configuration ---"

# Check for admin keys
ADMIN_COUNT=$(echo "$CONFIG_CONTENT" | grep -c 'admin:\s*true' || echo "0")
if [ "$ADMIN_COUNT" -gt 0 ]; then
    pass "$ADMIN_COUNT admin key(s) configured"
    if [ "$ADMIN_COUNT" -gt 3 ]; then
        warn "Many admin keys ($ADMIN_COUNT) - principle of least privilege recommends fewer"
    fi
else
    warn "No admin keys configured - cannot manage rules or approve requests"
fi

# Check for disabled keys
DISABLED_COUNT=$(echo "$CONFIG_CONTENT" | grep -c 'enabled:\s*false' || echo "0")
if [ "$DISABLED_COUNT" -gt 0 ]; then
    warn "$DISABLED_COUNT disabled entries found - consider removing unused keys"
fi

# Check API keys use env vars for public keys
if echo "$CONFIG_CONTENT" | grep -q 'public_key_env:'; then
    pass "API keys reference public keys via environment variables"
fi
echo ""

# =============================================================================
# 5. Foundry / Solidity Rules
# =============================================================================
echo "--- [5/6] Foundry Configuration ---"

if echo "$CONFIG_CONTENT" | grep -A5 'foundry:' | grep -q 'enabled:\s*true'; then
    pass "Foundry is enabled for Solidity rules"

    # Check timeout
    FOUNDRY_TIMEOUT=$(echo "$CONFIG_CONTENT" | grep -A10 'foundry:' | grep 'timeout' | grep -oP '[0-9]+' | head -1 || echo "")
    if [ -n "$FOUNDRY_TIMEOUT" ] && [ "$FOUNDRY_TIMEOUT" -le 60 ]; then
        pass "Foundry timeout is ${FOUNDRY_TIMEOUT}s"
    elif [ -n "$FOUNDRY_TIMEOUT" ] && [ "$FOUNDRY_TIMEOUT" -gt 60 ]; then
        warn "Foundry timeout is ${FOUNDRY_TIMEOUT}s (high - may allow DoS via complex expressions)"
    fi
else
    pass "Foundry disabled (no Solidity rule execution risk)"
fi
echo ""

# =============================================================================
# 6. Logging
# =============================================================================
echo "--- [6/6] Logging ---"

if echo "$CONFIG_CONTENT" | grep -q 'level:.*"debug"'; then
    warn "Log level is debug - may expose sensitive data in logs. Use 'info' or higher in production"
else
    pass "Log level is not debug"
fi
echo ""

# =============================================================================
# Summary
# =============================================================================
echo "=============================================="
echo " Summary"
echo "=============================================="
echo -e "  Errors:   ${RED}$ERRORS${NC}"
echo -e "  Warnings: ${YELLOW}$WARNINGS${NC}"
echo ""

if [ $ERRORS -gt 0 ]; then
    echo -e "${RED}Configuration has $ERRORS error(s) that MUST be fixed before production deployment.${NC}"
    exit 1
elif [ $WARNINGS -gt 0 ]; then
    echo -e "${YELLOW}Configuration has $WARNINGS warning(s). Review before production deployment.${NC}"
    exit 0
else
    echo -e "${GREEN}Configuration looks good for production.${NC}"
    exit 0
fi
