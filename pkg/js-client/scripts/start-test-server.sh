#!/bin/bash
# Start Go test server for e2e tests

set -e

# Get the project root (three levels up from pkg/js-client/scripts)
PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$PROJECT_ROOT"

# Default port
PORT=${E2E_API_PORT:-8548}

echo "Starting test server on port $PORT..."
echo "Project root: $PROJECT_ROOT"

# Generate Ed25519 key pair for API authentication
echo "Generating Ed25519 key pair..."
ADMIN_PUB_KEY=$(openssl genpkey -algorithm ed25519 -outform DER 2>/dev/null | openssl pkey -pubout -outform DER 2>/dev/null | xxd -p -c 256 | head -c 64)
ADMIN_PRIV_KEY=$(openssl genpkey -algorithm ed25519 -outform DER 2>/dev/null | xxd -p -c 256 | head -c 64)

if [ -z "$ADMIN_PUB_KEY" ] || [ -z "$ADMIN_PRIV_KEY" ]; then
    echo "Warning: Failed to generate keys with OpenSSL, using test keys"
    ADMIN_PUB_KEY="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    ADMIN_PRIV_KEY="a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890"
fi

ADMIN_KEY_ID="test-admin-$(date +%s)"

# Export environment variables for Go test
export E2E_API_PORT=$PORT
export E2E_API_KEY_ID=$ADMIN_KEY_ID
export E2E_PRIVATE_KEY=$ADMIN_PRIV_KEY
export E2E_SIGNER_ADDRESS="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
export E2E_CHAIN_ID="1"

echo "API Key ID: $ADMIN_KEY_ID"
echo "Private Key: $ADMIN_PRIV_KEY"
echo ""
echo "To use this server in tests, set:"
echo "  export E2E_EXTERNAL_SERVER=true"
echo "  export E2E_BASE_URL=http://localhost:$PORT"
echo "  export E2E_API_KEY_ID=$ADMIN_KEY_ID"
echo "  export E2E_PRIVATE_KEY=$ADMIN_PRIV_KEY"
echo ""

# Start the test server
go test -tags=e2e -run TestMain ./e2e
