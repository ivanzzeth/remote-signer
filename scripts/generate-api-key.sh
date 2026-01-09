#!/bin/bash
# =============================================================================
# Generate Ed25519 API Key Pair for Remote Signer
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="${PROJECT_DIR}/data"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# =============================================================================
# Usage
# =============================================================================
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Generate Ed25519 API key pair for Remote Signer authentication.

Options:
    -o, --output DIR    Output directory (default: ./data)
    -n, --name NAME     Key file prefix (default: api)
    -f, --force         Overwrite existing keys
    -h, --help          Show this help message

Examples:
    $0                          # Generate keys in ./data/
    $0 -o /etc/signer/keys      # Generate keys in custom directory
    $0 -n admin                 # Generate admin_private.pem and admin_public.pem
EOF
}

# =============================================================================
# Parse arguments
# =============================================================================
OUTPUT_DIR="$DATA_DIR"
KEY_NAME="api"
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -n|--name)
            KEY_NAME="$2"
            shift 2
            ;;
        -f|--force)
            FORCE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# =============================================================================
# Main
# =============================================================================
PRIVATE_KEY_FILE="${OUTPUT_DIR}/${KEY_NAME}_private.pem"
PUBLIC_KEY_FILE="${OUTPUT_DIR}/${KEY_NAME}_public.pem"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check if keys already exist
if [ -f "$PRIVATE_KEY_FILE" ] && [ "$FORCE" != true ]; then
    log_warn "Key files already exist!"
    echo "  Private: $PRIVATE_KEY_FILE"
    echo "  Public:  $PUBLIC_KEY_FILE"
    echo ""
    echo "Use -f or --force to overwrite."
    exit 1
fi

log_info "Generating Ed25519 key pair..."

# Generate private key
openssl genpkey -algorithm ed25519 -out "$PRIVATE_KEY_FILE"
chmod 600 "$PRIVATE_KEY_FILE"

# Extract public key
openssl pkey -in "$PRIVATE_KEY_FILE" -pubout -out "$PUBLIC_KEY_FILE"

log_info "Key pair generated successfully!"
echo ""
echo -e "${CYAN}=== Key Files ===${NC}"
echo "Private key: $PRIVATE_KEY_FILE"
echo "Public key:  $PUBLIC_KEY_FILE"
echo ""

# Extract base64 encoded keys
echo -e "${CYAN}=== Base64 Encoded Keys ===${NC}"
echo ""
echo -e "${YELLOW}Private Key (for TUI client):${NC}"
PRIVATE_KEY_BASE64=$(openssl pkey -in "$PRIVATE_KEY_FILE" -outform DER 2>/dev/null | base64 | tr -d '\n')
echo "$PRIVATE_KEY_BASE64"
echo ""

echo -e "${YELLOW}Public Key (for config.yaml api_keys):${NC}"
PUBLIC_KEY_BASE64=$(openssl pkey -in "$PUBLIC_KEY_FILE" -pubin -outform DER 2>/dev/null | base64 | tr -d '\n')
echo "$PUBLIC_KEY_BASE64"
echo ""

# Generate a random API key ID
API_KEY_ID="api-key-$(openssl rand -hex 4)"

echo -e "${CYAN}=== Configuration Example ===${NC}"
echo ""
echo "Add this to your config.yaml under 'api_keys':"
echo ""
echo -e "${GREEN}api_keys:"
echo "  - id: \"$API_KEY_ID\""
echo "    name: \"Generated API Key\""
echo "    public_key: \"$PUBLIC_KEY_BASE64\""
echo "    enabled: true"
echo -e "    rate_limit: 100${NC}"
echo ""

echo -e "${CYAN}=== TUI Connection Example ===${NC}"
echo ""
echo "./remote-signer-tui \\"
echo "  -url http://localhost:8548 \\"
echo "  -api-key-id $API_KEY_ID \\"
echo "  -private-key $PRIVATE_KEY_BASE64"
echo ""

log_warn "Keep the private key secure! Never commit it to version control."
