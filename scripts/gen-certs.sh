#!/usr/bin/env bash
#
# gen-certs.sh — Generate CA + server + client certificates for TLS/mTLS
#
# Usage:
#   ./scripts/gen-certs.sh [extra-ip1] [extra-ip2] ...
#
# Defaults:
#   - SAN includes 127.0.0.1, ::1, localhost
#   - Auto-detects LAN IP and adds it to SAN
#   - Auto-detects public IP (for VPS deployment) and adds it to SAN
#   - Extra IPs can be passed as arguments
#
# Output directory: ./certs/
#   ca.crt, ca.key        — Root CA
#   server.crt, server.key — Server certificate
#   client.crt, client.key — Client certificate

set -euo pipefail

CERT_DIR="${CERT_DIR:-./certs}"
DAYS="${DAYS:-365}"
KEY_SIZE="${KEY_SIZE:-4096}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Check for openssl
if ! command -v openssl &>/dev/null; then
    error "openssl is required but not installed."
    exit 1
fi

# Create output directory
mkdir -p "$CERT_DIR"
info "Certificate output directory: $CERT_DIR"

# =============================================================================
# Overwrite guard (default: do not overwrite)
# =============================================================================

existing_certs=false
for f in ca.crt ca.key server.crt server.key client.crt client.key; do
    if [ -f "$CERT_DIR/$f" ]; then
        existing_certs=true
        break
    fi
done

if [ "$existing_certs" = true ] && [ "${CERTS_FORCE:-0}" != "1" ]; then
    warn "Certificates already exist in $CERT_DIR"
    read -rp "Overwrite existing certificates? (y/N): " OVERWRITE_CERTS
    if [[ ! "$OVERWRITE_CERTS" =~ ^[Yy]$ ]]; then
        info "Keeping existing certificates (no overwrite)."
        info "Tip: to regenerate (e.g. to add SAN IPs), run: CERTS_FORCE=1 $0 [extra-ip...]"
        exit 0
    fi
    rm -f "$CERT_DIR/ca.crt" "$CERT_DIR/ca.key" \
        "$CERT_DIR/server.crt" "$CERT_DIR/server.key" \
        "$CERT_DIR/client.crt" "$CERT_DIR/client.key" \
        "$CERT_DIR/server.csr" "$CERT_DIR/client.csr" \
        "$CERT_DIR/server_ext.cnf" "$CERT_DIR/client_ext.cnf" \
        "$CERT_DIR/ca.srl"
fi

# =============================================================================
# Collect SAN IPs
# =============================================================================

SAN_IPS=("127.0.0.1" "::1")

# Auto-detect LAN IP
detect_lan_ip() {
    local ip=""
    # Try Linux
    if command -v ip &>/dev/null; then
        ip=$(ip -4 route get 8.8.8.8 2>/dev/null | grep -oP 'src \K\S+' || true)
    fi
    # Try macOS
    if [ -z "$ip" ] && command -v ifconfig &>/dev/null; then
        ip=$(ifconfig | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}')
    fi
    echo "$ip"
}

# Auto-detect public IP (for VPS deployment; requires outbound HTTPS)
detect_public_ip() {
    local ip=""
    for url in "https://api.ipify.org" "https://ifconfig.me/ip" "https://icanhazip.com"; do
        ip=$(curl -sSf --max-time 5 "$url" 2>/dev/null | tr -d '\r\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true)
        [ -n "$ip" ] && break
    done
    echo "$ip"
}

LAN_IP=$(detect_lan_ip)
if [ -n "$LAN_IP" ]; then
    SAN_IPS+=("$LAN_IP")
    info "Detected LAN IP: $LAN_IP"
fi

PUBLIC_IP=$(detect_public_ip)
if [ -n "$PUBLIC_IP" ]; then
    # Avoid duplicate if same as LAN
    if [[ " ${SAN_IPS[*]} " != *" $PUBLIC_IP "* ]]; then
        SAN_IPS+=("$PUBLIC_IP")
        info "Detected public IP: $PUBLIC_IP (for VPS/remote access)"
    fi
fi

# Add user-specified extra IPs
for extra_ip in "$@"; do
    SAN_IPS+=("$extra_ip")
    info "Added extra IP: $extra_ip"
done

# Build SAN string for openssl
# Format: IP:127.0.0.1,IP:::1,DNS:localhost,...
SAN_ENTRIES=("DNS:localhost")
for ip in "${SAN_IPS[@]}"; do
    SAN_ENTRIES+=("IP:$ip")
done

SAN_STRING=$(IFS=','; echo "${SAN_ENTRIES[*]}")
info "SAN: $SAN_STRING"

# =============================================================================
# 1. Generate CA
# =============================================================================

info "Generating CA certificate..."

openssl genrsa -out "$CERT_DIR/ca.key" "$KEY_SIZE" 2>/dev/null

openssl req -new -x509 \
    -key "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -days "$DAYS" \
    -subj "/C=US/ST=CA/O=RemoteSigner/CN=RemoteSigner CA" \
    2>/dev/null

info "CA certificate generated: $CERT_DIR/ca.crt"

# =============================================================================
# 2. Generate Server Certificate
# =============================================================================

info "Generating server certificate..."

openssl genrsa -out "$CERT_DIR/server.key" "$KEY_SIZE" 2>/dev/null

openssl req -new \
    -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/C=US/ST=CA/O=RemoteSigner/CN=remote-signer-server" \
    2>/dev/null

# Create extensions file for server cert
cat > "$CERT_DIR/server_ext.cnf" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$SAN_STRING
EOF

openssl x509 -req \
    -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/server.crt" \
    -days "$DAYS" \
    -extfile "$CERT_DIR/server_ext.cnf" \
    2>/dev/null

info "Server certificate generated: $CERT_DIR/server.crt"

# =============================================================================
# 3. Generate Client Certificate
# =============================================================================

info "Generating client certificate..."

openssl genrsa -out "$CERT_DIR/client.key" "$KEY_SIZE" 2>/dev/null

openssl req -new \
    -key "$CERT_DIR/client.key" \
    -out "$CERT_DIR/client.csr" \
    -subj "/C=US/ST=CA/O=RemoteSigner/CN=remote-signer-client" \
    2>/dev/null

# Create extensions file for client cert
cat > "$CERT_DIR/client_ext.cnf" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
EOF

openssl x509 -req \
    -in "$CERT_DIR/client.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/client.crt" \
    -days "$DAYS" \
    -extfile "$CERT_DIR/client_ext.cnf" \
    2>/dev/null

info "Client certificate generated: $CERT_DIR/client.crt"

# =============================================================================
# Cleanup temporary files
# =============================================================================

rm -f "$CERT_DIR/server.csr" "$CERT_DIR/client.csr"
rm -f "$CERT_DIR/server_ext.cnf" "$CERT_DIR/client_ext.cnf"
rm -f "$CERT_DIR/ca.srl"

# =============================================================================
# Set permissions
# =============================================================================

chmod 644 "$CERT_DIR/ca.crt" "$CERT_DIR/server.crt" "$CERT_DIR/client.crt"
chmod 600 "$CERT_DIR/ca.key" "$CERT_DIR/server.key" "$CERT_DIR/client.key"

# =============================================================================
# Summary
# =============================================================================

echo ""
info "=== Certificate Generation Complete ==="
echo ""
echo "  CA:      $CERT_DIR/ca.crt   (share with clients for server verification)"
echo "           $CERT_DIR/ca.key   (keep secret!)"
echo ""
echo "  Server:  $CERT_DIR/server.crt"
echo "           $CERT_DIR/server.key"
echo ""
echo "  Client:  $CERT_DIR/client.crt (for mTLS client authentication)"
echo "           $CERT_DIR/client.key"
echo ""
echo "  SAN IPs: ${SAN_IPS[*]}"
echo ""
info "=== Usage Examples ==="
echo ""
echo "  # config.yaml (server)"
echo "  server:"
echo "    tls:"
echo "      enabled: true"
echo "      cert_file: \"$CERT_DIR/server.crt\""
echo "      key_file: \"$CERT_DIR/server.key\""
echo "      ca_file: \"$CERT_DIR/ca.crt\""
echo "      client_auth: true  # Enable mTLS"
echo ""
echo "  # Client with mTLS"
echo "  curl --cacert $CERT_DIR/ca.crt \\"
echo "       --cert $CERT_DIR/client.crt \\"
echo "       --key $CERT_DIR/client.key \\"
echo "       https://localhost:8548/health"
echo ""
