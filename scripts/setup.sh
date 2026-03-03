#!/bin/bash
# =============================================================================
# Remote Signer — Guided Setup
#
# Interactive setup script for new users. Generates API keys, configures TLS,
# and produces a ready-to-run config file in 5 steps.
#
# Can run standalone (auto-clones repo if needed):
#   bash <(curl -fsSL https://raw.githubusercontent.com/ivanzzeth/remote-signer/main/scripts/setup.sh)
#
# Or from inside the repo:
#   ./scripts/setup.sh
#
# For non-interactive setup, use: ./scripts/deploy.sh init
# =============================================================================
set -e

# === Constants & Colors ======================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="${PROJECT_DIR}/data"

# GitHub repo for release downloads (public repo required for unauthenticated download)
REMOTE_SIGNER_REPO="${REMOTE_SIGNER_RELEASE_REPO:-ivanzzeth/remote-signer}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# === Utility Functions ========================================================

log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Prompt helper: read a single choice with default
# Usage: ask "prompt" DEFAULT CHOICES...
#   e.g. ask "Select" 1 1 2 3
ask() {
    local prompt="$1" default="$2"
    shift 2
    local choices=("$@")
    local choice
    while true; do
        read -rp "$prompt (default: $default): " choice
        choice="${choice:-$default}"
        for c in "${choices[@]}"; do
            if [ "$choice" = "$c" ]; then
                echo "$choice"
                return
            fi
        done
        echo -e "${RED}Invalid choice. Please enter one of: ${choices[*]}${NC}" >&2
    done
}

# Map current OS/arch to release asset suffix (e.g. linux-amd64, darwin-arm64)
tui_release_asset_suffix() {
    local goos goarch
    case "$(uname -s)" in
        Linux)  goos=linux ;;
        Darwin) goos=darwin ;;
        *) echo "unknown"; return 1 ;;
    esac
    case "$(uname -m)" in
        x86_64)  goarch=amd64 ;;
        aarch64|arm64) goarch=arm64 ;;
        *) echo "unknown"; return 1 ;;
    esac
    echo "${goos}-${goarch}"
}

# Download TUI binary from GitHub Releases (latest). Works only when repo is public.
# Returns 0 on success, 1 on failure (no release, 404, or private repo).
download_tui_from_release() {
    local suffix url dest
    suffix="$(tui_release_asset_suffix)" || return 1
    url="https://github.com/${REMOTE_SIGNER_REPO}/releases/latest/download/remote-signer-tui-${suffix}"
    dest="$PROJECT_DIR/remote-signer-tui"
    log_info "Downloading TUI binary (${suffix})..."
    if curl -SLf -# -o "$dest" "$url" && [ -s "$dest" ]; then
        chmod +x "$dest"
        return 0
    fi
    rm -f "$dest"
    return 1
}

detect_os() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        Linux)
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                case "$ID" in
                    ubuntu|debian) echo "ubuntu" ;;
                    *) echo "linux-other" ;;
                esac
            else
                echo "linux-other"
            fi
            ;;
        *) echo "unknown" ;;
    esac
}

# === Project Directory Detection ==============================================

ensure_project_dir() {
    # Check if we're inside the project directory (marker: go.mod with remote-signer)
    if [ -f "$PROJECT_DIR/go.mod" ] && grep -q "remote-signer" "$PROJECT_DIR/go.mod" 2>/dev/null; then
        return 0  # Already in project directory
    fi

    # Not in project directory — need to clone
    log_info "Remote Signer source code not found. Let's clone it first."
    echo ""

    # Ensure git is installed
    if ! command -v git &>/dev/null; then
        local os
        os=$(detect_os)
        case "$os" in
            ubuntu)
                log_info "Installing git..."
                sudo apt-get update -qq && sudo apt-get install -y -qq git
                ;;
            macos)
                log_info "Installing git via Xcode command line tools..."
                xcode-select --install 2>/dev/null || true
                # Wait for user to complete the install
                echo "  After the Xcode CLT installation completes, press Enter to continue."
                read -r
                ;;
            *)
                log_error "git is required. Please install git and re-run this script."
                exit 1
                ;;
        esac
    fi

    # Clone
    local CLONE_DIR="${HOME}/remote-signer"
    read -rp "  Clone to directory (default: $CLONE_DIR): " CUSTOM_DIR
    CLONE_DIR="${CUSTOM_DIR:-$CLONE_DIR}"

    log_info "Cloning remote-signer to $CLONE_DIR..."
    git clone https://github.com/ivanzzeth/remote-signer.git "$CLONE_DIR"

    # Re-execute setup from the cloned directory
    log_info "Continuing setup from $CLONE_DIR..."
    exec "$CLONE_DIR/scripts/setup.sh"
}

# === Dependency Checks ========================================================

check_openssl() {
    if ! command -v openssl &>/dev/null; then
        log_error "openssl is required but not installed."
        exit 1
    fi
}

check_go() {
    if ! command -v go &>/dev/null; then
        log_warn "go is not installed. You'll need Go 1.24+ to build the binary."
    fi
}

install_docker_ubuntu() {
    log_info "Installing Docker via official script..."
    curl -fsSL https://get.docker.com | sudo sh

    # Add current user to docker group
    if ! groups "$USER" | grep -q docker; then
        sudo usermod -aG docker "$USER"
        log_warn "Added $USER to docker group. You may need to log out and back in."
        log_info "For now, using 'sudo' for Docker commands..."
    fi

    # Verify
    if docker compose version &>/dev/null || sudo docker compose version &>/dev/null; then
        log_info "Docker installed successfully!"
    else
        log_error "Docker installation failed. Please install manually: https://docs.docker.com/engine/install/"
        exit 1
    fi
}

install_docker_macos() {
    echo ""
    log_error "Docker Desktop is required on macOS."
    echo ""
    echo "  Please install it from:"
    echo "    https://www.docker.com/products/docker-desktop/"
    echo ""
    echo "  After installing, start Docker Desktop and re-run this script."
    echo ""
    exit 1
}

ensure_docker() {
    # Check docker + docker compose
    if command -v docker &>/dev/null && docker compose version &>/dev/null; then
        log_info "Docker detected: $(docker --version)"
        return 0
    fi

    log_warn "Docker is not installed."
    local os
    os=$(detect_os)

    case "$os" in
        ubuntu)
            echo ""
            echo "  Docker can be installed automatically via the official script."
            echo ""
            read -rp "  Install Docker now? (Y/n): " INSTALL_DOCKER
            if [[ ! "$INSTALL_DOCKER" =~ ^[Nn]$ ]]; then
                install_docker_ubuntu
            else
                log_error "Docker is required for Docker deployment mode."
                exit 1
            fi
            ;;
        macos)
            install_docker_macos
            ;;
        *)
            log_error "Please install Docker manually: https://docs.docker.com/engine/install/"
            exit 1
            ;;
    esac
}

check_screen() {
    if ! command -v screen &>/dev/null; then
        log_warn "screen is not installed (needed by deploy.sh for background sessions)."
        local os
        os=$(detect_os)
        case "$os" in
            ubuntu)
                read -rp "  Install screen now? (Y/n): " INSTALL_SCREEN
                if [[ ! "$INSTALL_SCREEN" =~ ^[Nn]$ ]]; then
                    sudo apt-get install -y screen
                fi
                ;;
            macos)
                if command -v brew &>/dev/null; then
                    read -rp "  Install screen via brew? (Y/n): " INSTALL_SCREEN
                    if [[ ! "$INSTALL_SCREEN" =~ ^[Nn]$ ]]; then
                        brew install screen
                    fi
                else
                    log_warn "Install screen: brew install screen"
                fi
                ;;
        esac
    fi
}

# === Banner ===================================================================

print_banner() {
    echo ""
    echo -e "${BOLD}=============================================================${NC}"
    echo -e "${BOLD}  Remote Signer — Guided Setup${NC}"
    echo -e "${BOLD}=============================================================${NC}"
    echo ""
    echo "A secure, policy-driven signing service for EVM chains."
    echo ""
    echo -e "Key concepts:"
    echo -e "  ${CYAN}API Keys${NC}    Ed25519 key pairs authenticate clients"
    echo -e "  ${CYAN}Rules${NC}       Policy engine controls what gets signed"
    echo -e "  ${CYAN}TLS/mTLS${NC}    Transport security between client & server"
    echo -e "  ${CYAN}TUI${NC}         Terminal UI for management & approvals"
    echo -e "  ${CYAN}Signers${NC}     EVM signing keys (add after setup via TUI or API)"
    echo ""
}

# === Step Functions ===========================================================

step_deployment_mode() {
    echo -e "${BOLD}=============================================================${NC}"
    echo -e "${BOLD}  Step 1/5: Deployment Mode${NC}"
    echo -e "${BOLD}=============================================================${NC}"
    echo ""
    echo "How do you want to run remote-signer?"
    echo -e "  ${CYAN}1)${NC} Docker ${DIM}(PostgreSQL + security hardening)${NC} \u2b50 recommended"
    echo -e "  ${CYAN}2)${NC} Local  ${DIM}(SQLite, no Docker needed) — for development only${NC}"
    echo ""
    DEPLOY_MODE_CHOICE=$(ask "Select [1/2]" 1 1 2)

    if [ "$DEPLOY_MODE_CHOICE" = "2" ]; then
        DEPLOY_MODE="local"
        CONFIG_FILE="config.local.yaml"
        DSN='file:./data/remote-signer.db?_journal_mode=WAL&_busy_timeout=5000'
        PORT=8548
        log_info "Selected: Local deployment (SQLite)"
    else
        DEPLOY_MODE="docker"
        CONFIG_FILE="config.yaml"
        POSTGRES_PASSWORD=$(openssl rand -base64 18 | tr -d '/+=' | head -c 24)
        DSN="\${DATABASE_DSN:-postgres://signer:${POSTGRES_PASSWORD}@postgres:5432/remote_signer?sslmode=disable}"
        PORT=8548
        log_info "Selected: Docker deployment (PostgreSQL)"
    fi
    echo ""
}

step_api_keys() {
    echo -e "${BOLD}=============================================================${NC}"
    echo -e "${BOLD}  Step 2/5: API Keys${NC}"
    echo -e "${BOLD}=============================================================${NC}"
    echo ""
    echo "Generating two API key pairs:"
    echo ""
    echo -e "  ${CYAN}admin${NC}  Full access: manage signers, approve requests, manage rules"
    echo -e "  ${CYAN}dev${NC}    Limited: submit sign requests only"
    echo ""

    mkdir -p "$DATA_DIR"

    # Generate admin key
    log_info "Generating admin API key..."
    "$SCRIPT_DIR/generate-api-key.sh" -n admin -o "$DATA_DIR" -f > /dev/null 2>&1
    ADMIN_PUBLIC_KEY=$(openssl pkey -in "$DATA_DIR/admin_public.pem" -pubin -outform DER 2>/dev/null | base64 | tr -d '\n')
    ADMIN_PRIVATE_KEY=$(openssl pkey -in "$DATA_DIR/admin_private.pem" -outform DER 2>/dev/null | base64 | tr -d '\n')
    echo -e "  Key ID:      ${GREEN}admin${NC}"
    echo -e "  Private key: ${DIM}$DATA_DIR/admin_private.pem${NC}  (keep secret!)"
    echo -e "  Public key:  ${DIM}$DATA_DIR/admin_public.pem${NC}"
    echo ""

    # Generate dev key
    log_info "Generating dev API key..."
    "$SCRIPT_DIR/generate-api-key.sh" -n dev -o "$DATA_DIR" -f > /dev/null 2>&1
    DEV_PUBLIC_KEY=$(openssl pkey -in "$DATA_DIR/dev_public.pem" -pubin -outform DER 2>/dev/null | base64 | tr -d '\n')
    DEV_PRIVATE_KEY=$(openssl pkey -in "$DATA_DIR/dev_private.pem" -outform DER 2>/dev/null | base64 | tr -d '\n')
    echo -e "  Key ID:      ${GREEN}dev${NC}"
    echo -e "  Private key: ${DIM}$DATA_DIR/dev_private.pem${NC}  (keep secret!)"
    echo -e "  Public key:  ${DIM}$DATA_DIR/dev_public.pem${NC}"
    echo ""
}

step_tls() {
    echo -e "${BOLD}=============================================================${NC}"
    echo -e "${BOLD}  Step 3/5: TLS Certificates${NC}"
    echo -e "${BOLD}=============================================================${NC}"
    echo ""
    echo "Transport security mode:"

    if [ "$DEPLOY_MODE" = "docker" ]; then
        # Docker mode: default mTLS
        echo -e "  ${CYAN}1)${NC} HTTP   ${DIM}plain, no encryption (development only)${NC}"
        echo -e "  ${CYAN}2)${NC} TLS    ${DIM}server-side only, clients verify server identity${NC}"
        echo -e "  ${CYAN}3)${NC} mTLS   ${DIM}mutual TLS, both sides verify each other${NC} \u2b50 recommended"
        echo ""
        TLS_CHOICE=$(ask "Select [1/2/3]" 3 1 2 3)
    else
        # Local mode: default HTTP
        echo -e "  ${CYAN}1)${NC} HTTP   ${DIM}plain, no encryption (fine for localhost development)${NC}"
        echo -e "  ${CYAN}2)${NC} TLS    ${DIM}server-side only, clients verify server identity${NC}"
        echo -e "  ${CYAN}3)${NC} mTLS   ${DIM}mutual TLS, both sides verify each other (recommended for production)${NC}"
        echo ""
        TLS_CHOICE=$(ask "Select [1/2/3]" 1 1 2 3)
    fi

    TLS_ENABLED="false"
    CLIENT_AUTH="false"
    SCHEME="http"

    case "$TLS_CHOICE" in
        2)
            TLS_ENABLED="true"
            CLIENT_AUTH="false"
            SCHEME="https"
            log_info "Selected: TLS (server-side)"
            echo ""
            log_info "Generating TLS certificates..."
            "$SCRIPT_DIR/gen-certs.sh"
            ;;
        3)
            TLS_ENABLED="true"
            CLIENT_AUTH="true"
            SCHEME="https"
            log_info "Selected: mTLS (mutual)"
            echo ""
            log_info "Generating TLS certificates..."
            "$SCRIPT_DIR/gen-certs.sh"
            ;;
        *)
            log_info "Selected: HTTP (no TLS)"
            ;;
    esac
    echo ""
}

install_foundry() {
    mkdir -p "$DATA_DIR/foundry" "$DATA_DIR/forge-workspace"

    if [ ! -f "$DATA_DIR/foundry/forge" ]; then
        log_info "Downloading Foundry binaries (for Solidity expression rules)..."
        FOUNDRY_VERSION="v1.5.1"

        case "$(uname -s)-$(uname -m)" in
            Linux-x86_64)      FOUNDRY_PLATFORM="linux_amd64" ;;
            Linux-aarch64)     FOUNDRY_PLATFORM="linux_arm64" ;;
            Darwin-x86_64)     FOUNDRY_PLATFORM="darwin_amd64" ;;
            Darwin-arm64)      FOUNDRY_PLATFORM="darwin_arm64" ;;
            *)
                log_warn "Unsupported platform ($(uname -s)-$(uname -m)) for Foundry auto-download."
                log_warn "Install Foundry manually: https://book.getfoundry.sh/getting-started/installation"
                FOUNDRY_PLATFORM=""
                ;;
        esac

        if [ -n "${FOUNDRY_PLATFORM:-}" ]; then
            curl -sL "https://github.com/foundry-rs/foundry/releases/download/${FOUNDRY_VERSION}/foundry_${FOUNDRY_VERSION}_${FOUNDRY_PLATFORM}.tar.gz" | \
                tar -xzf - -C "$DATA_DIR/foundry" 2>/dev/null
            chmod +x "$DATA_DIR/foundry/"* 2>/dev/null || true
            log_info "Foundry binaries downloaded to $DATA_DIR/foundry/"
        fi
    else
        log_info "Foundry binaries already present"
    fi

    # Install forge-std
    if [ ! -d "$DATA_DIR/forge-workspace/lib/forge-std/src" ]; then
        FORGE_BIN="$DATA_DIR/foundry/forge"
        if [ -x "$FORGE_BIN" ]; then
            log_info "Installing forge-std..."
            cat > "$DATA_DIR/forge-workspace/foundry.toml" << 'FOUNDRY_EOF'
[profile.default]
src = "."
test = "."
out = "out"
libs = ["lib"]
remappings = ["forge-std/=lib/forge-std/src/"]
via_ir = true
optimizer = false
incremental = true
FOUNDRY_EOF
            (cd "$DATA_DIR/forge-workspace" && "$FORGE_BIN" install foundry-rs/forge-std --no-git 2>/dev/null) || \
                log_warn "Failed to install forge-std. Solidity rules may not work until installed."
        fi
    else
        log_info "forge-std already present"
    fi
}

step_generate_config() {
    echo -e "${BOLD}=============================================================${NC}"
    echo -e "${BOLD}  Step 4/5: Generate Configuration${NC}"
    echo -e "${BOLD}=============================================================${NC}"
    echo ""

    cd "$PROJECT_DIR"

    # Check if config already exists
    if [ -f "$CONFIG_FILE" ]; then
        log_warn "$CONFIG_FILE already exists."
        read -rp "Overwrite? (y/N): " OVERWRITE
        if [[ ! "$OVERWRITE" =~ ^[Yy]$ ]]; then
            log_info "Keeping existing $CONFIG_FILE"
            SKIP_CONFIG=true
        fi
    fi

    if [ "${SKIP_CONFIG:-}" != "true" ]; then
        cat > "$CONFIG_FILE" << CONFIGEOF
# Generated by setup.sh — $(date '+%Y-%m-%d %H:%M:%S')
# Full reference: docs/CONFIGURATION.md
# All options:    config.example.yaml

server:
  host: "0.0.0.0"
  port: $PORT
  tls:
    enabled: $TLS_ENABLED
    cert_file: "./certs/server.crt"
    key_file: "./certs/server.key"
    ca_file: "./certs/ca.crt"
    client_auth: $CLIENT_AUTH

database:
  dsn: "$DSN"

chains:
  evm:
    enabled: true
    signers:
      private_keys: []
      # keystores: []      # Create via TUI or API after startup
      # hd_wallets: []     # Create via TUI or API after startup
    keystore_dir: "./data/keystores"
    hd_wallet_dir: "./data/hd-wallets"
    foundry:
      enabled: true
      forge_path: ""
      cache_dir: "./data/forge-cache"
      temp_dir: "./data/forge-workspace"
      timeout: "30s"

security:
  max_request_age: "60s"
  rate_limit_default: 100
  nonce_required: true
  manual_approval_enabled: true
  rules_api_readonly: true      # blocks rule/template CRUD via API (default: true)
  signers_api_readonly: false   # blocks signer/HD-wallet creation via API (default: false)

logger:
  level: "info"
  pretty: true

api_keys:
  - id: "admin"
    name: "Admin"
    public_key: "$ADMIN_PUBLIC_KEY"
    admin: true
    enabled: true
    rate_limit: 1000

  - id: "dev"
    name: "Dev"
    public_key: "$DEV_PUBLIC_KEY"
    admin: false
    enabled: true
    rate_limit: 100
CONFIGEOF

        log_info "Configuration written to $CONFIG_FILE"
    fi

    # Create .env for Docker mode with random password
    if [ "$DEPLOY_MODE" = "docker" ]; then
        if [ ! -f ".env" ]; then
            cat > .env << ENVEOF
# PostgreSQL
POSTGRES_USER=signer
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
POSTGRES_DB=remote_signer
POSTGRES_PORT=5432

# EVM Signer (hex private key, without 0x prefix)
# Add after creating a signer, or leave empty for API/TUI-managed signers
EVM_SIGNER_KEY_1=

# Optional: Notifications
SLACK_BOT_TOKEN=
PUSHOVER_APP_TOKEN=
ENVEOF
            log_info ".env created with auto-generated PostgreSQL password."
        else
            log_info ".env already exists, keeping it."
        fi
    fi

    # Create directories
    mkdir -p "$DATA_DIR/keystores" "$DATA_DIR/hd-wallets" "$DATA_DIR/forge-cache"

    # Summary
    echo ""
    echo -e "  ${DIM}Config:${NC}    $CONFIG_FILE"

    if [ "$DEPLOY_MODE" = "local" ]; then
        echo -e "  ${DIM}Database:${NC}  SQLite (file:./data/remote-signer.db)"
    else
        echo -e "  ${DIM}Database:${NC}  PostgreSQL (via Docker)"
    fi

    echo -e "  ${DIM}Server:${NC}    ${SCHEME}://localhost:${PORT}"
    echo -e "  ${DIM}API Keys:${NC}  admin (admin), dev (limited)"
    echo -e "  ${DIM}Foundry:${NC}   enabled"

    case "$TLS_CHOICE" in
        1) echo -e "  ${DIM}TLS:${NC}       disabled" ;;
        2) echo -e "  ${DIM}TLS:${NC}       TLS (server-side)" ;;
        3) echo -e "  ${DIM}TLS:${NC}       mTLS (mutual)" ;;
    esac
    echo ""
}

step_done() {
    echo -e "${BOLD}=============================================================${NC}"
    echo -e "${BOLD}  Step 5/5: Done!${NC}"
    echo -e "${BOLD}=============================================================${NC}"
    echo ""

    # --- Start command ---
    echo -e "${CYAN}Start the server:${NC}"
    if [ "$DEPLOY_MODE" = "local" ]; then
        echo "  ./scripts/deploy.sh local-run"
    else
        echo "  ./scripts/deploy.sh run --no-screen   # background, no screen (recommended after setup)"
        echo "  ./scripts/deploy.sh run              # with screen (only if you need to enter keystore password)"
        echo ""
        echo -e "${CYAN}Docker (optional):${NC} If you use 'run' without --no-screen, detach with  ${BOLD}Ctrl+A${NC} then  ${BOLD}D${NC}; reattach: ./scripts/deploy.sh attach"
        echo ""
    fi
    echo ""

    # --- Health check ---
    echo -e "${CYAN}Health check:${NC}"
    if [ "$TLS_CHOICE" = "3" ]; then
        echo "  curl --cacert certs/ca.crt --cert certs/client.crt --key certs/client.key ${SCHEME}://localhost:${PORT}/health"
    elif [ "$TLS_CHOICE" = "2" ]; then
        echo "  curl --cacert certs/ca.crt ${SCHEME}://localhost:${PORT}/health"
    else
        echo "  curl ${SCHEME}://localhost:${PORT}/health"
    fi
    echo ""

    # --- Add signer ---
    # Prefer downloading TUI from GitHub Release (public repo); fall back to local go build
    TUI_BIN="$PROJECT_DIR/remote-signer-tui"
    if ! download_tui_from_release; then
        if command -v go &>/dev/null && [ -f "$PROJECT_DIR/go.mod" ]; then
            (cd "$PROJECT_DIR" && go build -o remote-signer-tui ./cmd/tui 2>/dev/null) || true
        fi
    fi

    echo -e "${CYAN}Add a signer (after server is running):${NC}"
    echo ""
    echo "  Via TUI (recommended: use -api-key-file to avoid paste):"
    if [ -x "$TUI_BIN" ]; then
        echo "    ./remote-signer-tui -api-key-id admin -api-key-file data/admin_private.pem \\"
    else
        echo "    go build -o remote-signer-tui ./cmd/tui   # requires Go 1.24+ (https://go.dev/dl/)"
        echo "    ./remote-signer-tui -api-key-id admin -api-key-file data/admin_private.pem \\"
    fi
    if [ "$TLS_CHOICE" = "3" ]; then
        echo "      -url ${SCHEME}://localhost:${PORT} \\"
        echo "      -tls-ca ./certs/ca.crt \\"
        echo "      -tls-cert ./certs/client.crt \\"
        echo "      -tls-key ./certs/client.key"
    elif [ "$TLS_CHOICE" = "2" ]; then
        echo "      -url ${SCHEME}://localhost:${PORT} \\"
        echo "      -tls-ca ./certs/ca.crt"
    else
        echo "      -url ${SCHEME}://localhost:${PORT}"
    fi
    echo ""
    echo "    Or set REMOTE_SIGNER_PRIVATE_KEY and omit -api-key-file. Then use Signers tab to add keystore or HD wallet."
    echo ""
    if [ ! -x "$TUI_BIN" ]; then
        echo "  (No Go? Add signers via API instead — see docs/API.md)"
        echo ""
    fi
    echo "  Via API (create keystore):"
    echo "    See docs/API.md for authenticated request examples."
    echo ""

    # --- Or add signer in config ---
    echo -e "${CYAN}Or add a signer directly in config:${NC}"
    echo "  Edit $CONFIG_FILE -> chains.evm.signers.private_keys"
    echo "  See config.example.yaml for examples."
    echo ""

    # --- Documentation ---
    echo -e "${CYAN}Documentation:${NC}"
    echo "  README.md               Quick start & overview"
    echo "  docs/CONFIGURATION.md   Full config reference"
    echo "  docs/RULE_SYNTAX.md     Rule types & examples"
    echo "  docs/API.md             API reference"
    echo "  docs/DEPLOYMENT.md      Production deployment"
    echo "  docs/TLS.md             TLS/mTLS setup"
    echo ""

    log_info "Setup complete!"
    echo ""
}

# Ask to start the server, then optionally launch TUI to add signers (one-click deploy + import flow)
start_server_now() {
    echo ""
    read -rp "Start the server now? (Y/n): " START_NOW
    START_NOW="${START_NOW:-Y}"
    if [ "$START_NOW" = "y" ] || [ "$START_NOW" = "Y" ]; then
        log_info "Starting server..."
        cd "$PROJECT_DIR"
        if [ "$DEPLOY_MODE" = "docker" ]; then
            "$SCRIPT_DIR/deploy.sh" run --no-screen
        else
            "$SCRIPT_DIR/deploy.sh" local-run
        fi
        # Offer to open TUI so user can add signers without pasting key
        echo ""
        read -rp "Open TUI to add signers now? (Y/n): " OPEN_TUI
        OPEN_TUI="${OPEN_TUI:-Y}"
        if [ "$OPEN_TUI" = "y" ] || [ "$OPEN_TUI" = "Y" ]; then
            if [ -x "$TUI_BIN" ] && [ -f "$PROJECT_DIR/data/admin_private.pem" ]; then
                log_info "Launching TUI (use Signers tab to create keystore or HD wallet)..."
                run_tui_for_setup
            elif [ ! -x "$TUI_BIN" ]; then
                log_warn "TUI binary not found. Build with: go build -o remote-signer-tui ./cmd/tui"
                log_info "When ready, run: ./scripts/deploy.sh $([ "$DEPLOY_MODE" = "docker" ] && echo 'run --no-screen' || echo local-run)"
            else
                log_warn "data/admin_private.pem not found; run setup again or use TUI with REMOTE_SIGNER_PRIVATE_KEY."
                log_info "When ready, run: ./scripts/deploy.sh $([ "$DEPLOY_MODE" = "docker" ] && echo 'run --no-screen' || echo local-run)"
            fi
        else
            log_info "When ready, run: ./scripts/deploy.sh $([ "$DEPLOY_MODE" = "docker" ] && echo 'run --no-screen' || echo local-run)"
        fi
    else
        log_info "When ready, run: ./scripts/deploy.sh $([ "$DEPLOY_MODE" = "docker" ] && echo 'run --no-screen' || echo local-run)"
    fi
}

# Read port from config file (server.port); default 8548
tui_port_from_config() {
    local cfg="${1:-$CONFIG_FILE}"
    local p
    if [ -n "$cfg" ] && [ -f "$PROJECT_DIR/$cfg" ]; then
        p=$(grep '^\s*port:' "$PROJECT_DIR/$cfg" 2>/dev/null | head -1 | sed 's/.*port:\s*//' | tr -d ' "')
    fi
    echo "${p:-8548}"
}

# Run TUI with -api-key-file; URL and TLS flags are built from the same config the server uses
run_tui_for_setup() {
    cd "$PROJECT_DIR"
    # Use port and TLS from the config we wrote (so TUI matches server)
    local tui_port
    tui_port=$(tui_port_from_config "$CONFIG_FILE")
    local tui_scheme="http"
    local tui_tls_ca="" tui_tls_cert="" tui_tls_key=""
    if [ -f "$PROJECT_DIR/$CONFIG_FILE" ] && grep -A1 '^\s*tls:' "$PROJECT_DIR/$CONFIG_FILE" 2>/dev/null | grep -q 'enabled:\s*true'; then
        tui_scheme="https"
        tui_tls_ca="-tls-ca ./certs/ca.crt"
        if grep -A5 '^\s*tls:' "$PROJECT_DIR/$CONFIG_FILE" 2>/dev/null | grep -q 'client_auth:\s*true'; then
            tui_tls_cert="-tls-cert ./certs/client.crt"
            tui_tls_key="-tls-key ./certs/client.key"
        fi
    fi
    local tui_url="${tui_scheme}://localhost:${tui_port}"
    # Build and run the exact command that matches server config
    if [ -n "$tui_tls_key" ]; then
        exec "$TUI_BIN" -api-key-id admin -api-key-file data/admin_private.pem -url "$tui_url" \
            $tui_tls_ca $tui_tls_cert $tui_tls_key
    elif [ -n "$tui_tls_ca" ]; then
        exec "$TUI_BIN" -api-key-id admin -api-key-file data/admin_private.pem -url "$tui_url" $tui_tls_ca
    else
        exec "$TUI_BIN" -api-key-id admin -api-key-file data/admin_private.pem -url "$tui_url"
    fi
}

# === Main Flow ================================================================

main() {
    print_banner

    # Ensure we're inside the project directory (auto-clone if not)
    ensure_project_dir

    # Pre-flight: required dependencies
    check_openssl
    check_go

    # Step 1/5: Deployment mode
    step_deployment_mode

    # Docker mode: ensure Docker is installed
    if [ "$DEPLOY_MODE" = "docker" ]; then
        ensure_docker
    fi

    # screen is needed only for local-run; Docker one-click uses run --no-screen
    if [ "$DEPLOY_MODE" = "local" ]; then
        check_screen
    fi

    # Step 2/5: API Keys
    step_api_keys

    # Step 3/5: TLS
    step_tls

    # Foundry installation (non-interactive, both modes need it)
    install_foundry

    # Step 4/5: Generate configuration
    step_generate_config

    # Step 5/5: Done
    step_done

    # One-click: offer to start the server (exec deploy.sh)
    start_server_now
}

main
