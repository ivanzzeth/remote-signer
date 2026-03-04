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
# Binaries from release go here; added to PATH so remote-signer-cli, remote-signer-tui, remote-signer-validate-rules are available
BIN_DIR="${REMOTE_SIGNER_BIN_DIR:-$PROJECT_DIR/bin}"

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
release_asset_suffix() {
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

# Download a single binary from GitHub Releases (latest). Asset name: ${name}-${suffix}, installed as ${BIN_DIR}/${name}.
# Returns 0 on success, 1 on failure (no release, 404, or private repo).
download_release_binary() {
    local name="$1"
    local suffix url dest
    suffix="$(release_asset_suffix)" || return 1
    url="https://github.com/${REMOTE_SIGNER_REPO}/releases/latest/download/${name}-${suffix}"
    dest="$BIN_DIR/$name"
    log_info "Downloading $name (${suffix})..."
    if curl -SLf -# -o "$dest" "$url" 2>/dev/null && [ -s "$dest" ]; then
        chmod +x "$dest"
        return 0
    fi
    rm -f "$dest"
    return 1
}

# Download all release binaries (remote-signer-tui, remote-signer-validate-rules, remote-signer-cli) into BIN_DIR and add BIN_DIR to PATH.
# Exports PATH for current process; optionally appends to user's shell rc so new terminals have it.
download_release_binaries_and_set_path() {
    mkdir -p "$BIN_DIR"
    export PATH="$BIN_DIR:$PATH"

    local suffix
    suffix="$(release_asset_suffix)" 2>/dev/null || true
    if [ -z "$suffix" ]; then
        log_warn "Unsupported OS/arch for release binaries; skipping download."
        return 1
    fi

    local got_any=0
    if download_release_binary "remote-signer-tui"; then got_any=1; fi
    if download_release_binary "remote-signer-validate-rules"; then got_any=1; fi
    if download_release_binary "remote-signer-cli"; then got_any=1; fi

    if [ "$got_any" -eq 0 ]; then
        return 1
    fi
    add_bin_dir_to_path
    return 0
}

# Build remote-signer-tui, remote-signer-validate-rules, remote-signer-cli from source into BIN_DIR.
# Requires Go and go.mod in PROJECT_DIR. Exports PATH and adds BIN_DIR to shell rc on success.
build_from_source_binaries() {
    mkdir -p "$BIN_DIR"
    export PATH="$BIN_DIR:$PATH"

    if ! command -v go &>/dev/null; then
        log_warn "Go not found; install from https://go.dev/dl/"
        return 1
    fi
    if [ ! -f "$PROJECT_DIR/go.mod" ]; then
        log_warn "Not a Go module (no go.mod); cannot build from source."
        return 1
    fi

    log_info "Building CLI tools from source (this may take a minute)..."
    local ok=0
    if (cd "$PROJECT_DIR" && go build -o "$BIN_DIR/remote-signer-tui" ./cmd/tui 2>/dev/null); then
        log_info "Built remote-signer-tui"
        ok=1
    else
        log_warn "Failed to build remote-signer-tui"
    fi
    if (cd "$PROJECT_DIR" && go build -o "$BIN_DIR/remote-signer-validate-rules" ./cmd/validate-rules 2>/dev/null); then
        log_info "Built remote-signer-validate-rules"
        ok=1
    else
        log_warn "Failed to build remote-signer-validate-rules"
    fi
    if (cd "$PROJECT_DIR" && go build -o "$BIN_DIR/remote-signer-cli" ./cmd/remote-signer-cli 2>/dev/null); then
        log_info "Built remote-signer-cli"
        ok=1
    else
        log_warn "Failed to build remote-signer-cli"
    fi

    if [ "$ok" -eq 0 ]; then
        return 1
    fi
    add_bin_dir_to_path
    return 0
}

# Add BIN_DIR to PATH in the user's shell rc so new terminals have remote-signer-cli, remote-signer-tui, remote-signer-validate-rules on PATH.
add_bin_dir_to_path() {
    local rc line
    if [ -n "${ZSH_VERSION:-}" ]; then
        rc="${ZDOTDIR:-$HOME}/.zshrc"
    else
        rc="$HOME/.bashrc"
    fi
    # Prefer existing line that adds our bin dir
    line="export PATH=\"$BIN_DIR:\$PATH\""
    if [ -f "$rc" ] && grep -qF "$BIN_DIR" "$rc" 2>/dev/null; then
        return 0
    fi
    echo "" >> "$rc"
    echo "# Remote Signer CLI/TUI/remote-signer-validate-rules (added by setup.sh)" >> "$rc"
    echo "$line" >> "$rc"
    log_info "Added $BIN_DIR to PATH in $rc. Run \`source $rc\` or open a new terminal to use remote-signer-cli, remote-signer-tui, remote-signer-validate-rules from anywhere."
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
    if [ ! -f "$PROJECT_DIR/go.mod" ] || ! grep -q "remote-signer" "$PROJECT_DIR/go.mod" 2>/dev/null; then
        # Not in project directory — need to clone
        goto_clone
        return
    fi

    # Already in project directory — show version and optionally offer to update
    if [ -d "$PROJECT_DIR/.git" ]; then
        cd "$PROJECT_DIR" || return 0
        local hash tag
        hash=$(git rev-parse --short HEAD 2>/dev/null) || hash=""
        tag=$(git describe --tags --exact-match HEAD 2>/dev/null) || true
        log_info "Repository: ${hash}${tag:+ ($tag)}"

        local branch
        branch=$(git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's|^refs/remotes/origin/||') || branch="main"
        if git fetch origin --quiet 2>/dev/null; then
            local behind
            behind=$(git rev-list HEAD.."origin/$branch" --count 2>/dev/null) || behind=0
            if [ "${behind:-0}" -gt 0 ]; then
                local remote_hash remote_tag
                remote_hash=$(git rev-parse --short "origin/$branch" 2>/dev/null) || remote_hash=""
                remote_tag=$(git describe --tags "origin/$branch" 2>/dev/null) || true
                echo ""
                log_warn "Local repository is behind remote."
                echo "  Current: ${hash}${tag:+ ($tag)}"
                echo "  Remote:  ${remote_hash}${remote_tag:+ ($remote_tag)}"
                echo ""
                read -rp "  Update to latest? (y/N): " UPDATE_REPO
                if [[ "$UPDATE_REPO" =~ ^[Yy]$ ]]; then
                    git pull origin "$branch"
                    log_info "Updated to latest."
                fi
            fi
        fi
    fi
    return 0
}

goto_clone() {
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

    if [ -d "$CLONE_DIR" ]; then
        if [ -f "$CLONE_DIR/go.mod" ] && grep -q "remote-signer" "$CLONE_DIR/go.mod" 2>/dev/null; then
            log_info "Directory already exists and appears to be remote-signer. Continuing setup from there."
            exec "$CLONE_DIR/scripts/setup.sh"
        fi
        log_error "Destination already exists and is not empty: $CLONE_DIR"
        log_error "Choose a different directory, or remove it and re-run setup."
        exit 1
    fi

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
    # Docker binary must exist
    if ! command -v docker &>/dev/null; then
        log_warn "Docker is not installed."
    else
        # Docker binary exists; check if we can run it (direct or via sudo)
        if docker compose version &>/dev/null; then
            log_info "Docker detected: $(docker --version)"
            return 0
        fi
        if sudo docker compose version &>/dev/null; then
            if ! groups "$USER" | grep -q docker; then
                log_info "Adding $USER to docker group (sudo may prompt for your password)..."
                sudo usermod -aG docker "$USER"
                log_warn "Added $USER to docker group. Run 'newgrp docker' in this terminal (or log out and back in) for it to take effect, then continue."
            else
                log_warn "Docker is installed but this shell does not have the docker group yet. Run 'newgrp docker' or open a new login."
            fi
            log_info "Docker detected: $(sudo docker --version)"
            return 0
        fi
        log_warn "Docker is installed but the daemon may not be running or current user has no permission to access it."
    fi

    # Not available: offer install or exit
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
        # Use 127.0.0.1: remote-signer uses network_mode: host, cannot resolve Docker hostname "postgres"
        DSN="\${DATABASE_DSN:-postgres://signer:${POSTGRES_PASSWORD}@127.0.0.1:25432/remote_signer?sslmode=disable}"
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
    echo "Two API key pairs (admin + dev):"
    echo ""
    echo -e "  ${CYAN}admin${NC}  Full access: manage signers, approve requests, manage rules"
    echo -e "  ${CYAN}dev${NC}    Limited: submit sign requests only"
    echo ""

    mkdir -p "$DATA_DIR"

    REGENERATE_KEYS=true
    if [ -f "$DATA_DIR/admin_private.pem" ] || [ -f "$DATA_DIR/admin_public.pem" ]; then
        echo -e "  ${YELLOW}Existing API keys found in $DATA_DIR/${NC}"
        read -rp "  Regenerate keys? (y/N): " REGEN
        if [[ ! "$REGEN" =~ ^[Yy]$ ]]; then
            REGENERATE_KEYS=false
            log_info "Using existing API keys (config will use these so TUI can connect)."
        fi
        echo ""
    fi

    if [ "$REGENERATE_KEYS" = true ]; then
        log_info "Generating admin API key..."
        "$SCRIPT_DIR/generate-api-key.sh" -n admin -o "$DATA_DIR" -f > /dev/null 2>&1
        log_info "Generating dev API key..."
        "$SCRIPT_DIR/generate-api-key.sh" -n dev -o "$DATA_DIR" -f > /dev/null 2>&1
    fi

    # Load public/private key values (from newly generated or existing files)
    ADMIN_PUBLIC_KEY=$(openssl pkey -in "$DATA_DIR/admin_public.pem" -pubin -outform DER 2>/dev/null | base64 | tr -d '\n')
    ADMIN_PRIVATE_KEY=$(openssl pkey -in "$DATA_DIR/admin_private.pem" -outform DER 2>/dev/null | base64 | tr -d '\n')
    if [ -z "$ADMIN_PUBLIC_KEY" ] || [ -z "$ADMIN_PRIVATE_KEY" ]; then
        log_error "Failed to read admin key from $DATA_DIR/admin_*.pem"
        exit 1
    fi
    echo -e "  Key ID:      ${GREEN}admin${NC}"
    echo -e "  Private key: ${DIM}$DATA_DIR/admin_private.pem${NC}  (keep secret!)"
    echo -e "  Public key:  ${DIM}$DATA_DIR/admin_public.pem${NC}"
    echo ""

    if [ ! -f "$DATA_DIR/dev_private.pem" ] || [ ! -f "$DATA_DIR/dev_public.pem" ]; then
        log_info "Generating dev API key..."
        "$SCRIPT_DIR/generate-api-key.sh" -n dev -o "$DATA_DIR" -f > /dev/null 2>&1
    fi
    DEV_PUBLIC_KEY=$(openssl pkey -in "$DATA_DIR/dev_public.pem" -pubin -outform DER 2>/dev/null | base64 | tr -d '\n')
    DEV_PRIVATE_KEY=$(openssl pkey -in "$DATA_DIR/dev_private.pem" -outform DER 2>/dev/null | base64 | tr -d '\n')
    if [ -z "$DEV_PUBLIC_KEY" ] || [ -z "$DEV_PRIVATE_KEY" ]; then
        log_error "Failed to read dev key from $DATA_DIR/dev_*.pem"
        exit 1
    fi
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

# Optional: set IP whitelist (allowed_ips only; trust_proxy/trusted_proxies are not managed here)
step_ip_whitelist() {
    IP_WHITELIST_ENABLED=false
    IP_WHITELIST_ALLOWED_IPS=()

    echo -e "${BOLD}  IP whitelist (optional)${NC}"
    echo "Restrict API access to specific IPs or CIDR ranges."
    read -rp "Set IP whitelist? (y/N): " SET_IP_WHITELIST
    if [[ ! "$SET_IP_WHITELIST" =~ ^[Yy]$ ]]; then
        return 0
    fi

    echo "Enter allowed IPs or CIDRs (comma or newline separated; empty line to finish):"
    while true; do
        read -r line
        line=$(printf '%s' "$line" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$line" ]] && break
        IFS=',' read -ra parts <<< "$line"
        for p in "${parts[@]}"; do
            p=$(printf '%s' "$p" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            [[ -n "$p" ]] && IP_WHITELIST_ALLOWED_IPS+=("$p")
        done
    done

    if [ ${#IP_WHITELIST_ALLOWED_IPS[@]} -eq 0 ]; then
        log_warn "No IPs entered; IP whitelist will remain disabled."
        return 0
    fi
    IP_WHITELIST_ENABLED=true
    log_info "IP whitelist enabled with ${#IP_WHITELIST_ALLOWED_IPS[@]} entry/entries."
}

step_generate_config() {
    echo -e "${BOLD}=============================================================${NC}"
    echo -e "${BOLD}  Step 4/5: Generate Configuration${NC}"
    echo -e "${BOLD}=============================================================${NC}"
    echo ""

    cd "$PROJECT_DIR"

    NEWLINE=$'\n'
    # Build allowed_ips YAML for ip_whitelist (only when enabled; trust_proxy/trusted_proxies unchanged)
    IP_WHITELIST_ALLOWED_IPS_YAML=""
    if [ "${IP_WHITELIST_ENABLED:-false}" = "true" ] && [ ${#IP_WHITELIST_ALLOWED_IPS[@]} -gt 0 ] 2>/dev/null; then
        IP_WHITELIST_ALLOWED_IPS_YAML="allowed_ips:${NEWLINE}"
        for ip in "${IP_WHITELIST_ALLOWED_IPS[@]}"; do
            IP_WHITELIST_ALLOWED_IPS_YAML="${IP_WHITELIST_ALLOWED_IPS_YAML}      - \"${ip}\"${NEWLINE}"
        done
    else
        IP_WHITELIST_ALLOWED_IPS_YAML="allowed_ips: []"
    fi

    # Always overwrite config so TLS, port, and keys stay in sync with setup choices
    if [ -f "$CONFIG_FILE" ]; then
        log_info "Updating existing $CONFIG_FILE"
    fi
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
  manual_approval_enabled: false  # default: no manual approval; no-match => reject
  rules_api_readonly: true
  signers_api_readonly: false
  allow_sighup_rules_reload: false
  approval_guard:
    enabled: false
  ip_whitelist:
    enabled: ${IP_WHITELIST_ENABLED:-false}
    $IP_WHITELIST_ALLOWED_IPS_YAML
    trust_proxy: false

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
    allow_all_signers: true      # setup: allow any signer for local dev
    allow_all_hd_wallets: true   # setup: allow any HD wallet for local dev
CONFIGEOF

    log_info "Configuration written to $CONFIG_FILE"

    # Ensure admin public_key in config matches current data/admin_public.pem
    if [ -f "$PROJECT_DIR/$CONFIG_FILE" ] && [ -n "${ADMIN_PUBLIC_KEY:-}" ]; then
        awk -v key="$ADMIN_PUBLIC_KEY" '
            /^[[:space:]]*- id: "admin"/ { in_admin=1 }
            in_admin && /^[[:space:]]*public_key:/ { sub(/"([^"]*)"/, "\"" key "\""); in_admin=0 }
            { print }
        ' "$PROJECT_DIR/$CONFIG_FILE" > "$PROJECT_DIR/$CONFIG_FILE.tmp" && mv "$PROJECT_DIR/$CONFIG_FILE.tmp" "$PROJECT_DIR/$CONFIG_FILE"
    fi

    # Create .env for Docker mode with random password
    if [ "$DEPLOY_MODE" = "docker" ]; then
        if [ ! -f ".env" ]; then
            cat > .env << ENVEOF
# PostgreSQL
POSTGRES_USER=signer
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
POSTGRES_DB=remote_signer
POSTGRES_PORT=25432

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

# Interactive step: optionally add rule(s) from preset(s). Prompts for preset choice and variable overrides (with descriptions from template).
step_preset_rules() {
    echo -e "${BOLD}=============================================================${NC}"
    echo -e "${BOLD}  Step 4b: Add rules from preset (optional)${NC}"
    echo -e "${BOLD}=============================================================${NC}"
    echo ""
    echo "You can add a rule from a preset (e.g. Polymarket Safe). Variables will be prompted with descriptions from the template."
    echo ""
    read -rp "Add a rule from a preset? (Y/n): " ADD_PRESET
    ADD_PRESET="${ADD_PRESET:-Y}"
    if [[ "$ADD_PRESET" =~ ^[Nn]$ ]]; then
        return 0
    fi

    # Ensure CLI is available (same dir as TUI; download or PATH)
    export PATH="$BIN_DIR:$PATH"
    if ! command -v remote-signer-cli &>/dev/null; then
        if ! download_release_binaries_and_set_path 2>/dev/null; then
            if command -v go &>/dev/null && [ -f "$PROJECT_DIR/go.mod" ]; then
                export PATH="$PROJECT_DIR:$PATH"
                if (cd "$PROJECT_DIR" && go build -o remote-signer-cli ./cmd/remote-signer-cli 2>/dev/null); then
                    mv "$PROJECT_DIR/remote-signer-cli" "$BIN_DIR/remote-signer-cli" 2>/dev/null || true
                    export PATH="$BIN_DIR:$PATH"
                fi
            fi
        else
            export PATH="$BIN_DIR:$PATH"
        fi
    fi
    if ! command -v remote-signer-cli &>/dev/null; then
        log_warn "remote-signer-cli not found; skipping preset step. Install from release or build with: go build -o remote-signer-cli ./cmd/remote-signer-cli"
        return 0
    fi

    PRESETS_DIR="${PROJECT_DIR}/rules/presets"
    if [ ! -d "$PRESETS_DIR" ]; then
        log_warn "Presets directory not found: $PRESETS_DIR"
        return 0
    fi

    while true; do
        # List presets: output is "# Preset file | template(s)" then "file.yaml | Template Name"
        list_out=$(remote-signer-cli preset list --presets-dir "$PRESETS_DIR" 2>/dev/null) || break
        presets=()
        while IFS= read -r line; do
            [[ "$line" =~ ^# ]] && continue
            [[ -z "$line" ]] && continue
            # First column (before " | ")
            name="${line%% | *}"
            name="${name%.yaml}"
            name="${name%.yml}"
            [[ -n "$name" ]] && presets+=("$name")
        done <<< "$list_out"

        if [ ${#presets[@]} -eq 0 ]; then
            log_warn "No presets found in $PRESETS_DIR"
            break
        fi

        echo ""
        echo "Available presets:"
        for i in "${!presets[@]}"; do
            echo -e "  ${CYAN}$((i+1)))${NC} ${presets[$i]}"
        done
        echo ""
        read -rp "Select preset [1]: " choice
        choice="${choice:-1}"
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#presets[@]} ]; then
            log_warn "Invalid choice; skipping preset."
            break
        fi
        PRESET_NAME="${presets[$((choice-1))]}"
        # Pass full filename to CLI (preset list strips .yaml/.yml; add back for .preset and .preset.js.yaml)
        PRESET_FILE="$PRESET_NAME"
        [[ "$PRESET_FILE" != *.yaml ]] && [[ "$PRESET_FILE" != *.yml ]] && PRESET_FILE="${PRESET_FILE}.yaml"

        # Get variables to prompt (name + description from template)
        set_args=()
        vars_out=$(remote-signer-cli preset vars "$PRESET_FILE" --presets-dir "$PRESETS_DIR" --project-dir "$PROJECT_DIR" 2>/dev/null) || true
        if [ -n "$vars_out" ]; then
            echo ""
            echo "Enter values for the following variables (descriptions from template)."
            echo "  Use comma-separated (a,b,c) or newline-separated (one per line; empty line to finish)."
            # Read vars from fd 3 so that 'read -rp' below still reads from terminal (stdin), not from vars_out
            while IFS= read -r line <&3; do
                [[ -z "$line" ]] && continue
                name="${line%%$'\t'*}"
                desc="${line#*$'\t'}"
                if [ -n "$name" ]; then
                    val=""
                    first=1
                    while true; do
                        if [ "$first" -eq 1 ]; then
                            if [ -n "$desc" ]; then
                                read -rp "  $name ($desc): " ln
                            else
                                read -rp "  $name: " ln
                            fi
                            first=0
                        else
                            read -rp "    " ln
                        fi
                        ln=$(printf '%s' "$ln" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                        [[ -z "$ln" ]] && break
                        val="${val:+$val,}$ln"
                    done
                    set_args+=(--set "$name=$val")
                fi
            done 3<<< "$vars_out"
        fi

        log_info "Adding rule from preset: $PRESET_NAME"
        if [ ${#set_args[@]} -gt 0 ]; then
            remote-signer-cli preset create-from "$PRESET_FILE" --config "$PROJECT_DIR/$CONFIG_FILE" --write --presets-dir "$PRESETS_DIR" "${set_args[@]}" || log_warn "Failed to add preset rule"
        else
            remote-signer-cli preset create-from "$PRESET_FILE" --config "$PROJECT_DIR/$CONFIG_FILE" --write --presets-dir "$PRESETS_DIR" || log_warn "Failed to add preset rule"
        fi

        echo ""
        read -rp "Add another preset? (y/N): " ANOTHER
        if [[ ! "$ANOTHER" =~ ^[Yy]$ ]]; then
            break
        fi
    done
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
    # Get CLI tools: user chooses download from release or build from source
    echo -e "${CYAN}CLI tools (remote-signer-tui, remote-signer-validate-rules, remote-signer-cli):${NC}"
    echo "  1) Download from release (latest; no Go required)"
    echo "  2) Build from source (quick verify without waiting for release; requires Go)"
    echo ""
    BINARIES_CHOICE=$(ask "Choose [1/2]" 1 1 2)

    TUI_BIN="$BIN_DIR/remote-signer-tui"
    if [ "$BINARIES_CHOICE" = "2" ]; then
        if ! build_from_source_binaries; then
            log_warn "Build from source failed; trying download from release..."
            download_release_binaries_and_set_path || true
        fi
    else
        if ! download_release_binaries_and_set_path; then
            log_warn "Download failed; trying build from source..."
            build_from_source_binaries || true
        fi
    fi
    # If TUI still not in BIN_DIR, prefer PROJECT_DIR binary for backward compat
    if [ ! -x "$TUI_BIN" ] && [ -x "$PROJECT_DIR/remote-signer-tui" ]; then
        TUI_BIN="$PROJECT_DIR/remote-signer-tui"
    fi

    echo -e "${CYAN}Add a signer (after server is running):${NC}"
    echo ""
    echo "  Via TUI (recommended: use -api-key-file to avoid paste):"
    if [ -x "$TUI_BIN" ]; then
        echo "    remote-signer-tui -api-key-id admin -api-key-file data/admin_private.pem \\"
        echo "      # or: $TUI_BIN -api-key-id admin -api-key-file data/admin_private.pem \\"
    else
        echo "    go build -o remote-signer-tui ./cmd/tui   # requires Go 1.24+ (https://go.dev/dl/)"
        echo "    remote-signer-tui -api-key-id admin -api-key-file data/admin_private.pem \\"
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
    if [ -d "$BIN_DIR" ] && [ -x "$BIN_DIR/remote-signer-tui" ]; then
        echo -e "  ${DIM}CLI tools on PATH:${NC} remote-signer-tui, remote-signer-validate-rules, remote-signer-cli (from $BIN_DIR)"
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

# Check if server is already running on the configured port; if so, offer to stop and restart (default: yes).
# Detects Docker (container remote-signer-app or compose service) vs local (PID file or process on port).
# Sets SKIP_START=1 if user declines to stop (caller should skip starting).
check_server_running_and_maybe_stop() {
    SKIP_START=0
    local port
    port=$(tui_port_from_config "$CONFIG_FILE")
    # Portable port-in-use check: try /dev/tcp (bash), then ss, then lsof
    local port_in_use=0
    if (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
        port_in_use=1
    elif command -v ss &>/dev/null && ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        port_in_use=1
    elif command -v lsof &>/dev/null && lsof -i ":$port" -sTCP:LISTEN 2>/dev/null | grep -q .; then
        port_in_use=1
    fi
    [ "$port_in_use" -eq 0 ] && return 0

    # Detect Docker vs local
    local running_as=""
    cd "$PROJECT_DIR"
    if command -v docker &>/dev/null; then
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -qE 'remote-signer-app|remote-signer'; then
            running_as="Docker"
        elif (cd "$PROJECT_DIR" && docker compose ps --status running 2>/dev/null) | grep -q .; then
            running_as="Docker"
        fi
    fi
    if [ -z "$running_as" ] && [ -f "$PROJECT_DIR/.local-signer.pid" ]; then
        local pid
        pid=$(cat "$PROJECT_DIR/.local-signer.pid" 2>/dev/null)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            running_as="local process"
        fi
    fi
    if [ -z "$running_as" ]; then
        running_as="process on port $port"
    fi

    echo ""
    log_warn "Server is already running ($running_as)."
    read -rp "Stop and restart the service? (Y/n): " STOP_RESTART
    STOP_RESTART="${STOP_RESTART:-Y}"
    if [ "$STOP_RESTART" != "y" ] && [ "$STOP_RESTART" != "Y" ]; then
        log_info "Skipping stop. Server remains running; restart later with: ./scripts/deploy.sh $([ "$DEPLOY_MODE" = "docker" ] && echo 'run --no-screen' || echo 'local-run')"
        SKIP_START=1
        return 0
    fi
    if [ "$running_as" = "Docker" ]; then
        log_info "Stopping Docker services..."
        "$SCRIPT_DIR/deploy.sh" stop
    else
        log_info "Stopping local server..."
        "$SCRIPT_DIR/deploy.sh" local-down
    fi
    # Brief pause so port is released
    sleep 2
}

# Ask to start the server, then optionally launch TUI to add signers (one-click deploy + import flow)
start_server_now() {
    # If server is already running, offer to stop and restart (default: yes)
    check_server_running_and_maybe_stop
    if [ "${SKIP_START:-0}" -eq 1 ]; then
        return 0
    fi

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

    # Optional: IP whitelist (allowed_ips only)
    step_ip_whitelist

    # Step 4/5: Generate configuration
    step_generate_config

    # Step 4b: Optionally add rules from presets (interactive)
    step_preset_rules

    # Step 5/5: Done
    step_done

    # One-click: offer to start the server (exec deploy.sh)
    start_server_now
}

main
