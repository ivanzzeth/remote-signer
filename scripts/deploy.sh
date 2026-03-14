#!/bin/bash
# =============================================================================
# Remote Signer Deployment Script
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Resolve the docker compose command once at startup.
# DOCKER_COMPOSE is an array so "docker compose" (two words) works correctly with "$@".
if docker compose version &>/dev/null 2>&1; then
    DOCKER_COMPOSE=(docker compose)
elif command -v docker-compose &>/dev/null && docker-compose version &>/dev/null 2>&1; then
    DOCKER_COMPOSE=(docker-compose)
else
    # Allow commands that don't need docker (e.g. gen-certs, local-run) to proceed
    DOCKER_COMPOSE=()
fi

# Wrapper function for convenience within the script
docker_compose() {
    if [ ${#DOCKER_COMPOSE[@]} -eq 0 ]; then
        log_error "Docker Compose not found. Install the 'docker compose' plugin or standalone 'docker-compose'."
        exit 1
    fi
    "${DOCKER_COMPOSE[@]}" "$@"
}

# =============================================================================
# Usage
# =============================================================================
usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

Docker Commands:
    init        Initialize deployment environment (create directories, generate keys)
    up          Start all services (background mode)
    run         Start remote-signer (use --no-screen for background, no password/screen)
    run --no-screen   Start in background (no screen; use when no keystore password needed)
    attach      Reattach to running remote-signer session (only when started with 'run' without --no-screen)
    down        Stop all services
    restart     Restart remote-signer interactively (for password input)
    logs        View service logs
    build       Build Docker images
    clean       Remove all containers and volumes

Local Commands (no Docker):
    local-run     Build & start remote-signer locally (for keystore password input)
    local-down    Stop locally running remote-signer
    local-logs    Tail local remote-signer logs
    local-attach  Reattach to running local screen session

Common Commands:
    gen-certs   Generate TLS certificates (CA + server + client)
    status      Check service status (auto-detects TLS and local/docker mode)

Options:
    -h, --help  Show this help message

Examples:
    $0 init                 # Initialize environment
    $0 gen-certs            # Generate TLS/mTLS certificates
    $0 gen-certs 10.0.0.5   # Generate certs with extra SAN IP
    $0 local-run            # Build & run locally (enter keystore password)
    $0 local-down           # Stop local instance
    $0 status               # Check health (auto-detects TLS)
    $0 run                  # Start in Docker with screen (for password input)
    $0 run --no-screen      # Start in Docker in background (no screen, recommended after setup)
    $0 logs -f              # Follow Docker logs
    $0 down                 # Stop Docker services
EOF
}

# =============================================================================
# Initialize environment
# =============================================================================
init_environment() {
    log_info "Initializing deployment environment..."

    cd "$PROJECT_DIR"

    # Create data directories (forge-workspace holds lib/forge-std for Solidity rules; mounted into Docker)
    mkdir -p data/keystores data/foundry data/forge-workspace
    # Preset API: directory for preset YAML files (Docker mounts ./rules:/app/rules)
    mkdir -p rules/presets

    # Download Foundry binaries if not present
    if [ ! -f "data/foundry/forge" ]; then
        log_info "Downloading Foundry binaries (stable v1.5.1)..."
        FOUNDRY_VERSION="v1.5.1"

        # Detect architecture for Docker container
        # On Apple Silicon, Docker runs arm64 containers by default
        ARCH=$(uname -m)
        case "$ARCH" in
            x86_64)
                FOUNDRY_ARCH="linux_amd64"
                ;;
            aarch64|arm64)
                FOUNDRY_ARCH="linux_arm64"
                ;;
            *)
                log_error "Unsupported architecture: $ARCH"
                exit 1
                ;;
        esac

        log_info "Detected architecture: $ARCH -> downloading $FOUNDRY_ARCH"
        curl -L "https://github.com/foundry-rs/foundry/releases/download/${FOUNDRY_VERSION}/foundry_${FOUNDRY_VERSION}_${FOUNDRY_ARCH}.tar.gz" | \
            tar -xzf - -C data/foundry
        chmod +x data/foundry/*
        log_info "Foundry binaries downloaded to data/foundry/"
    else
        log_info "Foundry binaries already exist"
    fi

    # Install forge-std in workspace (used by Solidity rules; mount data/forge-workspace in Docker to avoid install in container)
    if [ ! -d "data/forge-workspace/lib/forge-std/src" ]; then
        log_info "Installing forge-std in data/forge-workspace..."
        FORGE_BIN="$PROJECT_DIR/data/foundry/forge"
        if [ ! -x "$FORGE_BIN" ]; then
            log_error "forge not found at $FORGE_BIN; run init again after Foundry download"
            exit 1
        fi
        # Write foundry.toml so forge install has a project root
        cat > data/forge-workspace/foundry.toml << 'FOUNDRY_EOF'
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
        (cd data/forge-workspace && "$FORGE_BIN" install foundry-rs/forge-std --no-git)
        log_info "forge-std installed in data/forge-workspace/"
    else
        log_info "forge-std already present in data/forge-workspace"
    fi

    # Create .env file if not exists
    if [ ! -f ".env" ]; then
        log_info "Creating .env file..."
        cat > .env << 'EOF'
# =============================================================================
# Remote Signer Environment Configuration
# =============================================================================

# PostgreSQL Configuration
POSTGRES_USER=signer
POSTGRES_PASSWORD=change_me_in_production
POSTGRES_DB=remote_signer
POSTGRES_PORT=25432

# Remote Signer Port
SIGNER_PORT=8548

# EVM Signer Private Key (hex, without 0x prefix)
# Generate with: openssl rand -hex 32
EVM_SIGNER_KEY_1=

# Optional: Notification Tokens
SLACK_BOT_TOKEN=
PUSHOVER_APP_TOKEN=
EOF
        log_warn ".env file created. Please edit it with your configuration!"
    else
        log_info ".env file already exists"
    fi

    # Create config.yaml if not exists
    if [ ! -f "config.yaml" ]; then
        log_info "Creating config.yaml from example..."

        # Check if config.example.yaml exists
        if [ -f "config.example.yaml" ]; then
            cp config.example.yaml config.yaml

            # Update database DSN for Docker
            if command -v sed &> /dev/null; then
                sed -i.bak 's|dsn:.*|dsn: "postgres://signer:change_me_in_production@postgres:5432/remote_signer?sslmode=disable"|' config.yaml
                rm -f config.yaml.bak
            fi

            log_warn "config.yaml created. Please review and update it!"
        else
            log_error "config.example.yaml not found!"
            exit 1
        fi
    else
        log_info "config.yaml already exists"
    fi

    # Generate API key if not exists
    if [ ! -f "data/api_private.pem" ]; then
        log_info "Generating API key pair..."
        "$SCRIPT_DIR/generate-api-key.sh"
    else
        log_info "API key pair already exists"
    fi

    log_info "Initialization complete!"
    log_warn "Next steps:"
    echo "  1. Edit .env file with your EVM signer private key"
    echo "  2. Edit config.yaml with your settings"
    echo "  3. Add the API public key to config.yaml under api_keys"
    echo "  4. Run: $0 up"
}

# =============================================================================
# Start services
# =============================================================================
start_services() {
    log_info "Starting services..."
    cd "$PROJECT_DIR"

    # Check config (required); .env is optional (env vars can be set in shell)
    if [ ! -f ".env" ]; then
        log_warn ".env file not found. Continuing without it (env vars from shell will be used)."
    fi

    if [ ! -f "config.yaml" ]; then
        log_error "config.yaml not found! Run '$0 init' or copy from config.example.yaml."
        exit 1
    fi

    # Always rebuild to ensure latest code is deployed
    log_info "Building latest image..."
    docker_build_with_retry remote-signer

    docker_compose up -d

    log_info "Services started!"
    log_info "Checking service status..."
    sleep 3
    docker_compose ps
}

# =============================================================================
# Start remote-signer in background (no screen, no TTY — for setup when no keystore password)
# =============================================================================
run_no_screen() {
    log_info "Starting remote-signer in background (no screen)..."
    cd "$PROJECT_DIR"

    if [ ! -f ".env" ]; then
        log_warn ".env file not found. Continuing without it (env vars from shell will be used)."
    fi

    if [ ! -f "config.yaml" ]; then
        log_error "config.yaml not found! Run '$0 init' or copy from config.example.yaml."
        exit 1
    fi

    log_info "Building image..."
    docker_build_with_retry remote-signer

    log_info "Starting postgres and remote-signer..."
    docker_compose up -d

    log_info "Server is running in background."
    log_info "View logs: $0 logs -f"
    log_info "Status:   $0 status"
}

# =============================================================================
# Start remote-signer interactively (for password input)
# =============================================================================
run_interactive() {
    log_info "Starting remote-signer interactively..."
    cd "$PROJECT_DIR"

    # Check required files
    if [ ! -f ".env" ]; then
        log_warn ".env file not found. Continuing without it (env vars from shell will be used)."
    fi

    if [ ! -f "config.yaml" ]; then
        log_error "config.yaml not found! Run '$0 init' or copy from config.example.yaml."
        exit 1
    fi

    # Clean up any existing remote-signer container
    docker rm -f remote-signer-app 2>/dev/null || true

    # Start postgres first (in background)
    log_info "Starting postgres..."
    docker_compose up -d postgres

    # Wait for postgres to be healthy
    log_info "Waiting for postgres to be healthy..."
    until docker_compose exec -T postgres pg_isready -U ${POSTGRES_USER:-signer} -d ${POSTGRES_DB:-remote_signer} > /dev/null 2>&1; do
        sleep 1
    done
    log_info "Postgres is ready!"

    # Run remote-signer interactively using screen
    log_info "Starting remote-signer (enter keystore password when prompted)..."
    log_info ""
    log_info ">>> After entering password, press Ctrl+A then D to detach screen <<<"
    log_info ">>> The container will continue running in background.            <<<"
    log_info ">>> Use './scripts/deploy.sh attach' to reattach                  <<<"
    log_info ""

    # Kill any existing screen session
    screen -S remote-signer -X quit 2>/dev/null || true

    # Always rebuild to ensure latest code is deployed
    log_info "Building latest image..."
    docker_build_with_retry remote-signer

    # Start in screen session (interactive)
    cd "$PROJECT_DIR"
    exec screen -S remote-signer "${DOCKER_COMPOSE[@]}" run -it --service-ports --name remote-signer-app remote-signer
}

# =============================================================================
# Stop services
# =============================================================================
stop_services() {
    log_info "Stopping services..."
    cd "$PROJECT_DIR"

    # Kill any screen session
    screen -S remote-signer -X quit 2>/dev/null || true

    # Stop and remove the interactive container (created by docker_compose run)
    docker stop remote-signer-app 2>/dev/null || true
    docker rm -f remote-signer-app 2>/dev/null || true

    # Stop all compose services
    docker_compose down
    log_info "Services stopped!"
}

# =============================================================================
# Restart services (interactive mode for password input)
# =============================================================================
restart_services() {
    log_info "Restarting services..."
    cd "$PROJECT_DIR"

    # Stop remote-signer first
    docker_compose stop remote-signer 2>/dev/null || true
    docker rm -f remote-signer-app 2>/dev/null || true

    # Run remote-signer interactively using screen
    log_info "Starting remote-signer (enter keystore password when prompted)..."
    log_info ""
    log_info ">>> After entering password, press Ctrl+A then D to detach screen <<<"
    log_info ">>> The container will continue running in background.            <<<"
    log_info ">>> Use './scripts/deploy.sh attach' to reattach                  <<<"
    log_info ""

    # Kill any existing screen session
    screen -S remote-signer -X quit 2>/dev/null || true

    # Always rebuild to ensure latest code is deployed
    log_info "Building latest image..."
    docker_build_with_retry remote-signer

    # Start in screen session (interactive)
    cd "$PROJECT_DIR"
    exec screen -S remote-signer "${DOCKER_COMPOSE[@]}" run -it --service-ports --name remote-signer-app remote-signer
}

# =============================================================================
# View logs
# =============================================================================
view_logs() {
    cd "$PROJECT_DIR"
    docker_compose logs "$@"
}

# =============================================================================
# Config helpers — all accept an explicit config file path
# =============================================================================

# Config file constants
LOCAL_CONFIG="config.local.yaml"
DOCKER_CONFIG="config.yaml"

# Read port from a given config file, default 8548
port_from_config() {
    local cfg="$1"
    if [ -n "$cfg" ] && [ -f "$PROJECT_DIR/$cfg" ]; then
        local port
        port=$(grep '^\s*port:' "$PROJECT_DIR/$cfg" | head -1 | sed 's/.*port:\s*//' | tr -d ' "')
        if [ -n "$port" ]; then
            echo "$port"
            return
        fi
    fi
    echo "8548"
}

# Check if TLS is enabled in a given config file
tls_enabled_in() {
    local cfg="$1"
    [ -n "$cfg" ] && [ -f "$PROJECT_DIR/$cfg" ] && \
        grep -A1 '^\s*tls:' "$PROJECT_DIR/$cfg" | grep -q 'enabled:\s*true'
}

# Check if mTLS (client_auth) is enabled in a given config file
mtls_enabled_in() {
    local cfg="$1"
    [ -n "$cfg" ] && [ -f "$PROJECT_DIR/$cfg" ] && \
        grep -A5 '^\s*tls:' "$PROJECT_DIR/$cfg" | grep -q 'client_auth:\s*true'
}

# Build curl args for health check against a given config file
health_curl_args_for() {
    local cfg="$1"
    local port
    port=$(port_from_config "$cfg")
    if tls_enabled_in "$cfg"; then
        local args="--cacert ${PROJECT_DIR}/certs/ca.crt"
        if mtls_enabled_in "$cfg"; then
            args="$args --cert ${PROJECT_DIR}/certs/client.crt --key ${PROJECT_DIR}/certs/client.key"
        fi
        echo "$args https://localhost:${port}/health"
    else
        echo "http://localhost:${port}/health"
    fi
}

# =============================================================================
# Generate TLS certificates
# =============================================================================
generate_certs() {
    cd "$PROJECT_DIR"
    "$SCRIPT_DIR/gen-certs.sh" "$@"
}

# =============================================================================
# Local deployment (no Docker)
# =============================================================================
LOCAL_PID_FILE="$PROJECT_DIR/.local-signer.pid"
LOCAL_LOG_FILE="$PROJECT_DIR/data/remote-signer.log"

local_run() {
    log_info "Building remote-signer binary..."
    cd "$PROJECT_DIR"

    # Local commands always use config.local.yaml
    local config_file="$LOCAL_CONFIG"
    if [ ! -f "$config_file" ]; then
        log_error "config.local.yaml not found!"
        log_error "Create it: cp config.example.yaml config.local.yaml"
        log_error "Then set database.dsn to SQLite and adjust settings."
        exit 1
    fi
    log_info "Using config: $config_file"

    # Load .env if exists
    if [ -f ".env" ]; then
        set -a
        source .env
        set +a
    fi

    # Check if already running
    if [ -f "$LOCAL_PID_FILE" ]; then
        local old_pid
        old_pid=$(cat "$LOCAL_PID_FILE")
        if kill -0 "$old_pid" 2>/dev/null; then
            log_error "Remote-signer is already running (PID: $old_pid)"
            log_error "Stop it first with: $0 local-down"
            exit 1
        else
            rm -f "$LOCAL_PID_FILE"
        fi
    fi

    # Build
    mkdir -p build data
    go build -o ./build/remote-signer ./cmd/remote-signer/
    log_info "Build complete: ./build/remote-signer"

    # TLS status
    if grep -A1 '^\s*tls:' "$config_file" | grep -q 'enabled:\s*true'; then
        log_info "TLS is ENABLED"
        if grep -A5 '^\s*tls:' "$config_file" | grep -q 'client_auth:\s*true'; then
            log_info "mTLS is ENABLED (client certificates required)"
        fi
    else
        log_info "TLS is DISABLED (plain HTTP)"
    fi

    log_info ""
    log_info "Starting remote-signer locally..."
    log_info ">>> Enter keystore password when prompted                    <<<"
    log_info ">>> After startup, press Ctrl+A then D to detach screen     <<<"
    log_info ">>> Use '$0 local-down' to stop                             <<<"
    log_info ">>> Use '$0 local-logs' to view logs                        <<<"
    log_info ">>> Use 'screen -r remote-signer-local' to reattach         <<<"
    log_info ""

    # Kill any existing screen session
    screen -S remote-signer-local -X quit 2>/dev/null || true

    # Create a launcher script to avoid shell escaping issues
    local launcher="$PROJECT_DIR/.local-signer-launcher.sh"
    cat > "$launcher" << 'LAUNCHER_HEADER'
#!/bin/bash
LAUNCHER_HEADER
    cat >> "$launcher" << LAUNCHER_BODY
cd "$PROJECT_DIR"
PID_FILE="$LOCAL_PID_FILE"
CONFIG_FILE="$config_file"
LAUNCHER_BODY
    cat >> "$launcher" << 'LAUNCHER_TAIL'
cleanup() {
    rm -f "$PID_FILE"
}
trap cleanup EXIT

# exec replaces this shell with remote-signer
# stdin stays connected for interactive keystore password input
# screen -L handles logging to file automatically
echo $$ > "$PID_FILE"
exec ./build/remote-signer -config "$CONFIG_FILE"
LAUNCHER_TAIL
    chmod +x "$launcher"

    # Start in screen session (interactive for password input)
    # -L enables screen logging, -Logfile sets the log path
    # This keeps stdin connected for keystore password while logging output
    exec screen -L -Logfile "$LOCAL_LOG_FILE" -S remote-signer-local "$launcher"
}

local_down() {
    log_info "Stopping local remote-signer..."
    cd "$PROJECT_DIR"

    # Kill screen session
    screen -S remote-signer-local -X quit 2>/dev/null || true

    # Kill by PID file
    if [ -f "$LOCAL_PID_FILE" ]; then
        local pid
        pid=$(cat "$LOCAL_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            log_info "Killed remote-signer (PID: $pid)"
        fi
        rm -f "$LOCAL_PID_FILE"
    fi

    # Fallback: kill by process name
    pkill -f "build/remote-signer" 2>/dev/null || true

    log_info "Local remote-signer stopped."
}

local_logs() {
    cd "$PROJECT_DIR"
    if [ -f "$LOCAL_LOG_FILE" ]; then
        tail -f "$LOCAL_LOG_FILE"
    else
        log_error "No log file found at $LOCAL_LOG_FILE"
        log_info "Is remote-signer running? Try: $0 local-run"
    fi
}

# =============================================================================
# Check status (auto-detects TLS and local/docker mode)
# =============================================================================
check_status() {
    cd "$PROJECT_DIR"

    # --- Local instance (config.local.yaml) ---
    echo "=== Local Instance (config: $LOCAL_CONFIG) ==="
    local local_running=false
    if [ -f "$LOCAL_PID_FILE" ]; then
        local pid
        pid=$(cat "$LOCAL_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            local_running=true
            echo -e "${GREEN}  Process: Running (PID: $pid)${NC}"
        else
            echo -e "${YELLOW}  Process: Stale PID file (not running)${NC}"
            rm -f "$LOCAL_PID_FILE"
        fi
    else
        echo -e "${YELLOW}  Process: Not running${NC}"
    fi

    if [ -f "$PROJECT_DIR/$LOCAL_CONFIG" ]; then
        local local_port
        local_port=$(port_from_config "$LOCAL_CONFIG")
        echo "  Port: $local_port"
        _health_check "$LOCAL_CONFIG"
    else
        echo "  Config: not found (skipping health check)"
    fi

    echo ""

    # --- Docker instance (config.yaml) ---
    echo "=== Docker Instance (config: $DOCKER_CONFIG) ==="
    if command -v docker &>/dev/null && docker_compose ps --status running 2>/dev/null | grep -q remote-signer; then
        echo -e "${GREEN}  Container: Running${NC}"
    else
        echo -e "${YELLOW}  Container: Not running${NC}"
    fi

    if [ -f "$PROJECT_DIR/$DOCKER_CONFIG" ]; then
        local docker_port
        docker_port=$(port_from_config "$DOCKER_CONFIG")
        echo "  Port: $docker_port"
        _health_check "$DOCKER_CONFIG"
    else
        echo "  Config: not found (skipping health check)"
    fi
}

# Internal: run health check for a given config file
_health_check() {
    local cfg="$1"
    local curl_args
    curl_args=$(health_curl_args_for "$cfg")

    if tls_enabled_in "$cfg"; then
        echo "  TLS: enabled$(mtls_enabled_in "$cfg" && echo " (mTLS)" || echo "")"
    else
        echo "  TLS: disabled"
    fi

    if curl -s --max-time 3 $curl_args > /dev/null 2>&1; then
        echo -e "  ${GREEN}Health: OK${NC}"
        curl -s $curl_args 2>/dev/null | python3 -m json.tool 2>/dev/null || curl -s $curl_args 2>/dev/null
    else
        echo -e "  ${RED}Health: Not responding${NC}"
        if tls_enabled_in "$cfg"; then
            log_warn "  Hint: if using mTLS, ensure certs/ directory has valid certificates"
        fi
    fi
}

# =============================================================================
# Docker build with retry on network/timeout (e.g. TLS handshake timeout)
# =============================================================================
docker_build_with_retry() {
    local max_attempts=5
    local attempt=1
    while [ $attempt -le $max_attempts ]; do
        local out
        out=$("${DOCKER_COMPOSE[@]}" build "$@" 2>&1)
        local ret=$?
        printf '%s\n' "$out"
        if [ $ret -eq 0 ]; then
            return 0
        fi
        if echo "$out" | grep -qE 'TLS handshake timeout|failed to resolve source metadata|failed to do request|net/http:.*timeout'; then
            log_warn "Docker build failed due to network/timeout (attempt $attempt/$max_attempts), retrying in 10s..."
            [ $attempt -lt $max_attempts ] && sleep 10
            attempt=$((attempt + 1))
        else
            return $ret
        fi
    done
    log_error "Docker build failed after $max_attempts attempts."
    return 1
}

# =============================================================================
# Build images
# =============================================================================
build_images() {
    log_info "Building Docker images..."
    cd "$PROJECT_DIR"
    docker_build_with_retry "$@"
    log_info "Build complete!"
}

# =============================================================================
# Clean up
# =============================================================================
clean_up() {
    log_warn "This will remove all containers and volumes!"
    read -p "Are you sure? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Cleaning up..."
        cd "$PROJECT_DIR"
        docker_compose down -v
        log_info "Cleanup complete!"
    else
        log_info "Cleanup cancelled."
    fi
}

# =============================================================================
# Main
# =============================================================================
case "${1:-}" in
    init)
        init_environment
        ;;
    up|start)
        start_services
        ;;
    run)
        shift
        if [ "${1:-}" = "--no-screen" ] || [ "${1:-}" = "-n" ]; then
            run_no_screen
        else
            run_interactive
        fi
        ;;
    attach)
        screen -r remote-signer
        ;;
    down|stop)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    logs)
        shift
        view_logs "$@"
        ;;
    status|ps)
        check_status
        ;;
    build)
        shift
        build_images "$@"
        ;;
    clean)
        clean_up
        ;;
    # --- Local deployment commands ---
    local-run)
        local_run
        ;;
    local-down)
        local_down
        ;;
    local-logs)
        local_logs
        ;;
    local-attach)
        screen -r remote-signer-local
        ;;
    # --- Common commands ---
    gen-certs)
        shift
        generate_certs "$@"
        ;;
    -h|--help|help|"")
        usage
        ;;
    *)
        log_error "Unknown command: $1"
        usage
        exit 1
        ;;
esac
