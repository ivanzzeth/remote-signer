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

# =============================================================================
# Usage
# =============================================================================
usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

Commands:
    init        Initialize deployment environment (create directories, generate keys)
    up          Start all services (background mode)
    run         Start remote-signer interactively (for password input)
    attach      Reattach to running remote-signer session
    down        Stop all services
    restart     Restart remote-signer interactively (for password input)
    logs        View service logs
    status      Check service status
    build       Build Docker images
    clean       Remove all containers and volumes

Options:
    -h, --help  Show this help message

Examples:
    $0 init                 # Initialize environment
    $0 up                   # Start services (background)
    $0 run                  # Start interactively (for keystore password input)
    $0 logs -f              # Follow logs
    $0 down                 # Stop services
EOF
}

# =============================================================================
# Initialize environment
# =============================================================================
init_environment() {
    log_info "Initializing deployment environment..."

    cd "$PROJECT_DIR"

    # Create data directories
    mkdir -p data/keystores data/foundry

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
POSTGRES_PORT=5432

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

    # Check required files
    if [ ! -f ".env" ]; then
        log_error ".env file not found! Run '$0 init' first."
        exit 1
    fi

    if [ ! -f "config.yaml" ]; then
        log_error "config.yaml not found! Run '$0 init' first."
        exit 1
    fi

    docker compose up -d

    log_info "Services started!"
    log_info "Checking service status..."
    sleep 3
    docker compose ps
}

# =============================================================================
# Start remote-signer interactively (for password input)
# =============================================================================
run_interactive() {
    log_info "Starting remote-signer interactively..."
    cd "$PROJECT_DIR"

    # Check required files
    if [ ! -f ".env" ]; then
        log_error ".env file not found! Run '$0 init' first."
        exit 1
    fi

    if [ ! -f "config.yaml" ]; then
        log_error "config.yaml not found! Run '$0 init' first."
        exit 1
    fi

    # Clean up any existing remote-signer container
    docker rm -f remote-signer-app 2>/dev/null || true

    # Start postgres first (in background)
    log_info "Starting postgres..."
    docker compose up -d postgres

    # Wait for postgres to be healthy
    log_info "Waiting for postgres to be healthy..."
    until docker compose exec -T postgres pg_isready -U ${POSTGRES_USER:-signer} -d ${POSTGRES_DB:-remote_signer} > /dev/null 2>&1; do
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

    # Start in screen session (interactive)
    cd "$PROJECT_DIR"
    exec screen -S remote-signer docker compose run -it --service-ports --name remote-signer-app remote-signer
}

# =============================================================================
# Stop services
# =============================================================================
stop_services() {
    log_info "Stopping services..."
    cd "$PROJECT_DIR"

    # Kill any screen session
    screen -S remote-signer -X quit 2>/dev/null || true

    # Stop and remove the interactive container (created by docker compose run)
    docker stop remote-signer-app 2>/dev/null || true
    docker rm -f remote-signer-app 2>/dev/null || true

    # Stop all compose services
    docker compose down
    log_info "Services stopped!"
}

# =============================================================================
# Restart services (interactive mode for password input)
# =============================================================================
restart_services() {
    log_info "Restarting services..."
    cd "$PROJECT_DIR"

    # Stop remote-signer first
    docker compose stop remote-signer 2>/dev/null || true
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

    # Start in screen session (interactive)
    cd "$PROJECT_DIR"
    exec screen -S remote-signer docker compose run -it --service-ports --name remote-signer-app remote-signer
}

# =============================================================================
# View logs
# =============================================================================
view_logs() {
    cd "$PROJECT_DIR"
    docker compose logs "$@"
}

# =============================================================================
# Check status
# =============================================================================
check_status() {
    log_info "Service status:"
    cd "$PROJECT_DIR"
    docker compose ps

    echo ""
    log_info "Health check:"
    if curl -s http://localhost:${SIGNER_PORT:-8548}/health > /dev/null 2>&1; then
        echo -e "${GREEN}Remote Signer: Healthy${NC}"
    else
        echo -e "${RED}Remote Signer: Not responding${NC}"
    fi
}

# =============================================================================
# Build images
# =============================================================================
build_images() {
    log_info "Building Docker images..."
    cd "$PROJECT_DIR"
    docker compose build "$@"
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
        docker compose down -v
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
        run_interactive
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
    -h|--help|help|"")
        usage
        ;;
    *)
        log_error "Unknown command: $1"
        usage
        exit 1
        ;;
esac
