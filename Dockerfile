# =============================================================================
# Stage 1: Build Go binaries
# =============================================================================
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Set Go proxy for China
ENV GOPROXY=https://goproxy.cn,direct

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binaries with optimizations (architecture auto-detected from build platform)
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o /remote-signer ./cmd/remote-signer
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o /remote-signer-tui ./cmd/tui

# =============================================================================
# Stage 2: Final minimal image
# =============================================================================
FROM debian:bookworm-slim

# Install runtime dependencies (git required for forge install forge-std at first run)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    tzdata \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 signer
WORKDIR /app

# Copy binaries from builder
COPY --from=builder /remote-signer /app/remote-signer
COPY --from=builder /remote-signer-tui /app/remote-signer-tui

# Note: Foundry binaries (forge, cast) are mounted via docker-compose volume
# from host ./data/foundry/ to container /usr/local/bin/

# Create directories (layout matches repo: config at root, data/ under root)
RUN mkdir -p /app/data /app/data/keystores /app/data/hd-wallets /var/cache/remote-signer/forge && \
    chown -R signer:signer /app /var/cache/remote-signer

# Copy example config (at /app root to match repo layout)
COPY config.example.yaml /app/config.example.yaml

# Switch to non-root user
USER signer

# Expose port
EXPOSE 8548

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8548/health || exit 1

# Default command (config at /app so ./data/forge-cache resolves to /app/data/forge-cache)
CMD ["/app/remote-signer", "-config", "/app/config.yaml"]
