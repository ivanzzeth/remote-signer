# =============================================================================
# Stage 1: Build the JS SDK and the React UI bundle
# =============================================================================
#
# The Go binary embeds internal/web/dist via the embed_web build tag. That
# directory is gitignored (each vite hash filename used to add ~380 KB of
# git pack history per UI change, see GIT.md), so the container has to
# produce it fresh — we can't rely on the host having run `make build-embed`
# before the docker build context was captured. The web workspace also
# consumes the SDK via file:../pkg/js-client, which needs its dist/ before
# vite resolves the import.
FROM node:20-alpine AS webbuilder

WORKDIR /app

COPY pkg/js-client/package.json pkg/js-client/package-lock.json ./pkg/js-client/
COPY web/package.json web/package-lock.json ./web/

# Install both workspaces' deps. file:../pkg/js-client resolves to a
# symlink/copy of the SDK source under node_modules; the actual build
# happens in the next step.
RUN cd pkg/js-client && npm ci --no-audit --no-fund
RUN cd web && npm ci --no-audit --no-fund

# Now copy the rest of the SDK + web sources and build them. Order matters
# only for caching: package*.json above is the cache-stable layer, sources
# change every build.
COPY pkg/js-client/ ./pkg/js-client/
COPY web/ ./web/
RUN cd pkg/js-client && npm run build
RUN cd web && npm run build
# vite writes to ../internal/web/dist (configured in web/vite.config.ts).
# That output is what the Go stage embeds.


# =============================================================================
# Stage 2: Build the Go binary
# =============================================================================
FROM golang:1.24-alpine AS gobuilder

# git is needed for `go mod download` against private/transitive deps
# resolved by tag. ca-certificates for HTTPS to the module proxy.
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Set Go proxy for China users; doesn't hurt elsewhere.
ENV GOPROXY=https://goproxy.cn,direct

# Cache module download independently of source. `go mod download` reads
# only go.{mod,sum} so this layer rebuilds on dep changes, not source.
COPY go.mod go.sum ./
RUN go mod download

# Source + the vite output baked in stage 1.
COPY . .
COPY --from=webbuilder /app/internal/web/dist ./internal/web/dist

# VERSION is injected at build time by CI (release.yml passes ${GITHUB_REF_NAME#v});
# locally `docker build --build-arg VERSION=$(git describe --tags --always)`
# keeps the binary's `remote-signer version` honest. The default 'docker'
# sentinel makes it obvious when an ad-hoc build skipped the injection.
ARG VERSION=docker

RUN CGO_ENABLED=0 go build \
    -tags embed_web \
    -ldflags="-w -s -X github.com/ivanzzeth/remote-signer/internal/version.Version=${VERSION}" \
    -o /remote-signer \
    ./cmd/remote-signer


# =============================================================================
# Stage 3: Minimal runtime image
# =============================================================================
FROM debian:bookworm-slim

# ca-certificates for outbound TLS (gateway RPC, notifications).
# git is kept because foundry's `forge install` clones repos at first use;
# tzdata so log timestamps make sense; wget for the healthcheck;
# gosu for the entrypoint's drop-to-non-root step (avoids a sudo install
# and matches the pattern used by the official postgres / mysql images).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    gosu \
    tzdata \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Non-root user. uid 1000 by default; the entrypoint can override at
# runtime via HOST_UID / HOST_GID so a bind-mounted ~/.remote-signer
# from the host stays readable to the host user even when the docker
# daemon auto-created the mount target as root.
RUN useradd -m -u 1000 signer
WORKDIR /app

COPY --from=gobuilder /remote-signer /app/remote-signer

RUN mkdir -p /app/data /app/data/keystores /app/data/hd-wallets /var/cache/remote-signer/forge && \
    chown -R signer:signer /app /var/cache/remote-signer

# Example config; users typically override via volume mount or env.
COPY config.example.yaml /app/config.example.yaml

# Entrypoint handles the bind-mount-ownership / drop-privileges dance so
# a bare `docker compose up` works for new users without manual chown.
# See docker-entrypoint.sh for the full flow + rationale.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# IMPORTANT: container starts as root, not as `signer`. The entrypoint
# decides whether to drop to HOST_UID:HOST_GID (default: signer's 1000)
# after fixing the bind mount's ownership. Compose files / docker run
# can still pin `user: …` to bypass the entrypoint's auto-uid path.

EXPOSE 8548

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8548/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/app/remote-signer", "server", "start", "-config", "/app/config.yaml"]
