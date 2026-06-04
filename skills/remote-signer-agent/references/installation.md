# Installation

## Download Binary (recommended for most users)

```bash
curl -sSLf -o remote-signer \
  "https://github.com/ivanzzeth/remote-signer/releases/latest/download/remote-signer-$(uname -s | tr A-Z a-z)-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" \
  && chmod +x remote-signer

./remote-signer version
```

## Via Go

```bash
go install github.com/ivanzzeth/remote-signer/cmd/...@latest
```

## Via Setup Script

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ivanzzeth/remote-signer/main/scripts/setup.sh)
```

## From Source

```bash
git clone https://github.com/ivanzzeth/remote-signer.git && cd remote-signer && make build
```

## Docker (personal)

```bash
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose -f docker-compose.local.yml up -d
```

Pulls `ghcr.io/ivanzzeth/remote-signer:latest`, bind-mounts `~/.remote-signer` into the container. Same SQLite DB, admin keystore, signers, and API keys as the native daemon.

## Desktop App

Each release ships `.dmg` (macOS), `.exe` (Windows), and `.AppImage` (Linux) from the [Releases](https://github.com/ivanzzeth/remote-signer/releases) page.

## Installation Guide (for AI agents)

When a user asks to install remote-signer, walk through these questions:

**Step 1 — Understand the environment:**

| Question | Options |
|----------|---------|
| What OS / platform? | macOS, Linux, Windows |
| Running locally or on a server? | Local dev, VPS, homelab, K8s |
| Do you have Go installed? | `go version` |
| Do you have Docker installed? | `docker --version` |

**Step 2 — Recommend the install method:**

| User Profile | Recommend | Reason |
|-------------|-----------|--------|
| Local dev, no Docker | Download binary | Single file, no deps |
| Local dev, has Docker | Docker (personal) | Isolated, same as native |
| Go developer | `go install` | Fits Go toolchain |
| Server / CI | Download binary + env var bootstrap | Minimal deps, automatable |
| Production multi-instance | Docker + PostgreSQL | HA, see deployment guide |
| Desktop user (non-CLI) | Desktop App | .dmg / .exe / .AppImage |

**Step 3 — Ask about configuration:**

> "Where would you like to store your config? Default is `~/.remote-signer/`."
> "Do you need TLS? (Recommended if not localhost-only.)"
> "Would you like me to help set up API keys now, or just start the server?"

## Bootstrap (first-time admin setup)

Three converging paths to create the admin API key:

| Path | Mechanism | Best for |
|------|-----------|----------|
| Env var | `REMOTE_SIGNER_KEYSTORE_PASSWORD` | CI / Kubernetes / systemd |
| Web UI | `/api/v1/bootstrap/admin` | Desktop / Electron / Docker |
| CLI | `remote-signer api-key bootstrap` | SSH / headless / `docker exec` |
