[中文](README.zh.md) | **English**

---

# Remote Signer

A secure, policy-driven signing service for EVM chains. Controls **what** gets signed through a rule engine, not just **who** can sign.

## Quick Start

### One-Command Single-Instance (SQLite, no Docker, no config)

```bash
curl -sSLf -o remote-signer \
  "https://github.com/ivanzzeth/remote-signer/releases/latest/download/remote-signer-$(uname -s | tr A-Z a-z)-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" \
  && chmod +x remote-signer

./remote-signer
```

First launch creates `~/.remote-signer/` with a default config (SQLite, `:8548`, no TLS) and generates an admin Ed25519 keypair. The private key path is printed once to stderr.

### Interactive Setup

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ivanzzeth/remote-signer/main/scripts/setup.sh)
```

### Manual Clone

```bash
git clone https://github.com/ivanzzeth/remote-signer.git && cd remote-signer && ./scripts/setup.sh
```

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Core concepts, relationships, data flow (Signer, Wallet, API Key, Rule, Template, Preset, Budget, Audit) |
| [SECURITY.md](SECURITY.md) | Threat model, security boundaries, key management, breach impact analysis |
| [Configuration Reference](docs/configuration.md) | Full `config.yaml` reference |
| [Deployment Guide](docs/deployment.md) | Docker, Kubernetes, HA, monitoring, backup |
| [Rules, Templates & Presets](docs/rules-templates-and-presets.md) | Concepts: rule templates, instances, presets |
| [Rule Syntax Reference](docs/rule-syntax.md) | All rule types with examples |
| [Integration Guide](INTEGRATION.md) | Go/TS/Rust SDKs, MCP server |
| [TLS / mTLS Guide](docs/tls.md) | Certificate trust model, generation, production practices |
| [TUI Guide](docs/tui.md) | Terminal UI: build, run, key bindings |
| [Testing Guide](docs/testing.md) | Unit tests, E2E, rule validation |

## License

MIT License
