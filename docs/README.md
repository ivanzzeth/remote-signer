# Remote Signer Documentation

This directory contains documentation for the Remote Signer service.

## Document Index

- [Configuration Reference](configuration.md) — Full `config.yaml` reference
- [Deployment Guide](deployment.md) — Docker, Kubernetes, HA, monitoring, backup
- [Rules, Templates & Presets](rules-templates-and-presets.md) — Rule templates, instances, presets
- [Rule Syntax Reference](rule-syntax.md) — All rule types with examples
- [TLS / mTLS Guide](tls.md) — Certificate trust model, generation, production practices
- [TUI Guide](tui.md) — Terminal UI: build, run, key bindings
- [TUI Rules Subtabs Design](tui-rules-subtabs-design.md) — TUI rules management UX
- [TUI Signers HD Wallets Design](tui-signers-hdwallets-design.md) — TUI signer management UX
- [Testing Guide](testing.md) — Unit tests, E2E, rule validation
- [SDK ⇄ CLI Matrix](sdk-cli-matrix.md) — Auditable mapping of pkg/client vs remote-signer

## Rule Tutorials (by Protocol)

- [Polymarket (EN)](rules/polymarket.en.md) / [Polymarket (中文)](rules/polymarket.zh.md)
- [Predict (EN)](rules/predict.en.md) / [Predict (中文)](rules/predict.zh.md)
- [Uniswap (EN)](rules/uniswap.en.md) / [Uniswap (中文)](rules/uniswap.zh.md)
- [USDC (EN)](rules/usdc.en.md) / [USDC (中文)](rules/usdc.zh.md)

## Related

- [ARCHITECTURE.md](../ARCHITECTURE.md) — Core concepts and data flow
- [SECURITY.md](../SECURITY.md) — Threat model, security boundaries, key management
