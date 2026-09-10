# Contributing Guide

## Development Environment

See [本地开发](docs/development.md) for local development setup.

## Git Workflow

See [GIT.md](./GIT.md) for branch strategy, commit conventions, and release flow.

## AI Agent Workflow

See [AI 协作工作流](docs/agent-workflow.md) for the full issue-to-submission workflow.

## Testing

See [TESTING.md](./TESTING.md) for test tier strategy, build tag conventions, and coverage requirements.

```bash
make test               # Unit tests
make test-integration   # Unit + internal integration tests
make integration        # Black-box integration tests
go test -tags e2e ./e2e/...  # E2E tests
```

## Code Quality

```bash
go vet ./...            # Static analysis
go fmt ./...            # Format
```

Pre-commit hooks run automatically:
1. Secret scan (Ed25519/secp256k1 keys, keystore passwords, API keys)
2. Large file check (>1MB)
3. `go vet`
4. Unit + integration tests

## Pull Request Process

1. Create a feature/fix branch from `main`
2. Implement changes with tests (coverage ≥ 80%)
3. Run all tests locally (`make test-integration`)
4. Update relevant documentation (see [AI 协作工作流](docs/agent-workflow.md) §⑥)
5. Submit PR against `main`
6. Ensure CI passes

### Commit Format

```
<type>: <description>

<optional body>
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`

## Architecture Documentation

- [ARCHITECTURE.md](./ARCHITECTURE.md) — Core concepts (Signer, Wallet, Rule, Template, Preset, Budget, Audit)
- [SECURITY.md](./SECURITY.md) — Threat model, defense-in-depth layers
- [docs/rules-templates-and-presets.md](./docs/rules-templates-and-presets.md) — Rule engine concepts
- [docs/rule-syntax.md](./docs/rule-syntax.md) — Rule type reference
- [docs/deployment.md](./docs/deployment.md) — Docker, Kubernetes, HA
- [SDK / MCP 集成](docs/integration.md) — Go/TS/Rust SDKs, MCP server
