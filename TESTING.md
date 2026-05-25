# Testing

## Three-Tier Test Architecture

Tests are split into three tiers using Go build tags:

| Tier | Build Tag | Run with | Characteristics |
|------|-----------|----------|----------------|
| **Unit** | none (default) | `go test ./...` | Pure in-memory, no DB/FS/network/external processes |
| **Integration** | `//go:build integration` | `go test -tags integration ./...` | GORM+SQLite, httptest.NewServer, real FS, forge |
| **E2E** | `//go:build e2e` | `go test -tags e2e ./...` | Full server, real chain RPC |

When you run `go test -tags integration ./...`, untagged (unit) files are **always compiled** alongside integration-tagged files. So `go test -tags integration ./internal/...` covers both unit and integration tests in one pass.

## When to Use Each Tier

### Unit (no build tag)

Use unit tests when the test uses ONLY:
- Pure in-memory data structures (maps + sync.RWMutex)
- `t.TempDir()` for sandboxed temporary files
- `httptest.NewRecorder` / `httptest.NewRequest` (no real network round-trip)
- Table-driven tests with no external dependencies

### Integration (`//go:build integration`)

Add `//go:build integration` when the test uses ANY of:
- GORM + SQLite (even in-memory `:memory:`)
- `httptest.NewServer` (real HTTP round-trips)
- `os.WriteFile`, `os.MkdirAll`, `os.ReadFile` with non-temp paths or `os.Chdir`
- `exec.Command` for external processes (forge/foundry)
- `os.Setenv`/`os.Unsetenv` (process-wide state, flaky when parallel)

### E2E (`//go:build e2e`)

Use e2e when the test needs:
- A running server instance
- Real chain RPC endpoints
- Multi-process orchestration

## Shared Test Helpers

Shared test helpers (mock types, constructors, utility functions) go into **untagged** files named `shared_test_helpers.go`. This ensures both unit and integration test files can use them.

Example:
```go
// shared_test_helpers.go (no build tag)
package mypackage

type mockRepo struct { ... }
func newTestLogger() *slog.Logger { ... }
```

## How to Run

```bash
# Unit tests only
go test ./...

# Unit + internal integration tests
go test -tags integration ./internal/...

# Black-box integration tests
go test -tags integration ./tests/integration/...

# E2E tests (requires running server)
go test -tags e2e ./e2e/...
```

## Pre-commit Hook

The pre-commit hook runs `go test -tags integration ./internal/...`, covering unit + internal integration tests.

## Adding New Tests

1. Decide the tier based on the criteria above
2. If adding an integration test, put `//go:build integration` on line 1, followed by a blank line, then `package <name>`
3. If adding shared helpers (mocks, constructors), put them in an untagged `shared_test_helpers.go` file
4. Never import integration-tagged packages or symbols from unit test files

## File Naming Conventions

- `*_test.go` — standard Go test file
- `shared_test_helpers.go` — shared mocks, constructors, utilities (untagged)
- No special naming needed for integration vs unit files; the build tag is the differentiator
