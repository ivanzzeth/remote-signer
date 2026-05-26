---
name: go-testing
description: Go testing patterns including table-driven tests, subtests, benchmarks, fuzzing, build tags, and test coverage. Adapted for remote-signer project conventions.
---

# Go Testing Patterns

Comprehensive Go testing patterns for the remote-signer project.

## Build Tags (remote-signer convention)

| Tier | Build Tag | Run with | Characteristics |
|------|-----------|----------|----------------|
| Unit | none (default) | `go test ./...` | Pure in-memory, no DB/FS/network/external |
| Integration | `//go:build integration` | `go test -tags integration ./...` | GORM+SQLite, httptest.NewServer, real FS, forge |
| E2E | `//go:build e2e` | `go test -tags e2e ./...` | Full server, chain RPC |

**Shared test helpers** (mock types, constructors, utility functions) go into untagged files (e.g., `shared_test_helpers.go`). This ensures both unit and integration test files can use them.

A test file gets `//go:build integration` if it uses ANY of:
- GORM + SQLite (even in-memory `:memory:`)
- `httptest.NewServer` (real HTTP round-trips)
- `os.WriteFile`, `os.MkdirAll`, `os.ReadFile` with non-temp paths or `os.Chdir`
- `exec.Command` for external processes (forge/foundry)
- `os.Setenv`/`os.Unsetenv` (process-wide state, flaky when parallel)

## TDD Workflow

```
RED     → Write a failing test first
GREEN   → Write minimal code to pass the test
REFACTOR → Improve code while keeping tests green
```

## Table-Driven Tests

```go
func TestAdd(t *testing.T) {
    tests := []struct {
        name     string
        a, b     int
        expected int
    }{
        {"positive numbers", 2, 3, 5},
        {"negative numbers", -1, -2, -3},
        {"zero values", 0, 0, 0},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got := Add(tt.a, tt.b)
            if got != tt.expected {
                t.Errorf("Add(%d, %d) = %d; want %d", tt.a, tt.b, got, tt.expected)
            }
        })
    }
}
```

## Test Helpers

```go
func setupTestDB(t *testing.T) *gorm.DB {
    t.Helper()
    db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
    if err != nil {
        t.Fatalf("failed to open database: %v", err)
    }
    t.Cleanup(func() { db.Close() })
    return db
}
```

## Mocking with Interfaces

```go
type MockRuleRepository struct {
    GetFunc  func(id string) (*Rule, error)
    ListFunc func() ([]*Rule, error)
}

func (m *MockRuleRepository) Get(id string) (*Rule, error) {
    return m.GetFunc(id)
}

func (m *MockRuleRepository) List() ([]*Rule, error) {
    return m.ListFunc()
}
```

## Test Coverage

```bash
go test -cover ./...
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
go test -race -coverprofile=coverage.out ./...
```

Coverage targets: critical business logic 100%, public APIs 90%+, general code 80%+.

## Testing Commands

```bash
go test ./...                                           # unit only
go test -tags integration ./internal/...                # unit + integration
go test -tags integration ./tests/integration/...      # black-box integration
go test -tags e2e ./e2e/...                            # e2e
go test -v -run TestCreate ./...                        # specific test
go test -count=10 ./...                                # flaky test detection
go test -bench=. -benchmem ./...                        # benchmarks
```

## Best Practices

**DO:**
- Write tests FIRST (TDD)
- Use table-driven tests for comprehensive coverage
- Use `t.Helper()` in helper functions
- Use `t.Cleanup()` for resource cleanup
- Use `t.TempDir()` for sandboxed temporary files
- Put shared helpers in untagged `shared_test_helpers.go`

**DON'T:**
- Use `time.Sleep()` in tests (use channels or conditions)
- Test private functions directly (test through public API)
- Ignore flaky tests (fix or remove them)
- Mix build tags incorrectly (integration helpers go in untagged files)
