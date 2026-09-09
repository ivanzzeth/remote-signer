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

Build tags say **what a test may touch** (the tiers above). Layers say **which slice
you run right now**. Layers are defined once in
[`scripts/lib/layers.sh`](scripts/lib/layers.sh) — the single source of truth; the
Makefile and the structure gate both read it.

```bash
make check                        # seconds (~13s): fmt, vet, staticcheck, test structure, arch constraints
make test                         # default layers: unit http cli  (~16s cold)
make test LAYER=unit              # zero/low-IO only — fastest feedback
make test LAYER=http              # handler → router
make test LAYER=cli               # CLI / TUI / SDK
make test LAYER=integration       # -tags integration ./internal/...   (real SQLite lives here)
make test LAYER=blackbox          # -tags integration ./tests/integration/...
make test LAYER=e2e               # -tags e2e ./e2e/...
make test LAYER=all               # everything
make test LAYER=unit RUN=TestFoo  # narrow by test name
```

Cold timings: `unit` 5.3s · `http` 2.5s · `cli` 7.8s. The whole default set beats
the old single `go test -tags integration ./internal/...` pass by more than 10×.

⚠️ There is deliberately **no `repo` layer**. `internal/storage`'s *untagged* tests
are pure (only `repair_timestamps_test.go` touches gorm); the real repository tests
carry the `integration` tag. A layer named "repo — real SQLite" that actually ran
pure tests would be a lie, so untagged storage tests sit in `unit` and the real ones
in `integration`.

## Structure and architecture gates

`make check` enforces things no compiler or linter checks. Each one below was
**negatively verified** — a deliberate violation was introduced to confirm the gate
goes red. A gate never proven to catch anything is worse than none: it creates the
illusion that someone is watching.

| Gate | Invariant | Why (real incident) |
|---|---|---|
| `check-tests.sh` ① | Every `*_test.go` is compiled by some layer | `e2e/` held 46 test files while the Makefile had **no e2e target at all** — that tier had never been run by `make` |
| `check-tests.sh` ② | No filename collides with a GOOS/GOARCH | `e2e_rule_evm_js_test.go`'s `_js` suffix = `GOOS=js`. 576 lines, 10 test funcs, **never once ran** on linux — and `go test` stayed green and silent |
| `check-tests.sh` ③ | Files in `e2e/`, `tests/integration/` carry their build tag | A missing tag doesn't skip the test — it drags it into the untagged tier, so a test that needs a live daemon runs in the unit layer and shows up as "the unit layer is flaky" |
| `check-arch.sh` ① | `ValidateWithInput` is called only from `internal/chain/evm/testcase_runner.go` | template/preset/rule validation each kept its own copy of the test-case loop; two of them substituted variables *before* validating, so **matrix presets validated every test case against the wrong chain** — silently, for months |
| `check-arch.sh` ③ | `signer` / `test_signer` / `from` hold only allowlisted or structurally-impossible addresses | `b922718` scrubbed operator wallets once; new aori/stargate work reintroduced the same address **23 times**, 2 of them buried inside calldata hex (`…000764602fead…`) where grepping for the address misses them. This submodule is open-source, so a real EOA in a signer field publishes someone's wallet |
| `check-arch.sh` ② | Every preset's `template_ids` resolve | A dangling id makes `preset apply` install one rule fewer **without erroring** — it surfaces later as "a signature mysteriously went to `authorizing`" |

The address gate is **allowlist-shaped and fail-closed**: an unregistered address is
assumed to be a real wallet ([`scripts/lib/approved-test-addresses.txt`](scripts/lib/approved-test-addresses.txt)).
Same direction as lingxiao's `an_unknown_tool_is_assumed_to_write` — the worst case
is one more placeholder to fix (someone reports it) rather than a published wallet
(nobody notices). Low-entropy addresses (≤3 distinct hex digits: `0x1111…`, `0xdead…`)
pass on a *structural* rule, because a real key producing one is effectively
impossible; that is deliberately not a "looks like a placeholder" heuristic, which
would misfire — and a gate that misfires ends up behind `|| true`.

Judgement to apply when adding one: *if this went wrong right now, would anything
turn red?* If not, the gate belongs in `scripts/`, not in a comment.

Every gate here has been negatively verified in both directions where it matters.
Writing one is not enough: the address gate's first version matched only YAML's bare
`signer:` key, so a deliberately planted address in a Go map literal (`"signer": "0x…"`)
sailed straight through — and 4 of the original 23 offenders were exactly that shape.
It was the negative test, not review, that caught it.

## Pre-commit / pre-push

`pre-commit` runs **only** `make check` + `make test LAYER=unit` — seconds, by design.

⚠️ It previously ran `go test -tags integration ./internal/...`: measured at
**208 seconds**, and it had been **red** for some time (an unused import in
`uniswap_template_test.go`, visible only under the `integration` tag). Every commit
in that window was therefore made with `--no-verify` — the gate existed on paper only.
A gate slow enough to bypass is worse than no gate, because it manufactures the
belief that something is being checked.

Slow tiers are covered by `pre-push`, CI, and `make test LAYER=all` before a release.
**If the unit layer gets slow, fix the performance — do not raise the budget.** It is
zero-IO; it can only slow down because someone added IO or the test data exploded.

## Adding New Tests

1. Decide the tier based on the criteria above
2. If adding an integration test, put `//go:build integration` on line 1, followed by a blank line, then `package <name>`
3. If adding shared helpers (mocks, constructors), put them in an untagged `shared_test_helpers.go` file
4. Never import integration-tagged packages or symbols from unit test files

## File Naming Conventions

- `*_test.go` — standard Go test file
- `shared_test_helpers.go` — shared mocks, constructors, utilities (untagged)
- No special naming needed for integration vs unit files; the build tag is the differentiator
