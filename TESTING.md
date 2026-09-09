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

Shared test helpers (mock types, constructors, utility functions) go into
**untagged `_test.go`** files named `shared_test_helpers_test.go`. Untagged means
every tier's test binary compiles them, so unit *and* integration tests can share
one copy; the `_test.go` suffix keeps them out of the production binary.

```go
// shared_test_helpers_test.go (no build tag)
package mypackage

type mockRepo struct { ... }
func newTestLogger() *slog.Logger { ... }
```

⛔ The `_test.go` suffix is not optional. These files were named
`shared_test_helpers.go` until 2026-09-09, and Go decides what ships by the
**`_test.go` suffix**, not by whether the name contains "test" — so seven files
worth of mock repositories, plus `import "testing"`, were compiled into the
`remote-signer` daemon, the process that holds the private keys. Gate ④ in
`scripts/check-tests.sh` now fails on any untagged, non-`_test.go` file that
carries a test-only signal.

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
| `check-tests.sh` ④ | No test-only file reaches the production binary | Seven `shared_test_helpers.go` files carried **no build tag**, so every mock repository — and `import "testing"` — was compiled into the daemon that holds the private keys. The old arch gate skipped them by matching the `_test` *substring*; Go decides by the `_test.go` **suffix**. Two criteria that disagree is a blind spot the gate cannot see into |
| `check-tests.sh` ⑤ 🔒 | `*coverage_boost*_test.go` only shrinks | 13 files, 15,819 lines — 12% of the test code, named after the metric they move rather than the behaviour they describe. Their failures say "a line was not reached", not "this broke", so nobody fixes one; it gets commented out. ⛔ But measured, not assumed: removing all 13 drops `internal/api/handler/evm` from 71.4% to 53.5% and stops `internal/chain/evm` compiling at all — they hold shared mocks other tests use. The ratchet is for moving pieces out one at a time, not for deleting the set |
| `check-tests.sh` ⑥ | Every layer in `layers.sh` is run by a CI job, as `make test LAYER=<name>` | Twice now a tier has been invisible in one direction or the other. `e2e/` had 46 test files and no Makefile target; after that was fixed, CI still had **no e2e job at all** — the day its 21 failures were fixed, CI would not have noticed either way. `web-e2e` was invisible the other way round: CI runs it, `make` did not know it existed, so its 20 failures never showed up in a local full run |
| `arch/10` | `ValidateWithInput` is called only from `internal/chain/evm/testcase_runner.go` | template/preset/rule validation each kept its own copy of the test-case loop; two of them substituted variables *before* validating, so **matrix presets validated every test case against the wrong chain** — silently, for months |
| `arch/20` | Every preset's `template_ids` resolve | A dangling id makes `preset apply` install one rule fewer **without erroring** — it surfaces later as "a signature mysteriously went to `authorizing`" |
| `arch/30` | `signer` / `test_signer` / `from` hold only allowlisted or structurally-impossible addresses | `b922718` scrubbed operator wallets once; new aori/stargate work reintroduced the same address **23 times**, 2 of them buried inside calldata hex (`…000764602fead…`) where grepping for the address misses them. This submodule is open-source, so a real EOA in a signer field publishes someone's wallet |
| `arch/05` 🔒 | **AST**, not text: Clean Architecture dependency direction; settings knobs frozen into struct fields (this retired `50-dependency-direction` and `80-settings-single-source` too — one property should not carry two baselines); rule-repo holders and unvalidated writers; `write*` helpers with more than one argument order | Every grep gate here carries a note about a case its text criterion got wrong, and two were the same mistake: the Solidity ratchet counted `evm_solidity_expression` in comments, and the retired grep gate `40-rule-write-chokepoint` flagged `cmd/archcheck`'s own doc comment for the words `storage.RuleRepository`. Reading declarations instead of lines also widened what is visible — grep saw 3 files breaking dependency direction, the AST saw **13 package edges**, including the `internal/api → internal/config` class it never reported at all. All 13 are now fixed and the baseline is empty |
| `arch/60` 🔒 | The set of `${var}` substitution implementations only shrinks | Validation uses the strict one (`core/service/substitute.go`, reports errors); evaluation uses the lenient one (`core/rule/effective_config.go`, never errors). One divergence between them = a rule whose test cases are green authorizing something else at runtime |
| `arch/70` 🔒 | Per-handler `write*` helpers, `RouterConfig` fields and hand-rolled method checks only go down; no new in-handler `HasPermission` | 48 write helpers in **three different argument orders** — swap two and it still compiles (`any` + `int`), shipping errors inside a 200. A permission check in a function body means forgetting one is a bypass, and nothing reports it |
| `arch/90` | Every `scripts/arch/NN-*.sh` has a row in the table above, every `arch/NN` named here exists, and each script is executable and runnable standalone | This table said "5 gates" while 7 existed — the count was never updated when gates 6 and 7 landed. The damage is not the wrong number: a newcomer reads it as the complete list and never learns `scripts/arch/` exists, so the next gate gets bolted somewhere else. The gate caught itself on its first run |
| `arch/95` 🔒 | Only baselined files spawn subprocesses; the Solidity engine's size, its **rule declarations** in `rules/` (counted as `type: evm_solidity_expression`, not as mentions — the first version counted grep hits and 15 of the 88 were comments saying the template does *not* use it) and the 3 shipped presets that still need forge only shrink; shipped configs keep `foundry.enabled: false` | Evaluating an `evm_solidity_expression` rule forks `forge script` — a Solidity compiler and an EVM — inside the daemon holding the private keys, **on the signing path**: hundreds of ms to seconds per signature, and forge's attack surface lands in the one process that must not be compromised. It was made opt-in on 2026-09-09; "default off" is a one-line change to undo and nothing would have made a sound |

🔒 = **ratchet**, not a hard rule. These describe debt that grew over three
years, so "must be zero" would be red today — and a permanently red gate is not a
gate: people put `|| true` on it or drop it from `STEPS`. Instead each one registers
today's violations in [`scripts/lib/arch-baseline/`](scripts/lib/arch-baseline/) and
fails on two things: a violation **not** in the baseline (don't add more), and a
baseline entry that no longer exists (you fixed it — now delete the line, so the
baseline cannot become a permanent amnesty list). Those baseline files, each line
annotated with why it is still there, are also the refactor TODO list.

The AST gate is [`cmd/archcheck`](cmd/archcheck), standard library only (no
golangci-lint, no new module dependency — this repo's public SDK shares the
module) and it parses the whole tree in about 0.2s. Layers are declared in
[`cmd/archcheck/layers.go`](cmd/archcheck/layers.go); each carries the reason
the constraint exists, so a violation reads as an arrow pointing the wrong way
rather than as a lint code. Run one check, or find packages nobody has assigned
a layer to:

```bash
go run ./cmd/archcheck layers
go run ./cmd/archcheck -unclassified
```

⛔ Widening a layer's `MayImport` to silence a violation is shortening the ruler
to make someone taller. The baseline is where a violation goes, with its reason.

Each gate lives in its own file under [`scripts/arch/`](scripts/arch/) and runs
standalone, which is what you want while fixing one:

```bash
./scripts/arch/50-dependency-direction.sh
```

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
3. If adding shared helpers (mocks, constructors), put them in an untagged `shared_test_helpers_test.go` file — untagged so every tier sees them, `_test.go` so they stay out of the daemon binary
4. Never import integration-tagged packages or symbols from unit test files

## File Naming Conventions

- `*_test.go` — standard Go test file
- `shared_test_helpers_test.go` — shared mocks, constructors, utilities (untagged, so all tiers compile them)
- No special naming needed for integration vs unit files; the build tag is the differentiator
