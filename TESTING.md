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
make check                        # seconds (~5.5s warm): fmt, vet, staticcheck, ignored errors, test structure, arch constraints
make test                         # default layers: unit http cli  (~16s cold)
make test LAYER=unit              # zero/low-IO only — fastest feedback
make test LAYER=http              # handler → router
make test LAYER=cli               # CLI / TUI / SDK
make test LAYER=integration       # -tags integration ./internal/...   (real SQLite lives here)
make test LAYER=blackbox          # -tags integration ./tests/integration/...
make test LAYER=e2e               # -tags e2e ./e2e/...
make test LAYER=web-unit          # Vitest over web/src (node only, no browser)
make test LAYER=web-e2e           # Playwright over the embedded UI (needs a browser)
make test LAYER=all               # everything except web-e2e
make test LAYER=everything        # ...web-e2e included
make test LAYER=unit RUN=TestFoo  # narrow by test name
```

The two `web-*` layers are `@cmd` layers — npm, not `go test` — and they are split
on what they need, not on speed alone: `web-unit` needs only node, so it is in
`all`; `web-e2e` needs a Playwright browser and a built daemon, so it stays opt-in
and a machine that cannot install browsers goes red on its environment rather than
on the code. ⛔ `npm test` in `web/` was red for **every one of its 47 files** until
2026-09-10 — Vitest had no `test.exclude`, so it collected the 42 Playwright specs
and each one died with "Playwright Test did not expect test() to be called here".
Nothing ran it: `make check` is Go-only and `layers.sh` knew only about `web-e2e`.

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
| `arch/10` | `ValidateWithInput` — the direct JS entry point — is called only from `internal/chain/evm/testcase_runner.go`. ⚠️ Not "test cases have one execution path": they have two, answering different questions (the script alone, vs. the whole engine including blocklists and delegation), and `remote-signer validate` deliberately uses the second | template/preset/rule validation each kept its own copy of the test-case loop; two of them substituted variables *before* validating, so **matrix presets validated every test case against the wrong chain** — silently, for months |
| `arch/20` | Every preset's `template_ids` resolve | A dangling id makes `preset apply` install one rule fewer **without erroring** — it surfaces later as "a signature mysteriously went to `authorizing`" |
| `arch/30` | `signer` / `test_signer` / `from` hold only allowlisted or structurally-impossible addresses | `b922718` scrubbed operator wallets once; new aori/stargate work reintroduced the same address **23 times**, 2 of them buried inside calldata hex (`…000764602fead…`) where grepping for the address misses them. This submodule is open-source, so a real EOA in a signer field publishes someone's wallet |
| `arch/05` 🔒 | **AST**, not text: Clean Architecture dependency direction; settings knobs frozen into struct fields (this retired `50-dependency-direction` and `80-settings-single-source` too — one property should not carry two baselines); rule-repo holders and unvalidated writers; `write*` helpers with more than one argument order; **mirror structs** — several structs parsing one config format, compared by serialization tag; **rule-type table** — a declared rule type missing from the one table everything derives from; **engine dispatch** — callers that ask which engine a rule uses; **duplication** — functions whose normalized shape is ≥88% identical; **handler path dispatch** — handlers under `internal/api/handler/**` that still slice `r.URL.Path` instead of reading `r.PathValue`; **route auth** — four checks that together make a route with no authorization decision unrepresentable, and a route whose decision *changed* impossible to land silently: `route-auth` (⛔ zero baseline — nobody reaches the mux except `(*Router).handle`, and every route that declares no permission carries a written reason), `route-auth-exempt` (🔒 the list of routes with no permission, 15 today, expiring by itself in both directions), `route-mutating-perm` (🔒 a state-changing route gated on a read-only permission), `route-perm-binding` (🔒 every pattern→permission binding, 46 today — ⛔ **a record of current truth, not a debt list**: it is supposed to have one line per permitted route and is not supposed to shrink) | The route-auth incident is in the first three checks' own comments; the fourth has its own, measured during proposal S3 on 2026-09-10: the first three are asymmetric **in the dangerous direction**. Tightening a mutating route into a read permission is caught; a route losing its permission outright is caught; but loosening a *read* route — `GET /api/v1/wallets/{id}` from `Permitted(PermManageWallets)` to `Permitted(PermReadSigners)`, i.e. handing every strategy key someone else's wallet — left `make check` **green on all 15 gates**. The only thing standing there was one hand-written per-PR assertion (`TestWalletRoutes_RegistersExactlyTheProductionPatterns`), which is a test, not a gate, and does not scale to the ~50 routes S4–S8 still splits out of prefix handlers. ⚠️ The key carries **both** halves (`GET /api/v1/wallets/{id} manage_wallets`) — keyed on the pattern alone it would not move when the permission moved, which is that same bug one level up. Earlier, on the grep gates: every one carries a note about a case its text criterion got wrong, and two were the same mistake: the Solidity ratchet counted `evm_solidity_expression` in comments, and the retired grep gate `40-rule-write-chokepoint` flagged `cmd/archcheck`'s own doc comment for the words `storage.RuleRepository`. Reading declarations instead of lines also widened what is visible — grep saw 3 files breaking dependency direction, the AST saw **13 package edges**, including the `internal/api → internal/config` class it never reported at all. All 13 are now fixed and the baseline is empty |
| `arch/40` 🔒 | No tracked file is a binary (git's own content-based verdict, not an extension list) and none exceeds 1 MB — both read the **index**, so the gate is red before the commit exists rather than after | `cmd/archcheck`'s 3.8 MB build output was committed and stayed for 8 revisions, ~25 MB of history for a file no clone uses. Removing it took a full-history rewrite, a force-push of both repos' `main` and 32 tags, and rewriting 41 submodule pointers in the parent repo. ⛔ `.githooks/pre-commit` already had a >1 MB check — it never ran, because `core.hooksPath` had never been set and nothing checked whether it was. That is why this lives in `make check` (which CI runs) and not only in a hook. The two criteria are both needed: a 500 KB ELF passes the size check, a 3 MB minified bundle is text and passes the binary check |
| `arch/60` 🔒 | The set of `${var}` substitution implementations only shrinks | Validation uses the strict one (`core/service/substitute.go`, reports errors); evaluation uses the lenient one (`core/rule/effective_config.go`, never errors). One divergence between them = a rule whose test cases are green authorizing something else at runtime |
| `arch/70` 🔒 | Per-handler `write*` helpers, `RouterConfig` fields and hand-rolled method checks only go down; no new in-handler `HasPermission` | 48 write helpers in **three different argument orders** — swap two and it still compiles (`any` + `int`), shipping errors inside a 200. A permission check in a function body means forgetting one is a bypass, and nothing reports it |
| `arch/90` | Every `scripts/arch/NN-*.sh` has a row in the table above, every `arch/NN` named here exists, and each script is executable and runnable standalone | This table said "5 gates" while 7 existed — the count was never updated when gates 6 and 7 landed. The damage is not the wrong number: a newcomer reads it as the complete list and never learns `scripts/arch/` exists, so the next gate gets bolted somewhere else. The gate caught itself on its first run |
| `check-lint.sh` ⑫a | **Zero, hard, no baseline**: no returned error is silently discarded anywhere in `internal/core/service`, `internal/chain/evm`, `internal/core/rule` — the code that decides whether and what to sign. ⑫c `forcetypeassert` is zero repo-wide. ⑫b 🔒 everything else ratchets, split nine ways (dropped / blanked / assert × signing-path / elsewhere, plus `errorlint` and `nilerr`) in [`ignored-errors.txt`](scripts/lib/arch-baseline/ignored-errors.txt) | `make check` ran `go vet` + `staticcheck`, and **neither does errcheck** — so in a daemon that holds private keys, "the returned error was thrown away" was checked by nothing: 50 such sites in production files, 221 counting `_ =` and `v, _ := x.(T)`. ⚠️ An earlier measurement of this said **0**, and that 0 was errcheck *crashing* on a package that did not compile with its stderr discarded. That is why the gate asserts golangci's exit code is 0/1, that the config it actually loaded is this repo's, that `max-issues-per-linter` is 0 (**golangci's default is 50 and it truncates silently** — the first draft of this config reported "errcheck: 50" against a real 184), and that no finding comes from a linter we did not enable (`typecheck` there = a package did not compile, so every zero in that run is fake — verified by planting one undefined symbol, which turns the whole run into nine zeros) |
| `arch/95` 🔒 | Only baselined files spawn subprocesses; the Solidity engine's size, its **rule declarations** in `rules/` (counted as `type: evm_solidity_expression`, not as mentions — the first version counted grep hits and 15 of the 88 were comments saying the template does *not* use it) and the 3 shipped presets that still need forge only shrink; shipped configs keep `foundry.enabled: false` | Evaluating an `evm_solidity_expression` rule forks `forge script` — a Solidity compiler and an EVM — inside the daemon holding the private keys, **on the signing path**: hundreds of ms to seconds per signature, and forge's attack surface lands in the one process that must not be compromised. It was made opt-in on 2026-09-09; "default off" is a one-line change to undo and nothing would have made a sound |
| `check-js-lint.sh` ⑬ 🔒 | The TS/JS half. **Type-aware** eslint (pinned exactly, `eslint.config.mjs` per package) over `pkg/js-client/src` and `web/src`; counts ratchet per package × rule in [`js-lint.txt`](scripts/lib/arch-baseline/js-lint.txt), and **a rule with no baseline row is a hard zero** — so `no-floating-promises`, `no-misused-promises`, `only-throw-error` and `ban-ts-comment` are zero-tolerance in `pkg/js-client`, as are the last two in `web` | `pkg/js-client/.eslintrc.json` and `"lint": "eslint src --ext .ts"` both existed and **eslint appeared nowhere in `make check`, `layers.sh` or `.github/workflows/*`** — a configured gate that had never executed. Running it for the first time on 2026-09-11 produced **3 errors** it had been red on, unseen. ⚠️ Third time this repo has hit that exact shape (`.githooks` never installed; the blackbox layer replaying `ok (cached)` for 10 commits; this). And the config `extends plugin:@typescript-eslint/recommended`, which is **not type-aware**: the three promise rules were never enabled at all in a client whose job is to get signatures, and `no-explicit-any` was `"warn"` — in a gate, `warn` is nothing. `web/` (16,668 lines of TSX embedded in the daemon binary) had **no eslint config at all**, while its source carried two `// eslint-disable-next-line react-hooks/exhaustive-deps` comments for a rule no config has ever provided. Turning it on measured **61 promise errors in `web/`** (54 `no-misused-promises`, mostly `onClick={async …}` whose rejection no error boundary catches, + 7 `no-floating-promises`). The gate therefore asserts: eslint's exit code is 0/1 (≥2 = it crashed, and its empty stdout must not read as "clean"), **zero fatal parse errors** (a file that failed to parse was not linted, so its zero findings are fake — measured: one config missing its parser turned 48 files into parse errors and every rule count into 0), **a floor on how many files were linted** (`eslint <wrong path>` prints nothing and exits 0), every tool version is **exact** in `package.json` *and* matches what is installed, the installed TypeScript sits inside typescript-eslint's own declared peer range (⛔ `typescript@latest` is **7.0.2** while typescript-eslint 8 requires `<6.1.0`; installing both silently resolves TS *down*), and — read back out of `eslint --print-config` — that `parserOptions.projectService` is set and those five rules really are severity `error` |

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

The **mirror-structs** check is the one that reads a wire format rather than a
dependency. Three times in one week a field was added to one struct parsing a
YAML file and not to the others parsing the same file, and nothing failed —
yaml discards a key it has no home for, so the only symptom was behaviour that
depended on which code path read the file (a dropped `variables:` override, a
dropped `priority:`, an ignored `budget_metering:`). It reported 1333 pairs
before three conditions cut it to the real ones: both sides must carry yaml
tags (a config file, not a response DTO), the smaller side must be roughly a
subset (a mirror is a reduced copy), and three generic single-word tags is a
coincidence while four — or one shared compound key — is a format.

⛔ The fix is to give the format one struct and alias it (`type X = pkg.X`), not
to top up the missing field. Topping up lasts until the next field.

The **rule-type-table** and **engine-dispatch** checks are the same idea applied
to engines. The list of rule types was written out seven times — the constants,
`ValidRuleTypes`, ruleconfig's config-validation switch, the CLI validate
branches, the evaluator wiring, the RBAC deny-lists, and a test asserting there
were exactly ten. They had drifted: `evm_internal_transfer` is declared and has
an evaluator registered in four places, and every path that creates a rule
called the type unknown, so a fully wired engine could not be reached.

`types.ruleTypes` is now the one table, with a descriptor carrying the questions
callers used to answer for themselves — `TakesTestCases` rather than naming
`evm_js`, `RequiresToolchain` rather than naming `evm_solidity_expression`,
`ExecutesArbitraryCode` / `GovernsSignerAccess` for the RBAC deny-lists (which
were fail-open as literals: a new engine was agent-writable by omission).

- **rule-type-table** keeps a zero baseline. It is a two-line invariant with one
  known way to break it, not debt to work off.
- **engine-dispatch** flags a file naming two or more rule-type constants. One is
  an engine declaring its own `Type()`. Its baseline separates registries, where
  an entry per engine is the intended cost, from callers, which are what remains.

⛔ Neither baseline shrinks by removing an engine. Capability is not the lever.

The **duplication** check is the general form of all three. It normalizes every
function body — identifiers, string literals and numbers erased, so a copy that
renamed its loop variable still scores 100% — and ratchets the number of pairs
at ≥88% similarity, each at least 30 lines.

The 30-line floor was measured, not guessed: at 15 lines the check reports 145
pairs and a third of them are Bubble Tea boilerplate, where every TUI model
implements `SetSize` and `View` the same way because the framework says to. At
30 lines it reports 7, none of them boilerplate.

⚠️ Similar is not duplicated. Two functions can look alike and mean different
things, and merging those makes the code worse — such a pair belongs in the
baseline with its reason. What the ratchet forbids is the count growing.

The **handler-path-dispatch** check is the one that measures a migration rather
than a past incident. 20 functions across 17 files register one mux pattern and
then fan it out into several logical endpoints by hand, from the request path —
`handler/evm/rule.go:171-289` serves **12 endpoints behind one pattern**,
`wallet.go` 8, `settings.go` 18. ⛔ A per-endpoint OpenAPI annotation on such a
function can only be a guess: there is no one path and no one method to annotate.
So the annotation work has to wait for the decomposition into Go 1.22+
method+wildcard patterns, and this ratchet is what makes that decomposition
monotonic — fix one handler, the baseline shrinks; regress, it goes red.

⭐ It counts the *handler* side deliberately. `router.go:437,445,446` already
register `{address}` wildcards while `grep -rn "PathValue" internal/` returns **0**
repo-wide: the wildcards are decorative, because the handlers still slice the
path themselves. A gate counting registrations would read as partly fixed with
nothing behind them changed.

`internal/api/middleware/` is out of scope, and that was verified rather than
assumed: `auth.go:97-100` must sign `EscapedPath()` — the exact bytes the client
signed, since preset ids contain `/` and arrive as `%2F` while `PathValue`
returns a decoded segment — and every other middleware read puts the request
line into the audit log, which has to name the whole path.

The **route-auth** trio is the one gate that is only one third of its own
mechanism, and the other two thirds are in the daemon.

Before it, 55 mux patterns were registered in five different shapes and only one
of them — `handlePerm` — recorded what it had decided, so `RoutePermissions()`
described fewer than half the surface. `r.mux.Handle(p, r.withAuth(h))` looked
exactly like a deliberate "authenticated, no permission needed" and exactly like
somebody forgetting, and nothing could tell them apart. The test that claimed to
cover this built a `&Router{routePerms: …}` literal with **two hand-written
rows** and never called `setupRoutes`; all 55 real routes could have been gated
wrong with it still green.

| Layer | Where | What it makes impossible |
|---|---|---|
| type | [`internal/api/route_auth.go`](internal/api/route_auth.go) | Omitting the decision does not compile: `handle(pattern, RouteAuth, h)` takes it positionally, and the exemption constructors take the reason as an argument. The mux field is unexported, so nothing outside package api can reach it |
| AST | `route-auth` in [`cmd/archcheck/routeauth.go`](cmd/archcheck/routeauth.go) | Nothing inside package api reaches the mux either, and no exemption ships without a reason a person wrote |
| runtime | `Router.Handler` | A pattern that reached the mux anyway — from a `_test.go` or build-tagged file archcheck does not parse — is answered **403**, not served |

⚠️ How far the type layer actually reaches, since "structurally impossible"
invites over-claiming: inside package api the composite literal `RouteAuth{}` is
still writable and Go cannot forbid it. It is rejected at startup (the daemon
panics rather than serving an undecided route) and statically by the gate.
Compile-time it is not.

⛔ **The limit worth reading twice**: a prefix pattern serving many endpoints can
declare only ONE permission. `/api/v1/evm/rules/` declares `PermListRules` for
all twelve endpoints behind it while `handler/evm/rule.go:200-203` separately
checks admin inside the handler for `validate`. So "every route declares a
permission" is satisfiable today **while the per-endpoint permissions are still
wrong**, and none of the three layers can see that — they count patterns, and a
pattern is not an endpoint. This reaches full strength only after the handler
decomposition. ⭐ What it is worth now: every route that decomposition creates
must declare a permission at birth, and the routes that declare none are a list
of 14 with written reasons that goes red when any of them changes.

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
