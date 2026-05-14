# Integration tests — the `remote-signer` binary

Black-box integration tests that exercise the shipped binary end-to-end: zero-config bootstrap, the admin HTTP API, and the operator CLI subcommands. Distinct from `e2e/` which links against internal packages — these tests only see the binary's published surface (CLI + HTTP) and so are reusable from any consumer that wants to verify a release artifact.

## Running

```bash
# Default: build the binary on the fly into a tempdir, then run every test.
go test -tags integration ./tests/integration/...

# Use a pre-built binary (skips the build step; ideal for CI artifact verification).
REMOTE_SIGNER_BIN=$(pwd)/dist/remote-signer-linux-amd64 \
  go test -tags integration ./tests/integration/...

# Verbose / single test:
go test -tags integration -v -run TestBootstrap ./tests/integration/...
```

`go test ./...` (no tag) skips this directory entirely, so the unit-test fast path is unaffected.

## What is covered

| File | Surface | Scenarios |
|------|---------|-----------|
| `bootstrap_test.go` | first-launch behaviour | home dir mode 0700, default config.yaml written, admin keypair files, DB seeded, second launch is a no-op, `/health` returns 200 |
| `apikey_test.go` | `api-key keygen` + admin lifecycle | files written with correct modes, public-key hex shape, `--print-public` stdout-only mode; create → list → delete via API (with restart for readonly flip) |
| `rule_test.go` | `rule` CRUD + `list-templates` | empty list → create → get → list → toggle → delete; rejection under default readonly; local `list-templates` against the daemon's config |
| `template_test.go` | `template` CRUD | empty → create → get → list → delete |
| `validate_test.go` | offline `validate` | -h exit 0; -version agrees with `version`; valid rule file passes; bad config fails; no-args rejected |
| `settings_test.go` | `settings show/set` + `/api/v1/admin/settings/:group` | all eight groups GET; PUT round-trip on `security` and `notify`; dot-notation set on nested fields; unknown group rejected |
| `signer_test.go` | `keystore` + `evm signer` + `sign` reject path | local keystore create/show/verify/list; admin signer create/list/lock/unlock; sign rejects with no matching rule (happy-path sign covered by internal/api/handler/evm tests) |
| `readonly_test.go` | read-only commands | `version`, `keystore list`, `preset list`, `acl ip-whitelist`, `audit list`, `doctor`, `metrics`/`health` no-auth, `completion bash`, root `--help` lists every subcommand |
| `config_test.go` | `config show/path` + config validation | `config path` returns the resolved location; `config show` parses; legacy `api_keys:` and `rules:` blocks fail fast |

## Conventions

- Every test gets its own `$REMOTE_SIGNER_HOME` (a tempdir) and an OS-assigned port — tests can run in parallel without contention.
- A `daemon` helper starts the binary as a subprocess, polls `/health` until ready, and registers `t.Cleanup` to send SIGTERM and reap.
- A `cli` helper invokes the binary one-shot with the daemon's admin credentials wired in.
