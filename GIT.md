# Git, Releases, and Versioning

This document captures the release-engineering conventions for the
`remote-signer` monorepo so future contributors (and future-you) can
operate the pipeline without re-deriving everything from CI logs.

## First-time setup

On the first launch against an empty `~/.remote-signer/`, the daemon
needs to provision an admin API key. There are three converging paths
to do that, each suited to a different deployment style:

| Path | When it fires | When to pick it |
| ---- | ------------- | --------------- |
| **Env var** — `REMOTE_SIGNER_KEYSTORE_PASSWORD` | At startup, before HTTP comes up | CI / Kubernetes / systemd — anywhere a Secret can be injected as env. The daemon comes up fully configured; no UI dance. |
| **Web UI** — `/api/v1/bootstrap/admin` | After startup, via the browser | Local desktops / Electron / docker. The daemon boots in a "soft-started" state; the web app detects `needs_bootstrap=true` and prompts for a password with confirm. |
| **CLI** — `remote-signer api-key bootstrap` | After startup, via terminal | SSH / headless servers / `docker exec` situations where you don't have a browser at hand. Prompts on stdin and calls the same HTTP endpoint the UI uses. |

Properties shared across all three:

- Exactly one wins. The HTTP endpoint enforces single-shot semantics:
  the second POST gets `410 Gone` with `code=admin_already_exists`. The
  env-var path silently no-ops on an already-configured daemon.
- All three converge on `CreateAdminKeystore` in
  `internal/cli/server/bootstrap.go`. There's one implementation; the
  paths are just three different ways to hand it a password.
- The password protects the encrypted Ed25519 keystore the daemon writes
  to `~/.remote-signer/apikeys/admin.keystore.json`. **There is no
  recovery if you lose it.**
- The daemon does NOT need the password on subsequent starts.
  Signature verification reads the public key from the `api_keys` table.

### Web-UI bootstrap flow

The SPA fetches `GET /api/v1/bootstrap/status` on mount, **before** any
auth check. If the daemon reports `needs_bootstrap=true`, the route
guard renders the Bootstrap page (`web/src/pages/Bootstrap.tsx`)
instead of Login. After a successful POST the page receives the
encrypted keystore JSON in the response, persists it client-side
(scrypt-wrapped under the same password the operator just typed), and
calls `setCredentials()` — so the operator lands directly on the
dashboard, no extra login round-trip.

### CLI bootstrap flow

```bash
remote-signer api-key bootstrap --url http://127.0.0.1:8548
# → prompts for password (twice), POSTs to the daemon, prints
#   keystore_path + public_key_hex.
```

The CLI subcommand is the ONLY place a TTY password prompt happens in
this codebase. The daemon's own startup no longer reads from stdin
(removed when soft-start landed) — the surprising "I started the
daemon and nothing happened, oh it's waiting for input" UX is gone.

### Common pitfalls

- **Soft-started daemon, no follow-up.** The daemon logs a single WARN
  on boot when admin is missing — `bootstrap pending — daemon started
  without an admin API key`. If you see that line stuck and `/health`
  is up but `/login` is not loading, the bootstrap page should be
  reachable. Check the daemon URL in the browser and walk the modal.
- **410 Gone on a second submit.** Someone else (or you, in another
  tab) already finished bootstrap. The UI auto-reloads to the login
  page; the CLI exits non-zero with a clear message.
- **Forgot the password.** No recovery. Stop the daemon, delete
  `~/.remote-signer/apikeys/admin.keystore.json` plus the
  `admin` row in the `api_keys` table (sqlite/postgres directly), and
  restart — the soft-start flow lets you set a new one.

## TL;DR — cutting a release

```bash
# from a clean main checkout
git tag -a v0.4.0 -m "Release v0.4.0"
git push origin v0.4.0
```

Pushing the tag triggers `.github/workflows/release.yml`, which produces
and publishes:

| Artefact                                    | Lives in                |
| ------------------------------------------- | ----------------------- |
| `remote-signer-linux-{amd64,arm64}`         | GitHub Releases assets  |
| `remote-signer-darwin-{amd64,arm64}`        | GitHub Releases assets  |
| `remote-signer-extension.zip`               | GitHub Releases assets  |
| `Remote Signer-{ver}-{arch}.dmg`            | GitHub Releases assets  |
| `Remote Signer-{ver}.AppImage`              | GitHub Releases assets  |
| `Remote Signer Setup {ver}.exe`             | GitHub Releases assets  |
| `remote-signer-client@{ver}` (SDK)          | npmjs.org               |

All artefacts share the same version: the tag with the leading `v`
stripped.

## Branches and tags

- `main` is the only long-lived branch. Feature work happens in PRs;
  small fixes go in via direct commit. No `dev` / `release/*` branches.
- Tags follow `v<semver>` (e.g. `v0.4.0`, `v0.4.1`). The leading `v` is
  required — the release workflow filter is `tags: 'v*'`.
- Don't force-push tags. If a release fails midway, roll the next
  patch (`v0.4.1`) rather than overwriting the original. Force-pushed
  tags break anyone who already fetched the old hash.

## Version sources of truth

Everything published is versioned from **one** input: the git tag.
There are four places the version string ends up, and each is injected
at build/publish time — none of them is hand-maintained per release:

| Where                                  | How CI sets it                                                                                 | Default on `main` |
| -------------------------------------- | ---------------------------------------------------------------------------------------------- | ----------------- |
| `internal/version.Version` (Go binary) | `-ldflags "-X .../internal/version.Version=<tag>"` in release.yml + Makefile                   | `"dev"`           |
| `electron/package.json` `version`      | `npm version <tag>` step before electron-builder in release.yml's `desktop` matrix             | `"0.0.0-dev"`     |
| `pkg/js-client/package.json` `version` | `npm version <tag>` step before `npm publish` in release.yml's `sdk-publish` job               | `"0.0.0-dev"`     |
| GitHub Release tag                     | Inferred from the pushed tag itself                                                            | n/a               |

Source-tree defaults are sentinels — `"dev"` / `"0.0.0-dev"` — meant to
be overridden. If you see one of these in a released artefact, the
release pipeline didn't run; investigate before shipping.

### Why `var` not `const` for `internal/version.Version`

`-ldflags -X` can only patch package-level variables, not constants.
The package was migrated `const → var` so the release pipeline can
inject the tag without source-tree churn each release. The default
value (`"dev"`) is what you get from `go build` outside the Makefile
or CI.

### Local `make build` versioning

The Makefile derives `VERSION` from `git describe --tags --always --dirty`:

```bash
$ git describe --tags --always --dirty
v0.4.0-3-gabc1234-dirty
$ make build && ./remote-signer version
remote-signer v0.4.0-3-gabc1234-dirty
```

So a local build always reports something traceable: the most recent
tag, how many commits ahead, the short SHA, and `-dirty` if there are
uncommitted changes. Useful for triage when an operator says "I built
it from main last week" — `version` tells you exactly which commit.

Outside a git checkout (e.g. building from a downloaded tarball)
`git describe` fails and the default `"dev"` survives. That's fine.

## CI workflows

### `.github/workflows/release.yml`

Triggered by `push: tags: 'v*'`. Three jobs:

1. **`release`** — ubuntu-latest. Builds the SDK and web bundle,
   cross-builds the 4 Go binaries with the tag injected via ldflags,
   packs the Chrome extension, and creates the GitHub Release with
   all of those as assets.
2. **`desktop`** — matrix across `macos-14` (arm64), `macos-13` (x64),
   `ubuntu-latest` (x64), `windows-latest` (x64). Each runner:
   - Builds the SDK and web bundle.
   - Builds the Go binary for its own GOOS/GOARCH with tag injection.
   - Syncs `electron/package.json` version to the tag.
   - Runs `electron-builder` for its platform + arch.
   - Appends the resulting installer to the same GitHub Release.
3. **`sdk-publish`** — ubuntu-latest. Syncs
   `pkg/js-client/package.json` version to the tag, builds, and
   publishes to npm using the `NPM_TOKEN` secret.

`desktop` and `sdk-publish` both `needs: release`, so they only run
once the main GitHub Release exists.

### `.github/workflows/ci.yml`

Triggered on push to `main` / `dev` and on PRs. Four independent jobs:

- **`go-test`** — pure `go test ./...`.
- **`integration`** — `go test -tags integration ./tests/integration/...`.
  Uses the keystore-based admin credential (the password lives in the
  test fixture's env, not the source tree).
- **`extension-build`** — builds the SDK first (the extension imports
  `remote-signer-client` via `file:../pkg/js-client`), then bundles the
  extension with esbuild and uploads the zip as a workflow artefact.
- **`web-e2e`** — builds the SDK, runs `make build-embed` to bake the
  React UI into the daemon, then drives the suite under Playwright.

None of these run on tag pushes — they're for normal CI hygiene, not
release work.

## Adding the `NPM_TOKEN` secret

The `sdk-publish` job needs an npm token with permission to publish
`remote-signer-client`. Recommended setup:

1. **Generate the token on npmjs.org.** Account settings →
   *Access Tokens* → *Generate New Token*.
   - Type: **Classic Token**, role **Automation** (Automation tokens
     bypass 2FA by design — see "Why classic" below).
   - Or: **Granular Access Token** with these settings:
     - Packages and scopes: only `remote-signer-client`
     - Permissions: Read and write
     - **Allow this token to bypass 2FA when publishing** ✅
     - Reasonable expiration (90 days–1 year is fine; tokens are
       auto-rotatable so don't pick "never").
2. **Add it to the repo as a secret.** GitHub → Settings → Secrets
   and variables → Actions → New repository secret.
   - Name: `NPM_TOKEN` (exact case — release.yml references
     `${{ secrets.NPM_TOKEN }}`).
   - Value: paste the token string from npm. GitHub redacts the
     value once saved; you can't read it back, only overwrite or
     delete.
3. **Verify scope before saving.** A token granted "all packages"
   would let a compromised workflow publish to other npm packages on
   your account. Scope to `remote-signer-client` if you use granular,
   or rotate immediately if a classic token leaks.

### Why classic (Automation) vs granular

Granular tokens have a "Bypass 2FA" checkbox that's easy to miss in
the npm UI; if you skip it, `npm publish` from CI fails with
`EOTP requires a one-time password` and the workflow halts. Classic
**Automation** tokens always bypass 2FA — there's nothing to forget.
Trade-off: granular tokens scope more tightly, so for a single-package
publisher they're more secure when configured correctly. Either is
acceptable; pick whichever you'll remember to configure right.

## Common pitfalls

- **Forgetting to push the tag.** `git tag` alone doesn't trigger CI.
  Use `git push origin v0.4.0` (or `git push --tags` if you mean
  every local tag).
- **Tagging the wrong commit.** Tags are commit pointers, so a typo
  ships an unintended snapshot. Always `git log` the SHA before
  tagging.
- **Tag exists but no release artefacts.** The release workflow ran
  and failed partway through. Check Actions → Release → the run for
  the failed job, fix the underlying issue, then roll the next patch
  rather than overwriting the broken tag.
- **`Remote Signer-0.0.0-dev.dmg` in the release.** The "Sync package
  version with release tag" step didn't run, or ran in the wrong
  working directory. The fix is in release.yml's desktop matrix
  step "Compile electron main + package installer"; it sets
  `electron/package.json`'s version from `GITHUB_REF_NAME` before
  invoking electron-builder.
- **SDK didn't appear on npm.** `sdk-publish` job failed — most often
  because `NPM_TOKEN` is unset, expired, or scoped wrong. The Actions
  log shows the npm error verbatim.

## When the release breaks midway

If e.g. the desktop matrix fails on Windows but the main `release`
job already created the GitHub Release object, the partial release
stays published. Two recovery paths:

1. **Roll the next patch.** Cut `v0.4.1` with the fix. The broken
   `v0.4.0` remains as a historical record. This is the recommended
   default — semver allows a patch to ship for any reason, including
   "the previous release was incomplete".
2. **Delete and re-tag (only if nothing depends on the broken tag).**
   `gh release delete v0.4.0` and `git push --delete origin v0.4.0`,
   then push the tag again. Only safe if you're certain no one
   downloaded or referenced the artefacts.

Don't combine the two — once you've shipped a `v0.4.1` fix, leave
`v0.4.0` alone so the history matches what consumers saw.

## Running via Docker

Pre-built images live at **`ghcr.io/ivanzzeth/remote-signer`**, pushed
by the release workflow for every tag. Available tags:

- `:latest` — newest non-prerelease tag.
- `:0.3.8`, `:0.4.0`, … — pinned to a specific release.
- `:0.3`, `:0.4`, … — floating major.minor; tracks patch releases.

Multi-arch: `linux/amd64` + `linux/arm64`. The image starts private —
make it public at github.com/users/ivanzzeth/packages/container/remote-signer/settings
if you want unauthenticated `docker pull`.

Two compose files in the repo root, picked by use case. Both default
to pulling the `:latest` image from ghcr; both still support local
`docker compose build` if you want to bake source changes.

### `docker-compose.local.yml` — personal / single-machine

Bind-mounts `~/.remote-signer` into the container and runs as the host
UID, so the SQLite DB, admin keystore, signer keystores, audit log,
and API keys are the exact files the native daemon was using. You get
Docker's restart-on-crash and (with a one-line systemd unit or
`docker compose --restart=always`) auto-start at boot, without
migrating any data.

```bash
# Pull + run (default — uses the ghcr image, no local build)
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose -f docker-compose.local.yml up -d

# Pin to a specific release:
REMOTE_SIGNER_IMAGE=ghcr.io/ivanzzeth/remote-signer:0.3.8 \
  UID=$(id -u) GID=$(id -g) \
  docker compose -f docker-compose.local.yml up -d

# Build from local source instead of pulling (dev mode):
docker compose -f docker-compose.local.yml build
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose -f docker-compose.local.yml up -d

# Logs
docker compose -f docker-compose.local.yml logs -f
```

No PostgreSQL, no production security hardening — this mode trades
defence-in-depth for "drop in for the native daemon, change nothing".

**First-run setup**: on a brand-new `~/.remote-signer/`, the
container starts in soft-started mode (no admin keystore yet). Open
`http://127.0.0.1:8548` in your browser; the web UI prompts for a new
admin password (with confirmation), creates the keystore inside the
mounted home directory, and signs you in. Alternatively, set
`REMOTE_SIGNER_KEYSTORE_PASSWORD` in the environment (or a `.env` file
alongside this compose) to have the daemon bootstrap inline at
startup. See "First-time setup" at the top of this document for the
full menu.

### `docker-compose.yml` — production / multi-instance

Postgres-backed, host network, full hardening (read-only fs, dropped
caps, seccomp profile, `IPC_LOCK` for `mlockall`, no swap). Mounts
repo-relative paths under `./data/` — designed for managed deployments,
not ad-hoc local use.

```bash
docker compose up -d
```

Use this when running multiple replicas behind a load balancer, or
when you want the operational data on the same host as the source
checkout rather than under `~`.

### Version stamping inside the image

Both compose files pass a `VERSION` build arg to the Dockerfile. CI's
release workflow injects the bare tag (`${GITHUB_REF_NAME#v}`), so a
release image's `remote-signer version` reports the actual tag. For
local builds set it explicitly when you care:

```bash
VERSION=$(git describe --tags --always --dirty) \
  docker compose -f docker-compose.local.yml build
```

Otherwise the image stamps itself `docker` / `docker-local` so it's
obvious where a binary came from when triaging an issue.
