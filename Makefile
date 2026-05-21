# Build targets for the remote-signer monorepo.
#
# Two build modes:
#   make build         → Go-only binary. Serves a placeholder web page;
#                        no Node toolchain needed. Use this for backend
#                        dev, CI test passes, etc.
#   make build-embed   → Runs vite first, then `go build -tags embed_web`
#                        to bake the real React bundle into the binary.
#                        Use this for releases or local UI testing.
#
# The split exists so the repo doesn't have to track internal/web/dist —
# vite emits there at build-embed time, and .gitignore keeps the artefacts
# out of version control (each vite hash was previously adding ~380 KB
# per UI change to history).

.PHONY: help build build-embed web test integration clean tidy desktop-dev desktop-dist

# Pick up the system Go install when goenv complains about a missing toolchain.
GO ?= go
NPM ?= npm

# VERSION drives the value baked into `remote-signer version` and the
# `doctor` output. Sourced from `git describe`:
#
#   - On the v0.4.0 tag with a clean tree → "v0.4.0"
#   - One extra commit after that tag      → "v0.4.0-1-gabc1234"
#   - Uncommitted changes on top           → "v0.4.0-1-gabc1234-dirty"
#   - Outside a git checkout               → "dev"
#
# CI release.yml overrides via the same -ldflags path with the bare tag
# string (no leading 'v', no describe suffix) so released binaries report
# the clean release number. See GIT.md for the convention.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -w -s -X github.com/ivanzzeth/remote-signer/internal/version.Version=$(VERSION)

help:
	@echo "Targets:"
	@echo "  web           Install JS deps and build the React bundle (writes to internal/web/dist)"
	@echo "  build         Build the daemon binary, no embedded UI (placeholder page)"
	@echo "  build-embed   Build the daemon binary with the React UI embedded (release-equivalent)"
	@echo "  test          Run the Go unit + storage test suite"
	@echo "  integration   Run black-box integration tests against a freshly built binary"
	@echo "  desktop-dev   Launch the Electron desktop shell against the local build"
	@echo "  desktop-dist  Package signed installers via electron-builder (mac/win/linux)"
	@echo "  tidy          Tidy go.mod"
	@echo "  clean         Remove build artefacts"

web:
	cd web && $(NPM) ci --no-audit --no-fund && $(NPM) run build

build:
	CGO_ENABLED=0 $(GO) build -ldflags="$(LDFLAGS)" -o remote-signer ./cmd/remote-signer

build-embed: web
	CGO_ENABLED=0 $(GO) build -tags embed_web -ldflags="$(LDFLAGS)" -o remote-signer ./cmd/remote-signer

# Pure-Go test pass. Skips the web bundle to keep CI iterations cheap.
test:
	$(GO) test ./...

# Black-box CLI/HTTP integration tests. Uses the build tag so plain
# `go test ./...` stays fast.
integration:
	$(GO) test -tags integration ./tests/integration/...

tidy:
	$(GO) mod tidy

clean:
	rm -f remote-signer
	rm -rf internal/web/dist/assets
	$(NPM) --prefix web run clean 2>/dev/null || true
	rm -rf electron/dist electron/out

# Desktop launcher (Electron). `desktop-dev` requires the Go binary at
# repo root — the Electron main process finds it via its dev-fallback
# search path. `desktop-dist` produces signed installers; needs Apple/
# Windows code-signing identities configured externally (see
# electron-builder docs).
desktop-dev: build-embed
	cd electron && $(NPM) install --no-audit --no-fund && $(NPM) start

desktop-dist: build-embed
	cd electron && $(NPM) install --no-audit --no-fund && $(NPM) run dist
