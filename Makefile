# Build targets for the remote-signer monorepo.
#
# The Go binary embeds the web UI from internal/web/dist. The npm pipeline
# in web/ has its outDir pointed at that directory (see web/vite.config.ts)
# so `make web` followed by `make build` produces a self-contained binary
# without copying files around.

.PHONY: help build web test integration clean tidy desktop-dev desktop-dist

# Pick up the system Go install when goenv complains about a missing toolchain.
GO ?= go
NPM ?= npm

help:
	@echo "Targets:"
	@echo "  web           Install JS deps and build the React bundle (writes to internal/web/dist)"
	@echo "  build         Build the unified remote-signer binary (CGO disabled)"
	@echo "  test          Run the Go unit + storage test suite"
	@echo "  integration   Run black-box integration tests against a freshly built binary"
	@echo "  desktop-dev   Launch the Electron desktop shell against the local build"
	@echo "  desktop-dist  Package signed installers via electron-builder (mac/win/linux)"
	@echo "  tidy          Tidy go.mod"
	@echo "  clean         Remove build artefacts"

web:
	cd web && $(NPM) ci --no-audit --no-fund && $(NPM) run build

build: web
	CGO_ENABLED=0 $(GO) build -ldflags="-w -s" -o remote-signer ./cmd/remote-signer

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
desktop-dev: build
	cd electron && $(NPM) install --no-audit --no-fund && $(NPM) start

desktop-dist: build
	cd electron && $(NPM) install --no-audit --no-fund && $(NPM) run dist
