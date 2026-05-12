# Build targets for the remote-signer monorepo.
#
# The Go binary embeds the web UI from internal/web/dist. The npm pipeline
# in web/ has its outDir pointed at that directory (see web/vite.config.ts)
# so `make web` followed by `make build` produces a self-contained binary
# without copying files around.

.PHONY: help build web test integration clean tidy

# Pick up the system Go install when goenv complains about a missing toolchain.
GO ?= go
NPM ?= npm

help:
	@echo "Targets:"
	@echo "  web         Install JS deps and build the React bundle (writes to internal/web/dist)"
	@echo "  build       Build the unified remote-signer binary (CGO disabled)"
	@echo "  test        Run the Go unit + storage test suite"
	@echo "  integration Run black-box integration tests against a freshly built binary"
	@echo "  tidy        Tidy go.mod"
	@echo "  clean       Remove build artefacts"

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
