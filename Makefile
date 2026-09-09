# Build targets for the remote-signer monorepo.
#
# Two build modes:
#   make build         → Default. Alias for build-embed (React UI baked in).
#   make build-embed   → Same as build: vite + `go build -tags embed_web`.
#   make build-cli     → Go-only binary, placeholder "UI not bundled" page;
#                        no Node toolchain. Backend-only / fast CI iteration.
#
# The split exists so the repo doesn't have to track internal/web/dist —
# vite emits there at build-embed time, and .gitignore keeps the artefacts
# out of version control (each vite hash was previously adding ~380 KB
# per UI change to history).

.PHONY: help check build build-embed build-cli web test test-unit test-integration integration clean tidy desktop-dev desktop-dist

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
	@echo "  build         Build daemon with embedded React UI (default; same as build-embed)"
	@echo "  build-embed   Same as build"
	@echo "  build-cli     Go-only binary, no embedded UI (placeholder page; fast backend dev)"
	@echo "  check         Fast feedback gates (fmt/vet/staticcheck/test-structure/arch) — parallel, seconds"
	@echo "  test          Default layers: unit http cli"
	@echo "  test LAYER=x  One layer: unit|http|cli|integration|blackbox|e2e"
	@echo "  test LAYER=all         Every layer, slow ones included"
	@echo "  test LAYER=unit RUN=TestFoo   Narrow by test name"
	@echo "  test-unit     Alias for test LAYER=unit"
	@echo "  test-integration  Alias for test LAYER=integration"
	@echo "  integration   Alias for test LAYER=blackbox"
	@echo "  desktop-dev   Launch the Electron desktop shell against the local build"
	@echo "  desktop-dist  Package signed installers via electron-builder (mac/win/linux)"
	@echo "  tidy          Tidy go.mod"
	@echo "  clean         Remove build artefacts"

js-client:
	cd pkg/js-client && $(NPM) ci --no-audit --no-fund && $(NPM) run build

web: js-client
	cd web && $(NPM) ci --no-audit --no-fund && $(NPM) run build

build: build-embed

build-embed: web
	CGO_ENABLED=0 $(GO) build -tags embed_web -ldflags="$(LDFLAGS)" -o remote-signer ./cmd/remote-signer

build-cli:
	CGO_ENABLED=0 $(GO) build -ldflags="$(LDFLAGS)" -o remote-signer ./cmd/remote-signer

## check — 反馈循环(秒级):格式 + vet + staticcheck + 测试结构 + 架构约束。
##         改一行想知道对不对跑这个,不要跑 test。并行执行,顺序打印。
check:
	@# ⛔ 先断言依赖再开跑 —— 缺工具时门禁的结论不可信,绿和红都不可信。
	@# 新增门禁加在 scripts/run-checks.sh 的 STEPS 里,别加回这里(加回来就变串行)。
	@bash scripts/run-checks.sh

## test — 验收。分层定义在 scripts/lib/layers.sh(**唯一事实来源**)。
##
##   make test                      默认层:unit http cli
##   make test LAYER=unit           只跑单元(零/低 IO,最快反馈)
##   make test LAYER=http           接口(handler → router)
##   make test LAYER=e2e            端到端(真起 daemon)
##   make test LAYER=all            全部层级
##   make test LAYER=unit RUN=TestFoo   再按用例名收窄
##
## ⚠️ integration / blackbox / e2e 不进默认:要真二进制/真 daemon,慢。
## 判据(docs/testing.md):*这个 bug 最早能在哪一层被抓到?* 那就是它该待的层。
test:
	@GO="$(GO)" RUN="$(RUN)" bash scripts/run-tests.sh $(LAYER)

test-unit:
	@GO="$(GO)" RUN="$(RUN)" bash scripts/run-tests.sh unit

test-integration:
	@GO="$(GO)" RUN="$(RUN)" bash scripts/run-tests.sh integration

integration:
	@GO="$(GO)" RUN="$(RUN)" bash scripts/run-tests.sh blackbox

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

# Spin up a real Linux VM via OrbStack, sync the current tree into
# it, and exercise the docker-compose.local.yml flow end-to-end.
# Catches Linux-specific bugs (bind-mount permissions, gosu / userns)
# that macOS Docker Desktop hides — needed because the project ships
# a non-trivial entrypoint script that doesn't behave the same way
# under the macOS Docker VM. Requires `brew install orbstack` first.
docker-smoke:
	sh scripts/docker-smoke-linux.sh

desktop-dist: build-embed
	cd electron && $(NPM) install --no-audit --no-fund && $(NPM) run dist

docker-local:
	PULL_POLICY=build docker compose -f docker-compose.local.yml up -d

# Build from source via BUILD_MODE (alternative to PULL_POLICY=build):
#   BUILD_MODE=source make docker-local
.PHONY: docker-local
