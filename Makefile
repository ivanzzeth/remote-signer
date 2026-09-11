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

.PHONY: help check hooks build build-embed build-cli web web-deps lint-deps lint-js test test-unit test-integration integration clean tidy desktop-dev desktop-dist

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
	@echo "  lint-deps     Install node_modules + build the SDK dist that gate ⑬ needs"
	@echo "  lint-js       Run gate ⑬ only (type-aware eslint over pkg/js-client + web)"
	@echo "  check         Fast feedback gates (fmt/vet/staticcheck/ts-js-lint/test-structure/arch) — parallel, seconds"
	@echo "  hooks         Install .githooks as this clone's hooks (git config core.hooksPath)"
	@echo "  test          Default layers: unit http cli"
	@echo "  test LAYER=x  One layer: unit|http|cli|integration|blackbox|e2e|web-unit|web-e2e"
	@echo "  test LAYER=all         Every layer, slow ones + web-unit included (web-e2e needs LAYER=everything)"
	@echo "  test LAYER=unit RUN=TestFoo   Narrow by test name"
	@echo "  test-unit     Alias for test LAYER=unit"
	@echo "  test-integration  Alias for test LAYER=integration"
	@echo "  integration   Alias for test LAYER=blackbox"
	@echo "  desktop-dev   Launch the Electron desktop shell against the local build"
	@echo "  desktop-dist  Package signed installers via electron-builder (mac/win/linux)"
	@echo "  tidy          Tidy go.mod"
	@echo "  clean         Remove build artefacts"

## npm_install — 只在依赖真的变了时重装。
##
## ⛔ `npm ci` 每次都删掉 node_modules 重装,而 web-e2e 的 pretest 会调用它:
## 一次不改任何代码的验证跑,也要付两次完整重装的代价。这里用 package-lock
## 的哈希作为标记文件,锁没变就跳过。
##
## ⚠️ 判据仍是 `npm ci` 的语义(严格按锁文件装),不是 `npm install` ——
## 变的只是「什么时候需要装」,不是「怎么装」。
define npm_install
	@cd $(1) && 	  stamp=node_modules/.deps-stamp; 	  want=$$(sha256sum package-lock.json 2>/dev/null | cut -d' ' -f1); 	  if [ ! -f "$$stamp" ] || [ "$$(cat $$stamp 2>/dev/null)" != "$$want" ]; then 	    $(NPM) ci --no-audit --no-fund && printf '%s' "$$want" > "$$stamp"; 	  else 	    echo "deps up to date ($(1))"; 	  fi
endef

js-client:
	$(call npm_install,pkg/js-client)
	cd pkg/js-client && $(NPM) run build

web: js-client
	$(call npm_install,web)
	cd web && $(NPM) run build

## web-deps — 只装 web 的依赖,不构建。`make test LAYER=web-unit` 用它。
##
## ⚠️ 为什么单独有这个目标:web-unit 层跑的是 vitest,不需要 bundle,也不需要
## js-client 的 dist(src/lib 只 `import type` 它,transform 阶段就被剥掉)。
## 走 `web` 会白白付一次 vite 构建。⛔ 但也不能什么都不做 —— 那样一台干净的机器
## 上 `make test LAYER=all` 会红在 "vitest: not found",即红在环境而不是代码。
web-deps:
	$(call npm_install,web)

## lint-deps — 门禁 ⑬(TS/JS lint)需要的 node_modules。
##
## ⛔ `make check` **不会**自动调它:一条会顺手跑 `npm ci` 的门禁,在一台干净的
## 机器上第一次就要几十秒,而 `make check` 的全部意义是秒级。缺依赖时
## scripts/check-js-lint.sh 直接红并指向这个 target —— 与 staticcheck /
## golangci-lint 缺失时的处理一致(不跳过,因为跳过得到的绿是假的)。
##
## ⚠️ 锁文件哈希做标记,锁没变就跳过 —— 重复调用几乎不花时间。
##
## ⛔ 依赖 `js-client`(装 + **构建 dist**),不是只 npm_install。实测过不这么做
## 的后果:`web` 通过 `file:../pkg/js-client` 消费 SDK,没有 dist/index.d.ts 时
## TypeScript 解析不到 `remote-signer-client` 的类型,于是
##
##   · `tsc --noEmit` 在 web 上冒出 20+ 条 TS2307「找不到模块」
##   · **类型感知的 eslint 规则数字会变**:no-base-to-string 7→6、
##     no-unnecessary-type-assertion 10→6、no-redundant-type-constituents 0→22、
##     require-await 0→3
##
## 也就是说「有没有构建 SDK」决定了门禁 ⑬ 的基线数字。CI 上只跑 npm ci 而本地
## 有 dist,就是「本地绿、CI 红」—— 而那种红人会当成噪声。
## ⚠️ 门禁自己也会断言 dist/index.d.ts 在(check-js-lint.sh ①c),所以这一条
## 就算被人改回去也不会变成静默的错数字。
lint-deps: js-client
	$(call npm_install,web)

## lint-js — 只跑门禁 ⑬(等价于 `make check` 里的 js-lint 那一步)。
lint-js:
	@bash scripts/check-js-lint.sh

build: build-embed

build-embed: web
	CGO_ENABLED=0 $(GO) build -tags embed_web -ldflags="$(LDFLAGS)" -o remote-signer ./cmd/remote-signer

build-cli:
	CGO_ENABLED=0 $(GO) build -ldflags="$(LDFLAGS)" -o remote-signer ./cmd/remote-signer

## check — 反馈循环(秒级):格式 + vet + staticcheck + 丢掉的错误(⑫)
##         + TS/JS lint(⑬)+ 测试结构 + 架构约束。
##         改一行想知道对不对跑这个,不要跑 test。并行执行,顺序打印。
##
## ⚠️ ⑬ 需要 node 与两个包的 node_modules + SDK 的 dist:先跑一次 `make lint-deps`
## (锁没变时它几乎不花时间)。缺了的话 ⑬ **直接红并告诉你跑什么**,不会跳过。
check:
	@# ⛔ 先断言依赖再开跑 —— 缺工具时门禁的结论不可信,绿和红都不可信。
	@# 新增门禁加在 scripts/run-checks.sh 的 STEPS 里,别加回这里(加回来就变串行)。
	@bash scripts/run-checks.sh

## hooks — 把 .githooks/ 装成这个 clone 的 hooks 目录。
##
## ⛔ 这个 target 存在的原因是一次真实事故:.githooks/pre-commit 里一直有
## >1MB 大文件拦截,而 2026-09-10 一个 3.8 MB 的构建产物照样被提交了 ——
## 因为 `core.hooksPath` 从来没人设过,那个 hook 一次都没跑过。
## 「仓库里有个 hook 文件」和「hook 在跑」是两回事,而当时没有任何东西
## 区分这两者。
##
## ⚠️ hook 是**本地快反馈**,不是保证 —— 它挡不住 `--no-verify`,也挡不住
## 一个没跑过 `make hooks` 的新 clone。保证在 .github/workflows/check.yml:
## 那里的 `make check` 跑在每一个分支的每一次 push 上,绕不过去。
hooks:
	@git config core.hooksPath .githooks
	@echo "ok: core.hooksPath = .githooks  (pre-commit / pre-push 已生效)"
	@echo "    ⚠️ 这只是本地快反馈;真正的门禁在 CI 的 check workflow。"

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
