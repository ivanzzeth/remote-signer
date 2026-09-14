#!/usr/bin/env bash
# 依赖断言 —— ⛔ 必须在其余门禁**之前**单独跑完。
#
# 缺工具时门禁的结论**不可信,绿和红都不可信**:staticcheck 没装时
# `staticcheck ./... || true` 是绿的,而它什么都没检查。这种绿比红危险,
# 因为它让人以为有人在看着。
#
# 判据:*这条门禁用到的每个外部命令,都在这里点过名了吗?*
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0

need() {
    local cmd=$1 why=$2 how=$3
    if ! command -v "$cmd" >/dev/null 2>&1; then
        printf '  ✗ %-16s %s\n' "$cmd" "$why" >&2
        printf '    装法: %s\n' "$how" >&2
        fail=1
    fi
}

need go        "编译 + 测试 + vet"        "https://go.dev/dl/"
need gofmt     "格式门禁(随 go 分发)"    "随 go 一起装"
need staticcheck "静态分析(go vet 之外)"  "go install honnef.co/go/tools/cmd/staticcheck@latest"
need python3   "yaml 目录门禁 + ⑫ 分类"   "apt install python3"

# ---------- node / npm:门禁 ⑬(TS/JS lint)要它们 ----------
#
# ⚠️ 这不是新增门槛:`make build` 默认就走 vite,web-unit 层也要 node。
# ⛔ 包内的 eslint 版本由 scripts/check-js-lint.sh 自己断言(它是 package-local
# 的二进制,不在 PATH 上),这里只点名解释器本身。
need node      "⑬ TS/JS lint(类型感知 eslint)" "https://nodejs.org/(建议 20+)"
need npm       "⑬ 的依赖安装(make lint-deps)"  "随 node 一起装"

# ---------- golangci-lint:装了还不够,**版本要对** ----------
#
# ⛔ 为什么这一条要比版本:golangci-lint 的**发现集随版本变**(默认排除表、
# 各 linter 的实现都会动)。scripts/check-lint.sh 是一条计数棘轮 ——
# 换一个版本,同一棵树上的数字就变了,于是门禁在这台机器上红、在 CI 上绿,
# 或者反过来。⚠️ 那种红人会当成噪声,然后整条门禁就失效了。
#
# 版本的唯一真值是 .golangci-version(CI 的安装步骤读同一个文件)。
GOLANGCI_WANT=$(tr -d 'v \t\r\n' < .golangci-version 2>/dev/null)
need golangci-lint "⑫ 被丢掉的错误(errcheck 等)" \
    "curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b \$(go env GOPATH)/bin v${GOLANGCI_WANT}"
if command -v golangci-lint >/dev/null 2>&1; then
    if [ -z "$GOLANGCI_WANT" ]; then
        printf '  ✗ %-16s .golangci-version 读不到 —— 版本钉不住,⑫ 的数字就不可比\n' "golangci-lint" >&2
        fail=1
    else
        got=$(golangci-lint --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if [ "$got" != "$GOLANGCI_WANT" ]; then
            printf '  ✗ %-16s 版本 %s,本仓库钉的是 %s\n' "golangci-lint" "${got:-未知}" "$GOLANGCI_WANT" >&2
            printf '    ⛔ 不是洁癖:发现集随版本变,而 ⑫ 是计数棘轮 —— 版本不同,同一棵树的数字不同。\n' >&2
            printf '    装法: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s -- -b $(go env GOPATH)/bin v%s\n' "$GOLANGCI_WANT" >&2
            printf '    真要升版本:改 .golangci-version,重跑 ./scripts/check-lint.sh,\n' >&2
            printf '              按它报的数字更新 scripts/lib/arch-baseline/ignored-errors.txt,并在那里写明这次升级。\n' >&2
            fail=1
        fi
    fi
fi

# ---------- swag(门禁 ⑭ / `make openapi`):版本钉在 .swag-version ----------
#
# ⛔ 这里点的名和上面几条不一样,理由写清楚免得被人「补齐」成 `need swag ...`:
# 生成器**不从 PATH 取**,走 `go run github.com/swaggo/swag/v2/cmd/swag@v<pin>`。
# 两个实测的理由:
#
#   · `swag --version` 打印 "swag version v2.0.0" —— rc 后缀被它自己吃掉,
#     PATH 上的 rc5 和 rc6 用版本断言分不开,而两者生成的文档不一样。
#   · v1 与 v2 的二进制同名。本机 PATH 上就有一个 v1.16.4(别的项目装的),
#     而 v1 只出 Swagger 2.0 —— 拿它生成等于换掉文档格式。
#
# 所以这里能断言的只有**版本文件本身**:它读不到,`make openapi` 与 ⑭ 都跑不了。
# ⚠️ 故意不在这里跑一次 `go run ...@pin --version` 去证明模块能拿到:那要 0.7s
# (冷机上是一次下载),而 check-prereqs 是串行前置。拿不到时 ⑭ 自己会红,
# 并且明确说「生成失败,本次结论作废」——⛔ 不会读成「没有违规」。
SWAG_WANT=$(tr -d 'v \t\r\n' < .swag-version 2>/dev/null)
if [ -z "$SWAG_WANT" ]; then
    printf '  ✗ %-16s .swag-version 读不到 —— 门禁 ⑭ 与 `make openapi` 钉不住版本\n' "swag" >&2
    printf '    改法:写回一个精确版本(今天是 2.0.0-rc6)。⛔ 别改成从 PATH 取 swag:\n' >&2
    printf '          `swag --version` 不打印 rc 后缀,而 rc5/rc6 生成的文档不同。\n' >&2
    fail=1
fi

# ---------- oapi-codegen(门禁 ⑮ 的漂移档 / `make sdk`):版本钉在 .oapi-codegen-version ----------
#
# 与 swag 一模一样的形状,连理由都一样:生成器**不从 PATH 取**,走
# `go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v<pin>`,
# 所以这里能断言的只有版本文件本身。
#
# ⚠️ 但它比 swag 多一条代价,写在这里免得被人当成没有:**oapi-codegen v2.8.0 的
# go.mod 要求 go >= 1.25.0**,而本仓库的 go.mod 是 1.24.x。`go run` 因此会切换
# 工具链(实测下载 go1.26.8)。⛔ 所以 `make check` 里的 ⑮ **不重新生成**,
# 它比对的是 pkg/client/internal/gen/GENERATED.txt 里记的 spec sha256;
# 真正重新生成一遍的那一档在 .github/workflows/check.yml 的 sdk-drift job,
# 那是个独立 job,不占 `make check` 的秒级预算。
OAPI_WANT=$(tr -d 'v \t\r\n' < .oapi-codegen-version 2>/dev/null)
if [ -z "$OAPI_WANT" ]; then
    printf '  ✗ %-16s .oapi-codegen-version 读不到 —— 门禁 ⑮ 与 `make sdk` 钉不住版本\n' "oapi-codegen" >&2
    printf '    改法:写回一个精确版本(今天是 2.8.0)。⛔ 别改成从 PATH 取 —— 生成结果随版本变,\n' >&2
    printf '          而 ⑮ 的漂移档逐字节比对生成结果。\n' >&2
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    echo >&2
    echo "FAIL: 缺依赖 —— 先装上再跑门禁。" >&2
    echo "      ⛔ 不要跳过缺失项继续跑:那样得到的绿是假的。" >&2
    exit 1
fi

echo "ok: 依赖齐全"
