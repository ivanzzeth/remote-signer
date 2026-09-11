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

if [ "$fail" -ne 0 ]; then
    echo >&2
    echo "FAIL: 缺依赖 —— 先装上再跑门禁。" >&2
    echo "      ⛔ 不要跳过缺失项继续跑:那样得到的绿是假的。" >&2
    exit 1
fi

echo "ok: 依赖齐全"
