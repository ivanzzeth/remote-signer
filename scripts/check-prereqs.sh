#!/usr/bin/env bash
# 依赖断言 —— ⛔ 必须在其余门禁**之前**单独跑完。
#
# 缺工具时门禁的结论**不可信,绿和红都不可信**:staticcheck 没装时
# `staticcheck ./... || true` 是绿的,而它什么都没检查。这种绿比红危险,
# 因为它让人以为有人在看着。
#
# 判据:*这条门禁用到的每个外部命令,都在这里点过名了吗?*
set -uo pipefail

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
need python3   "yaml 目录门禁"            "apt install python3"

if [ "$fail" -ne 0 ]; then
    echo >&2
    echo "FAIL: 缺依赖 —— 先装上再跑门禁。" >&2
    echo "      ⛔ 不要跳过缺失项继续跑:那样得到的绿是假的。" >&2
    exit 1
fi

echo "ok: 依赖齐全"
