#!/usr/bin/env bash
# `make check` 的执行器 —— **并行跑,顺序打印**。
#
# 为什么要有这个文件:`make check` 要做到「秒级反馈」。⚠️ 慢的门禁不是「慢一点」
# 这么简单 —— 人开始 `--no-verify`,而那比没有 hook 更糟。本仓库已经踩到:
# pre-commit 跑 `go test -tags integration ./internal/...`,实测 **208 秒**,
# 而且当时**正红着**(一个 unused import)。判据:*人会不会为了省这段时间绕过它?*
#
# ⛔ 三条不许动的性质:
#   1. **输出保序** —— 各自收进临时文件,按声明顺序打印。抢同一个终端会把
#      输出交错成一团,那时人读不出是哪条红了,门禁的信息价值归零。
#   2. **全部都跑完** —— 不因为前面红了就跳过后面。一次看到所有违规,
#      不必修一条跑一遍。
#   3. **任一红则整体红** —— 出口码是所有步骤的或。
#
# ⚠️ `check-prereqs` 必须**先单独跑完**:缺工具时其余门禁的结论不可信,
# 绿和红都不可信。所以它是唯一一条串行的前置。
set -uo pipefail
cd "$(dirname "$0")/.."

./scripts/check-prereqs.sh || exit 1

# 每项:`名字|命令`。**最慢的排前面** —— 并发度有限时先启动的先占核。
STEPS=(
    "staticcheck|staticcheck ./... 2>&1 | head -40"
    "vet|go vet ./... && go vet -tags integration ./internal/... && go vet -tags e2e ./e2e/..."
    "tests-struct|./scripts/check-tests.sh"
    "arch|./scripts/check-arch.sh"
    "fmt|out=\$(gofmt -l \$(git ls-files '*.go' | grep -v ^vendor/)); [ -z \"\$out\" ] || { echo \"未格式化:\"; echo \"\$out\"; false; }"
)

tmpdir=$(mktemp -d); trap 'rm -rf "$tmpdir"' EXIT
pids=()
for i in "${!STEPS[@]}"; do
    cmd=${STEPS[$i]#*|}
    ( eval "$cmd" ) >"$tmpdir/$i.out" 2>&1 &
    pids+=($!)
done

rc=0
for i in "${!STEPS[@]}"; do
    name=${STEPS[$i]%%|*}
    if wait "${pids[$i]}"; then
        printf '\033[32mok\033[0m   %s\n' "$name"
    else
        printf '\033[31mFAIL\033[0m %s\n' "$name"
        sed 's/^/     /' "$tmpdir/$i.out"
        rc=1
    fi
done

[ "$rc" -eq 0 ] && echo "✅ check 全绿" || echo "❌ check 有红项(见上)"
exit "$rc"
