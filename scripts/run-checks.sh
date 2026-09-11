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
    # ⑬ TS/JS 侧的 lint(类型感知 eslint + tsc --noEmit)。今天是最慢的一条
    # (单独跑 7.1–7.7s,绝大部分是 web 那 16,668 行 TSX 的 TS program),所以排第一。
    #
    # ⚠️ **实测代价**(16 核 i5-12600H,热跑):
    #     加它之前                        5.84 / 5.92 / 5.99 s
    #     只加 eslint 两个包              8.81 / 8.82 / 9.28 s
    #     再加 tsc --noEmit 两个包       10.25 / 10.47 / 10.70 / 11.53 / 12.25 s
    #   ⚠️ 单独量 tsc 时它几乎白送(eslint×2 = 6.9/7.1s;eslint×2 + tsc×2 =
    #   6.5/7.2s),但在 `make check` 里所有步骤一起抢核,它就变回 ≈2s。
    #
    # ⛔ 没有用 `eslint --cache`:本仓库刚被「重放缓存的绿」咬过一次(blackbox 层
    # 连续 10 个提交 `ok (cached)`),门禁里不放缓存。
    #
    # ⭐ **一个留给人的决定**:5.9s → 10.7s 是接近翻倍。如果它开始让人想绕过
    # `make check`,两个正确的动作是 (a) 删掉 check-js-lint.sh 里 ⑨ 那一段
    # tsc(退回 ≈8.8s,代价是 web 的 tsconfig 收紧只剩 ci.yml 的 web-e2e job
    # 在执行,而那个 job 不跑在 feature 分支上),或 (b) 把整条 ⑬ 挪进 check.yml
    # 的一个独立 job。⛔ 不许的那条是「降低判据」。
    #
    # ⛔ 为什么在这里而不在 layers.sh:见 scripts/check-js-lint.sh 顶注
    # (layers.sh 是**测试**的事实来源;而且 check.yml 跑在每个分支每次 push 上,
    #  ci.yml 只跑 main/dev + PR —— 放这里 CI 覆盖面严格更宽)。
    "js-lint|./scripts/check-js-lint.sh"
    "staticcheck|staticcheck ./... 2>&1 | head -40"
    "lint|./scripts/check-lint.sh"
    "vet|go vet ./... && go vet -tags integration ./internal/... && go vet -tags e2e ./e2e/..."
    "tests-struct|./scripts/check-tests.sh"
    "arch|./scripts/check-arch.sh"
    "docs|./scripts/check-docs.sh"
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
