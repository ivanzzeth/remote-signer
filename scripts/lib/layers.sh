# 测试分层的**唯一事实来源** —— Makefile 的 `test LAYER=` 与
# scripts/check-tests.sh 都 source 这个文件。
#
# ⛔ 不要在 Makefile 里另抄一份包列表。抄第二份的那天两份就开始漂,而漂的表现是
# 「某一层永远跑不到,全量仍然是绿的」—— 没人会发现。本仓库已经踩过:e2e/ 有 46 个
# 测试文件,而 Makefile 里**一个目标都没有**,那一层从建立起就没被 make 跑过。
#
# 每项格式:`层名|构建 tag(空=无 tag)|包 pattern`
#
# ⭐ `unit` 的 pattern 是 `@rest` —— **算出来的余量**:无 tag 的全部包,减去
# repo/http/cli 已认领的。这样**新包不可能逃出所有层**:它会自动落进 unit,
# 而不是静悄悄谁都不跑。写死一串 pattern 的那一版正是漏了 7 个包
# (internal/{audit,bootstrap,logger,metrics,preset,ruleconfig,secure}),
# 它们的单测只在 208 秒的 integration 层里被顺带跑到,`LAYER=unit` 全跳过。
#
# 判据(docs/testing.md):*这个 bug 最早能在哪一层被抓到?* 那就是它该待的层。
LAYERS=(
    # 零/低 IO:规则引擎、JS 求值、类型、配置。改一行逻辑先跑这层。
    "unit||@rest"
    # ⛔ 曾经有一层 `repo|| ./internal/storage/...`,已删。
    # 理由:`internal/storage` 的**无 tag** 测试其实是纯内存的(6 个文件里只有
    # repair_timestamps_test.go 碰 gorm),真 SQLite 的仓储测试都带 `integration`
    # tag。所以那一层名叫「仓储 · 真 SQLite」而实际跑的是纯测试 —— 一个会骗人
    # 的层名比没有这层更糟。无 tag 的 storage 测试现在由 unit(@rest)收着,
    # 真仓储测试在 integration 层。
    # 接口:handler → router 一整条,含错误码
    "http|| ./internal/api/..."
    # CLI / TUI / 对外 SDK
    "cli|| ./internal/cli/... ./internal/web/... ./tui/... ./pkg/..."
    # 内部集成(需要 integration tag)
    "integration|integration| ./internal/..."
    # 黑盒:对着真二进制跑 CLI/HTTP
    "blackbox|integration| ./tests/integration/..."
    # 端到端:真起 daemon
    "e2e|e2e| ./e2e/..."
    # ⭐ 非 go test 的层:tag 写 `@cmd`,第三段就是要执行的 shell 命令。
    #
    # 为什么必须把它登记在这里,而不是「CI 里有就行」:web-e2e 在 CI 里红着
    # **20 个用例**,而本地 `make test LAYER=all` 全绿 —— 因为 make 根本不认识
    # 这一层。这与 2026-09-09 发现的「e2e/ 46 个文件从没被 make 跑过」是同一个
    # 形状:一个 tier 只要不在这张表里,它的红就没人看得见。
    #
    # ⚠️ 它要 node + playwright 浏览器,比 e2e 还慢,所以不进 all —— 见
    # run-tests.sh 的 SLOW_LAYERS / OPT_IN_LAYERS。
    "web-e2e|@cmd|cd web && npm run test:e2e"
)

layer_tag()   { local l; for l in "${LAYERS[@]}"; do [ "${l%%|*}" = "$1" ] && { local r=${l#*|}; echo "${r%%|*}"; return; }; done; return 1; }
layer_names() { local l; for l in "${LAYERS[@]}"; do echo "${l%%|*}"; done; }
layer_raw()   { local l; for l in "${LAYERS[@]}"; do [ "${l%%|*}" = "$1" ] && { echo "${l##*|}"; return; }; done; return 1; }

# 无 tag 层里被 repo/http/cli 显式认领的包 —— unit 要减掉的就是这些。
_claimed_untagged_pkgs() {
    local n raw
    for n in $(layer_names); do
        [ "$(layer_tag "$n")" = "" ] || continue
        raw=$(layer_raw "$n")
        [ "$raw" = "@rest" ] && continue
        # shellcheck disable=SC2086
        go list -f '{{.ImportPath}}' $raw 2>/dev/null
    done
}

# layer_pkgs <名> —— 该层真正要跑的包列表(@rest 在此展开)。
layer_pkgs() {
    local raw; raw=$(layer_raw "$1") || return 1
    if [ "$raw" != "@rest" ]; then
        echo "$raw"; return
    fi
    local claimed; claimed=$(_claimed_untagged_pkgs | sort -u)
    # ⛔ 必须排除 node_modules:`web/node_modules/flatted/golang/pkg/flatted` 是
    # 一个 npm 包里**自带的 Go 包**,`go list ./...` 会把它收进来。它不是本项目的
    # 代码,却会被 @rest 收进 unit 层 —— 于是单元层的绿/红取决于第三方 npm 依赖,
    # 而 `npm ci` 换个版本就可能让它消失或变红。(2026-09-09 由 pre-push 实跑发现)
    go list -f '{{.ImportPath}}' ./... 2>/dev/null | grep -v '/node_modules/' | sort -u \
        | comm -23 - <(printf '%s\n' "$claimed") | tr '\n' ' '
}
