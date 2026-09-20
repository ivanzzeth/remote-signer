#!/usr/bin/env bash
# ---------- ⑦ API 层的重复与「函数体内做权限检查」 ----------
#
# ⑦a 46+ 份各自的 writeJSON/writeError,**三种不同的参数顺序**:
#       (w, data, status) / (w, status, body) / (w, v, code)
#     后果不是「不好看」:改错顺序编译**照样通过**(两个都是 interface{} + int),
#     线上表现为 200 里塞着错误体。
#
# ⑦b RouterConfig 的字段数。40 个字段,大半带注释「optional: nil → 该路由不注册」
#     —— **API 表面取决于 wiring 时哪些字段非 nil,静态读代码判定不了线上注册了
#     哪些路由**。这是个服务定位器,不是配置。
#
# ⑦c 手写 `r.Method != http.MethodX`。35 处。漏一处 = 一个 GET 能触发写操作。
#
# ⑦d **handler 函数体内**做 HasPermission。12 处。
#     🔴 这条最危险:权限检查在函数体里 = 漏写一个 handler 就是权限绕过,
#     而漏写这件事没有任何东西会提醒你。正确的位置是路由层(middleware/rbac.go),
#     那里「没登记 = 拒绝」是默认行为(fail-closed)。
#
# 计数型棘轮:这四条的重构方式是「一次抽干净」,过程中数字会大幅下跌,
# 用集合反而每次都要重写整张表。
set -uo pipefail
cd "$(dirname "$0")/../.."
. scripts/lib/arch.sh
fail=0

echo "==> API 层重复"

# 把 `grep -hc` 的逐文件计数加起来。
#
# ⛔ 这里原来是 `paste -sd+ | bc`,而 `-sd+` 是 GNU paste 的拼法 —— BSD paste
# (macOS 自带的那个)直接打 usage 并返回空。awk 两边都一样,还少一个 bc 依赖。
sum_lines() { awk '{ s += $1 } END { print s + 0 }'; }

# 被扫的文件列表。⛔ 空列表也是「量不到」,不是「一个都没有」。
#
# awk 对空输入老老实实打 0,而 0 会让棘轮宣布「修好了,把基线改成 0」——
# 和下面 require_count 挡的是同一件事的另一半:目录改了名、arch_prod_files
# 的过滤条件变了,都会让这里静悄悄地量到 0 个文件。
API_FILES=$(arch_prod_files internal/api)
if [ -z "$API_FILES" ]; then
    printf '  ✗ internal/api 下一个生产文件都没扫到 —— 这次检查的结论作废。\n' >&2
    printf '      ⛔ 不许当成「0 处违规」:目录改名或过滤条件变了长得一模一样。\n' >&2
    exit 2
fi

# ⛔ 数不出来的时候**不许**退回 0。
#
# 上面那两处原来写的是 `"${n:-0}"`。于是在 macOS 上 paste 一失败,`n` 就是空,
# 棘轮拿到 0,然后宣布:
#
#     ✗ ⑦a 各 handler 自己的 write* 方法:实际 0 < 基线 1 —— 修好了,请把基线数字改成 0
#
# 一条**量坏了**的检查,反过来劝你把基线永久调低。那比它直接报错糟得多:
# 基线一旦被改成 0,真正的违规回来时没有任何东西会红。
require_count() {
    case "${2:-}" in
        '' | *[!0-9]*)
            printf '  ✗ %s:数不出来(得到 %s)—— 这次检查的结论作废。\n' "$1" "${2:-<空>}" >&2
            printf '      ⛔ 不许当成 0:那会让棘轮把「量不到」读成「已经修好了」。\n' >&2
            exit 2
            ;;
    esac
}

BASE=scripts/lib/arch-baseline/api-layer-counts.txt
b() { sed 's/#.*//' "$BASE" | awk -v k="$1" '$1==k{print $2}'; }

n=$(printf '%s\n' "$API_FILES" | xargs -r grep -hcE '^func \(h \*[A-Za-z]+\) (writeJSON|writeError|writeHTTPError|writeRPCError)\(' 2>/dev/null | sum_lines)
require_count "⑦a 各 handler 自己的 write* 方法" "$n"
arch_ratchet_count "⑦a 各 handler 自己的 write* 方法" "$(b write_helpers)" "$n" \
    "抽一个 internal/api/respond 包,统一 (w, status, body) 一种顺序。" "$BASE" || fail=1

n=$(awk '/^type RouterConfig struct/{f=1;next} f&&/^}/{exit} f&&/^\t[A-Z][A-Za-z0-9_]*[ \t]/{n++} END{print n+0}' internal/api/router.go)
arch_ratchet_count "⑦b RouterConfig 字段数" "$(b router_config_fields)" "$n" \
    "改成 feature module 自注册(type Module interface{ Routes(mux) }),各模块自己持有依赖。" "$BASE" || fail=1

n=$(printf '%s\n' "$API_FILES" | xargs -r grep -hc 'r\.Method != http\.Method' 2>/dev/null | sum_lines)
require_count "⑦c 手写 method 检查" "$n"
arch_ratchet_count "⑦c 手写 method 检查" "$(b manual_method_checks)" "$n" \
    "路由注册时声明方法(mux.HandleFunc(\"POST /x\", ...)),别在函数体里判。" "$BASE" || fail=1

# ⑦d 用集合:middleware/rbac.go 是**唯一合法**的位置,其余每一个都是一处潜在绕过。
arch_prod_files internal/api \
    | grep -v '^internal/api/middleware/rbac\.go$' \
    | xargs -r grep -l 'HasPermission' 2>/dev/null | sort -u \
    | arch_ratchet_set "⑦d 在 handler 里做权限检查的文件" \
        scripts/lib/arch-baseline/inline-permission-checks.txt \
        "把权限声明挪到路由层(middleware/rbac.go);那里「没登记 = 拒绝」是默认行为。" || fail=1

exit "$fail"
