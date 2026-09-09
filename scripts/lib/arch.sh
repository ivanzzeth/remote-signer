#!/usr/bin/env bash
# 架构门禁的共享底座 —— **棘轮**(ratchet):基线只许往下走。
#
# 为什么不是「达标/不达标」而是棘轮:本仓库的架构问题**不是新写的代码引入的**,
# 是三年长出来的。一条「必须为 0」的门禁在今天就是红的,而**红着的门禁等于没有
# 门禁** —— 人会 `|| true` 掉它,或者干脆把它从 STEPS 里删掉。
#
# 所以每条门禁的形态是:
#   1. 把**今天的违规**逐条登记进基线文件(它同时就是重构的 TODO 清单)
#   2. 出现基线里没有的新违规 → **红**(这是「避免后续再犯」)
#   3. 基线里的条目被修好了但没从基线里删 → **也红**(这是「保证基线真的在缩」)
#
# ⛔ 第 3 条不许拿掉。少了它,基线会变成一张只增不减的免罪清单 ——
# 修好的条目留在里面,下一个人以为那儿本来就允许违规,于是照着抄。
# 踩过的形态:`.secrets.baseline` 里躺着两年前就删掉的文件。

# arch_ratchet_set <人类可读的门禁名> <基线文件> <改法提示>
# 实际违规从 stdin 读,一行一条(通常是 `路径` 或 `路径:行号`)。
#
# ⚠️ 基线文件里 `#` 之后是注释,空行忽略 —— 每条违规**都该带一句为什么它还在**,
# 否则重构的人不知道能不能直接删。
arch_ratchet_set() {
    local label="$1" baseline="$2" hint="${3:-}"
    local actual expected added removed
    actual=$(sort -u)
    expected=$(sed 's/#.*//' "$baseline" 2>/dev/null | sed 's/[[:space:]]*$//' | grep -v '^$' | sort -u)

    added=$(comm -23 <(printf '%s\n' "$actual") <(printf '%s\n' "$expected"))
    removed=$(comm -13 <(printf '%s\n' "$actual") <(printf '%s\n' "$expected"))

    local rc=0
    if [ -n "$added" ]; then
        printf '  ✗ %s:新增了基线之外的违规\n' "$label" >&2
        printf '%s\n' "$added" | sed 's/^/      + /' >&2
        [ -n "$hint" ] && printf '    改法:%s\n' "$hint" >&2
        printf '    ⛔ 别把它加进 %s 了事 —— 基线是历史债的清单,不是新债的收容所。\n' "$baseline" >&2
        rc=1
    fi
    if [ -n "$removed" ]; then
        printf '  ✗ %s:基线里有已经不存在的条目(说明修好了)\n' "$label" >&2
        printf '%s\n' "$removed" | sed 's/^/      - /' >&2
        printf '    改法:把上面这几行从 %s 删掉。棘轮只许往下走。\n' "$baseline" >&2
        rc=1
    fi
    return $rc
}

# arch_ratchet_count <门禁名> <基线数字> <实际数字> <改法提示> <基线所在文件:行>
#
# ⚠️ 实际数字**变小也红** —— 理由同上:那一刻正是该把基线数字改小的时候,
# 而那是一行编辑。放过它,基线就永远停在三年前的高位。
arch_ratchet_count() {
    local label="$1" baseline="$2" actual="$3" hint="${4:-}" where="${5:-}"
    if [ "$actual" -gt "$baseline" ]; then
        printf '  ✗ %s:%d → %d(基线 %d,涨了)\n' "$label" "$baseline" "$actual" "$baseline" >&2
        [ -n "$hint" ] && printf '    改法:%s\n' "$hint" >&2
        return 1
    fi
    if [ "$actual" -lt "$baseline" ]; then
        printf '  ✗ %s:实际 %d < 基线 %d —— 修好了,请把基线数字改成 %d\n' "$label" "$actual" "$baseline" "$actual" >&2
        [ -n "$where" ] && printf '    位置:%s\n' "$where" >&2
        return 1
    fi
    return 0
}

# arch_go_src —— 所有「算数」的 Go 源文件:排除测试、vendor、node_modules。
# ⚠️ 各门禁必须共用这一个定义。第一版有两条门禁各自写了 find,其中一条漏了
# `-not -path './pkg/js-client/node_modules/*'`,于是它的计数里混进了第三方代码。
arch_go_src() {
    find "$@" -name '*.go' -not -name '*_test.go' \
        -not -path '*/vendor/*' -not -path '*/node_modules/*' 2>/dev/null | sort
}

# arch_prod_files —— 「会进生产二进制的 Go 文件」的**唯一**定义。
#
# ⚠️ 三个排除各有一次踩坑记录,少一个门禁就开始算错数:
#   · `*_test.go`          —— 编译器就不会把它放进二进制
#   · 带 `//go:build` 约束 —— e2e/test_server.go、cmd/e2e-test-server 都是
#                             `//go:build e2e`,它们不在守护进程里
#   · vendor / node_modules —— 第三方代码不是本仓库的架构债
#
# ⛔ 别用「路径里有没有 e2e」来判断:cmd/e2e-test-server 靠名字能猜,
# internal/config/shared_test_helpers.go 靠名字猜就猜错了 —— 它没有 build tag,
# 是**真的**编译进了守护进程(2026-09-09 发现,7 个文件,已改名为 _test.go)。
# 判据必须是 build tag 本身。
arch_prod_files() {
    local f
    while IFS= read -r f; do
        head -5 "$f" | grep -q '^//go:build ' && continue
        printf '%s\n' "$f"
    done < <(arch_go_src "$@")
}
