#!/usr/bin/env bash
# ---------- ⑫ 不许悄悄丢掉错误 ----------
#
# 这个进程持有私钥。一个被丢掉的 error 在这里的表现是**一条静默的成功路径** ——
# 写库失败了但调用方以为成功、Unmarshal 失败了但拿着零值继续算规则、
# 断言失败了但地址变成空字符串然后去匹配白名单。
#
# ⛔ 2026-09-11 之前这一整类问题**没有任何东西在检查**:`make check` 跑
# go vet + staticcheck,而**两者都不做 errcheck**。实测当时:
#
#   严格(-blank -asserts)生产文件                       221
#   普通(error 被完全丢掉)生产文件                       50
#   其中签名路径(core/service + chain/evm + core/rule)    1  ← 一条 defer Close
#
# ⚠️ 更早一次测到的是「0」,而那是 errcheck 在一个编译不过的测试包上崩了、
# stderr 被 `2>/dev/null` 吃掉的结果。**一个报告成功却什么都没检查的门禁。**
# 所以这个脚本自己也要防这件事,见下面「④ 工具没在装死」。
#
# ---------- 两种形态,别混 ----------
#
# ⭐ 不是一条通用基线。measurement 说有更好的形状可用:
#
#   ⑫a **签名路径零容忍(硬约束)** —— core/service + chain/evm + core/rule 里
#       「返回的 error 一个字都没接」今天是 **0**(唯一那条 defer resp.Body.Close()
#       由 .golangci.yml 里一条带理由的窄排除处理)。⛔ 没有基线文件,没有涨的余地。
#
#   ⑫b **其余走棘轮** —— 剩下的分布在 internal/cli、internal/api、cmd/、tui/。
#       今天就是红的门禁等于没有门禁(人会 `|| true`),所以登记进
#       scripts/lib/arch-baseline/ignored-errors.txt,双向:涨了红,
#       修好了没改数字**也红**。
#
# ⑫c forcetypeassert(`x.(T)` 不带 ok,直接 panic)全仓今天 0 —— 硬约束。
#
# 判据(和其它门禁一致):*这个错误再犯一次,什么会变红?*
set -uo pipefail
cd "$(dirname "$0")/.."
. scripts/lib/arch.sh

fail=0
echo "==> 被丢掉的错误(golangci-lint)"

out=$(mktemp); err=$(mktemp); trap 'rm -f "$out" "$err" "$out.keys" "$out.perr"' EXIT

# ---------- ⓿ 用的是**本仓库**的配置,而且它还长着该有的样子 ----------
#
# golangci 会从 cwd 往上找配置。⚠️ 没有这一条断言时,一个放在 $HOME 的
# .golangci.yml、或者本文件被人从别的目录调用,都会让门禁跑在另一套规则上
# 而**照样是绿的**。
# ⚠️ `config path` 把路径打到 **stderr**(不是 stdout),而且是相对 cwd 的。
# 第一版写成 `2>/dev/null` 于是永远拿到空串 —— 门禁当场红,这才发现。
cfg=$(golangci-lint config path 2>&1 >/dev/null | tr -d '\r')
if [ "$cfg" != ".golangci.yml" ] && [ "$cfg" != "$PWD/.golangci.yml" ]; then
    printf '  ✗ ⑫ golangci 用的配置是 %s,不是本仓库的 .golangci.yml\n' "${cfg:-<none>}" >&2
    printf '    ⛔ 换了配置的绿不算绿。\n' >&2
    exit 1
fi
if ! golangci-lint config verify >/dev/null 2>"$err"; then
    printf '  ✗ ⑫ .golangci.yml 不合 schema —— 这次检查的结论作废\n' >&2
    sed 's/^/      /' "$err" >&2
    exit 1
fi
# ⛔ 上限必须是 0。golangci 的默认是 50 / 3,而它**静默截断**:一棵有 184 条
# errcheck 的树会被报成 50。棘轮读到偏小的数字后,基线以下随便涨都不会响。
# ⚠️ 截断不会让 golangci 自报的总数和我们解析的条数不一致(它报的就是截断后的
# 数字),所以这一条只能直接断言配置本身。
for k in max-issues-per-linter max-same-issues; do
    grep -qE "^[[:space:]]*${k}:[[:space:]]*0[[:space:]]*$" .golangci.yml || {
        printf '  ✗ ⑫ .golangci.yml 里 %s 不是 0 —— golangci 会静默截断发现数\n' "$k" >&2
        printf '    ⛔ 截断后的数字喂给棘轮 = 基线以下随便涨,一个字都不说。\n' >&2
        exit 1
    }
done

golangci-lint run --output.text.print-issued-lines=false ./... >"$out" 2>"$err"
rc=$?

# ---------- ④ 工具没在装死 ----------
#
# ⛔ golangci-lint 的 0 和 1 是「没发现」和「有发现」;**其它任何退出码都是它
# 自己出了事**(配置错、包编译不过、内部 panic)。那时 stdout 可能是空的,
# 而一个只看 stdout 行数的门禁会把它读成「零违规」—— 正是本门禁要防的那种绿。
if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
    printf '  ✗ ⑫ golangci-lint 退出码 %d(不是 0/1)—— 它自己失败了,这次检查的结论作废\n' "$rc" >&2
    sed 's/^/      /' "$err" >&2
    printf '    ⛔ 别把它当成「没有违规」。常见原因:某个包编译不过、配置写错。\n' >&2
    exit 1
fi

python3 - "$out" <<'PY' >"$out.keys" 2>"$out.perr"
import re, sys, collections

SIGN = ('internal/core/service/', 'internal/chain/evm/', 'internal/core/rule/')
EXPECTED = {'errcheck', 'errorlint', 'nilerr', 'forcetypeassert'}

rows, foreign = [], collections.Counter()
summary = None
for line in open(sys.argv[1]):
    m = re.match(r'^(\S+?):(\d+):(\d+): (.*) \((\w[\w-]*)\)\s*$', line)
    if m:
        f, ln, msg, lint = m.group(1), int(m.group(2)), m.group(4), m.group(5)
        if lint not in EXPECTED:
            foreign[lint] += 1
        else:
            rows.append((f, ln, msg, lint))
        continue
    m = re.match(r'^(\d+) issues?:', line)
    if m:
        summary = int(m.group(1))

# ⛔ 有 typecheck(或任何我们没开的 linter)出现 = 有包没编译过,
# 那么 errcheck 在那个包上的「零发现」是假的。这正是第一次测出 0 的原因。
if foreign:
    print('FOREIGN ' + ','.join(f'{k}={v}' for k, v in sorted(foreign.items())))

# ⛔ 交叉核对:golangci 自己报的总数必须等于我们解析出来的条数。
# 不等 = 输出格式变了而这里的正则漏了行 —— 那会让棘轮读到偏小的数字。
# ⚠️ 它**抓不到**截断:golangci 自报的总数就是截断后的数。截断由上面那条
# 「max-issues-per-linter 必须是 0」的配置断言负责。
if summary is not None and summary != len(rows) + sum(foreign.values()):
    print(f'MISMATCH {summary} {len(rows) + sum(foreign.values())}')
if summary is None and rows:
    print('MISMATCH nosummary %d' % len(rows))


def klass(f, ln, msg, lint):
    if lint != 'errcheck':
        return lint
    # 类型断言的消息没有函数名:`v, _ := x.(T)`
    if msg == 'Error return value is not checked':
        return 'assert'
    # 「显式扔进 _」和「一个字都没接」在源码里分得开,而在 errcheck 的消息里分不开。
    # ⚠️ 判据是**报告位置那一行**里有没有 `_ =` / `, _ :=` —— 前者 review 时看得见,
    # 后者连痕迹都没有,所以签名路径的零容忍只钉后者。
    try:
        src = open(f, encoding='utf-8', errors='replace').read().split('\n')[ln - 1]
    except Exception:
        return 'dropped'   # 读不到就按更严的那一类算
    return 'blanked' if re.search(r'(^|[\s(,\[])_\s*:?=', src) else 'dropped'


c = collections.Counter()
detail = []
for f, ln, msg, lint in rows:
    k = klass(f, ln, msg, lint)
    scope = 'signpath' if f.startswith(SIGN) else 'offpath'
    c[f'{scope}_{k}'] += 1
    if scope == 'signpath' and k == 'dropped':
        detail.append(f'{f}:{ln}: {msg}')
    if k == 'forcetypeassert':
        detail.append(f'{f}:{ln}: {msg}')

for k in ('signpath_dropped', 'signpath_blanked', 'signpath_assert',
          'signpath_errorlint', 'signpath_nilerr', 'signpath_forcetypeassert',
          'offpath_dropped', 'offpath_blanked', 'offpath_assert',
          'offpath_errorlint', 'offpath_nilerr', 'offpath_forcetypeassert'):
    print(f'COUNT {k} {c[k]}')
for d in detail:
    print('DETAIL ' + d)
PY

if [ -s "$out.perr" ]; then
    printf '  ✗ ⑫ 分类脚本失败 —— 这次检查的结论作废\n' >&2
    sed 's/^/      /' "$out.perr" >&2
    rm -f "$out.keys" "$out.perr"
    exit 1
fi

if grep -q '^FOREIGN ' "$out.keys"; then
    printf '  ✗ ⑫ golangci 报了没开的 linter:%s\n' "$(grep '^FOREIGN ' "$out.keys" | cut -d' ' -f2)" >&2
    printf '    几乎总是 typecheck —— 有包编译不过。那种情况下 errcheck 在该包上的\n' >&2
    printf '    「零发现」是**假的**(2026-09-11 第一次测出「0 条」就是这个原因)。\n' >&2
    printf '    改法:先让 `go build ./...` 和 `go vet ./...` 绿。\n' >&2
    fail=1
fi

if grep -q '^MISMATCH ' "$out.keys"; then
    printf '  ✗ ⑫ 解析条数与 golangci 自报总数不一致:%s\n' "$(grep '^MISMATCH ' "$out.keys")" >&2
    printf '    ⛔ 别调基线 —— golangci 的输出格式变了,本脚本的正则漏了行,\n' >&2
    printf '       而漏掉的行不会出现在任何一档计数里。先修正则。\n' >&2
    fail=1
fi

v() { awk -v k="$1" '$1=="COUNT" && $2==k {print $3}' "$out.keys"; }

# ---------- ⑫a 签名路径零容忍(硬约束,没有基线) ----------
n=$(v signpath_dropped)
if [ "${n:-0}" -ne 0 ]; then
    printf '  ✗ ⑫a 签名路径上有 %s 处返回的 error 一个字都没接:\n' "$n" >&2
    grep '^DETAIL ' "$out.keys" | sed 's/^DETAIL /      /' >&2
    printf '    ⛔ 这里**没有基线**,也不许加。core/service + chain/evm + core/rule\n' >&2
    printf '       是决定「签不签、签什么」的代码,一个被丢掉的 error 在这里等于\n' >&2
    printf '       一条静默的成功路径。\n' >&2
    printf '    改法:接住它并往上返回。真的无法处理时,在 .golangci.yml 的\n' >&2
    printf '       exclude-functions 里加一行**带理由**的窄排除(按类型+方法,不是按路径)。\n' >&2
    fail=1
fi

# ---------- ⑫c forcetypeassert 零基线 ----------
n=$(( $(v signpath_forcetypeassert) + $(v offpath_forcetypeassert) ))
if [ "$n" -ne 0 ]; then
    printf '  ✗ ⑫c 有 %s 处 `x.(T)` 不带 ok —— 断言失败直接 panic 掉守护进程\n' "$n" >&2
    grep '^DETAIL ' "$out.keys" | sed 's/^DETAIL /      /' >&2
    printf '    改法:`v, ok := x.(T)`,失败时返回错误。\n' >&2
    fail=1
fi

# ---------- ⑫b 其余走棘轮 ----------
BASE=scripts/lib/arch-baseline/ignored-errors.txt
b() { sed 's/#.*//' "$BASE" | awk -v k="$1" '$1==k{print $2}'; }

ratchet() { # key 人类可读名 改法
    arch_ratchet_count "⑫b $2" "$(b "$1")" "$(v "$1")" "$3" "$BASE" || fail=1
}

ratchet signpath_blanked   "签名路径 · 显式 \`_ =\` 丢掉" \
    "接住它往上返回。⚠️ 这里的每一条都在决定签不签,比 offpath 的同类严重。"
ratchet signpath_assert    "签名路径 · \`v, _ := x.(T)\` 静默取零值" \
    "改 \`v, ok :=\` 并在失败时返回错误 —— 地址断言失败变成空字符串,然后去匹配白名单。"
ratchet signpath_errorlint "签名路径 · error 包装/比较" \
    "%v 改 %w;== 改 errors.Is。"
ratchet signpath_nilerr    "签名路径 · err != nil 却 return nil" \
    "🔴 每一条都是一条静默的成功路径,优先修这一档。"
ratchet offpath_dropped    "其余 · error 一个字都没接" \
    "接住它。⚠️ 这一档里约 105 条是 cmd/ 与 internal/cli 的 fmt.Fprint* 表格输出 —— 见 .golangci.yml 里为什么没排除它们。"
ratchet offpath_blanked    "其余 · 显式 \`_ =\` 丢掉" "接住它往上返回。"
ratchet offpath_assert     "其余 · \`v, _ := x.(T)\`" "改 \`v, ok :=\`。"
ratchet offpath_errorlint  "其余 · error 包装/比较" "%v 改 %w;== 改 errors.Is。"
ratchet offpath_nilerr     "其余 · err != nil 却 return nil" "把错误返回出去。"

rm -f "$out.keys" "$out.perr"

if [ "$fail" -ne 0 ]; then
    printf '\n' >&2
    echo "FAIL: 有错误被丢掉(见上)。单独跑这一条:./scripts/check-lint.sh" >&2
    echo "      看全部发现:golangci-lint run ./..." >&2
    exit 1
fi
echo "ok: 被丢掉的错误(⑫a 签名路径 0 / ⑫c forcetypeassert 0 / ⑫b 棘轮)"
