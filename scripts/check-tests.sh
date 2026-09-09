#!/usr/bin/env bash
# 测试结构门禁 —— go vet / staticcheck 没有对应规则,只能自己写。
#
# ---------- ① 每个带测试的包都必须被某一层跑到 ----------
#
# 分层不是装饰:`make test LAYER=repo` 靠它筛选。**少登记一个包,那一层就永远
# 跑不到,而全量仍然是绿的** —— 没人会发现。
#
# 本仓库踩过的实例(2026-09-09 发现):`e2e/` 下 46 个测试文件,Makefile 里
# **一个目标都没有**。那 46 个文件从建立起就没被 `make` 跑过一次,而
# `make test` 一直是绿的。判据:*抽掉某一层的登记,这条门禁会不会红?*
#
# 所以本门禁比对两个集合:
#   ALL     = 磁盘上所有「带测试文件的包」(含每个 build tag 下的)
#   COVERED = scripts/lib/layers.sh 里各层 pattern 实际展开到的包
# ALL \ COVERED 非空即红。
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/lib/layers.sh

fail=0

# 列出某组 pattern 在某个 tag 下**实际会被编译的测试文件**(绝对路径)。
#
# ⛔ 判据是**文件**,不是「tag × 包」的笛卡尔积。第一版按后者写,于是冒出一堆
# 幻影:`e2e::internal/chain/evm` —— 那个包的测试跟 e2e tag 毫无关系,它在无 tag
# 那层已经跑过了。误报的门禁最后会被 `|| true` 掉,那时它就彻底没用了。
#
# 换成文件级之后判据变得精确且负向可验证:
#   *磁盘上这个 `*_test.go`,至少被某一层编译到了吗?* 没有 = 它永远不会跑。
test_files_of() {
    local tag=$1; shift
    local tagflag=()
    [ -n "$tag" ] && tagflag=(-tags "$tag")
    # shellcheck disable=SC2086
    go list "${tagflag[@]}" -f '{{$d := .Dir}}{{range .TestGoFiles}}{{$d}}/{{.}}
{{end}}{{range .XTestGoFiles}}{{$d}}/{{.}}
{{end}}' $* 2>/dev/null | sed '/^$/d'
}

echo "==> 每个测试文件都被某一层编译到"

all_list=$(mktemp); covered_list=$(mktemp)
trap 'rm -f "$all_list" "$covered_list"' EXIT

# ALL:磁盘上所有 *_test.go(vendor 除外)
find . -name '*_test.go' -not -path './vendor/*' -printf '%p\n' \
    | sed "s|^\./|$PWD/|" | sort -u > "$all_list"

# COVERED:各层 pattern 在自己 tag 下真的编译到的文件
for name in $(layer_names); do
    tag=$(layer_tag "$name")
    # @cmd 层不是 go test(web-e2e 跑的是 playwright),它覆盖不到 *_test.go,
    # 也不该被拿去喂 go list。
    [ "$tag" = "@cmd" ] && continue
    pkgs=$(layer_pkgs "$name")
    test_files_of "$tag" $pkgs >> "$covered_list"
done
sort -u -o "$covered_list" "$covered_list"

missing=$(comm -23 "$all_list" "$covered_list" | sed "s|^$PWD/||")
if [ -n "$missing" ]; then
    count=$(printf '%s\n' "$missing" | wc -l)
    printf '  ✗ %s 个测试文件没有任何 LAYER 编译得到 —— 它们永远不会跑:\n' "$count" >&2
    printf '%s\n' "$missing" | sed 's/^/      /' >&2
    printf '    改法:把它所在的包加进 scripts/lib/layers.sh 对应层的 pattern。\n' >&2
    printf '    ⛔ 不要放松本门禁的判据 —— 那等于把「这层跑不到」永久静音。\n' >&2
    fail=1
fi

# ---------- ② 文件名不许撞 GOOS / GOARCH ----------
#
# Go 把文件名的 `_<GOOS>` / `_<GOARCH>` 后缀当**隐式构建约束**(去掉 `_test` 后再看)。
# 于是 `e2e_rule_evm_js_test.go` 的 `_js` = GOOS=js,它在 linux 上**永远被忽略** ——
# 576 行、10 个 Test 函数,从写下那天起一次都没跑过,而 `go test` 全程绿灯、
# 不打任何一句警告(2026-09-09 由本门禁的上一版抓到)。
#
# ⛔ 这条必须是门禁而不是注释:它没有任何报错,`go vet` 不管,CI 也不管。
# 判据:*去掉 `_test` 之后,最后一段是不是某个 GOOS/GOARCH?*
echo "==> 文件名不撞 GOOS/GOARCH"
GOOS_LIST=$(go tool dist list | cut -d/ -f1 | sort -u)
GOARCH_LIST=$(go tool dist list | cut -d/ -f2 | sort -u)
while IFS= read -r f; do
    base=$(basename "$f" .go); base=${base%_test}
    last=${base##*_}
    [ "$last" = "$base" ] && continue   # 没有下划线段
    if printf '%s\n' "$GOOS_LIST" | grep -qx "$last" || printf '%s\n' "$GOARCH_LIST" | grep -qx "$last"; then
        printf '  ✗ %s —— 文件名以 `_%s` 结尾,Go 视作 GOOS/GOARCH 约束,本平台上**永不编译**\n' "$f" "$last" >&2
        printf '     改法:去掉那个下划线(如 `..._evm_js_test.go` → `..._evmjs_test.go`)\n' >&2
        fail=1
    fi
done < <(find . -name '*_test.go' -not -path './vendor/*')

# ---------- ③ 每个 e2e/integration 文件必须带对应 build tag ----------
#
# 漏一个 tag 的后果**不是少跑**,而是它被 `go test ./...` 无条件带进「无 tag」那层
# —— 于是一个要真起 daemon 的测试跑在单元层里,表现为「单元层偶发失败」,
# 而那是最难查的一类现象。
echo "==> build tag 与目录一致"
check_tag() {
    local dir=$1 want=$2
    for f in "$dir"/*.go; do
        [ -f "$f" ] || continue
        if ! head -5 "$f" | grep -q "^//go:build .*\b${want}\b"; then
            printf '  ✗ %s —— 缺 `//go:build %s`\n' "$f" "$want" >&2
            fail=1
        fi
    done
}
check_tag e2e e2e
check_tag tests/integration integration

# ---------- ④ 测试代码不许进生产二进制 ----------
#
# 判据是**结构性**的:一个 `.go` 文件要么以 `_test.go` 结尾(编译器不会把它放进
# 二进制),要么带 `//go:build` 约束,否则它就在守护进程里 —— 而那个进程持有私钥。
#
# 本仓库踩过(2026-09-09 审计发现):7 个 `shared_test_helpers.go` **不带任何 tag**,
# 全套 mock repository 连同 `import "testing"` 一起编译进了 remote-signer 二进制。
# 名字里带 test 骗过了所有人,包括当时的架构门禁 —— 它按 `_test` **子串**过滤,
# 于是把这些文件当成测试代码跳过了;而 Go 编译器按 `_test.go` **后缀**判断,不跳。
# 两套判据不一致 = 门禁看不见的盲区。
#
# 修法是改名 `shared_test_helpers.go` → `shared_test_helpers_test.go`:不带 build tag
# 的 `_test.go` 对**每个** tag 的测试二进制都编译,所以「所有 tier 可复用」这条
# 原有性质原封不动,只是不再进生产二进制。
#
# ⛔ 三条信号,每条都窄。第一版用「文件名里有 test」,当场误报两个:
#   internal/chain/evm/test_case_input.go / testcase_runner.go —— 那是**生产代码**,
#   实现规则 DSL 里的 `test_cases` 字段(领域概念,不是 Go 测试)。
# 会误报的门禁最后会被 `|| true` 掉,所以宁可收窄到只认下面三种:
#   (a) 名字里 `_test_` 作为**独立词段**出现(`shared_test_helpers.go`)——
#       它离「真的是测试文件」只差一次改名,而领域词 `testcase` / `test_case_input`
#       不含前置下划线,不会命中
#   (b) import "testing"      —— 标准库里的测试包,生产代码没有理由碰它
#   (c) import testify        —— 纯测试依赖
#
# 判据:*把某个 helper 改回不带后缀,这条门禁会不会红?* 会。
#      *把 test_case_input.go 放回来,它会不会红?* 不会。两个方向都验过。
echo "==> 测试代码不进生产二进制"
while IFS= read -r f; do
    [ -n "$f" ] || continue
    head -5 "$f" | grep -q '^//go:build ' && continue
    printf '  ✗ %s —— 测试辅助代码,但没有 `_test.go` 后缀也没有 build tag\n' "$f" >&2
    printf '     它会被编译进 remote-signer 二进制(那个进程持有私钥)。\n' >&2
    printf '     改法:改名为 `%s_test.go`;不带 tag 的 _test.go 对每个 tier 都可见,\n' "${f%.go}" >&2
    printf '           跨 tier 复用不受影响。\n' >&2
    fail=1
done < <(
    {
        find . -name '*_test_*.go' -not -name '*_test.go' \
            -not -path './vendor/*' -not -path '*/node_modules/*'
        grep -rlE '^[[:space:]]*("testing"|[a-z]* *"github.com/stretchr/testify)' \
            --include='*.go' . 2>/dev/null \
            | grep -v '_test\.go$' | grep -v '/vendor/' | grep -v '/node_modules/'
    } | sort -u
)

# ---------- ⑤ coverage_boost 测试只许缩 ----------
#
# 13 个文件、15,819 行,占测试代码的 12%。文件名直说了它们存在的理由是**抬覆盖率
# 数字**,不是描述行为 —— 那种测试的失败信息读不出「什么坏了」,只读得出
# 「某一行没被走到」,于是没人修,只会被注掉。
#
# ⛔ 不删,只上棘轮:里面混着少数**唯一覆盖某条错误路径**的用例,盲删会掉真覆盖。
# 正确的做法是逐个看:能说清它测的是什么行为的,改名搬去对应的 _test.go;
# 说不清的,删。两种做法都让这个数字变小。
#
# ⚠️ 变小也红 —— 那一刻正是把基线改小的时候(一行编辑)。
echo "==> coverage_boost 测试只许缩"
CB_BASE=scripts/lib/arch-baseline/coverage-boost.txt
cb() { sed 's/#.*//' "$CB_BASE" | awk -v k="$1" '$1==k{print $2}'; }
cb_files=$(find . -name '*coverage_boost*_test.go' -not -path './vendor/*' | wc -l)
cb_lines=$(find . -name '*coverage_boost*_test.go' -not -path './vendor/*' -exec cat {} + 2>/dev/null | wc -l)
for pair in "files:$cb_files" "lines:$cb_lines"; do
    k=${pair%%:*}; actual=${pair#*:}; base=$(cb "$k")
    if [ "$actual" -gt "$base" ]; then
        printf '  ✗ coverage_boost %s:%s → %s(涨了)\n' "$k" "$base" "$actual" >&2
        printf '     改法:新测试写进对应的 _test.go 并起个说明行为的名字,别往 coverage_boost 里塞。\n' >&2
        fail=1
    elif [ "$actual" -lt "$base" ]; then
        printf '  ✗ coverage_boost %s:实际 %s < 基线 %s —— 缩了,请把 %s 里的数字改成 %s\n' \
            "$k" "$actual" "$base" "$CB_BASE" "$actual" >&2
        fail=1
    fi
done

# ---------- ⑥ 每一层都必须在 CI 里被跑到 ----------
#
# 一个 tier 只要 CI 不跑,它的红就没人看得见 —— 而本仓库连续踩到两次:
#   · e2e/ 46 个测试文件,Makefile 里一个目标都没有(2026-09-09 发现)
#   · 补上 make 目标之后,CI 里**依然没有 e2e job** —— 那 21 个失败被修好的那天,
#     CI 也不会因此变绿或变红,因为它压根不跑(2026-09-10 发现)
#   · web-e2e 反过来:CI 跑,而 make 不认识它,20 个失败在本地全量里是看不见的
#
# 判据:*把某一层从 CI 里删掉,这条门禁会不会红?* 会。
#
# ⚠️ 判定方式是「CI 里必须出现 `make test LAYER=<名>`」,而不是「出现某个
# go test 命令」。这样 CI 与 layers.sh 共用同一个执行器,包列表只有一份 ——
# CI 里手抄一份 go test 正是上一次漂掉的原因。
echo "==> 每一层都在 CI 里被跑到"
CI_YML=.github/workflows/ci.yml
if [ ! -f "$CI_YML" ]; then
    printf '  ✗ 找不到 %s\n' "$CI_YML" >&2
    fail=1
else
    for name in $(layer_names); do
        # 默认层由不带 LAYER 的 `make test` 一起跑到
        case "$name" in
            unit|http|cli)
                grep -qE '^\s+run: make test\s*$' "$CI_YML" && continue
                printf '  ✗ %s 层:CI 里没有裸 `make test`(默认层 unit/http/cli 靠它跑)\n' "$name" >&2
                fail=1; continue ;;
        esac
        if ! grep -qE "run: make test LAYER=$name\b" "$CI_YML"; then
            printf '  ✗ %s 层:CI 里没有 `make test LAYER=%s` —— 这一层的红没人看得见\n' "$name" "$name" >&2
            printf '     改法:在 %s 加一个 job 跑它;要真的不跑就先把它从 layers.sh 删掉,\n' "$CI_YML" >&2
            printf '           别让一个登记在册却无人执行的层继续假装存在。\n' >&2
            fail=1
        fi
    done
fi

if [ "$fail" -ne 0 ]; then
    echo >&2
    echo "FAIL: 测试结构违规(见上)。" >&2
    exit 1
fi
echo "ok: 测试结构"
