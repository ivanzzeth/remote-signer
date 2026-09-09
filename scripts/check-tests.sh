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
    tag=$(layer_tag "$name"); pkgs=$(layer_pkgs "$name")
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

if [ "$fail" -ne 0 ]; then
    echo >&2
    echo "FAIL: 测试结构违规(见上)。" >&2
    exit 1
fi
echo "ok: 测试结构"
