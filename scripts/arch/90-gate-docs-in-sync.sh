#!/usr/bin/env bash
# ---------- ⑨ 门禁清单与文档一致 ----------
#
# 门禁本身也会漂。本仓库的实例:AGENTS.md 写着「含 5 条已负向验证的结构/架构
# 门禁」,而实际有 7 条 —— 那句话是加第 6 条时忘了改的。后果不是数字不准:
# 新来的人照文档以为「就这 5 条」,于是加门禁时不知道该往哪儿加、
# 也不知道 scripts/arch/ 这个目录存在。
#
# 三条硬约束(不是棘轮 —— 今天就是 0 违规,而且修起来是一行编辑):
#   ⑨a 每个 scripts/arch/NN-*.sh 都在 TESTING.md 的门禁表里有一行
#   ⑨b TESTING.md 提到的每个 arch/NN 都真的存在
#   ⑨c 每个门禁脚本可执行,且能单独跑(cd 到仓库根,不依赖被谁调用)
#   ⑨d AGENTS.md 里那个「N 条门禁」的数字是对的 —— 它就是漂掉的那一句本身
set -uo pipefail
cd "$(dirname "$0")/../.."
fail=0

echo "==> 门禁清单与文档一致"

DOC=TESTING.md
have=$(ls scripts/arch/[0-9]*.sh 2>/dev/null | sed 's|scripts/arch/\([0-9]*\)-.*|\1|' | sort -u)
doc=$(grep -oE '`arch/[0-9]+`' "$DOC" | tr -d '`' | sed 's|arch/||' | sort -u)

missing_in_doc=$(comm -23 <(printf '%s\n' $have) <(printf '%s\n' $doc))
if [ -n "$missing_in_doc" ]; then
    printf '  ✗ ⑨a 这些门禁没写进 %s 的门禁表:\n' "$DOC" >&2
    for n in $missing_in_doc; do printf '      arch/%s  (%s)\n' "$n" "$(ls scripts/arch/$n-*.sh)" >&2; done
    printf '    改法:在 %s 的门禁表里加一行 —— **写清它抓的是哪次真实事故**,\n' "$DOC" >&2
    printf '          那一列才是别人判断「这条门禁能不能删」的依据。\n' >&2
    fail=1
fi

missing_on_disk=$(comm -13 <(printf '%s\n' $have) <(printf '%s\n' $doc))
if [ -n "$missing_on_disk" ]; then
    printf '  ✗ ⑨b %s 提到了不存在的门禁:%s\n' "$DOC" "$(echo $missing_on_disk)" >&2
    printf '    改法:门禁删了就把那一行也删掉,别留个指向空气的引用。\n' >&2
    fail=1
fi

for g in scripts/arch/[0-9]*.sh; do
    [ -x "$g" ] || { printf '  ✗ ⑨c %s 没有可执行位(check-arch.sh 会静默跳过它)\n' "$g" >&2; fail=1; }
    # 单独跑的能力:必须自己 cd 到仓库根,否则「重构中只跑一条」这个用法是坏的
    grep -q 'cd "$(dirname "$0")/../\.\."' "$g" \
        || { printf '  ✗ ⑨c %s 不能单独跑(缺 cd 到仓库根那一行)\n' "$g" >&2; fail=1; }
done

# ⑨d —— 数字漂过一次,所以这里直接对着算出来的数比。
# ⚠️ 判据要能负向验证:把 AGENTS.md 的数字改错一个,这条必须红。
claimed=$(grep -oE '\*\*[0-9]+ 条已负向验证的门禁\*\*' AGENTS.md | grep -oE '[0-9]+' | head -1)
n_tests=$(grep -c '^# ---------- ' scripts/check-tests.sh)
n_arch=$(ls scripts/arch/[0-9]*.sh 2>/dev/null | wc -l)
actual=$((n_tests + n_arch))
if [ -z "$claimed" ]; then
    printf '  ✗ ⑨d AGENTS.md 里找不到「N 条已负向验证的门禁」那句话\n' >&2
    printf '    改法:别把它删掉 —— 那句话是新人判断「门禁一共有几条、在哪儿」的唯一入口。\n' >&2
    fail=1
elif [ "$claimed" -ne "$actual" ]; then
    printf '  ✗ ⑨d AGENTS.md 说有 %s 条门禁,实际 %s 条(%s 测试结构 + %s 架构)\n' \
        "$claimed" "$actual" "$n_tests" "$n_arch" >&2
    printf '    改法:把 AGENTS.md 里那个数字改成 %s。\n' "$actual" >&2
    fail=1
fi

exit "$fail"
