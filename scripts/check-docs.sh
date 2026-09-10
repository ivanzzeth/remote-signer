#!/usr/bin/env bash
# 文档门禁。
#
# 为什么是门禁而不是约定:文档不参与编译、不在测试里,所以它是唯一一种
# **漂了也全绿**的东西。这个仓库已经踩过两次同样的形状 —— 一次是
# arch/10 的注释说「evm_js test case 只有一条执行路径」,而实际有两条;
# 一次是 LoadTemplatesFromDir 的注释说「文件自己的元数据 downstream 会赢」,
# 而实际不会,我照着那句话改,e2e 当场红。**注释和文档写错的代价,是下一个人
# 照着它做决定。**
#
# 判据(和 make check 里其它门禁一致):*这个错误再犯一次,什么会变红?*
set -euo pipefail

fail=0

# ---------- 权威文档的长度上限 ----------
#
# ⛔ 上限的目的是**逼细则出去**,不是逼内容互相踩。超了就拆专题文档,
#    不要把两段压成一段更难读的长句。
#
# 为什么要卡:一份没人从头读的文档,和没有文档的区别只是它让人**以为**
# 有文档。lingxiao 的上一代把 architecture.md 写到 1557 行,结果代码慢慢
# 漂走,而文档"一直是对的"。
check_len() {
    local file="$1" max="$2" why="$3"
    [ -f "$file" ] || { echo "FAIL: $file 不存在" >&2; fail=1; return; }
    local lines
    lines=$(wc -l < "$file")
    if [ "$lines" -gt "$max" ]; then
        echo "FAIL: $file 有 $lines 行,上限 $max —— $why" >&2
        echo "      只写结论;细则拆到 docs/ 下的专题文档。" >&2
        fail=1
    else
        echo "  ok  $file $lines/$max 行"
    fi
}

echo "==> 权威文档长度"
check_len docs/prd.md      250 "PRD 是所有其它文档的源头,长到没人读完就失去了源头的作用"
check_len ARCHITECTURE.md  200 "架构只写'应该长什么样';怎么做属于模块文档"
check_len AGENTS.md        260 "每次会话都要读进上下文,长了等于没有"

# ---------- 索引双向完整 ----------
#
# 新增文档却忘了挂索引,它对下一个人(和下一个 agent)就等于不存在 ——
# 没有人会去 ls docs/,只会照着索引找,找不到就当没有,然后把同一件事
# 重新想一遍。反过来,索引里写了但文件不存在 = 断链,同样是骗人。
echo "==> 专题文档索引完整"
INDEX=docs/README.md
[ -f "$INDEX" ] || { echo "FAIL: $INDEX 不存在 —— 专题文档没有入口。" >&2; exit 1; }

for f in docs/*.md docs/rules/*.md; do
    [ -f "$f" ] || continue
    rel=${f#docs/}
    [ "$rel" = "README.md" ] && continue
    grep -qF "($rel)" "$INDEX" || {
        echo "FAIL: $f 没有被 $INDEX 索引 —— 下一个人找不到它。" >&2
        fail=1
    }
done

while IFS= read -r target; do
    case "$target" in
        /*|http*|../*) continue ;;   # 绝对路径 / 外链 / 指向仓库根,不在本检查范围
        */)  [ -d "docs/$target" ] || { echo "FAIL: $INDEX 链到不存在的目录 docs/$target" >&2; fail=1; }; continue ;;
        *\#*) target=${target%%\#*} ;;   # 去掉锚点
    esac
    [ -z "$target" ] && continue
    [ -f "docs/$target" ] || {
        echo "FAIL: $INDEX 链到 docs/$target,但那个文件不存在(断链)。" >&2
        fail=1
    }
done < <(grep -oE '\]\([^)]+\)' "$INDEX" | sed 's/^](//;s/)$//')

# ---------- 入口链不能断 ----------
#
# AGENTS.md 把细则拆出去,靠索引把它们挂回来。少了这个入口,拆出去的
# 东西就找不回来了。
grep -qF "docs/README.md" AGENTS.md || {
    echo "FAIL: AGENTS.md 没有指向 docs/README.md 的入口,专题文档等于断链。" >&2
    fail=1
}

# ---------- Markdown 表格不能被正文截断 ----------
#
# 表格中间插进一段正文后又继续写 `| data |`,渲染器会把后半截当普通文本,
# 而看 diff 时肉眼很容易以为仍在表内。忽略代码块;要求每一段 `|` 行的
# 第二行必须是表头分隔线。
echo "==> Markdown 表格完整"
for f in docs/*.md docs/rules/*.md ./*.md; do
    [ -f "$f" ] || continue
    awk '
        /^```/ { in_fence = !in_fence; next }
        in_fence { next }
        /^[[:space:]]*\|/ {
            if (!in_table) { in_table = 1; pending = 1; header_line = NR; next }
            if (pending) {
                if ($0 !~ /^[[:space:]]*\|[[:space:]]*:?-{3,}:?[[:space:]]*\|/) {
                    printf "FAIL: %s:%d 的表格缺表头分隔线(可能被正文截断)。\n", FILENAME, header_line > "/dev/stderr"
                    failed = 1
                }
                pending = 0
            }
            next
        }
        { if (pending) { printf "FAIL: %s:%d 的表格只有孤立表头。\n", FILENAME, header_line > "/dev/stderr"; failed = 1 }
          in_table = 0; pending = 0 }
        END { if (pending) { printf "FAIL: %s:%d 的表格只有孤立表头。\n", FILENAME, header_line > "/dev/stderr"; failed = 1 }
              exit failed }
    ' "$f" || fail=1
done

# ---------- README 里的命令必须真的存在 ----------
#
# README 是新人的第一条路径。命令改名/删除时最容易漏掉它(它不参与编译、
# 也不在测试里),而漂移的表现是 `make: *** No rule to make target` ——
# 一条完全不解释原因的错误。
echo "==> README 命令有效"
for f in README.md README.zh.md; do
    [ -f "$f" ] || continue
    while read -r target; do
        [ -z "$target" ] && continue
        grep -qE "^${target}:" Makefile || {
            echo "FAIL: $f 提到 \`make $target\`,但 Makefile 里没有这个目标。" >&2
            fail=1
        }
    done < <(grep -oE '\bmake [a-z][a-z-]*' "$f" | awk '{print $2}' | sort -u)
done

[ "$fail" -eq 0 ] && echo "✅ 文档门禁全绿"
exit "$fail"
