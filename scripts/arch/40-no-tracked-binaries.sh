#!/usr/bin/env bash
# ---------- ⑪ 版本库里不许有构建产物 ----------
#
# 2026-09-10 的真实事故:`cmd/archcheck` 编译出来的 3.8 MB 二进制被提交进库,
# 前后 8 个版本,历史里积了约 25 MB —— 而 clone 一次只用得上其中 0 字节。
# 清掉它要重写全历史、force-push 两个仓库的 main 和 32 个 tag,并把父仓库
# 41 个 submodule 指针一起改写。**代价全在事后,而拦住它只要一次判断。**
#
# ⛔ 它当时**本该被拦住**:.githooks/pre-commit 里一直有 >1MB 的大文件检查。
# 没拦住的原因是那个 hook 从来没生效过 —— `core.hooksPath` 没人设过,
# 而没有任何东西检查这件事。所以这条门禁必须活在 `make check` 里(CI 会跑),
# 而不是只活在 hook 里:**一道只在本地生效的门禁,等于一道可以不生效的门禁。**
#
#   ⑪a 已跟踪文件里不许有二进制 —— 判据是 git 自己的二进制判定,不是后缀名
#   ⑪b 已跟踪文件不许超过 1 MB —— 哪怕它是文本
#
# 两条都要,因为它们各自漏掉对方抓的东西:500 KB 的二进制过得了 ⑪b,
# 3 MB 的压缩 JS 过得了 ⑪a。事故那个文件两条都撞,却一条都没跑。
#
# ⚠️ 判据读的是 **index**(`--cached`),不是 HEAD。pre-commit 里 index 就是
# 「即将提交的内容」,所以这条门禁在**提交发生之前**就红;读 HEAD 的话
# 要等到下一次提交才发现,那时东西已经在历史里了 —— 而进了历史就只能靠
# 重写来清,也就是这次的代价。
#
# ⚠️ 真需要提交一个二进制(测试用的固件、字体)时:登记进基线并写明理由,
# 别放宽判据。基线是双向棘轮 —— 登记的文件删掉后不撤登记,同样红。
set -uo pipefail
cd "$(dirname "$0")/../.."
. scripts/lib/arch.sh
fail=0

echo "==> 版本库里的构建产物"

# git 的空树 —— 拿它当 diff 的一端,就能把「index 里的全部文件」当成一次变更列出来。
EMPTY=$(git hash-object -t tree /dev/null)

# ⑪a —— `--numstat` 对二进制文件输出 `-  -`,那就是 git 自己的判定,
# 比任何后缀白名单都准:它看内容,而攻击性的重命名骗不过它。
git diff --numstat --cached "$EMPTY" 2>/dev/null \
    | awk '$1 == "-" && $2 == "-" { print $3 }' | sort -u \
    | arch_ratchet_set "⑪a 已跟踪的二进制文件" \
        scripts/lib/arch-baseline/tracked-binaries.txt \
        "构建产物加进 .gitignore,别提交。真需要入库的二进制(固件/字体)登记进基线并写明理由。" || fail=1

# ⑪b —— 大小走 index 里的 blob,不走磁盘:磁盘上的文件可能还没 add,
# 也可能已经被改过,而入库的是 index 里那一份。
#
# ⚠️ `git ls-files -s` 的路径在 TAB 之后,前面才是 `mode sha stage`。按空白切
# 会把带空格的路径切断,而带空格的路径恰恰是最容易被漏掉的那一类。
# ⚠️ 一趟 `--batch-check` 而不是每文件一次 `cat-file -s`:后者在几千个文件上
# 是几千次 fork,慢到会让人想把这条门禁关掉 —— 而这正是 pre-commit 上一版
# 跑 208 秒之后发生的事。
MAX=$((1024 * 1024))
git ls-files -s \
    | awk -F'\t' '{ split($1, a, " "); print a[2] " " $2 }' \
    | git cat-file --batch-check='%(objectsize) %(rest)' 2>/dev/null \
    | awk -v max="$MAX" '$1 > max { $1 = ""; sub(/^ /, ""); print }' | sort -u \
    | arch_ratchet_set "⑪b 超过 1 MB 的已跟踪文件" \
        scripts/lib/arch-baseline/large-files.txt \
        "大文件走 Git LFS 或干脆别入库。⚠️ 生成的产物(dist/、lock 文件除外)应该由构建重建,不该提交。" || fail=1

exit "$fail"
