#!/usr/bin/env bash
# ---------- ⑩ 子进程不许爬回签名路径 ----------
#
# 这个进程持有私钥。它 fork 出去的每一个子进程,都是一次「把别人的攻击面拉进
# 我的地址空间」—— 而 evm_solidity_expression 规则做的正是这件事:求值时
# fork `forge script`,编译 Solidity + 跑一个 EVM,**就在签名路径上**,
# 每笔几百毫秒到秒级。
#
# 2026-09-09 已经把它改成 opt-in(`chains.evm.foundry.enabled`,默认关)。
# 但「默认关」是个**一行就能翻回去**的性质,而且翻回去了没有任何东西会响。
# 本门禁钉三件事:
#
#   ⑩a 只有登记过的文件可以 exec 子进程
#   ⑩b solidity 引擎的代码量只许缩(4162 行 / 11 文件)——迁移到 evm_js 是
#       已定方向,棘轮保证它不会停在半路,更不会反向长
#   ⑩c 出厂配置里 foundry.enabled 必须是 false —— 这条是**硬约束**,
#       因为它就是「默认关」这个决定本身
#
# ⛔ ⑩c 不许改成棘轮。「默认值」没有中间态:要么关,要么这条门禁没意义。
set -uo pipefail
cd "$(dirname "$0")/../.."
. scripts/lib/arch.sh
fail=0

echo "==> 子进程与 solidity 引擎"

arch_prod_files internal pkg cmd tui \
    | xargs -r grep -l 'exec\.Command' 2>/dev/null | sort -u \
    | arch_ratchet_set "⑩a fork 子进程的文件" \
        scripts/lib/arch-baseline/subprocess-spawners.txt \
        "别在持有私钥的进程里起子进程;要外部工具就放到独立的构建期服务里。" || fail=1

BASE=scripts/lib/arch-baseline/solidity-surface.txt
b() { sed 's/#.*//' "$BASE" | awk -v k="$1" '$1==k{print $2}'; }

n=$(arch_prod_files internal | grep solidity | xargs -r cat | wc -l)
arch_ratchet_count "⑩b solidity 引擎行数" "$(b solidity_lines)" "$n" \
    "把规则迁到 evm_js(sobek,进程内,不 fork);迁完删代码,然后把这里的数字改小。" "$BASE" || fail=1

n=$(arch_prod_files internal | grep -c solidity)
arch_ratchet_count "⑩b solidity 源文件数" "$(b solidity_files)" "$n" \
    "同上。" "$BASE" || fail=1

n=$(grep -rho 'evm_solidity_expression' rules/ 2>/dev/null | wc -l)
arch_ratchet_count "⑩b rules/ 里的 solidity 规则引用" "$(b rules_references)" "$n" \
    "把模板/preset 迁到 evm_js。⚠️ 这个功能默认关着,所以这些规则在出厂配置下是跑不了的。" "$BASE" || fail=1

# ⑩c —— 硬约束:出厂配置的默认值就是这个决定本身。
for f in config.example.yaml config.full.yaml; do
    [ -f "$f" ] || continue
    # 只看未注释的 enabled 行,且必须在 foundry: 块内
    val=$(awk '/^[[:space:]]*foundry:/{inb=1;next}
               inb && /^[[:space:]]*[a-z_]+:/ && !/^[[:space:]]*(enabled|forge_path|cache_dir|temp_dir|timeout):/{inb=0}
               inb && /^[[:space:]]*enabled:/{print $2; exit}' "$f")
    if [ "$val" = "true" ]; then
        printf '  ✗ ⑩c %s 里 foundry.enabled 是 true\n' "$f" >&2
        printf '    出厂配置默认打开 solidity = 每笔签名在持有私钥的进程里 fork forge。\n' >&2
        printf '    改法:改回 false。要给例子就写在注释里,别写进生效的默认值。\n' >&2
        fail=1
    fi
done

exit "$fail"
