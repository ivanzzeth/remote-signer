#!/usr/bin/env bash
# ---------- ⑥ ${var} 代换的实现数 ----------
#
# 这是全仓库**最危险**的一条重复,理由不是可读性,是资金安全:
#
#   校验期走 core/service/substitute.go —— 类型感知、JSON 编码、**遇到问题报错**
#   求值期走 core/rule/effective_config.go —— best-effort、**永不报错**
#
# 两者对同一个 `${var}` 的处理只要有一处不同,结果就是「test_case 全绿的规则,
# 在运行时授权了另一件事」。而这两份代码没有任何机制保证它们同步。
#
# 目前 7 份实现 + firstOfList 两份抄本。目标态是单一 `substitution` 包,
# 严格/宽松作为**参数**而不是另一份代码。
#
# ⚠️ 这里有个真实的设计取舍,不是纯粹的债:core/rule/effective_config.go 的注释
# 说明他们**故意**选择求值期实时代换,「so editing a rule's Variables takes effect
# on the next evaluation with no rendered snapshot that could drift」。
# 本门禁不预设结论,只保证:**要么收敛到一份,要么至少不再新增第 8 份**。
set -uo pipefail
cd "$(dirname "$0")/../.."
. scripts/lib/arch.sh
fail=0

echo "==> \${var} 代换实现数"

arch_prod_files internal pkg \
    | xargs -r grep -lE 'func [A-Za-z(). *]*[Ss]ubstitute' 2>/dev/null | sort -u \
    | arch_ratchet_set "⑥a 定义代换函数的文件" \
        scripts/lib/arch-baseline/substitution-impls.txt \
        "走已有的代换实现;差异(严格报错 vs 宽松跳过)用参数表达,不要再抄一份。" || fail=1

# ⑥b —— firstOfList 这类**纯函数小工具**的抄本。判据比 ⑥a 硬:它没有任何
# 「设计取舍」可言,两份就是纯粹的抄。
arch_prod_files internal pkg \
    | xargs -r grep -lE 'func firstOfList|func FirstOfList' 2>/dev/null | sort -u \
    | arch_ratchet_set "⑥b firstOfList 的抄本" \
        scripts/lib/arch-baseline/firstoflist-impls.txt \
        "抽到一个共享包里;它是纯函数,没有任何理由存在第二份。" || fail=1

exit "$fail"
