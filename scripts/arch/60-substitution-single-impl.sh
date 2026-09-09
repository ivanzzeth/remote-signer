#!/usr/bin/env bash
# ---------- ⑥ ${var} 展开只有一份实现 ----------
#
# 这曾是全仓库**最危险**的一条重复,理由不是可读性,是资金安全:
#
#   校验期走 core/service/substitute.go —— 展开后检查有没有剩下的 ${...},有就报错
#   求值期走 core/rule/effective_config.go —— 展开后原样返回
#
# 两份代码逐字相同,只差最后那个检查。而更糟的是另外五份**只认裸 `${k}`**:
# preset apply、config 的 budget 初始化、metering JSON、budget unit、
# 一次性迁移工具 —— 它们把 `${first:x}` / `${hex:x}` 原样留下,而引擎会展开。
# 同一个 preset,apply 时和求值时含义不同,没有任何报错。
#
# 2026-09-10 收成一份:internal/core/rule.ExpandPlaceholders。严格与宽松的差别
# 现在是**调用方展开之后做什么**(要不要用 UnresolvedPlaceholders 拒绝),
# 而不是各跑一份循环。
#
# ⛔ 判据是**结构性**的:除了那一份实现,任何地方都不许再手工拼 `"${"+k+"}"`。
# 那个拼接就是自造展开的起手式 —— 前一版门禁只数「定义了 Substitute 函数的
# 文件」,而上面那五份抄本一份都没被数到,因为它们的函数名叫
# substituteBudgetValue、substituteVarInValue、substituteUnitVariables。
set -uo pipefail
cd "$(dirname "$0")/../.."
. scripts/lib/arch.sh
fail=0

echo "==> \${var} 展开单一实现"

ALLOWED="internal/core/rule/substitution.go"
offenders=$(arch_prod_files internal pkg cmd tui \
    | grep -v "^${ALLOWED}$" \
    | xargs -r grep -l 'ReplaceAll([^)]*"${"' 2>/dev/null | sort -u)

if [ -n "$offenders" ]; then
    printf '  ✗ 这些文件在手工拼 ${...} 占位符,也就是自造了一份展开:\n' >&2
    printf '%s\n' "$offenders" | sed 's/^/      /' >&2
    printf '    改法:调 rule.ExpandPlaceholders(s, vars) —— 它认全部五种形式\n' >&2
    printf '          (${x} / ${hex:x} / ${paddedhex:x} / ${first:x} / ${hex:first:x});\n' >&2
    printf '          要拒绝未解析的,再调 rule.UnresolvedPlaceholders。\n' >&2
    printf '    ⛔ 少认一种形式 = 这份代码与引擎对同一条规则的理解不同,而且不报错。\n' >&2
    fail=1
fi

# firstOfList:纯函数,同样只许一份。
arch_prod_files internal pkg \
    | xargs -r grep -lE 'func firstOfList|func FirstOfList' 2>/dev/null | sort -u \
    | arch_ratchet_set "⑥b firstOfList 的实现" \
        scripts/lib/arch-baseline/firstoflist-impls.txt \
        "抽到一个共享包里;它是纯函数,没有任何理由存在第二份。" || fail=1

exit "$fail"
