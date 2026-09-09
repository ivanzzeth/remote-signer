#!/usr/bin/env bash
# ---------- ④ 规则写入的收口 ----------
#
# 一条规则就是一次**资金授权**:它决定哪些交易不经人工就自动签掉。所以
# 「谁能往 `rules` 表写行」是本仓库最该被钉住的一条性质。
#
# 现状(2026-09 审计):8 条独立写入路径,各带或不带自己的校验。强制校验被放在
# internal/api/handler/validation_mandatory.go —— 那是 **HTTP 层的策略**,
# 从 CLI / 启动种子 / 内部服务调 TemplateService.CreateInstance 的路径全部绕过。
# `7379347 fix: enforce mandatory validation on preset apply and template instantiate`
# 修的就是这个形状的两个实例。
#
# 本门禁不试图**修**它(那是重构),只保证它**不再长**:
#   ④a 只有登记过的文件可以拿到 rule repo 句柄
#   ④b 「会写库但不校验」的文件集合只许缩小
#
# 判据:*又有人要拿 rule repo 了吗?* 那就是第 9 条写入路径的开始。
set -uo pipefail
cd "$(dirname "$0")/../.."
. scripts/lib/arch.sh
fail=0

echo "==> 规则写入收口"

# ⚠️ 匹配面必须同时认**接口名**和**具体构造**。第一版只 grep `storage.RuleRepository`,
# 漏掉 5 处直接 `storage.NewGormRuleRepository(db)` 的 —— 其中
# internal/api/handler/preset.go:803 和 cmd/migrate-config-templateform/main.go
# 都是**真的在写 `rules` 表**。负向验证当场戳破:审计表里明明有 preset apply 这条
# 写入路径,门禁却说它不存在。
#
# ⛔ 不认 `MemoryRuleRepository`:它是校验期的临时草稿纸(validator / validate 子命令
# 用它装载规则跑一遍),写进去的行永远到不了数据库。把它算进来 = 6 个纯只读文件
# 常驻基线,而基线本该是**重构 TODO 清单**,混进永远删不掉的条目就没人看了。
RULE_REPO_RE='storage\.RuleRepository|GormRuleRepository'

holders=$(arch_prod_files internal pkg cmd tui \
    | grep -v '^internal/storage/' \
    | xargs -r grep -lE "$RULE_REPO_RE" 2>/dev/null | sort -u)

printf '%s\n' "$holders" | grep -v '^$' | arch_ratchet_set \
    "④a 持有 rule repo 句柄的文件" \
    scripts/lib/arch-baseline/rule-repo-holders.txt \
    "走已有的服务(TemplateService / RuleHandler),不要再拿一个裸 repo 句柄。" || fail=1

# ④b —— 判据保守:持有 rule repo + 有任何 .Create( / .Update( + 无 ValidateRuleConfig。
# ⚠️ 宁可多登记两个(有人会来删),不可漏掉一条(没人会发现)。
unvalidated=""
for f in $holders; do
    grep -qE '\.(Create|Update)\(' "$f" || continue
    grep -q 'ruleconfig\.ValidateRuleConfig' "$f" && continue
    unvalidated="${unvalidated}${f}"$'\n'
done

printf '%s' "$unvalidated" | grep -v '^$' | arch_ratchet_set \
    "④b 会写库但不过 ValidateRuleConfig 的文件" \
    scripts/lib/arch-baseline/rule-write-unvalidated.txt \
    "在写入前调 ruleconfig.ValidateRuleConfig(rule.Type, cfg);不要把校验留给调用方。" || fail=1

exit "$fail"
