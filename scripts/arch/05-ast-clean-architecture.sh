#!/usr/bin/env bash
# ---------- ⓪ AST 架构检查(Clean Architecture 依赖方向等) ----------
#
# 这条排在最前面(05),因为它是**唯一按结构判定**的一条:其余门禁读的是文本。
# 具体见 cmd/archcheck 的包注释 —— 那里列了两次 grep 判据出错的实例。
#
# 九条检查,各带自己的棘轮基线(scripts/lib/arch-baseline/ast/)。
# ⚠️ 这张表漂过:它长期写着「三条」,而 cmd/archcheck/main.go 的 checks 里
# 早就有八条 —— 权威是那份 checks,这里只是索引。
#   layers                 依赖方向:内层不许认识外层(层定义在 cmd/archcheck/layers.go)
#   frozen-settings        settings 开关被构造期冻进结构体字段
#   rule-write             谁能写规则表(规则是一份花钱授权)
#   duplication            归一化后形状 ≥88% 相同的函数对
#   rule-type-table        声明了却没进 types.ruleTypes 的规则类型(零基线)
#   engine-dispatch        调用方替引擎回答「这是哪种引擎」
#   mirror-structs         同一份配置格式被多个结构体各解析一遍
#   handler-path-dispatch  handler 自己切 r.URL.Path 分发(一条 pattern 背后多个端点)
#   respond-shape          同名 write helper 有多种参数顺序(两种都编译得过)
#
# 单独跑某一条:  go run ./cmd/archcheck layers
# 看未归层的包:  go run ./cmd/archcheck -unclassified
set -uo pipefail
cd "$(dirname "$0")/../.."
exec go run ./cmd/archcheck
