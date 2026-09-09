#!/usr/bin/env bash
# ---------- ⓪ AST 架构检查(Clean Architecture 依赖方向等) ----------
#
# 这条排在最前面(05),因为它是**唯一按结构判定**的一条:其余门禁读的是文本。
# 具体见 cmd/archcheck 的包注释 —— 那里列了两次 grep 判据出错的实例。
#
# 三条检查,各带自己的棘轮基线(scripts/lib/arch-baseline/ast/):
#   layers           依赖方向:内层不许认识外层(层定义在 cmd/archcheck/layers.go)
#   frozen-settings  settings 开关被构造期冻进结构体字段
#   respond-shape    同名 write helper 有多种参数顺序(两种都编译得过)
#
# 单独跑某一条:  go run ./cmd/archcheck layers
# 看未归层的包:  go run ./cmd/archcheck -unclassified
set -uo pipefail
cd "$(dirname "$0")/../.."
exec go run ./cmd/archcheck
