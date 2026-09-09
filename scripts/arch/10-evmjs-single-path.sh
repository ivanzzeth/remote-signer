#!/usr/bin/env bash
# 由 scripts/check-arch.sh 调用。单独跑也行(重构中修某一条时很有用)。
set -uo pipefail
cd "$(dirname "$0")/../.."
fail=0

# ---------- ① evm_js test case 只有一条执行路径 ----------
#
# `ValidateWithInput` 是「拿 script + input + config 跑一次 JS 规则」的底层入口。
# 它**只允许**被 internal/chain/evm/testcase_runner.go 调用。
#
# 为什么:template validate / preset validate / rule validate 曾各自抄了一份
# 「解析 config → 抽 script → 抽 test_cases → 逐条跑」的循环。三份抄本随后漂了 ——
# matrix preset 把每条链的覆盖值放在 Matrix 里、Rule.ChainID 为空,而其中两份
# 在校验前就把变量整份代换掉了,于是**多链 preset 的 test case 一直在用错的链参数
# 校验**,且全程绿灯。2026-09 的重构把三份收敛成 RunJSTestCases 一条。
#
# 判据:*又有人要直接跑 JS 规则了吗?* 那就是第四份抄本的开始。
# 要加新的校验入口 → 走 RunJSTestCases,或改本门禁的白名单并说明为什么它必须分叉。
echo "==> evm_js test case 单一执行路径"
ALLOWED_CALLER="internal/chain/evm/testcase_runner.go"
DEFINER="internal/chain/evm/js_evaluator.go"
offenders=$(grep -rn "ValidateWithInput(" --include='*.go' . 2>/dev/null \
    | grep -v '/vendor/' \
    | grep -v '_test\.go:' \
    | grep -v "^\./${ALLOWED_CALLER}:" \
    | grep -v "^\./${DEFINER}:" || true)
if [ -n "$offenders" ]; then
    printf '  ✗ ValidateWithInput 只许 %s 调用,以下是新的分叉:\n' "$ALLOWED_CALLER" >&2
    printf '%s\n' "$offenders" | sed 's/^/      /' >&2
    printf '    改法:走 evm.RunJSTestCases(script, cases, ctx) —— 它负责按每条 test case\n' >&2
    printf '          自己的 chain_id 做变量代换(matrix preset 必需)。\n' >&2
    fail=1
fi


exit "$fail"
