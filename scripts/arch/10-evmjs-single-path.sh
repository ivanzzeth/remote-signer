#!/usr/bin/env bash
# 由 scripts/check-arch.sh 调用。单独跑也行(重构中修某一条时很有用)。
set -uo pipefail
cd "$(dirname "$0")/../.."
fail=0

# ---------- ① 直接跑 JS 规则只有一个入口 ----------
#
# ⚠️ 这条门禁**不**保证「test case 只有一条执行路径」—— 那句话曾写在这里,
# 而它不是真的。test case 实际上有两条路,回答的是两个不同的问题:
#
#   RunJSTestCases(→ ValidateWithInput)  这个脚本单独跑,接受还是拒绝这个输入?
#     用于:template validate API、preset validate、rule validate
#
#   cli/validate 的引擎路径(EvaluateWithResult) 整个引擎(blocklist + 委派 +
#     这条规则)对这个输入是什么结论?
#     用于:`remote-signer validate`
#
# 两者可以合法地不一致 —— 一条白名单规则单独跑通过,但被某条 blocklist 拦下 ——
# cli/validate 里那个 `useFullEngine && isNoMatch && isWhitelistRule` 分支就是
# 在处理这件事。⛔ 所以别把它们合并,先想清楚要回答哪个问题。
#
# 本门禁钉住的是**其中一条**:直接跑 JS 的底层入口只许有一个调用者。
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
echo "==> 直接跑 JS 规则单一入口"
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
