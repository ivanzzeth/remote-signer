#!/usr/bin/env bash
# `make test` 的执行器。层的定义来自 scripts/lib/layers.sh(唯一事实来源)。
#
#   ./scripts/run-tests.sh              默认层全跑(unit http cli)
#   ./scripts/run-tests.sh unit         只跑一层
#   ./scripts/run-tests.sh all          含 integration / blackbox / e2e
#   RUN=TestFoo ./scripts/run-tests.sh unit    再按用例名收窄
#
# ⚠️ integration / blackbox / e2e **不进默认** —— 它们要真二进制 / 真 daemon,
# 慢。默认层是「改一行代码想知道对不对」的那个反馈循环。
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/lib/layers.sh

GO=${GO:-go}
DEFAULT_LAYERS="unit http cli"
SLOW_LAYERS="integration blackbox e2e"

want=${1:-}
case "$want" in
    "")    layers=$DEFAULT_LAYERS ;;
    all)   layers="$DEFAULT_LAYERS $SLOW_LAYERS" ;;
    *)
        if ! layer_raw "$want" >/dev/null 2>&1; then
            echo "FAIL: 没有 LAYER=$want" >&2
            echo "      可选: $(layer_names | tr '\n' ' ')(或 all)" >&2
            exit 1
        fi
        layers=$want ;;
esac

runflag=()
[ -n "${RUN:-}" ] && runflag=(-run "$RUN")

rc=0
for name in $layers; do
    tag=$(layer_tag "$name")
    pkgs=$(layer_pkgs "$name")
    if [ -z "$(printf '%s' "$pkgs" | tr -d ' ')" ]; then
        echo "==> $name 层:没有匹配的包,跳过"; continue
    fi
    tagflag=(); [ -n "$tag" ] && tagflag=(-tags "$tag")
    printf '==> %s 层%s\n' "$name" "${tag:+ (tags=$tag)}"
    # shellcheck disable=SC2086
    $GO test "${tagflag[@]}" "${runflag[@]}" $pkgs || rc=1
done
exit "$rc"
