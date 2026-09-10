#!/usr/bin/env bash
# `make test` 的执行器。层的定义来自 scripts/lib/layers.sh(唯一事实来源)。
#
#   ./scripts/run-tests.sh              默认层全跑(unit http cli)
#   ./scripts/run-tests.sh unit         只跑一层
#   ./scripts/run-tests.sh all          含 integration / blackbox / e2e / web-unit
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
# ⚠️ 需要 node + playwright 浏览器(`npx playwright install chromium`),装不上的
# 机器上会红在环境而不是代码 —— 所以 `all` 不含它,必须显式 LAYER=web-e2e。
# ⛔ 但它**必须**留在 layers.sh 里:不在那张表里的 tier,红了没人看得见。
OPT_IN_LAYERS="web-e2e"
# ⭐ 只要 node 的层 —— 进 `all`,不进默认。
#
# 不进默认:`make test` 是「改一行 Go 代码想知道对不对」的循环,不该为此付
# node 的启动代价;go-test 那个 CI job 也没有 setup-node。
# 进 `all`:它不要浏览器、不起 daemon、不构建二进制,冷跑 ≈18s,而 `make build`
# 默认就走 vite —— 所以「有 node」本来就是本仓库的既有前提,不是新增门槛。
# 依赖缺失由层命令里的 `make web-deps` 兜住,不会红在 "vitest: not found"。
NODE_LAYERS="web-unit"

want=${1:-}
case "$want" in
    "")    layers=$DEFAULT_LAYERS ;;
    all)   layers="$DEFAULT_LAYERS $SLOW_LAYERS $NODE_LAYERS" ;;
    everything) layers="$DEFAULT_LAYERS $SLOW_LAYERS $NODE_LAYERS $OPT_IN_LAYERS" ;;
    *)
        if ! layer_raw "$want" >/dev/null 2>&1; then
            echo "FAIL: 没有 LAYER=$want" >&2
            echo "      可选: $(layer_names | tr '\n' ' ')(或 all / everything)" >&2
            exit 1
        fi
        layers=$want ;;
esac

runflag=()
[ -n "${RUN:-}" ] && runflag=(-run "$RUN")

rc=0
for name in $layers; do
    tag=$(layer_tag "$name")
    # 非 go test 的层:第三段就是命令,原样执行。
    if [ "$tag" = "@cmd" ]; then
        cmd=$(layer_raw "$name")
        printf '==> %s 层 (%s)\n' "$name" "$cmd"
        bash -c "$cmd" || rc=1
        continue
    fi
    pkgs=$(layer_pkgs "$name")
    if [ -z "$(printf '%s' "$pkgs" | tr -d ' ')" ]; then
        echo "==> $name 层:没有匹配的包,跳过"; continue
    fi
    tagflag=(); [ -n "$tag" ] && tagflag=(-tags "$tag")

    # ⛔ blackbox 与 e2e 必须 -count=1,禁用 go 的测试结果缓存。
    #
    # 这两层测的不是被编译进测试二进制的代码 —— 它们**起一个单独构建的 daemon**
    # 然后打它的 HTTP 口。go 的缓存只看测试包自己的输入(源码 + 依赖 + 环境),
    # 它**看不见那个 daemon 二进制变了**,于是改完 internal/api 之后照样重放
    # 上一次的 `ok (cached)`。
    #
    # 2026-09-10 实测的后果:`/api/v1/` 兜底路由改了鉴权模式,
    # tests/integration 的 TestWeb_UnknownAPIRouteIsNotSwallowed 从那一刻起
    # 就是红的,而 pre-push 连续 **10 个提交**打印 `ok (cached)` 一次都没真跑。
    # ⚠️ 而 ci.yml 只在 main/dev 和 PR 上触发,feature 分支的 push 不跑这两层,
    # 所以两道门同时是哑的。
    #
    # 判据:*这个测试的结论依赖于测试二进制之外的东西吗?* 是,就不能吃缓存。
    countflag=()
    case "$name" in
        blackbox|e2e) countflag=(-count=1) ;;
    esac

    printf '==> %s 层%s\n' "$name" "${tag:+ (tags=$tag)}"
    # shellcheck disable=SC2086
    $GO test "${tagflag[@]}" "${countflag[@]}" "${runflag[@]}" $pkgs || rc=1
done
exit "$rc"
