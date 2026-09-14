#!/usr/bin/env bash
# 从 internal/apidocs/openapi.json 生成 SDK —— **唯一的生成入口**。
#
#   ./scripts/gen-sdk.sh            两个都生成
#   ./scripts/gen-sdk.sh go         只生成 Go
#   ./scripts/gen-sdk.sh ts         只生成 TS
#
# `make sdk` 调它;门禁 ⑮ 的漂移档(`SDK_REGEN=1 ./scripts/check-sdk-coverage.sh`)
# 也调它,生成到临时目录再和库里那份比。⛔ 两处各写一遍命令行就是两个事实源
# —— 门禁会拿**另一套参数**生成的代码去比对提交的那份,差异一出现,人第一反应
# 是改文件而不是查参数。scripts/gen-openapi.sh 顶上写的是同一件事。
#
# ---------- ⛔ 这条链路上「什么都没生成却报告成功」长什么样 ----------
#
# ⑭ 的形态是「一份从 0 个文件生成出来的 spec 和一份干净的 spec 长得一样」。
# 这一步的形态更糟,因为它**编译得过**:
#
#   实测(2026-09-14):拿 `{"openapi":"3.1.0","paths":{}}` 喂 oapi-codegen v2.8.0,
#   **退出码 0**,写出 3,804 字节合法 Go,里面是 `type ClientInterface interface {}`
#   —— 一个编译通过、go vet 干净、什么方法都没有的 SDK。
#   openapi-typescript 7.13.0 同样:退出码 0,写出 `export type paths = Record<string, never>`。
#
# 所以这里每生成一份都要**数一遍它暴露了几个操作**,并要求它等于 spec 里的
# operation 数。那是独立的第二个观测:一个数来自 .json,一个数来自生成出来的
# 代码本身。⛔ 别拿生成器自己的日志当证据 —— 它在装死的时候也是绿的。
set -uo pipefail
cd "$(dirname "$0")/.."

SPEC=internal/apidocs/openapi.json
GO_DIR=pkg/client/internal/gen
TS_DIR=pkg/js-client/src/gen

WHAT=${1:-all}
OUT_GO=${GEN_SDK_GO_OUT:-$GO_DIR}
OUT_TS=${GEN_SDK_TS_OUT:-$TS_DIR}

if [ ! -s "$SPEC" ]; then
    echo "  ✗ $SPEC 不存在或是空的 —— 先 make openapi" >&2
    exit 1
fi

# spec 里有几个 operation。⚠️ 这是**分母**,下面两种语言各自的计数都要等于它。
SPEC_OPS=$(python3 -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
M = ("get", "put", "post", "delete", "patch", "head", "options", "trace")
print(sum(1 for p, i in (d.get("paths") or {}).items() for m in i if m in M))
' "$SPEC")
if [ -z "$SPEC_OPS" ] || [ "$SPEC_OPS" -lt 50 ]; then
    echo "  ✗ spec 里只数出 $SPEC_OPS 个 operation —— 分母坏了,这次生成无意义" >&2
    exit 1
fi

# ---------- Go ----------
gen_go() {
    # 版本**精确**钉在 .oapi-codegen-version 上,理由与 .swag-version 一字不差:
    # 生成结果随版本变,而门禁逐字节比对它。
    #
    # ⚠️ 走 `go run <module>@<版本>` 而不是 PATH 上的 oapi-codegen ——
    # 同 gen-openapi.sh:PATH 上装的那个版本无从断言,而且它不进 go.mod 的
    # require 段。
    #
    # ⛔ 但这里有一处与 swag **不同**、必须说清楚的代价:**生成出来的代码有一个
    # 运行期依赖** `github.com/oapi-codegen/runtime`(+ apapsch/go-jsonmerge/v2),
    # 它**必须**进 go.mod。提案 §3.2 第 4 条「构建期工具不进 require 段」讲的是
    # 生成器本身,不覆盖生成物的运行期依赖 —— 后者没有别的去处。
    #
    # ⚠️ 另一处代价:oapi-codegen v2.8.0 的 go.mod 写着 `go 1.25.0`,而本仓库是
    # go 1.24.13。`go run` 会切换工具链(实测下载 go1.26.8,冷机约 1 分钟,
    # 热跑 2.0s)。⛔ 这就是为什么 `make check` 里的 ⑮ **不重新生成**(见
    # scripts/check-sdk-coverage.sh 顶注),漂移档另有去处。
    local want
    want=$(tr -d 'v \t\r\n' < .oapi-codegen-version 2>/dev/null)
    if [ -z "$want" ]; then
        echo "  ✗ 读不到 .oapi-codegen-version —— 版本钉不住,生成结果就不可比" >&2
        return 1
    fi
    local tool=("go" "run" "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v${want}")

    mkdir -p "$OUT_GO"
    local log
    log=$(mktemp); trap 'rm -f "$log"' RETURN

    # 两次生成,两份文件。⛔ 不是洁癖:单文件实测 1,050,892 字节,
    # 而 scripts/arch/40 的 ⑪b 拒绝超过 1 MB 的已跟踪文件。
    local cfg
    for cfg in types client; do
        if ! GOTOOLCHAIN=${GOTOOLCHAIN:-auto} "${tool[@]}" \
                -config "$GO_DIR/oapi-codegen.${cfg}.yaml" \
                -o "$OUT_GO/${cfg}.gen.go" \
                "$SPEC" >"$log" 2>&1; then
            echo "  ✗ oapi-codegen($cfg)失败:" >&2
            sed 's/^/      /' "$log" >&2
            return 1
        fi
    done

    # ---------- ① 工具没在装死 ----------
    #
    # 每个 operation 恰好生成一个 `func New<Op>Request(...)`,函数体里有一行
    # `operationPath := fmt.Sprintf("<字面量>")`。实测 92 个 operation → 92 行。
    # 一份从空 spec 生成出来的 client 这里是 **0**,而它照样编译、照样 vet 干净。
    local n
    n=$(grep -c 'operationPath := ' "$OUT_GO/client.gen.go" || true)
    if [ "$n" != "$SPEC_OPS" ]; then
        echo "  ✗ 生成的 Go client 暴露 $n 个操作,spec 里有 $SPEC_OPS 个" >&2
        echo "    ⛔ 这是「生成器在装死」那一档:空 spec 生成出来的 client 编译得过、" >&2
        echo "       go vet 干净、一个方法都没有。别读成「生成成功了」。" >&2
        return 1
    fi

    # ---------- ② 大小余量 ----------
    #
    # ⚠️ client.gen.go 今天 ≈954 KB,用掉了 ⑪b 那 1 MB 额度的 91%。再加十来个
    # 端点就会撞线,而那时门禁报的是「文件太大」,与真正该做的事(按 tag 拆包,
    # 或关掉 with-responses 那一层)隔着一次排查。所以这里提前说。
    local max=$((1024 * 1024)) warn=$((900 * 1024)) f sz
    for f in "$OUT_GO"/*.gen.go; do
        sz=$(stat -c %s "$f")
        if [ "$sz" -ge "$max" ]; then
            echo "  ✗ $f 是 $sz 字节,超过 scripts/arch/40 ⑪b 的 1 MB 上限" >&2
            echo "    改法:按 tag 拆成多个包,或去掉 with-responses 那一层。⛔ 别放宽 ⑪b。" >&2
            return 1
        fi
        [ "$sz" -ge "$warn" ] && printf '  ⚠️ %s 是 %s 字节,已用掉 ⑪b 额度的 %s%%\n' \
            "$f" "$sz" "$((sz * 100 / max))" >&2
    done

    # ---------- ③ 出处 ----------
    #
    # ⛔ `make check` 里的 ⑮ **不重新生成**(工具链切换太贵,见顶注),所以
    # 「spec 改了而 SDK 没跟上」要靠这份记录:它钉住生成这份代码时 spec 的
    # sha256。⚠️ 它证明不了生成器的输出没被人手改过 —— 那件事归 check.yml 的
    # sdk-drift job,它真的重新生成一遍逐字节比。两档各管一半,别互相冒充。
    {
        echo "# ⛔ 生成的,别手改 —— scripts/gen-sdk.sh 写的。"
        echo "generator github.com/oapi-codegen/oapi-codegen/v2 v${want}"
        echo "spec ${SPEC} sha256:$(sha256sum "$SPEC" | cut -d' ' -f1)"
        echo "operations ${SPEC_OPS}"
    } >"$OUT_GO/GENERATED.txt"

    echo "ok: $OUT_GO  ($n 个操作,oapi-codegen v${want})"
}

# ---------- TS ----------
gen_ts() {
    # openapi-typescript 是 pkg/js-client 的 devDependency,版本钉在它的
    # package.json 里(与 eslint / typescript 同一套做法,门禁 ⑬ 已经在断言
    # 那些版本)。⛔ 不用 `npx openapi-typescript@x`:那会在网络上取一个与
    # 本地 node_modules 无关的版本,而门禁读的是本地这一份。
    local bin=pkg/js-client/node_modules/.bin/openapi-typescript
    if [ ! -x "$bin" ]; then
        echo "  ✗ 缺 $bin —— 先 make lint-deps(它会 npm ci 两个包)" >&2
        return 1
    fi

    mkdir -p "$OUT_TS"
    local log
    log=$(mktemp); trap 'rm -f "$log"' RETURN
    if ! "$bin" "$SPEC" -o "$OUT_TS/schema.d.ts" >"$log" 2>&1; then
        echo "  ✗ openapi-typescript 失败:" >&2
        sed 's/^/      /' "$log" >&2
        return 1
    fi

    # ---------- ① 工具没在装死 ----------
    #
    # 空 spec → `export type paths = Record<string, never>`,退出码 0。
    # 数的是 paths 块里的 method 键;它必须等于 spec 的 operation 数。
    local n
    n=$(node -e '
const fs = require("fs");
const src = fs.readFileSync(process.argv[1], "utf8");
const start = src.indexOf("export interface paths {");
if (start < 0) { console.log(0); process.exit(0); }
const end = src.indexOf("\nexport ", start + 1);
const block = src.slice(start, end < 0 ? undefined : end);
const m = block.match(/^ {8}(get|put|post|delete|patch|head|options|trace): \{/gm);
console.log(m ? m.length : 0);
' "$OUT_TS/schema.d.ts")
    if [ "$n" != "$SPEC_OPS" ]; then
        echo "  ✗ 生成的 TS schema 暴露 $n 个操作,spec 里有 $SPEC_OPS 个" >&2
        # ⚠️ 单引号 —— 反引号在双引号里是**命令替换**。第一版写成双引号,
        # 于是这条错误消息会去执行 `export type paths = …`。shellcheck 当场判红(SC1073)。
        echo '    ⛔ 空 spec 生成出来的 .d.ts 是 `export type paths = Record<string, never>`,' >&2
        echo "       合法、退出码 0、一个端点都没有。" >&2
        return 1
    fi

    echo "ok: $OUT_TS  ($n 个操作,openapi-typescript $("$bin" --version 2>/dev/null | tail -1))"
}

rc=0
case "$WHAT" in
    go)  gen_go || rc=1 ;;
    ts)  gen_ts || rc=1 ;;
    all) gen_go || rc=1; gen_ts || rc=1 ;;
    *)   echo "用法: $0 [go|ts|all]" >&2; exit 2 ;;
esac
exit "$rc"
