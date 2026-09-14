#!/usr/bin/env bash
# ---------- ⑮ spec 里的每个端点都有 SDK 暴露它(门禁 C) ----------
#
# 这是提案(docs/drafts/openapi-chain-proposal.md)的门禁 C:`sdk-route-coverage`,
# 也是整条链路的最后一环。判据一直是同一句:
#
#     *一个新端点漏掉 SDK,什么会变红?*
#
# 前面几环已经接上了:
#   ⑭b「注册了但没注解」红 · ⑭c「注解了但没注册」红 · ⑮「在 spec 里但没 SDK」红。
#
# ---------- 五件事,不是一件 ----------
#
#   ⑮①  产物在,而且是**这份 spec** 生成的。
#        Go SDK 入库(提案 §4.2:`go build` 不跑代码生成,手写封装 import 它),
#        所以「spec 改了而 SDK 没跟上」是一个真实且安静的状态。
#        pkg/client/internal/gen/GENERATED.txt 记着生成时 spec 的 sha256 与
#        生成器版本,这一档就是比对那两个数。
#
#   ⑮②  **生成器没在装死。** 这一条和 ⑭③ 是同一个形状,只是更糟 ——
#        ⑭ 的形态是「空 spec 生成出来的文档和干净文档长得一样」;
#        这里的形态**编译得过**:
#
#          实测 2026-09-14:`{"openapi":"3.1.0","paths":{}}` 喂 oapi-codegen
#          v2.8.0 → 退出码 0,3,804 字节合法 Go,`type ClientInterface interface {}`。
#          go vet 干净、staticcheck 干净、一个方法都没有。
#          openapi-typescript 7.13.0 同样:`export type paths = Record<string, never>`。
#
#        所以这里数的是**生成出来的代码自己暴露了几个 operation**,并要求它等于
#        spec 里的数。两个数来自两个不同的文件,⛔ 别拿生成器的日志当证据。
#
#   ⑮a  **Go**:spec 的 (method, path) 集合 ⊆ 生成 SDK 的集合。
#   ⑮b  **TS**:同上。TS 侧的产物不入库(提案 §4.2),所以这一档**自己重新生成
#        一份**到临时目录再读 —— 实测 0.86s。⛔ 不读 pkg/js-client/src/gen/:
#        一个不入库的产物,门禁不能假设它存在,更不能假设它是新的。
#   ⑮c  **反向**:SDK 里有而 spec 里没有的 operation(幽灵方法)。硬零。
#
# ---------- ⛔ 这条门禁**不**重新生成 Go SDK,理由在这里 ----------
#
# oapi-codegen v2.8.0 的 go.mod 写着 `go 1.25.0`,本仓库的 go.mod 是 1.24.x,
# 于是 `go run …@v2.8.0` 会**切换 Go 工具链**(实测下载 go1.26.8;本机热跑 2.0s,
# 冷机约 1 分钟)。而 `make check` 的全部意义是秒级 —— 一条会在干净机器上花一分钟
# 的门禁,人会绕过它,而那比没有门禁更糟(本仓库的 pre-commit 跑过 208 秒,
# 结果是所有提交都在 `--no-verify`)。
#
# ⭐ 所以拆成两档,各管一半,⛔ 别互相冒充:
#   · 这里(`make check`,≈1.5s)证明的是**「这份 SDK 是这份 spec 生成的」**
#     —— sha256 + 版本 + 覆盖计数。
#   · 真正重新跑一遍生成器再逐字节比对,走 `SDK_REGEN=1 ./scripts/check-sdk-coverage.sh`,
#     由 .github/workflows/check.yml 的**独立 job** `sdk-drift` 执行。
#     ⚠️ 那个 workflow 跑在**每个分支的每次 push** 上(ci.yml 只跑 main/dev + PR,
#     而 2026-09-10 的事故正是顺着 feature 分支进来的),独立 job 所以不占秒级预算。
#
# ⚠️ sha256 那一档抓不到的东西,写在这里免得被当成抓得到:有人**手改**生成文件。
# 那归 sdk-drift 的逐字节比对。两档合起来才是完整的,单独任何一档都不是。
set -uo pipefail
cd "$(dirname "$0")/.."

BASE=scripts/lib/arch-baseline/sdk-routes.txt
SPEC=internal/apidocs/openapi.json
GO_DIR=pkg/client/internal/gen
REGEN=${SDK_REGEN:-0}

fail=0
echo "==> SDK 路由覆盖(⑮)"

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# ---------- ⑮① 产物在吗 ----------
for f in "$SPEC" "$GO_DIR/client.gen.go" "$GO_DIR/types.gen.go" "$GO_DIR/GENERATED.txt"; do
    if [ ! -s "$f" ]; then
        printf '  ✗ ⑮① %s 不存在或是空的 —— 这次检查的结论作废\n' "$f" >&2
        printf '    改法: make openapi && make sdk\n' >&2
        printf '    ⛔ 别把 %s 加进 .gitignore:手写封装 import 它,而 `go build` 不跑代码生成 ——\n' "$GO_DIR" >&2
        printf '       不入库则 fresh clone 编译不过(提案 §4.2)。\n' >&2
        exit 1
    fi
done

# ---------- TS:重新生成一份到临时目录 ----------
#
# ⚠️ 走 scripts/gen-sdk.sh —— 与 `make sdk` **同一条命令行**(同 ⑭ 对
# gen-openapi.sh 的做法)。两边各写一份参数的话,门禁会拿另一套参数生成的代码
# 去比,而人看到差异的第一反应是改文件,不是查参数。
ts_ok=1
if ! GEN_SDK_TS_OUT="$tmp/ts" bash scripts/gen-sdk.sh ts >"$tmp/ts.log" 2>&1; then
    printf '  ✗ ⑮b TS SDK 生成失败 —— TS 这一档的结论作废(⛔ 别读成「没有违规」)\n' >&2
    sed 's/^/      /' "$tmp/ts.log" >&2
    printf '    缺 node_modules 的话: make lint-deps\n' >&2
    ts_ok=0
    fail=1
fi

# ---------- 漂移档(只在 SDK_REGEN=1 时跑) ----------
if [ "$REGEN" = "1" ]; then
    echo "  ·  SDK_REGEN=1:重新生成 Go SDK 并逐字节比对"
    if ! GEN_SDK_GO_OUT="$tmp/go" bash scripts/gen-sdk.sh go >"$tmp/go.log" 2>&1; then
        printf '  ✗ ⑮d Go SDK 生成失败 —— 漂移档的结论作废\n' >&2
        sed 's/^/      /' "$tmp/go.log" >&2
        exit 1
    fi
    for f in client.gen.go types.gen.go GENERATED.txt; do
        if ! diff -q "$GO_DIR/$f" "$tmp/go/$f" >/dev/null 2>&1; then
            printf '  ✗ ⑮d %s/%s 与重新生成的不一致 —— 它被手改过,或者 spec 改了而 SDK 没重跑\n' "$GO_DIR" "$f" >&2
            diff "$GO_DIR/$f" "$tmp/go/$f" 2>/dev/null | head -20 | sed 's/^/      /' >&2
            printf '    改法: make sdk WHAT=go   然后把改动一起提交\n' >&2
            printf '    ⛔ 别手改 *.gen.go —— 要改接口形状改 handler 注解,要改鉴权/重试改手写封装。\n' >&2
            fail=1
        fi
    done
fi

python3 - "$SPEC" "$GO_DIR" "$tmp/ts/schema.d.ts" "$BASE" "$ts_ok" <<'PY' >"$tmp/out" 2>"$tmp/perr"
import hashlib, json, os, re, sys

spec_path, go_dir, ts_path, base_path, ts_ok = sys.argv[1:6]
ts_ok = ts_ok == "1"
METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")

spec = json.load(open(spec_path, encoding="utf-8"))
paths = spec.get("paths") or {}
# ⚠️ 归一化:生成的 Go 把路径参数渲染成 fmt.Sprintf 的 %s,spec 里是 {id}。
# 比较必须在同一个形状上做。⛔ 这不会把两条不同的 path 混成一条 —— 除非它们
# **只**在参数名上不同,而那本身就是一份自相矛盾的 spec(下面直接断言)。
def norm(p):
    return re.sub(r"\{[^}]*\}", "%s", p)

spec_ops = {(m, norm(p)) for p, item in paths.items() for m in item if m in METHODS}
if len({norm(p) for p in paths}) != len(paths):
    print("HARD spec 里有两条 path 归一化后相同(只有参数名不同)—— 比较不成立")
if len(spec_ops) < 50:
    print(f"HARD spec 里只数出 {len(spec_ops)} 个 operation —— 分母坏了,这次比对无意义")

# ---------- ⑮① 出处 ----------
prov = {}
for line in open(os.path.join(go_dir, "GENERATED.txt"), encoding="utf-8"):
    line = line.split("#", 1)[0].strip()
    if line:
        k, _, v = line.partition(" ")
        prov[k] = v.strip()

want_sha = hashlib.sha256(open(spec_path, "rb").read()).hexdigest()
got = prov.get("spec", "")
if not got.endswith("sha256:" + want_sha):
    print(f"STALE 生成 Go SDK 时的 spec 不是现在这一份\n"
          f"      记录: {got or '<缺失>'}\n"
          f"      现在: {spec_path} sha256:{want_sha}")

pin_path = ".oapi-codegen-version"
pin = open(pin_path, encoding="utf-8").read().strip().lstrip("v") if os.path.exists(pin_path) else ""
want_gen = f"github.com/oapi-codegen/oapi-codegen/v2 v{pin}"
if not pin:
    print(f"HARD 读不到 {pin_path} —— 生成器版本钉不住,生成结果就不可比")
elif prov.get("generator", "") != want_gen:
    print(f"PIN 生成器版本对不上\n      记录: {prov.get('generator', '<缺失>')!r}\n      钉的: {want_gen!r}")

# ---------- Go:从生成的代码里抽出 (method, path) ----------
#
# ⭐ 提案 §9.2 说这件事「没看过 v2.8.0 的输出模板,如果路径只在 fmt.Sprintf 里,
# AST 提取会很脆」。实测结论:路径**确实**只在 fmt.Sprintf 里,但它是一个
# **字面量格式串**,而且每个 operation 恰好一处 —— 不脆,可以直接读,不需要
# 让 gen-sdk.sh 顺手吐一份 routes.txt(那是提案给的退路,这里用不上)。
#
# ⚠️ 但形状比 §9.2 猜的多一层,而这一层是**这个断言抓出来的**,不是读出来的:
# 带 body 的 operation 生成**两个**函数 —— `New<Op>RequestWithBody` 是真正拼路径
# 的那个,`New<Op>Request` 只是把 body 序列化后转调它。第一版抽取器按「每个
# New*Request 都有一行 operationPath」写,当场在 40 个函数上红。
#
# ⛔ 所以这里把两种形状都写成显式断言,任何第三种形状都是 HARD:
#   · 终端构造器:恰好 1 行 operationPath + 恰好 1 行 http.NewRequest
#   · 转调构造器:0 行两者,且恰好 1 处 `New…RequestWithBody(` 调用
# 抽取器自己的装死形态是「一条都没抽到而报告 0 个缺失」,这样它抓不到时会喊。
src = open(os.path.join(go_dir, "client.gen.go"), encoding="utf-8").read()
func_starts = [m for m in re.finditer(r"^func (New\w+Request(?:WithBody)?)\(", src, re.M)]
if len(func_starts) < 50:
    print(f"HARD 生成的 client.gen.go 里只找到 {len(func_starts)} 个 New*Request 函数 —— "
          f"抽取器坏了或者 SDK 是从空 spec 生成的,这次比对无意义")

go_ops = set()
n_terminal = n_delegating = 0
for i, m in enumerate(func_starts):
    end = func_starts[i + 1].start() if i + 1 < len(func_starts) else len(src)
    body = src[m.start():end]
    lit = re.findall(r'operationPath := fmt\.Sprintf\("([^"]*)"', body)
    meth = re.findall(r"http\.NewRequest\(http\.Method(\w+),", body)
    if len(lit) == 1 and len(meth) == 1:
        n_terminal += 1
        go_ops.add((meth[0].lower(), lit[0]))
        continue
    if not lit and not meth and len(re.findall(r"\breturn New\w+RequestWithBody\(", body)) == 1:
        n_delegating += 1
        continue
    print(f"HARD {m.group(1)} 既不是终端构造器(1 行 operationPath + 1 行 http.NewRequest,"
          f"实测 {len(lit)} / {len(meth)})也不是转调构造器 —— "
          f"oapi-codegen 的输出模板变了,抽取器要跟着改")

# ---------- ⑮② 生成器没在装死 ----------
# 两个独立观测:spec 的 operation 数,和生成代码自己暴露的数。
if len(go_ops) != len(spec_ops):
    print(f"COUNT_MISMATCH go 生成的 SDK 暴露 {len(go_ops)} 个 operation,spec 里有 {len(spec_ops)} 个")

# ---------- TS ----------
ts_ops = set()
if ts_ok:
    ts_src = open(ts_path, encoding="utf-8").read()
    start = ts_src.find("export interface paths {")
    if start < 0:
        print("HARD 生成的 schema.d.ts 里没有 `export interface paths {` —— "
              "一份从空 spec 生成出来的 .d.ts 写的是 `export type paths = Record<string, never>`")
    else:
        end = ts_src.find("\nexport ", start + 1)
        block = ts_src[start:end if end > 0 else len(ts_src)]
        cur = None
        for line in block.splitlines():
            mp = re.match(r'^ {4}"(/[^"]*)": \{', line)
            if mp:
                cur = norm(mp.group(1))
                continue
            mm = re.match(r"^ {8}(get|put|post|delete|patch|head|options|trace): \{", line)
            if mm and cur:
                ts_ops.add((mm.group(1), cur))
        if len(ts_ops) != len(spec_ops):
            print(f"COUNT_MISMATCH ts 生成的 schema 暴露 {len(ts_ops)} 个 operation,"
                  f"spec 里有 {len(spec_ops)} 个")

# ---------- 基线 ----------
baseline = {}
for ln, raw in enumerate(open(base_path, encoding="utf-8"), 1):
    line = raw.split("#", 1)[0].strip()
    if not line:
        continue
    m = re.match(r"^(exempt|todo)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE)\s+(/\S*)\s*(.*)$", line)
    if not m:
        print(f"HARD 基线第 {ln} 行看不懂:{line!r} —— 形状是 `exempt|todo METHOD /path [理由]`")
        continue
    cls, method, path, reason = m.group(1), m.group(2).lower(), m.group(3), m.group(4).strip()
    if cls == "exempt" and len(reason) < 20:
        print(f"HARD 基线第 {ln} 行:exempt {method.upper()} {path} 的理由是 {reason!r} —— "
              f"⛔ 没有理由的豁免等于关掉检查")
    baseline[(method, norm(path))] = (cls, reason)

covered, missing, exempted = [], [], []
for op in sorted(spec_ops):
    in_go = op in go_ops
    in_ts = (not ts_ok) or (op in ts_ops)          # TS 档作废时不拿它判缺失
    cls = baseline.get(op, (None, ""))[0]
    if in_go and in_ts:
        covered.append(op)
        if cls:
            print(f"FIXED {cls} {op[0].upper()} {op[1]}")
        continue
    where = []
    if not in_go:
        where.append("Go")
    if ts_ok and op not in ts_ops:
        where.append("TS")
    if cls == "exempt":
        exempted.append(op)
        continue
    if cls == "todo":
        missing.append(op)
        continue
    print(f"NEW {op[0].upper()} {op[1]}\t{'/'.join(where)} SDK 里没有")

for op, (cls, _) in baseline.items():
    if op not in spec_ops:
        print(f"GONE {cls} {op[0].upper()} {op[1]}")

# ---------- ⑮c 幽灵方法 ----------
for op in sorted(go_ops - spec_ops):
    print(f"GHOST go {op[0].upper()} {op[1]}")
for op in sorted(ts_ops - spec_ops):
    print(f"GHOST ts {op[0].upper()} {op[1]}")

print(f"COUNT spec {len(spec_ops)}")
print(f"COUNT go_terminal {n_terminal}")
print(f"COUNT go_delegating {n_delegating}")
print(f"COUNT go {len(go_ops)}")
print(f"COUNT ts {len(ts_ops)}")
print(f"COUNT covered {len(covered)}")
print(f"COUNT missing {len(missing)}")
print(f"COUNT exempt {len(exempted)}")
PY

if [ -s "$tmp/perr" ]; then
    printf '  ✗ ⑮ 比对脚本失败 —— 这次检查的结论作废\n' >&2
    sed 's/^/      /' "$tmp/perr" >&2
    exit 1
fi

if grep -q '^HARD ' "$tmp/out"; then
    grep '^HARD ' "$tmp/out" | sed 's/^HARD /  ✗ ⑮② /' >&2
    printf '    ⛔ 这一档是「门禁自己在装死」,不是端点的问题 —— 一份从空 spec 生成出来的\n' >&2
    printf '       Go client **编译得过、vet 干净、一个方法都没有**。先把它修好,本次其余结论都不可信。\n' >&2
    fail=1
fi

if grep -q '^COUNT_MISMATCH ' "$tmp/out"; then
    grep '^COUNT_MISMATCH ' "$tmp/out" | sed 's/^COUNT_MISMATCH /  ✗ ⑮② /' >&2
    printf '    改法: make openapi && make sdk\n' >&2
    printf '    ⛔ 两个数来自两个文件(spec 的 json / 生成出来的代码),相等是「生成器真的看见了\n' >&2
    printf '       这份 spec」的唯一独立证据。\n' >&2
    fail=1
fi

if grep -q '^STALE ' "$tmp/out"; then
    printf '  ✗ ⑮① 入库的 Go SDK 不是这份 spec 生成的\n' >&2
    # ⚠️ STALE 是**多行**的(记录的 sha256 / 现在的 sha256),后续行以空白开头。
    # ⛔ 别只 grep 那一行:两个 sha256 正是人要看的东西。
    awk '/^STALE /{p=1;next} p&&/^ /{print;next} p{p=0}' "$tmp/out" | sed 's/^/    /' >&2
    printf '    改法: make sdk WHAT=go   然后把 %s 的改动一起提交\n' "$GO_DIR" >&2
    printf '    ⛔ 那几个 .gen.go 被 pkg/client 的手写封装 import —— 它们过期 = 每个 Go 调用方\n' >&2
    printf '       拿到的都是旧契约,而编译**照样通过**。\n' >&2
    fail=1
fi

if grep -q '^PIN ' "$tmp/out"; then
    grep '^PIN ' "$tmp/out" | sed 's/^PIN /  ✗ ⑮① /' >&2
    awk '/^PIN /{p=1;next} p&&/^ /{print;next} p{p=0}' "$tmp/out" | sed 's/^/    /' >&2
    printf '    改法: make sdk WHAT=go(或者把 .oapi-codegen-version 改回去)\n' >&2
    printf '    ⛔ 生成结果随版本变,而漂移档逐字节比对它 —— 版本不同 = 本地绿 CI 红。\n' >&2
    fail=1
fi

if grep -q '^NEW ' "$tmp/out"; then
    printf '  ✗ ⑮a spec 里有这些 operation,而 SDK 没有暴露它们:\n' >&2
    grep '^NEW ' "$tmp/out" | sed 's/^NEW /      + /' >&2
    printf '    改法: make sdk\n' >&2
    printf '    ⛔ 别把它加进 %s 了事 —— 基线里的每一行都是一个「文档里有、SDK 里打不通」的端点,\n' "$BASE" >&2
    printf '       而调用方要到运行时才知道。\n' >&2
    fail=1
fi

if grep -q '^FIXED ' "$tmp/out"; then
    printf '  ✗ ⑮a 基线里有已经被 SDK 暴露的 operation(修好了):\n' >&2
    grep '^FIXED ' "$tmp/out" | sed 's/^FIXED /      - /' >&2
    printf '    改法:把 %s 里那几行删掉。棘轮只许往下走。\n' "$BASE" >&2
    fail=1
fi

if grep -q '^GONE ' "$tmp/out"; then
    printf '  ✗ ⑮a 基线里有对不上任何 spec operation 的条目:\n' >&2
    grep '^GONE ' "$tmp/out" | sed 's/^GONE /      - /' >&2
    printf '    改法:端点没了就把这行删掉;改名了就改成新名字。\n' >&2
    printf '    ⛔ 留着它 = 下次那个端点掉了 SDK 时这里**不会**变红。\n' >&2
    fail=1
fi

if grep -q '^GHOST ' "$tmp/out"; then
    printf '  ✗ ⑮c SDK 里有 spec 里不存在的 operation(零基线,硬约束):\n' >&2
    grep '^GHOST ' "$tmp/out" | sed 's/^GHOST /      + /' >&2
    printf '    改法: make sdk —— 它是从 spec 生成的,对不上只可能是产物旧了或被手改过。\n' >&2
    printf '    ⛔ 它比「少一个端点」更糟:调用方看到一个**打不通**的方法,要到 404 才知道。\n' >&2
    fail=1
fi

v() { awk -v k="$1" '$1=="COUNT" && $2==k {print $3}' "$tmp/out"; }
printf '  ·  spec %s 个 operation:Go SDK %s / TS SDK %s(已覆盖 %s / 豁免 %s / 待补 %s)\n' \
    "$(v spec)" "$(v go)" "$(v ts)" "$(v covered)" "$(v exempt)" "$(v missing)"
[ "$REGEN" = "1" ] || printf '  ·  ⚠️ 未重新生成 Go SDK(工具链切换太贵)—— 逐字节比对走 SDK_REGEN=1,由 check.yml 的 sdk-drift job 执行\n'

if [ "$fail" -ne 0 ]; then
    printf '\n' >&2
    echo "FAIL: SDK 路由覆盖(见上)。单独跑这一条:./scripts/check-sdk-coverage.sh" >&2
    exit 1
fi
echo "ok: spec 里的每个 operation 都有 Go 与 TS SDK 暴露(⑮① 出处 / ⑮② 计数 / ⑮a 覆盖棘轮 / ⑮c 无幽灵方法)"
