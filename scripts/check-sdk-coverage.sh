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
#   ⑮①  生成器版本钉得住。
#        ⚠️ 这一档**变小了**,2026-09-15:两侧产物都不入库之后,「spec 改了而 SDK
#        没跟上」这个状态**不存在了** —— 每一趟检查用的都是这一趟现生成的产物。
#        原来那句「Go SDK 入库(手写封装 import 它)」本身也是错的,见下。
#        留下的是生成器版本比对:版本不同则生成结果不同。
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
REGEN=${SDK_REGEN:-0}

fail=0
echo "==> SDK 路由覆盖(⑮)"

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# ---------- ⑮① spec 在吗 ----------
#
# ⚠️ 2026-09-15 起**只查 spec**。Go SDK 的产物不再入库(见下),所以「产物在不在」
# 对它已经不是一个有意义的问题 —— 在一台没生成过的机器上它本来就不在,那是正常
# 状态,不是违规。⛔ 别加回「文件在就检查、不在就跳过」:那种写法在本地(有旧产物)
# 绿、在 CI(干净 checkout)红,而且「静默跳过」正是本仓库反复吃亏的形状。
if [ ! -s "$SPEC" ]; then
    printf '  ✗ ⑮① %s 不存在或是空的 —— 这次检查的结论作废\n' "$SPEC" >&2
    printf '    改法: make openapi\n' >&2
    exit 1
fi

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

# ---------- Go:只在 SDK_REGEN=1 时生成并检查 ----------
#
# ⭐ 2026-09-15 起 Go SDK 的产物**不入库**(提案 §4.2 的 Go 那一半被推翻:它写着
# 「手写封装 import 它」,而 `go list` 实测只有 signing_differential_test.go 一个
# **测试**文件 import —— 那条理由是写提案时的预期,落地时从未兑现)。
#
# 两个后果,都写在这里免得被当成「门禁变弱了」:
#
#   · 原 ⑮d「把入库的那份与重新生成的逐字节比对」**失去了对象**。它防的是
#     「有人手改了生成文件」,而文件不进版本库就没人能手改 —— 这一类失败模式
#     是被消灭了,不是被放过。
#   · 原 ⑮① 记在 GENERATED.txt 里的 spec sha256 同理:它证明的是「**入库的**那份
#     是这份 spec 生成的」。现在每次都是现生成的,这个问题不存在。
#
# ⚠️ 代价是真的,说清楚:`make check` 里**不再检查 Go SDK 的覆盖**,因为生成要
# 切 Go 工具链(oapi-codegen v2.8.0 要 go ≥ 1.25,本仓库 1.24.x;冷机是一次 Go
# 发行版下载)。Go 档整体移到 SDK_REGEN=1,由 check.yml 的 sdk-drift job 执行 ——
# 那个 workflow 跑在**每个分支的每次 push** 上,所以覆盖面没有缩,只是反馈点从
# 本地挪到了 push。⛔ 不许为了让它回到 make check 而把生成器换成 PATH 上那个
# 版本不明的 oapi-codegen。
go_dir=""
if [ "$REGEN" = "1" ]; then
    echo "  ·  SDK_REGEN=1:生成 Go SDK 并检查覆盖"
    if ! GEN_SDK_GO_OUT="$tmp/go" bash scripts/gen-sdk.sh go >"$tmp/go.log" 2>&1; then
        printf '  ✗ ⑮ Go SDK 生成失败 —— Go 这一档的结论作废(⛔ 别读成「没有违规」)\n' >&2
        sed 's/^/      /' "$tmp/go.log" >&2
        exit 1
    fi
    go_dir="$tmp/go"
fi

python3 - "$SPEC" "$go_dir" "$tmp/ts/schema.d.ts" "$BASE" "$ts_ok" <<'PY' >"$tmp/out" 2>"$tmp/perr"
import hashlib, json, os, re, sys

spec_path, go_dir, ts_path, base_path, ts_ok = sys.argv[1:6]
ts_ok = ts_ok == "1"
# go_dir 为空 = 这一趟没生成 Go SDK(不是 SDK_REGEN=1)。Go 档整体不参与判断,
# ⛔ 而不是「当成通过」—— 下面每一处用到 go_ops 的地方都显式按 go_ok 分叉。
go_ok = bool(go_dir)
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
#
# ⚠️ 只在真生成过的时候才有意义。产物不入库之后,「生成时的 spec 是不是现在这份」
# 这个问题自己消失了 —— 这一趟的产物就是这一趟用这份 spec 生成的。留着这段是为了
# 钉住**生成器版本**:版本不同则生成结果不同,而下游按版本钉。
if go_ok:
    prov = {}
    with open(os.path.join(go_dir, "GENERATED.txt"), encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                k, _, v = line.partition(" ")
                prov[k] = v.strip()

    want_sha = hashlib.sha256(open(spec_path, "rb").read()).hexdigest()
    got = prov.get("spec", "")
    if not got.endswith("sha256:" + want_sha):
        print(f"STALE 刚生成的 Go SDK 记录的 spec 不是现在这一份\n"
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
go_ops = set()
n_terminal = n_delegating = 0
func_starts = []
if go_ok:
    src = open(os.path.join(go_dir, "client.gen.go"), encoding="utf-8").read()
    func_starts = [m for m in re.finditer(r"^func (New\w+Request(?:WithBody)?)\(", src, re.M)]
    if len(func_starts) < 50:
        print(f"HARD 生成的 client.gen.go 里只找到 {len(func_starts)} 个 New*Request 函数 —— "
              f"抽取器坏了或者 SDK 是从空 spec 生成的,这次比对无意义")

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
if go_ok and len(go_ops) != len(spec_ops):
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
    in_go = (not go_ok) or (op in go_ops)          # 没生成 Go 时不拿它判缺失
    in_ts = (not ts_ok) or (op in ts_ops)          # TS 档作废时不拿它判缺失
    cls = baseline.get(op, (None, ""))[0]
    if in_go and in_ts:
        covered.append(op)
        if cls:
            print(f"FIXED {cls} {op[0].upper()} {op[1]}")
        continue
    where = []
    if go_ok and op not in go_ops:
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
    printf '  ✗ ⑮① 刚生成的 Go SDK 记录的 spec 不是现在这一份\n' >&2
    # ⚠️ STALE 是**多行**的(记录的 sha256 / 现在的 sha256),后续行以空白开头。
    # ⛔ 别只 grep 那一行:两个 sha256 正是人要看的东西。
    awk '/^STALE /{p=1;next} p&&/^ /{print;next} p{p=0}' "$tmp/out" | sed 's/^/    /' >&2
    printf '    ⛔ 产物不入库之后这一条几乎不该出现 —— 它读的是**这一趟刚生成的**\n' >&2
    printf '       GENERATED.txt。对不上说明 gen-sdk.sh 在生成时读的 spec 与这里读的不是\n' >&2
    printf '       同一个文件(比如中途被改写),而不是「SDK 过期了」。\n' >&2
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
    printf '    ⛔ 产物是这一趟现生成的,所以「旧了」「被手改过」都不可能 —— 对不上只能是\n' >&2
    printf '       生成器把 spec 里没有的东西写了出来,那是生成器或 spec 的问题。\n' >&2
    printf '    ⛔ 它比「少一个端点」更糟:调用方看到一个**打不通**的方法,要到 404 才知道。\n' >&2
    fail=1
fi

v() { awk -v k="$1" '$1=="COUNT" && $2==k {print $3}' "$tmp/out"; }
if [ "$REGEN" = "1" ]; then
    printf '  ·  spec %s 个 operation:Go SDK %s / TS SDK %s(已覆盖 %s / 豁免 %s / 待补 %s)\n' \
        "$(v spec)" "$(v go)" "$(v ts)" "$(v covered)" "$(v exempt)" "$(v missing)"
else
    # ⛔ 这里**不打印** `Go SDK 0`。上一版就是那么写的,而 0 读起来像「Go SDK 暴露了
    # 0 个 operation」—— 一个没做的检查,不许长得像一个做了并且通过了的检查。
    printf '  ·  spec %s 个 operation:Go SDK 未检查 / TS SDK %s(已覆盖 %s / 豁免 %s / 待补 %s,**只算 TS**)\n' \
        "$(v spec)" "$(v ts)" "$(v covered)" "$(v exempt)" "$(v missing)"
    printf '  ·  ⚠️ 这一趟**没有检查 Go SDK**:生成它要切 Go 工具链(oapi-codegen v2.8.0 要\n'
    printf '     go ≥ 1.25,本仓库 1.24.x;冷机是一次 Go 发行版下载),而 make check 的意义是秒级。\n'
    printf '     Go 档由 check.yml 的 sdk-drift job 跑,那个 workflow 在**每个分支的每次 push**\n'
    printf '     上执行 —— 覆盖面没有缩,只是反馈点从本地挪到了 push。\n'
fi

if [ "$fail" -ne 0 ]; then
    printf '\n' >&2
    echo "FAIL: SDK 路由覆盖(见上)。单独跑这一条:./scripts/check-sdk-coverage.sh" >&2
    exit 1
fi
# ⛔ 结论必须说清这一趟**实际检查了什么**。上一版不论 Go 档跑没跑都印同一句
# 「每个 operation 都有 Go 与 TS SDK 暴露」—— 那在 make check 里是假的,
# 而一条在没检查的情况下报告通过的门禁,正是本仓库反复吃亏的那个形状。
if [ "$REGEN" = "1" ]; then
    echo "ok: spec 里的每个 operation 都有 Go 与 TS SDK 暴露(⑮① 版本 / ⑮② 计数 / ⑮a 覆盖棘轮 / ⑮c 无幽灵方法)"
else
    echo "ok: spec 里的每个 operation 都有 **TS** SDK 暴露(⑮② 计数 / ⑮a 覆盖棘轮 / ⑮c 无幽灵方法);⚠️ Go 档未检查,见上"
fi
