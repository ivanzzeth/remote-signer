#!/usr/bin/env bash
# ---------- ⑭ 每条路由都在 OpenAPI 文档里,而且那份文档没过期 ----------
#
# 这是提案(docs/drafts/openapi-chain-proposal.md)的门禁 B:`route-annotation`。
# 判据和链路上其它环节一样一句话:*一个新端点漏掉注解,什么会变红?*
#
# ---------- 三件事,不是一件 ----------
#
#   ⑭a **文档没过期** —— 重新生成一遍,和 internal/apidocs/openapi.json 逐字节比。
#       ⛔ 不是「看起来差不多」:那份文件被 //go:embed 编进二进制、被
#       `remote-signer openapi` 吐给客户端,它过期就是**所有下游都拿到旧契约**。
#       生成热跑 ≈1s,所以这里直接重生成而不是查时间戳 —— 时间戳判据在 rebase、
#       checkout、touch 之后都说谎。
#
#   ⑭b **注册了的路由都有注解** —— 路由表不是从活 router 来的(提案 §4.1 说了
#       为什么不能),而是 cmd/archcheck 从注册调用点 AST 抽出来的那 104 条,
#       与 route-auth / route-perm-binding 三条门禁读的是**同一个**抽取器。
#       没注解的逐条登记在基线里,双向棘轮。
#
#   ⑭c **注解不许描述不存在的端点** —— 零基线,硬约束。spec 里一个 operation
#       对不上任何注册路由,意味着 SDK 会长出一个打不通的方法;那比缺一个端点
#       更糟,因为它看起来是能用的。
#
# ---------- ⛔ 这条门禁自己的「什么都没检查却报告成功」 ----------
#
# 本仓库连着栽过三次(.githooks 没装过、blackbox 重放缓存、js-client 的 eslint
# 配了没人调),⑫ 和 ⑬ 因此各自带一组「工具没在装死」的断言。这条的形态是:
#
#   **一份从 0 个文件生成出来的 spec,长得和一份干净的 spec 一模一样。**
#
# 实测(2026-09-14):把 -d 指到一个没有注解的目录,swag **退出码 0**,写出一份
# 合法的 swagger.json,`paths: {}`。任何只看「生成成功了吗」的门禁在那一刻全绿,
# 而它检查的端点数是零。⑭③ 就是防这个:数源码里的 `@Router` 行(repo 全量,
# 与 swag 的 -d 无关),要求它**等于** spec 里的 operation 数。少了 = swag 没看见
# 某个文件;多了 = 解析器漏读了行,而漏掉的行不会出现在任何一档计数里。
set -uo pipefail
cd "$(dirname "$0")/.."
. scripts/lib/arch.sh

BASE=scripts/lib/arch-baseline/openapi-routes.txt
SPEC=internal/apidocs/openapi.json

fail=0
echo "==> OpenAPI 注解覆盖(⑭)"

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# ---------- ① 提交的那份在不在 ----------
#
# ⛔ 它是**故意**入库的(提案 §4.2):`go build` 不跑代码生成,而
# internal/apidocs 用 //go:embed 引它 —— 不提交的话新 clone 编译不过。
if [ ! -s "$SPEC" ]; then
    printf '  ✗ ⑭① %s 不存在或是空的\n' "$SPEC" >&2
    printf '    改法: make openapi\n' >&2
    printf '    ⛔ 别把它加进 .gitignore:它被 //go:embed 引用,不入库则 fresh clone 编译不过。\n' >&2
    exit 1
fi

# ---------- ② 重新生成一份来比 ----------
#
# ⚠️ 走 scripts/gen-openapi.sh —— 与 `make openapi` **同一条命令行**。两边各写
# 一份参数的话,门禁会拿另一套参数生成的文档去比对提交的那份,而人看到差异的
# 第一反应是改文件,不是查参数。
if ! bash scripts/gen-openapi.sh "$tmp/fresh.json" >"$tmp/gen.log" 2>&1; then
    printf '  ✗ ⑭② 生成失败 —— 这次检查的结论作废(⛔ 别读成「没有违规」)\n' >&2
    sed 's/^/      /' "$tmp/gen.log" >&2
    exit 1
fi

if ! diff -q "$SPEC" "$tmp/fresh.json" >/dev/null 2>&1; then
    printf '  ✗ ⑭a %s 过期了 —— 注解改了,文档没跟上\n' "$SPEC" >&2
    diff "$SPEC" "$tmp/fresh.json" | head -20 | sed 's/^/      /' >&2
    printf '    改法: make openapi   然后把改动一起提交\n' >&2
    printf '    ⛔ 那份文件被 //go:embed 编进二进制、由 `remote-signer openapi` 吐出来;\n' >&2
    printf '       它过期 = 每个下游拿到的都是旧契约。\n' >&2
    fail=1
fi

# ---------- ③ 路由表:AST 抽取,不是活 router ----------
#
# ⛔ 为什么不起一个 router 来问它有哪些路由(提案 §4.1):那要 5 个依赖和一个库,
# 而且 setupRoutes 是条件注册的 —— 得到的是**某一次部署**。这里读的是
# cmd/archcheck 的两条 -list,也就是 route-auth 家族三条门禁读的同一份抽取结果。
#
# ⚠️ 用 AST 而不是 grep 也是实测的:grep `reg.Handle("` 在今天这棵树上多数出
# **两条** —— module_rules.go 的注释里引用了两个已经删掉的旧 pattern。
if ! go run ./cmd/archcheck -list route-perm-binding >"$tmp/perm.txt" 2>"$tmp/arch.err"; then
    printf '  ✗ ⑭③ archcheck 抽路由表失败 —— 结论作废\n' >&2
    sed 's/^/      /' "$tmp/arch.err" >&2
    exit 1
fi
if ! go run ./cmd/archcheck -list route-auth-exempt >"$tmp/exempt.txt" 2>"$tmp/arch.err"; then
    printf '  ✗ ⑭③ archcheck 抽豁免表失败 —— 结论作废\n' >&2
    sed 's/^/      /' "$tmp/arch.err" >&2
    exit 1
fi

# 源码里的 @Router 行数 —— ⛔ 与 swag 的 -d 无关,故意的:它是「swag 是不是漏看了
# 某个文件」的唯一独立观测。⚠️ 排除 _test.go(archcheck 也不读它们)与 vendor。
grep -rn --include='*.go' '^[[:space:]]*//[[:space:]]*@Router[[:space:]]' . \
    | grep -v '/vendor/' | grep -v '_test\.go:' >"$tmp/routers.txt" || true

python3 - "$tmp" "$tmp/fresh.json" "$BASE" <<'PY' >"$tmp/out" 2>"$tmp/perr"
import json, os, re, sys

tmp, spec_path, base_path = sys.argv[1], sys.argv[2], sys.argv[3]
METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")

# ⚠️ 读的是**刚生成的**那份,不是提交的那份。两者相等由 ⑭a 单独断言(逐字节),
# 而覆盖率与「生成器看见了多少」都应该问源码生成出来的东西 —— 拿提交的旧文档
# 去算覆盖率,会把「文档过期」误报成「某个 handler 没看见」,两种红混在一起。
spec = json.load(open(spec_path, encoding="utf-8"))
paths = spec.get("paths") or {}
ops = {(m, p) for p, item in paths.items() for m in item if m in METHODS}

# ---------- ③ 工具没在装死 ----------
# 一份从 0 个解析文件生成出来的 spec 是合法的、干净的、空的。源码里的 @Router
# 行数是独立的第二个观测:两者必须相等。
n_src = sum(1 for _ in open(f"{tmp}/routers.txt", encoding="utf-8"))
if spec.get("openapi", "").split(".")[0:2] != ["3", "1"]:
    print(f"HARD spec 的 openapi 字段是 {spec.get('openapi')!r},不是 3.1.x —— 生成参数变了(--v3.1 掉了?)")
if n_src != len(ops):
    print(f"HARD 源码里有 {n_src} 行 @Router,spec 里只有 {len(ops)} 个 operation —— "
          f"swag 没看见某个被注解的文件,或者同一个 (method,path) 被注解了两次")

# ---------- 路由表 ----------
routes = []
for line in open(f"{tmp}/perm.txt", encoding="utf-8"):
    line = line.strip()
    if line:
        routes.append(line.rsplit(" ", 1)[0])       # "<pattern> <perm>"
for line in open(f"{tmp}/exempt.txt", encoding="utf-8"):
    line = line.strip()
    if line:
        routes.append(line.split(" ", 1)[1])        # "<mode> <pattern>"
routes = sorted(set(routes))
if len(routes) < 50:
    print(f"HARD archcheck 只抽出 {len(routes)} 条路由 —— 抽取器坏了,这次比对无意义")


def as_op(pattern):
    """Go 的 mux pattern → OpenAPI (method, path);表达不了就返回 None 和原因。"""
    parts = pattern.split(" ", 1)
    if len(parts) != 2:
        return None, "没有方法:这条 pattern 匹配**所有**动词,而 OpenAPI 的一个 operation 就是一个方法"
    method, path = parts[0].lower(), parts[1]
    if method not in METHODS:
        return None, f"方法 {parts[0]!r} 不是 HTTP 方法"
    if path.endswith("/"):
        return None, "尾斜杠前缀:它匹配整棵子树(任意深度、任意段),OpenAPI 的 path 是一条一条写的"
    return (method, path), ""


# ---------- 基线 ----------
# 行:`<class> <pattern>[ <理由>]`,class ∈ exempt|todo。
baseline = {}
for ln, raw in enumerate(open(base_path, encoding="utf-8"), 1):
    line = raw.split("#", 1)[0].strip()
    if not line:
        continue
    # ⚠️ pattern 可能带方法也可能不带(`/metrics` 这种匹配所有动词的),所以方法
    # 那一段必须按**方法名的字面量**认,不能写成「前两个 token」—— 后者会把
    # `exempt /metrics Prometheus …` 的第一个理由词吞进 pattern 里,于是基线那一行
    # 永远对不上任何路由,而它看起来完全正常。
    m = re.match(r"^(exempt|todo)\s+((?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+)?(/\S*)\s*(.*)$", line)
    if not m:
        print(f"HARD 基线第 {ln} 行看不懂:{line!r} —— 形状是 `exempt|todo [METHOD ]/path [理由]`")
        continue
    cls = m.group(1)
    pattern = ((m.group(2) or "").strip() + " " + m.group(3)).strip()
    reason = m.group(4).strip()
    if cls == "exempt" and len(reason) < 20:
        print(f"HARD 基线第 {ln} 行:exempt {pattern} 的理由是 {reason!r} —— "
              f"⛔ 没有理由的豁免等于关掉检查")
    baseline[pattern] = (cls, reason)

annotated, missing, exempted = [], [], []
for pattern in routes:
    op, why = as_op(pattern)
    cls = baseline.get(pattern, (None, ""))[0]
    if op and op in ops:
        annotated.append(pattern)
        if cls:                       # 已经注解了,基线里那一行必须删掉
            print(f"FIXED {cls} {pattern}")
        continue
    if cls == "exempt":
        exempted.append(pattern)
        continue
    if cls == "todo":
        missing.append(pattern)
        continue
    print(f"NEW {pattern}\t{why or '注册了,但 spec 里没有对应的 operation'}")

for pattern, (cls, _) in baseline.items():
    if pattern not in routes:
        print(f"GONE {cls} {pattern}")

# ---------- ⑭c spec 里有、路由表里没有 ----------
declared = set()
for pattern in routes:
    op, _ = as_op(pattern)
    if op:
        declared.add(op)
for op in sorted(ops - declared):
    print(f"GHOST {op[0].upper()} {op[1]}")

print(f"COUNT annotated {len(annotated)}")
print(f"COUNT missing {len(missing)}")
print(f"COUNT exempt {len(exempted)}")
print(f"COUNT routes {len(routes)}")
print(f"COUNT ops {len(ops)}")
PY

if [ -s "$tmp/perr" ]; then
    printf '  ✗ ⑭ 比对脚本失败 —— 这次检查的结论作废\n' >&2
    sed 's/^/      /' "$tmp/perr" >&2
    exit 1
fi

if grep -q '^HARD ' "$tmp/out"; then
    grep '^HARD ' "$tmp/out" | sed 's/^HARD /  ✗ ⑭③ /' >&2
    printf '    ⛔ 这一档是「门禁自己在装死」,不是端点的问题 —— 一份从 0 个文件生成出来的\n' >&2
    printf '       spec 和一份干净的 spec 长得一模一样(实测:swag 在没有注解的目录上退出码 0、\n' >&2
    printf '       写出 paths:{})。先把它修好,本次其余结论都不可信。\n' >&2
    fail=1
fi

if grep -q '^NEW ' "$tmp/out"; then
    printf '  ✗ ⑭b 这些注册了的路由在 OpenAPI 文档里找不到:\n' >&2
    grep '^NEW ' "$tmp/out" | sed 's/^NEW /      + /' >&2
    printf '    改法:在**处理这个端点的那个函数**上写 @Router/@Param/@Success,然后 make openapi。\n' >&2
    printf '    ⛔ 别把它加进 %s 了事 —— 基线里的每一行都是一个 SDK 生成不出来的端点。\n' "$BASE" >&2
    printf '    ⚠️ 如果它根本描述不了(没有方法的 pattern、尾斜杠子树、JSON-RPC 信封),\n' >&2
    printf '       那要写成 `exempt <pattern> <理由>` —— **理由是豁免本身**,不是注释。\n' >&2
    fail=1
fi

if grep -q '^FIXED ' "$tmp/out"; then
    printf '  ✗ ⑭b 基线里有已经注解好的路由(修好了):\n' >&2
    grep '^FIXED ' "$tmp/out" | sed 's/^FIXED /      - /' >&2
    printf '    改法:把 %s 里那几行删掉。棘轮只许往下走。\n' "$BASE" >&2
    fail=1
fi

if grep -q '^GONE ' "$tmp/out"; then
    printf '  ✗ ⑭b 基线里有对不上任何注册路由的条目(那条路由改了或没了):\n' >&2
    grep '^GONE ' "$tmp/out" | sed 's/^GONE /      - /' >&2
    printf '    改法:路由删了就把这行删掉;路由改名了就把这行改成新名字。\n' >&2
    printf '    ⛔ 留着它 = 下次那条路由丢掉注解时这里**不会**变红。\n' >&2
    fail=1
fi

if grep -q '^GHOST ' "$tmp/out"; then
    printf '  ✗ ⑭c 文档里有对不上任何注册路由的 operation(零基线,硬约束):\n' >&2
    grep '^GHOST ' "$tmp/out" | sed 's/^GHOST /      + /' >&2
    printf '    改法:改掉那条 @Router 让它与注册的 pattern 逐字一致,或者删掉注解。\n' >&2
    printf '    ⛔ 它比「少一个端点」更糟:SDK 会照着长出一个**打不通**的方法,\n' >&2
    printf '       而调用方要到 404 才知道。\n' >&2
    fail=1
fi

v() { awk -v k="$1" '$1=="COUNT" && $2==k {print $3}' "$tmp/out"; }
printf '  ·  路由 %s 条:已注解 %s / 豁免 %s / 待注解 %s(spec 里 %s 个 operation)\n' \
    "$(v routes)" "$(v annotated)" "$(v exempt)" "$(v missing)" "$(v ops)"

if [ "$fail" -ne 0 ]; then
    printf '\n' >&2
    echo "FAIL: OpenAPI 注解覆盖(见上)。单独跑这一条:./scripts/check-openapi.sh" >&2
    exit 1
fi
echo "ok: OpenAPI 文档与路由表一致(⑭a 未过期 / ⑭b 覆盖棘轮 / ⑭c 无幽灵端点)"
