#!/usr/bin/env bash
# ---------- ⑬ TypeScript/JavaScript 侧的 lint 门禁 ----------
#
# Go 侧对应的是 ⑫(scripts/check-lint.sh)。形状刻意一致:**跑真工具 → 解析
# 发现 → 按规则计数走棘轮 → 全程防「什么都没检查却报告成功」**。
#
# ---------- 为什么会有这个文件 ----------
#
# ⛔ 2026-09-11 之前:
#
#   · `pkg/js-client/.eslintrc.json` 存在,`package.json` 里有
#     `"lint": "eslint src --ext .ts"`,而 **`make check`、
#     `scripts/lib/layers.sh`、`.github/workflows/*` 里一次都没出现过 eslint**。
#     一条配好了却**从未执行**的门禁。第一次真的跑它:3 个 error。
#
#   · 那份配置 extends `plugin:@typescript-eslint/recommended` —— **不看类型**。
#     于是 `no-floating-promises` / `no-misused-promises` / `only-throw-error`
#     根本没被启用,而它们正是对一个**签名客户端**最要紧的三条:一个没被 await
#     的 promise 等于「调用方以为签完了」。`no-explicit-any` 是 "warn",
#     而门禁里 warn 等于没有(eslint 的退出码只看 error)。
#
#   · `web/`(16,668 行 TSX,嵌进守护进程二进制的 React UI)**一个 lint 配置
#     都没有**。
#
# ⚠️ 这是本仓库第三次踩到「配置在、执行者不在」这个形状:.githooks/pre-commit
# 从没被装过(core.hooksPath 没人设);blackbox 层连续 10 个提交重放 `ok (cached)`;
# 这一条。所以本脚本里占篇幅最多的不是规则,是那几条**「工具没在装死」的断言**
# (①⑤⑥⑦ 各防一种「什么都没检查却报告成功」)。
#
# ---------- 它为什么在 run-checks.sh 里,不在 layers.sh 里 ----------
#
# scripts/lib/layers.sh 是**测试**分层的唯一事实来源,check-tests.sh ⑥ 会要求
# 每一层在 ci.yml 里有 `make test LAYER=<名>`。把 lint 登记成一层有三个问题:
#
#   1. 它不是测试。`make test` 是「验收」那个循环,`make check` 是「改一行想
#      知道对不对」那个循环 —— lint 属于后者,和 ⑫ 一样。
#   2. **CI 覆盖面会变窄。** check.yml 是 `on: push`(每个分支每次 push);
#      ci.yml 是 `push: [main, dev]` + PR。放进 run-checks.sh 严格更宽。
#   3. `make test` 会因此开始跑 lint,把两个循环搅在一起。
#
# ⚠️ 代价:`make check` 从此需要 node + 两个包的 node_modules。那不是新增门槛
# —— `make build` 默认就走 vite,web-unit 层也要 node。缺依赖时本脚本**直接红**
# 并给出 `make lint-deps`,不会跳过后继续跑(跳过得到的绿是假的)。
#
# 判据(和其它门禁一致):*这个错误再犯一次,什么会变红?*
set -uo pipefail
cd "$(dirname "$0")/.."
. scripts/lib/arch.sh

BASE=scripts/lib/arch-baseline/js-lint.txt
PKGS=("pkg/js-client" "web")

# 每个包必须**精确钉死**的工具。⛔ 不是洁癖:eslint 与 typescript-eslint 的
# 发现集随版本变,而本门禁是计数棘轮 —— 版本不同,同一棵树两个数字,于是门禁
# 在一台机器上红、在另一台上绿。那种红人会当成噪声,然后整条门禁失效。
PINNED_pkg_js_client="eslint @eslint/js typescript-eslint eslint-plugin-security typescript"
PINNED_web="eslint @eslint/js typescript-eslint globals typescript"

# ⭐ 这五条是本次改动的**理由**,必须是 severity 2(error)。
# ⚠️ 棘轮本身不看 severity(它数所有消息),所以这条断言是**额外**的一道:
# 它防的是有人把规则悄悄降成 "warn" 并顺手把基线数字留着 —— 那样棘轮还是绿的,
# 而规则已经不再拦任何东西。
CRITICAL_RULES=(
    "@typescript-eslint/no-floating-promises"
    "@typescript-eslint/no-misused-promises"
    "@typescript-eslint/only-throw-error"
    "@typescript-eslint/ban-ts-comment"
    "@typescript-eslint/no-explicit-any"
)

fail=0
echo "==> TS/JS lint(类型感知 eslint)"

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# b <包>|<键> —— 读基线。没有条目 = 0(也就是硬约束)。
b() { sed 's/#.*//' "$BASE" | awk -v k="$1" '$1==k{print $2}'; }

pkgkey() { printf '%s' "$1" | tr -c 'A-Za-z0-9' '_'; }

# ---------- ① 依赖在不在(⛔ 缺了就红,不许跳过) ----------
#
# ⚠️ 这里不能「装了就跑、没装就跳过」。staticcheck 没装时
# `staticcheck ./... || true` 是绿的而它什么都没检查 —— 那种绿比红危险。
for p in "${PKGS[@]}"; do
    if [ ! -x "$p/node_modules/.bin/eslint" ]; then
        printf '  ✗ ⑬ %s/node_modules/.bin/eslint 不存在 —— 这次检查的结论作废\n' "$p" >&2
        printf '    装法: make lint-deps   (按 package-lock.json 严格安装,锁没变会跳过)\n' >&2
        printf '    ⛔ 不要跳过缺失项继续跑:那样得到的绿是假的。\n' >&2
        exit 1
    fi
done

# ---------- ①b 不许留着**已经失效**的旧配置 ----------
#
# ⛔ eslint 9 起只认 flat config(`eslint.config.*`),eslint 10 把 eslintrc
# 整个删掉了。所以一个留在原地的 `.eslintrc.json` **一个字都不起作用** ——
# 而它看起来完全像在起作用。⚠️ 这正是本门禁诞生的那个病的下一代形态:
# 有人去那里加规则、以为加上了。
#
# 2026-09-11 删掉的那份就是 `pkg/js-client/.eslintrc.json`。
for p in "${PKGS[@]}"; do
    for dead in .eslintrc .eslintrc.json .eslintrc.js .eslintrc.yml .eslintrc.yaml .eslintrc.cjs; do
        if [ -e "$p/$dead" ]; then
            printf '  ✗ ⑬①b %s/%s 还在 —— eslint 10 **完全不读它**\n' "$p" "$dead" >&2
            printf '    ⛔ 一份不起作用却看起来在起作用的配置,比没有配置更糟:\n' >&2
            printf '       下一个人会去那里加规则,然后以为加上了。\n' >&2
            printf '    改法:把需要的规则搬进 %s/eslint.config.mjs,删掉这个文件。\n' "$p" >&2
            fail=1
        fi
    done
    # ⛔ 反过来:flat config 必须在。没有它 eslint 10 直接报错(退出 2),
    # 那由 ⑥ 的退出码断言兜着 —— 这里点名是为了给出可读的原因。
    [ -f "$p/eslint.config.mjs" ] || {
        printf '  ✗ ⑬①b %s/eslint.config.mjs 不存在\n' "$p" >&2
        fail=1
    }
done

# ---------- ①c SDK 的 dist 必须在 —— 否则 web 是在另一套类型宇宙里被测的 ----------
#
# ⛔ 这一条是 2026-09-11 实测出来的,不是推理:`web` 通过
# `file:../pkg/js-client` 消费 SDK。**没有 dist/index.d.ts 时**,TypeScript
# 解析不到 `remote-signer-client` 的类型,于是同一棵 web/src 上:
#
#     tsc --noEmit                             0 → 20+ 条 TS2307「找不到模块」
#     no-redundant-type-constituents           0 → 22
#     require-await                            0 → 3
#     no-base-to-string                        7 → 6
#     no-unnecessary-type-assertion           10 → 6
#
# ⚠️ 注意最后两条是**变少**。也就是说「忘了构建 SDK」不只是让门禁乱红 ——
# 它会让某些规则**测不到东西**,而一条数字变小的棘轮看起来像是「修好了」。
# 所以这里要一条直说原因的断言,而不是让人去猜那 5 个数字为什么一起动了。
#
# ⚠️ `make lint-deps` 依赖 `js-client` 目标(装 + 构建),所以正常路径上它总在。
for f in pkg/js-client/dist/index.d.ts pkg/js-client/dist/index.d.mts; do
    [ -f "$f" ] || {
        printf '  ✗ ⑬①c %s 不存在 —— web 会在**没有 SDK 类型**的情况下被 lint\n' "$f" >&2
        printf '    ⛔ 那样测出来的数字和这里的基线不是同一套:实测 web 上\n' >&2
        printf '       tsc 多出 20+ 条 TS2307,而 no-base-to-string 反而从 7 掉到 6\n' >&2
        printf '       —— 一个看起来像「修好了」的假信号。\n' >&2
        printf '    改法: make lint-deps  (它依赖 `js-client` 目标:装 + npm run build)\n' >&2
        exit 1
    }
done

# ---------- ⑥ 先把两个包的 eslint 发射出去(并行),再在等它的时间里做断言 ----------
#
# ⚠️ 顺序是为了 wall clock:`make check` 的全部意义是秒级。两个包的 eslint 是
# 本门禁里唯一慢的部分(web 侧建一棵 TS program ≈6s),下面 ②③④⑤ 的断言
# 加起来不到 1s —— 让它们在 eslint 跑着的时候做完,省掉那 1s。
# ⛔ ① 必须留在前面:依赖不在的话连发射都不该发射。
pids=(); tscpids=()
for i in "${!PKGS[@]}"; do
    p=${PKGS[$i]}
    ( cd "$p" && ./node_modules/.bin/eslint src -f json ) \
        >"$tmp/$i.json" 2>"$tmp/$i.err" &
    pids+=($!)
    # ⑨ 顺手把 tsc 也发出去 —— 见下面 ⑨ 那一节的理由。实测它藏在 eslint 后面,
    # 对 wall clock 的贡献在噪声里(eslint×2 = 6.9/7.1s;eslint×2 + tsc×2 = 6.5/7.2s)。
    ( cd "$p" && ./node_modules/.bin/tsc -p tsconfig.json --noEmit ) \
        >"$tmp/$i.tsc" 2>&1 &
    tscpids+=($!)
done

# ---------- ② 版本钉死了 + ③ 装的就是钉的那个 ----------
#
# ⛔ ⓑ「钉死」判据是 package.json 里的值**长得像裸版本号**(`10.10.0`),
# 不是 `^10.10.0`。带 caret 的「钉」等于没钉:`npm install` 会把它抬到下一个
# minor,而那一刻同一棵树的数字就变了。
#
# ⛔ ⓒ 还要比**真的装了什么**:package.json 与 node_modules 不同步是常态
# (有人手动 npm install 过、lock 与 package.json 漂了),而 eslint 照样能跑完,
# 于是得到一个「版本对不上但绿」的结论。
for p in "${PKGS[@]}"; do
    list_var="PINNED_$(pkgkey "$p")"
    for dep in ${!list_var}; do
        want=$(node -e '
const fs=require("fs");
const pj=JSON.parse(fs.readFileSync(process.argv[1]+"/package.json","utf8"));
const d=(pj.devDependencies||{})[process.argv[2]]??(pj.dependencies||{})[process.argv[2]];
process.stdout.write(d??"");' "$p" "$dep")
        if [ -z "$want" ]; then
            printf '  ✗ ⑬② %s 的 package.json 里没有 %s —— 门禁用得到它,却没人声明依赖\n' "$p" "$dep" >&2
            fail=1; continue
        fi
        if ! printf '%s' "$want" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
            printf '  ✗ ⑬② %s 的 %s 钉成 "%s" —— 不是精确版本\n' "$p" "$dep" "$want" >&2
            printf '    ⛔ 没钉住的 linter 是一条会在机器之间漂的门禁:发现集随版本变,\n' >&2
            printf '       而 ⑬ 是计数棘轮。改法:npm i -D --save-exact %s@<版本>\n' "$dep" >&2
            fail=1; continue
        fi
        got=$(node -e '
const fs=require("fs");
try{process.stdout.write(JSON.parse(fs.readFileSync(process.argv[1]+"/node_modules/"+process.argv[2]+"/package.json","utf8")).version)}
catch(e){}' "$p" "$dep")
        if [ "$got" != "$want" ]; then
            printf '  ✗ ⑬③ %s:%s 装的是 %s,package.json 钉的是 %s\n' \
                "$p" "$dep" "${got:-未安装}" "$want" >&2
            printf '    装法: make lint-deps\n' >&2
            fail=1
        fi
    done
done

# ---------- ④ TypeScript 版本落在 typescript-eslint 支持的区间里 ----------
#
# ⛔ 这一条踩过真坑的形状:`typescript@latest` 现在是 **7.0.2**,而
# typescript-eslint 8.x 的 peer 是 `>=4.8.4 <6.1.0`。两者一起装时 npm 会
# **静默把 TS 降下来**,于是你以为在 7 上而其实在 5 上;反过来,如果哪天
# 有人把 TS 抬过 6.1,typescript-eslint 会退化——而那不一定会变红。
#
# ⚠️ 区间从 typescript-eslint 自己的 peerDependencies 读,**不在这里写死**:
# 写死的那份会在升级 typescript-eslint 的那天开始说谎。
for p in "${PKGS[@]}"; do
    node - "$p" <<'JS' || fail=1
const fs = require("fs");
const p = process.argv[2];
const read = (rel) => JSON.parse(fs.readFileSync(`${p}/${rel}`, "utf8"));
const range = read("node_modules/typescript-eslint/package.json").peerDependencies?.typescript;
const ts = read("node_modules/typescript/package.json").version;
if (!range) {
  console.error(`  ✗ ⑬④ ${p}: typescript-eslint 没声明 typescript peer —— 区间读不到,断言作废`);
  process.exit(1);
}
// 实际形状就是 `>=A <B`。⛔ 只认这个形状 —— 换了形状就红,而不是猜。
const m = range.match(/^>=\s*([\d.]+)\s+<\s*([\d.]+)$/);
if (!m) {
  console.error(`  ✗ ⑬④ ${p}: peer 区间 "${range}" 不是 '>=A <B' 形状,本断言看不懂它`);
  console.error(`    ⛔ 别删这条断言 —— 请把解析改对。它防的是 TS 被静默降版本。`);
  process.exit(1);
}
const num = (v) => v.split(".").map(Number);
const cmp = (a, b) => { for (let i = 0; i < 3; i++) { const d = (a[i] ?? 0) - (b[i] ?? 0); if (d) return d; } return 0; };
if (cmp(num(ts), num(m[1])) < 0 || cmp(num(ts), num(m[2])) >= 0) {
  console.error(`  ✗ ⑬④ ${p}: typescript ${ts} 不在 typescript-eslint 支持的 ${range} 内`);
  console.error(`    ⛔ 类型感知的规则会因此退化或直接不跑,而门禁可能照样是绿的。`);
  process.exit(1);
}
console.log(`  ·  ${p}: typescript ${ts} ∈ typescript-eslint peer ${range}`);
JS
done

# ---------- ⑤ 类型感知**真的开着**,而且那五条真的是 error ----------
#
# ⛔ 本门禁存在的第二个理由就是「配了但不看类型」。所以不能只相信配置文件长得
# 对 —— 直接问 eslint 自己:`--print-config <一个真文件>`。
#
# ⚠️ 判据两条都要:
#   · parserOptions 里有 projectService / project(没有它,类型感知的规则会
#     直接报错而不是静默降级 —— 但也可能有人把规则一起关掉)
#   · 那五条的 severity 是 2(有人把它降成 "warn",棘轮不会响,规则却不拦了)
for p in "${PKGS[@]}"; do
    probe=$(find "$p/src" -name '*.ts' -o -name '*.tsx' 2>/dev/null | sort | head -1)
    if [ -z "$probe" ]; then
        printf '  ✗ ⑬⑤ %s/src 下找不到 .ts/.tsx —— 没有可探针的文件,结论作废\n' "$p" >&2
        fail=1; continue
    fi
    if ! (cd "$p" && ./node_modules/.bin/eslint --print-config "${probe#"$p"/}") \
            >"$tmp/cfg.json" 2>"$tmp/cfg.err"; then
        printf '  ✗ ⑬⑤ %s: eslint --print-config 失败 —— 配置就没解析成功\n' "$p" >&2
        sed 's/^/      /' "$tmp/cfg.err" >&2
        fail=1; continue
    fi
    node - "$tmp/cfg.json" "$p" "${CRITICAL_RULES[*]}" <<'JS' || fail=1
const fs = require("fs");
const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const p = process.argv[3];
const want = process.argv[4].split(" ").filter(Boolean);
let bad = 0;
const po = cfg.languageOptions?.parserOptions ?? {};
if (!po.projectService && !po.project) {
  console.error(`  ✗ ⑬⑤ ${p}: parserOptions 里既没有 projectService 也没有 project`);
  console.error(`    ⛔ 没有类型信息 = no-floating-promises / no-misused-promises /`);
  console.error(`       only-throw-error 全部失效。那正是这条门禁存在的理由。`);
  bad = 1;
}
for (const r of want) {
  const e = cfg.rules?.[r];
  const sev = Array.isArray(e) ? e[0] : e;
  if (sev !== 2 && sev !== "error") {
    console.error(`  ✗ ⑬⑤ ${p}: 规则 ${r} 的 severity 是 ${JSON.stringify(sev)},不是 error`);
    console.error(`    ⛔ 门禁里 warn 等于没有 —— 上一版的 no-explicit-any 就是 "warn"。`);
    bad = 1;
  }
}
process.exit(bad);
JS
done

# ---------- ⑥ 收 eslint 的结果 ----------
rcs=()
for i in "${!PKGS[@]}"; do
    wait "${pids[$i]}"; rcs+=($?)
done

for i in "${!PKGS[@]}"; do
    p=${PKGS[$i]} rc=${rcs[$i]}
    # ⛔ eslint 的 0 / 1 是「没发现」和「有发现」;**其它退出码是它自己出了事**
    # (配置炸了、插件加载失败、内部异常)。那时 stdout 可能不是合法 JSON,
    # 而一个只数 JSON 里条目的门禁会把它读成「零违规」—— 正是本门禁要防的绿。
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
        printf '  ✗ ⑬⑥ %s: eslint 退出码 %d(不是 0/1)—— 它自己失败了,结论作废\n' "$p" "$rc" >&2
        sed 's/^/      /' "$tmp/$i.err" | head -20 >&2
        exit 1
    fi
done

# ---------- ⑦ 解析 + 防「零文件」「解析错误」 ----------
python3 - "$tmp" "${#PKGS[@]}" "${PKGS[@]}" <<'PY' >"$tmp/keys" 2>"$tmp/perr"
import json, sys, collections
tmp, n = sys.argv[1], int(sys.argv[2])
pkgs = sys.argv[3:3 + n]
for i, p in enumerate(pkgs):
    with open(f"{tmp}/{i}.json") as fh:
        data = json.load(fh)
    files = len(data)
    fatal = []
    c = collections.Counter()
    for f in data:
        for m in f["messages"]:
            # ⛔ fatal = 解析错误。那个文件**根本没被 lint**,它的「零发现」是假的。
            # 这与 ⑫ 里「golangci 报了 typecheck 说明有包没编译过」是同一条判据。
            # ⚠️ 实测过这个形态:一份忘了设 parser 的配置让 48 个文件全部变成
            # "Parsing error",而规则计数全是 0 —— 一个看起来极干净的结果。
            if m.get("fatal"):
                fatal.append(f'{f["filePath"]}:{m.get("line")}: {m["message"]}')
                continue
            rid = m.get("ruleId") or "<unused-disable-directive>"
            c[rid] += 1
    print(f"FILES {p} {files}")
    for d in fatal:
        print(f"FATAL {p} {d}")
    for rid, cnt in sorted(c.items()):
        print(f"COUNT {p}|{rid} {cnt}")
PY
if [ -s "$tmp/perr" ]; then
    printf '  ✗ ⑬⑦ 解析 eslint 输出失败 —— 这次检查的结论作废\n' >&2
    sed 's/^/      /' "$tmp/perr" >&2
    exit 1
fi

if grep -q '^FATAL ' "$tmp/keys"; then
    printf '  ✗ ⑬⑦ 有文件是**解析错误**,它们根本没被 lint —— 零发现是假的:\n' >&2
    grep '^FATAL ' "$tmp/keys" | sed 's/^FATAL /      /' | head -20 >&2
    printf '    ⛔ 别调基线。常见原因:tsconfig 的 include 没覆盖这个文件、\n' >&2
    printf '       或者某一段配置漏了 parser。\n' >&2
    fail=1
fi

for p in "${PKGS[@]}"; do
    got=$(awk -v p="$p" '$1=="FILES" && $2==p {print $3}' "$tmp/keys")
    min=$(b "$p|@files_min")
    if [ "${got:-0}" -lt "${min:-1}" ]; then
        printf '  ✗ ⑬⑦ %s: eslint 只 lint 了 %s 个文件,下限是 %s\n' "$p" "${got:-0}" "${min:-1}" >&2
        printf '    ⛔ 这是「什么都没检查却报告成功」的那种绿:`eslint <打错的路径>`\n' >&2
        printf '       打印空、退出 0。改法:先确认 %s/src 下的文件和 eslint.config.mjs\n' "$p" >&2
        printf '       的 ignores,不要动下限。\n' >&2
        fail=1
    else
        printf '  ·  %s: lint 了 %s 个文件(下限 %s)\n' "$p" "$got" "$min"
    fi
done

# ---------- ⑧ 棘轮:每个包 × 每条规则 ----------
#
# ⚠️ 为什么是**计数**而不是 file:line 集合:与 ⑫ 同一个理由 —— eslint 的发现
# 带行号,在被记录的行**上方**插一行无关代码就会同时产生「新增」和「已修好」
# 两种红。会误报的门禁人会绕过。切到「包 × 规则」两维,让档内互相抵消的空间
# 足够小。
#
# ⭐ 没有基线条目的规则 = 基线 0 = 硬约束。所以 no-floating-promises 在
# pkg/js-client 里今天涨到 1 就会红,不需要为它写任何条目。
declare -A seen=()
while read -r _ key cnt; do
    seen["$key"]=$cnt
    base=$(b "$key")
    base=${base:-0}
    hint="见 $BASE 里这一行的注释。"
    for cr in "${CRITICAL_RULES[@]}"; do
        if [ "${key#*|}" = "$cr" ]; then
            hint="🔴 这是本门禁存在的理由之一 —— 它抓的不是风格。$hint"
        fi
    done
    if [ "$base" -eq 0 ] && [ "$cnt" -gt 0 ]; then
        printf '  ✗ ⑬⑧ %s:%d 处,而基线是 0(硬约束,表里没有它的条目)\n' "$key" "$cnt" >&2
        printf '    改法:修掉它。⛔ 不要往 %s 里加条目 —— 基线是历史债的清单,\n' "$BASE" >&2
        printf '       不是新债的收容所。看细节:cd %s && ./node_modules/.bin/eslint src\n' "${key%%|*}" >&2
        [ -n "$hint" ] && printf '    %s\n' "$hint" >&2
        fail=1
        continue
    fi
    arch_ratchet_count "⑬ $key" "$base" "$cnt" "$hint" "$BASE" || fail=1
done < <(grep '^COUNT ' "$tmp/keys")

# 基线里有、实际已经不存在的条目 —— 修好了就该把那一行删掉。棘轮只许往下走。
while read -r key base; do
    case "$key" in ''|\#*) continue ;; esac
    case "$key" in *'|@files_min') continue ;; esac
    if [ -z "${seen[$key]+x}" ] && [ "${base:-0}" -ne 0 ]; then
        printf '  ✗ ⑬⑧ %s:基线写着 %s 处,实际已经是 0 —— 修好了\n' "$key" "$base" >&2
        printf '    改法:把 %s 里那一行删掉。棘轮只许往下走。\n' "$BASE" >&2
        fail=1
    fi
done < <(sed 's/#.*//' "$BASE" | awk 'NF==2{print $1, $2}')

# ---------- ⑨ tsc --noEmit:**零基线,硬约束** ----------
#
# ⛔ 为什么 lint 门禁里要跑 tsc:`web/tsconfig.json` 有 strict + noUnusedLocals
# + noUnusedParameters + noFallthroughCasesInSwitch(2026-09-11 又加了
# noImplicitOverride + noImplicitReturns,两条的代价实测都是 0),而在此之前
# **`make check` 一次都没有类型检查过 web/**:
#
#   · `tsc -b` 只在 `npm run build` 里(→ make web → make build)
#   · CI 里跑到它的是 ci.yml 的 web-e2e job,而 **ci.yml 只在 main/dev 与 PR 上触发**
#
# 也就是说一条 feature 分支的 push 上,tsconfig 里那些收紧**没有任何东西在执行**。
# ⚠️ 那正是 2026-09-10 那个 3.8 MB 二进制钻过的同一个洞(check.yml 跑在每次
# push 上,ci.yml 不是)。
#
# ⭐ 两个包今天都是干净的,所以这里是零基线 —— 没有基线文件,也不许加。
for i in "${!PKGS[@]}"; do
    p=${PKGS[$i]}
    if ! wait "${tscpids[$i]}"; then
        printf '  ✗ ⑬⑨ %s: tsc --noEmit 有错误 —— 零基线,硬约束\n' "$p" >&2
        sed 's/^/      /' "$tmp/$i.tsc" | head -20 >&2
        printf '    ⛔ 别靠放松 tsconfig 来变绿。要改 tsconfig 是另一件事,\n' >&2
        printf '       而且那要先量代价(见 %s/tsconfig.json 里记的数字)。\n' "$p" >&2
        fail=1
    else
        printf '  ·  %s: tsc --noEmit 干净\n' "$p"
    fi
done

# ---------- ⑩ 「有东西在跑它吗?」—— 对着 CI 文件问一次 ----------
#
# ⛔ 这条门禁诞生的**全部理由**就是「配置在、执行者不在」。那么它自己的执行者
# 呢?本地是 `make check`(run-checks.sh 的 STEPS),CI 是 check.yml 里的
# `run: make check`。⚠️ 在 2026-09-11 之前,**没有任何东西断言 check.yml 里
# 那一行还在** —— 删掉它,整个 `make check` 家族(15 条门禁 + ⑫ + ⑬)在 CI 上
# 就一条都不跑了,而所有人看到的仍然是一个绿勾。
#
# ⚠️ 这条断言覆盖的是整个 `make check` 家族,不只是 ⑬。它暂时住在这里是因为
# ⑬ 是把这个问题提出来的那条门禁;要搬去独立的门禁文件是一个后续的整理动作,
# ⛔ 不是删掉它的理由。
#
# ⚠️ 它当然挡不住「check.yml 整个被删」——那时本脚本会因为找不到文件而红,
# 这正是下面第一个分支。
CI_CHECK=.github/workflows/check.yml
if [ ! -f "$CI_CHECK" ]; then
    printf '  ✗ ⑬⑩ 找不到 %s —— `make check` 在 CI 上由**什么都没有**在执行\n' "$CI_CHECK" >&2
    fail=1
else
    for need in 'run: make check' 'run: make lint-deps'; do
        if ! grep -qF "$need" "$CI_CHECK"; then
            printf '  ✗ ⑬⑩ %s 里没有 `%s`\n' "$CI_CHECK" "$need" >&2
            printf '    ⛔ 本地跑绿不算数。这个仓库已经踩过三次「配置在、执行者不在」:\n' >&2
            printf '       .githooks 从没被装过、blackbox 层重放缓存 10 个提交、\n' >&2
            printf '       js-client 的 eslint 配了却从没被调用过。\n' >&2
            fail=1
        fi
    done
fi

if [ "$fail" -ne 0 ]; then
    printf '\n' >&2
    echo "FAIL: TS/JS lint(见上)。单独跑这一条:./scripts/check-js-lint.sh" >&2
    echo "      看某个包的全部发现:cd web && ./node_modules/.bin/eslint src" >&2
    exit 1
fi
echo "ok: TS/JS lint(类型感知 eslint 棘轮 + tsc --noEmit 零基线;pkg/js-client + web)"
