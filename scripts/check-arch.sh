#!/usr/bin/env bash
# 架构约束门禁 —— 钉住「重构之后不许再长回去」的那几条性质。
#
# 这些约束**没有任何编译器/linter 会管**:违反它的代码编译通过、测试全绿,
# 只是把一个已经收敛的路径重新叉开,然后两条叉路开始各自漂。
set -uo pipefail
cd "$(dirname "$0")/.."

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

# ---------- ② 每个 preset 引用的 template 都必须存在 ----------
#
# preset 的 template_ids 指向不存在的 template 时,`preset apply` 会少装一条规则
# 而**不报错** —— 用户以为白名单齐了,实际缺一条,表现为「某个签名莫名进
# authorizing」。可达性用例(同 lingxiao 的 every_domain_is_reachable_by_slug)。
echo "==> preset 引用的 template 都存在"
python3 - <<'PY' || fail=1
import pathlib, re, sys, yaml

tmpl_dir = pathlib.Path("rules/templates")
preset_dir = pathlib.Path("rules/presets")
if not tmpl_dir.is_dir() or not preset_dir.is_dir():
    print("  – rules/ 不在,跳过"); sys.exit(0)

known = set()
for f in tmpl_dir.rglob("*.yaml"):
    try:
        d = yaml.safe_load(f.read_text()) or {}
    except Exception as e:
        print(f"  ✗ {f}: YAML 解析失败 {e}"); sys.exit(1)
    for key in ("id", "template_id"):
        if isinstance(d, dict) and d.get(key):
            known.add(str(d[key]))
    # 目录形态也算一个 id:evm/aori
    known.add(f"{f.parent.name}/{f.stem}")
    known.add(f.stem)

bad = []
for f in preset_dir.rglob("*.yaml"):
    d = yaml.safe_load(f.read_text()) or {}
    if not isinstance(d, dict):
        continue
    for tid in d.get("template_ids") or []:
        if str(tid) not in known:
            bad.append((f, tid))

if bad:
    for f, tid in bad:
        print(f"  ✗ {f} 引用了不存在的 template `{tid}`")
    print("    改法:改正 template_ids,或把缺的 template 加进 rules/templates/。")
    print("    ⛔ 别忽略:preset apply 会静默少装一条规则,表现为签名莫名进 authorizing。")
    sys.exit(1)
PY

# ---------- ③ 签名者位置只许出现白名单里的地址 ----------
#
# 判据:`signer` / `test_signer` / `from` 在语义上**就是签名私钥对应的地址**。
# 一个真实 EOA 出现在那里,只可能是某个人的钱包 —— 而本仓库对外开源。
#
# ⛔ 白名单式、fail-closed:没登记过的地址一律当成真实钱包。方向同 lingxiao 的
# `an_unknown_tool_is_assumed_to_write` —— 最坏后果是多改一个占位符(有人会来报),
# 而不是某人的钱包被公开(没人会发现)。
# ⛔ 不用「看起来像不像占位符」这种模糊判据:0x1234…7890 像,0xf39Fd6e…(Hardhat
# account #0)不像但同样无害,而真钱包和随机 hex 分不开。模糊判据会误报,
# 会误报的门禁最后会被 `|| true` 掉。
#
# ⛔ 只管这三个字段,不管 `to` / `token` / `spender` —— 那些本来就该是真合约地址。
#
# 踩过两次:b922718 清过一轮 operator 地址;2026-09 新写的 aori/stargate 模板与
# 测试又把同一个地址硬编码了 23 处,其中 2 处**嵌在 calldata 十六进制里**
# (`...000764602fead...`),按地址 grep 会漏。
echo "==> 签名者字段在白名单内"
python3 - <<'PY_GATE' || fail=1
import pathlib, re, sys

allow = set()
for line in pathlib.Path("scripts/lib/approved-test-addresses.txt").read_text().split("\n"):
    line = line.split("#")[0].strip()
    if line:
        allow.add(line.lower())

# ⚠️ 三种写法都要认,少一种就等于那类文件根本没被扫:
#   YAML   :  signer: "0x…"          裸键 + 冒号
#   Go map :  "signer": "0x…",       **带引号的键**
#   Go const: testSigner = "0x…"     标识符 + 等号(驼峰)
# 第一版只写了 YAML 那种 —— 负向验证当场戳破:往 Go 测试里塞一个未登记地址,
# 门禁纹丝不动。而最初那 23 处硬编码里就有 4 处是 Go 的这两种形态。
NAMES = r'(?:signer|test_signer|testSigner|signer_address|signerAddress|signer_address_for_testing|from|fromAddr|fromAddress)'
def is_structural_dummy(addr: str) -> bool:
    """用**几乎不同的十六进制字符数**判定「这不可能是一个真实地址」。

    真实地址是 40 个近似均匀的十六进制位;只用 <=3 种字符(0x1111…、0xaaaa…、
    0x0000…0001、0xdead…)的概率小到可以当零。所以这条判据是**结构性**的,
    不是「看起来像不像占位符」那种模糊判断 —— 后者会误报,而会误报的门禁最后
    会被 `|| true` 掉。

    ⛔ 门槛不许放宽到 4 及以上:那会开始遮住真地址。
    """
    return len(set(addr[2:].lower())) <= 3


FIELD = re.compile(
    r'(?:^|[\s,{(])["\x27]?' + NAMES + r'["\x27]?\s*[:=]\s*["\x27](0x[0-9a-fA-F]{40})["\x27]',
    re.IGNORECASE)

files = list(pathlib.Path("rules").rglob("*.yaml"))
files += [f for f in pathlib.Path(".").rglob("*_test.go")
          if not {"vendor", "node_modules"} & set(f.parts)]

bad = {}
for f in sorted(set(files)):
    for n, line in enumerate(f.read_text(errors="replace").split("\n"), 1):
        if "arch-address-exempt" in line:
            continue
        for addr in FIELD.findall(line):
            if addr.lower() in allow or is_structural_dummy(addr):
                continue
            bad.setdefault(addr, []).append(f"{f}:{n}")

if bad:
    print(f"  ✗ {len(bad)} 个未登记的地址出现在签名者位置:")
    for addr, locs in sorted(bad.items(), key=lambda kv: -len(kv[1])):
        print(f"      {addr}  ({len(locs)} 处)  例:{locs[0]}")
    print("    这三个字段就是「签名私钥的地址」——真实 EOA 写在那里等于公开某人的钱包,")
    print("    而本仓库对外开源。二选一:")
    print("      · 换成占位符(0x…0001 这类),或")
    print("      · 确认它不属于任何人之后,登记进 scripts/lib/approved-test-addresses.txt")
    print("    单行豁免:该行加注释 `arch-address-exempt: <理由>`。")
    sys.exit(1)
PY_GATE

if [ "$fail" -ne 0 ]; then
    echo >&2; echo "FAIL: 架构约束违规(见上)。" >&2
    exit 1
fi
echo "ok: 架构约束"
