#!/usr/bin/env bash
# 由 scripts/check-arch.sh 调用。单独跑也行(重构中修某一条时很有用)。
set -uo pipefail
cd "$(dirname "$0")/../.."
fail=0

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


exit "$fail"
