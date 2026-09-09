#!/usr/bin/env bash
# 由 scripts/check-arch.sh 调用。单独跑也行(重构中修某一条时很有用)。
set -uo pipefail
cd "$(dirname "$0")/../.."
fail=0

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


exit "$fail"
