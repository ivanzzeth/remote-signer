#!/usr/bin/env bash
# ---------- ⑧ settings 单一事实源 ----------
#
# 这条不是「架构不好看」,是一个**可见 bug**:
# internal/settings/model.go 的包注释明写「settings written through the admin API
# or CLI become effective without a daemon restart」。而实际链路是
#
#   DB → security_seed.go 把 DB 值**拷回 cfg.Security** → run_router.go 冻结进
#   RouterConfig → 各 handler 的构造函数把它捕获成结构体字段
#
# 于是在 Web UI 里改 rules_api_readonly / max_rules_per_api_key / sign_timeout:
# DB 变了,Manager 的快照也变了,**行为不变** —— 直到重启。
# 全仓库只有 ApprovalGuard 有 router.syncApprovalGuard() 做回写。
#
# 判据是结构性的、可精确判定的:*这个安全开关有没有被存进某个结构体的字段?*
# 存进去了 = 它在构造那一刻就冻住了 = 那份文档对它是假的。
# 比数 `cfg.Security.*` 的出现次数准 —— 后者分不清「请求路径上做判断的读」和
# 「settings API 为了序列化而读」,那种糊判据做出来的门禁会误报。
set -uo pipefail
cd "$(dirname "$0")/../.."
. scripts/lib/arch.sh
fail=0

echo "==> settings 单一事实源"

fields=$(awk '/^type SecuritySnapshot struct/{f=1;next} f&&/^}/{exit} f&&/^\t[A-Z]/{print $1}' \
    internal/settings/snapshots.go)
[ -n "$fields" ] || { echo "  ✗ 读不到 SecuritySnapshot 字段(结构体改名了?)" >&2; exit 1; }
pat=$(printf '%s|' $fields | sed 's/|$//')

captures=$(arch_prod_files internal/api | while read -r f; do
    awk -v pat="$pat" -v file="$f" '
      /^type [A-Za-z]+ struct/{ins=1; sname=$2; next}
      ins && /^}/{ins=0; next}
      ins && match($0, /^\t([a-zA-Z][A-Za-z0-9_]*)[ \t]+/, m) {
        lc=tolower(m[1]); n=split(pat,arr,"|")
        for(i=1;i<=n;i++) if(lc==tolower(arr[i])) print file "\t" sname "." m[1]
      }' "$f"
done | sort -u)

printf '%s\n' "$captures" | grep -v '^$' | arch_ratchet_set \
    "⑧ 在构造期捕获安全开关的结构体字段" \
    scripts/lib/arch-baseline/settings-frozen-captures.txt \
    "请求路径上现读 settingsMgr.Security().<字段>,不要把它存成结构体字段。" || fail=1

exit "$fail"
