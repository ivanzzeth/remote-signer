#!/usr/bin/env bash
# 发版前必须过的一关。
#
# 为什么存在:2026-09-10 给一个版本打了标签并推送(推送即发布),而持续验证
# 那时已经连红四十多轮。打标签的人只跑了本机,本机绿 —— 因为
#   ① 本机装了某个外部工具链而验证机器没有;
#   ② 有整整一层验证本机从来没跑过(它不在 all 里,要单独点名)。
#
# ⛔ 所以这个脚本不问「你本机绿不绿」,它问「**远端那次跑绿没绿**」。
# 详见 docs/incidents.md。
set -euo pipefail

fail=0
say() { printf '  %s\n' "$*"; }

echo "==> 工作区干净"
if [ -n "$(git status --porcelain)" ]; then
    say "FAIL: 有未提交的改动 —— 标签会指向一个和你手上不一样的树。"
    fail=1
else
    say "ok"
fi

echo "==> 本地与远端同步"
git fetch -q origin 2>/dev/null || true
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse "@{u}" 2>/dev/null || echo "")
if [ -z "$REMOTE" ]; then
    say "FAIL: 当前分支没有上游 —— 无法判断远端验证跑的是不是这个提交。"
    fail=1
elif [ "$LOCAL" != "$REMOTE" ]; then
    say "FAIL: 本地 $(git rev-parse --short HEAD) 与远端 $(git rev-parse --short '@{u}') 不一致,先推送。"
    fail=1
else
    say "ok ($(git rev-parse --short HEAD))"
fi

# ---------- 远端验证必须是绿的 ----------
#
# ⚠️ 判据是「**这个提交**那次跑」,不是「最近一次跑」——后者可能是别的分支、
# 别的提交,甚至是重跑了一半。
echo "==> 远端验证对这个提交是绿的"
if ! command -v gh >/dev/null 2>&1; then
    say "FAIL: 没有 gh,无法查远端结论。⛔ 不要凭本机绿就发版 —— 那正是上次出事的原因。"
    fail=1
else
    concl=$(gh run list --workflow=CI --limit 20 \
              --json headSha,conclusion,status \
              -q "[.[] | select(.headSha==\"$LOCAL\")] | .[0] | \"\(.status)/\(.conclusion // \"—\")\"" 2>/dev/null || echo "")
    case "$concl" in
        completed/success) say "ok (CI success)" ;;
        "")                say "FAIL: 远端没有针对 $(git rev-parse --short HEAD) 的验证记录。推送后等它跑完。"; fail=1 ;;
        completed/*)       say "FAIL: 远端验证结论是 ${concl#*/} —— 修好再发。"; fail=1 ;;
        *)                 say "FAIL: 远端验证还在跑($concl),等它。"; fail=1 ;;
    esac
fi

# ---------- 不在 all 里的层,必须被点名 ----------
#
# 这些层慢、要额外依赖,所以 `make test LAYER=all` 不含它们。⛔ 但「不在 all 里」
# 不等于「发版可以不管」—— web-e2e 就是这样红了四十多轮没人看见的。
echo "==> 慢层在这次验证里跑过"
if command -v gh >/dev/null 2>&1; then
    jobs=$(gh run list --workflow=CI --limit 20 --json headSha,databaseId \
             -q "[.[] | select(.headSha==\"$LOCAL\")] | .[0].databaseId" 2>/dev/null || echo "")
    if [ -n "$jobs" ] && [ "$jobs" != "null" ]; then
        for layer in e2e web-e2e; do
            got=$(gh run view "$jobs" --json jobs -q ".jobs[] | select(.name==\"$layer\") | .conclusion" 2>/dev/null || echo "")
            case "$got" in
                success) say "ok  $layer" ;;
                "")      say "FAIL: 这次验证里没有 $layer —— 它没跑就等于它不存在。"; fail=1 ;;
                *)       say "FAIL: $layer = $got"; fail=1 ;;
            esac
        done
    fi
fi

if [ "$fail" -eq 0 ]; then
    echo "✅ 可以打标签"
else
    echo "❌ 不要打标签(见上)"
fi
exit "$fail"
