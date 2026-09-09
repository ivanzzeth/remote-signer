#!/usr/bin/env bash
# ---------- ⑤ 依赖方向 ----------
#
# 抽象都在,只是被绕过了。三条方向各有一个可验证的后果:
#
#   ⑤a  GORM 只许出现在 internal/storage
#       现在 8 个包直接 import gorm.io —— 换存储引擎要动 8 个包,
#       而 `storage` 那层接口写得挺好,只是没人被迫走它。
#
#   ⑤b  internal/core 不许 import internal/chain/evm
#       core 是领域层,evm 是**一个具体链的实现**。`types.ChainAdapter` 是个
#       6 方法的干净接口,`chain.Registry` 也在 —— 但 SignService 里直接放着
#       `simulationRule *evmchain.SimulationBudgetRule` 这种具体类型字段。
#       后果可量化:加第二条链(Solana)要改这里的每一个文件。
#
#   ⑤c  internal/config 不许 import 业务包
#       它名叫 config,实际是**第二个 bootstrap 层**:rule_init*.go /
#       template_init.go / apikey_init.go 全是「把 YAML 灌进 DB」的命令式逻辑。
#       名字骗人 → 谁也不敢动它。目标是拆成 `config`(纯解析,叶子包)
#       + `bootstrap`(装配)。
#
# ⛔ 三条都是**棘轮**,不是「必须为 0」。今天就为 0 是做不到的,而红着的门禁
# 等于没有门禁。集合只许缩 —— 缩了就改基线,那是一行编辑。
set -uo pipefail
cd "$(dirname "$0")/../.."
. scripts/lib/arch.sh
fail=0

echo "==> 依赖方向"

arch_prod_files internal pkg cmd tui \
    | grep -v '^internal/storage/' \
    | xargs -r grep -l 'gorm\.io/' 2>/dev/null | sort -u \
    | arch_ratchet_set "⑤a GORM 泄漏出 internal/storage" \
        scripts/lib/arch-baseline/gorm-outside-storage.txt \
        "走 storage 层的接口;需要事务就在 storage 里加一个 RunInTransaction 形态的方法。" || fail=1

arch_prod_files internal/core \
    | xargs -r grep -l 'internal/chain/evm' 2>/dev/null | sort -u \
    | arch_ratchet_set "⑤b internal/core 依赖具体链实现" \
        scripts/lib/arch-baseline/core-imports-evm.txt \
        "走 types.ChainAdapter / chain.Registry 接口,不要拿 evm 的具体类型。" || fail=1

arch_prod_files internal/config \
    | xargs -r grep -lE '"github.com/ivanzzeth/remote-signer/internal/(chain|core/rule|core/service|audit|notify|storage)' 2>/dev/null | sort -u \
    | arch_ratchet_set "⑤c internal/config 依赖业务包" \
        scripts/lib/arch-baseline/config-imports-business.txt \
        "把装配逻辑挪去 bootstrap;config 只负责解析 YAML 成结构体(叶子包)。" || fail=1

exit "$fail"
