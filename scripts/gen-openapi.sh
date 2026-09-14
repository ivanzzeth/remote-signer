#!/usr/bin/env bash
# 生成 OpenAPI 文档 —— **唯一的生成入口**。
#
#   ./scripts/gen-openapi.sh [输出路径]     默认 internal/apidocs/openapi.json
#
# `make openapi` 调它,门禁 ⑭(scripts/check-openapi.sh)也调它(输出到临时文件
# 再和库里那份比)。⛔ 两处各写一遍 swag 命令行就是两个事实源:门禁会拿**另一套
# 参数**生成的文档去比对提交的那份,差异一出现,人第一反应是改基线而不是查参数。
#
# ---------- ⛔ 为什么不从活 router 生成(提案 §4.1) ----------
#
# NewRouter 要 5 个依赖、依赖来自组装根、要库;setupRoutes 里有条件注册。把它们
# 全桩掉也只能得到**某一次部署**的路由表,而不是这份代码的 API —— e2e/test_server.go
# 就留了 14 个 RouterConfig 字段为 nil,rpc-proxy / broadcast / batch-sign / ACL /
# registry-refresh / request-simulation 一条都不注册。那样生成的 spec 会缺掉它们,
# 而且**看起来是完整的**。注解是静态的,所以文档描述的是代码本身。
#
# ⚠️ 代价写在这里免得被当成没有:静态注解**证明不了**它和真实路由一致。那件事由
# 门禁 ⑭ 做 —— 它拿 cmd/archcheck 从注册调用点 AST 抽出来的路由表逐条比对。
set -uo pipefail
cd "$(dirname "$0")/.."

OUT=${1:-internal/apidocs/openapi.json}

# ---------- ① 工具:**精确**钉在 .swag-version 上 ----------
#
# ⛔ 版本不是洁癖:swag 的 schema 渲染随版本变(rc5 → rc6 之间就改过 enum 与
# oneOf 的发射),而门禁 ⑭ 逐字节比对生成结果。换一个版本 = 同一棵树两份文档,
# 于是门禁在这台机器上红、在 CI 上绿,而那种红人会当成噪声关掉。
#
# ⚠️ 用 `go run <module>@<版本>` 而**不是** PATH 上的 swag,两个理由都是实测的:
#
#   1. `swag --version` 打印 "swag version v2.0.0" —— **rc 后缀它自己吃掉了**。
#      也就是说一个装在 PATH 上的 rc5 和一个 rc6,用版本断言分不开。
#   2. swag v1 与 v2 的二进制都叫 `swag`。本机 PATH 上就有一个 v1.16.4
#      (别的项目装的),而 v1 只出 **Swagger 2.0** —— 拿它生成等于换掉文档格式。
#
# `go run` 把版本写在命令行里,分得开、也不会和别人装的那个打架;⛔ 而且它不进
# go.mod 的 require 段 —— pkg/client 是本仓库对外的 SDK,不该因为一个构建期工具
# 多一条传递依赖(提案 §3.2 第 4 条)。
#
# ⚠️ 代价:冷机第一次要下载模块(≈18 MB 的依赖树),热跑 ≈0.7s。
WANT=$(tr -d 'v \t\r\n' < .swag-version 2>/dev/null)
if [ -z "$WANT" ]; then
    echo "  ✗ 读不到 .swag-version —— 版本钉不住,生成结果就不可比" >&2
    exit 1
fi
SWAG=(go run "github.com/swaggo/swag/v2/cmd/swag@v${WANT}")

# ---------- ② 生成 ----------
#
# -d 的第一个目录必须包含 -g 指的文件(swag 把 -g 当成相对第一个 -d 的路径)。
# ⚠️ 第二个目录是**整棵 internal/**:注解写在 handler 上,而 handler 引用的 DTO
# 散在 internal/core/types 等处 —— 少一个目录,swag 报 "cannot find type definition"
# 并**拒绝生成**(实测)。那是好消息:它不会悄悄发一个空 schema。
#
# ⚠️ --overridesFile 只为 json.RawMessage 存在,理由写在 .swaggo 里。
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
if ! "${SWAG[@]}" init -q \
        -g doc.go \
        -d ./internal/apidocs,./internal \
        --overridesFile .swaggo \
        --v3.1 \
        --outputTypes json \
        -o "$tmp" >"$tmp/.log" 2>&1; then
    echo "  ✗ swag 生成失败:" >&2
    sed 's/^/      /' "$tmp/.log" >&2
    exit 1
fi
if [ ! -s "$tmp/swagger.json" ]; then
    echo "  ✗ swag 退出码是 0,但没写出 swagger.json —— 结论作废" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUT")"
cp "$tmp/swagger.json" "$OUT"
echo "ok: $OUT  ($(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(len(d.get("paths",{})),"paths")' "$OUT"))"
