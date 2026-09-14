package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"sort"
)

// ---------- dead-permissions: 定义了、授权了、没有任何代码读它 ----------
//
// # 真实事故
//
// PermInstantiateTemplate 在 middleware/rbac.go 有定义、在 admin 与 agent 的角色
// 表里有授权,而**全仓没有任何一处检查它** —— 于是建/改/删模板与实例化模板一直
// 只要 read_templates 就能打。router.go 的注释写着「mutate:
// PermInstantiateTemplate checked in handler」,那句话是假的,而且假了很久:
// 注释是唯一说它被检查过的东西,没有任何机制去对账。
//
// 2026-09-14 修掉它之后数了一遍,它**不是孤例**:同一个形状还有 5 个
// (approve_signer / create_rule_any / delete_any_rule / modify_any_rule /
// unlock_signer)。一个从未被读取的权限,在角色表里看起来是一道门,
// 实际是一面画在墙上的门。
//
// ⭐ 这条门禁存在的理由,正是 route-perm-binding 看不见的那一半:
// 那条盯住「每条路由挂了哪个权限」,这条盯住「一个权限有没有人挂」。
// 两条合起来,「权限配好了」与「权限真的生效」之间才第一次有东西在对账。
//
// # 判据
//
// 一个 Permission 常量是**死的**,当且仅当对它的每一处引用都是:
//
//   - 它自己的声明,或
//   - 角色授权表里的一个 key(`PermXxx: true`)
//
// 也就是说没有任何**代码**读它。
//
// ⚠️ 判据刻意放宽:只要存在任何别的引用(传给 helper、存进变量、出现在 switch
// 里),就不算死。⛔ 误报一个活权限比漏报一个死权限更糟 —— 前者会让人去「修」
// 一个没坏的东西,而修法通常是把它挂到某条路由上,那是在改鉴权。
//
// # ⛔ 它看不见的
//
// archcheck 只读产品代码(非 _test.go、无 build tag、非生成 —— 见 repo.go)。
// 所以:
//
//   - 只在测试里被引用的权限,这里照样算死的。**那是对的**:测试引用不是执行。
//   - 用字符串字面量做的检查(`HasPermission(role, "unlock_signer")`)它看不见。
//     ⚠️ 2026-09-14 实测全仓没有这种写法;真写出来会让这条门禁变成静默的漏报,
//     所以那种写法本身就不该出现 —— 常量存在的意义就是让它可被静态追踪。
func permissionConsts(r *repo) (declFile map[string]*goFile, declLine map[string]int, declPos map[token.Pos]bool) {
	declFile = map[string]*goFile{}
	declLine = map[string]int{}
	declPos = map[token.Pos]bool{}
	for _, f := range r.Files {
		if f.Pkg != "internal/api/middleware" {
			continue
		}
		ast.Inspect(f.File, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			// const PermXxx Permission = "..."
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Permission" {
				return true
			}
			for _, name := range vs.Names {
				declFile[name.Name] = f
				declLine[name.Name] = f.Fset.Position(name.Pos()).Line
				declPos[name.Pos()] = true
			}
			return true
		})
	}
	return declFile, declLine, declPos
}

// grantKeyPositions marks every identifier that appears as a *key* in a
// composite literal — which is what a role grant looks like:
//
//	types.RoleAdmin: {PermUnlockSigner: true, ...}
//
// ⚠️ Keyed on position, not on name: the same identifier read anywhere else is
// a different occurrence and must still count as a use. Matching by name here
// would make every granted permission look used, which is the exact bug this
// check exists to find.
func grantKeyPositions(r *repo) map[token.Pos]bool {
	out := map[token.Pos]bool{}
	for _, f := range r.Files {
		ast.Inspect(f.File, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				switch k := kv.Key.(type) {
				case *ast.Ident:
					out[k.Pos()] = true
				case *ast.SelectorExpr:
					out[k.Sel.Pos()] = true
				}
			}
			return true
		})
	}
	return out
}

func checkDeadPermissions(r *repo) ([]finding, error) {
	declFile, declLine, declPos := permissionConsts(r)

	// Losing the subject is itself the failure: a check that silently finds
	// nothing is indistinguishable from a clean tree. ⚠️ Same shape as
	// rule-type-table's missing-table guard, and for the same reason.
	if len(declFile) == 0 {
		return []finding{{
			Check: "dead-permissions",
			Key:   "Permission",
			Path:  "internal/api/middleware/rbac.go",
			Line:  1,
			Msg:   "no Permission constants found in internal/api/middleware — this check has lost its subject and is now green for the wrong reason",
		}}, nil
	}

	grantPos := grantKeyPositions(r)

	used := map[string]bool{}
	for _, f := range r.Files {
		ast.Inspect(f.File, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if _, isPerm := declFile[id.Name]; !isPerm {
				return true
			}
			if declPos[id.Pos()] || grantPos[id.Pos()] {
				return true
			}
			used[id.Name] = true
			return true
		})
	}

	var out []finding
	for name, f := range declFile {
		if used[name] {
			continue
		}
		out = append(out, finding{
			Check: "dead-permissions",
			Key:   name,
			Path:  f.Path,
			Line:  declLine[name],
			Msg:   fmt.Sprintf("%s 被定义、被按角色授权,但全仓没有任何代码检查它 —— 角色表里那一行是一道画上去的门", name),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
