package main

import (
	"fmt"
	"go/ast"
	"sort"
)

// ---------- rule-type-table: every declared rule type is in the one table ----------
//
// types.ruleTypes is the single list the rest of the tree derives from. A
// constant declared beside it but missing from it is invisible to everything
// that derives — which is not hypothetical: RuleTypeEVMInternalTransfer was
// declared, registered as an evaluator in four places, and absent from
// ValidRuleTypes, so a fully wired engine rejected every attempt to create a
// rule for it. No shipped rule used the type, so nobody hit it.
//
// ⚠️ Zero baseline, and it should stay that way. This is not debt to work off;
// it is a two-line invariant with one known way to break it.
// ruleTypeConstNames returns the RuleTypeXxx constants actually declared in the
// domain, read from the AST.
//
// ⚠️ Not a prefix match. "RuleType" also prefixes the RuleTypes() accessor and
// the RuleTypeDescriptor type, and counting those made every file that derives
// from the table look like a file that branches on it — the engine-dispatch
// check reported internal/validate as still dispatching after its map had been
// replaced by a loop over RuleTypes().
func ruleTypeConstNames(r *repo) map[string]bool {
	out := map[string]bool{}
	for _, f := range r.Files {
		if f.Pkg != "internal/core/types" {
			continue
		}
		ast.Inspect(f.File, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "RuleType" {
				return true
			}
			for _, name := range vs.Names {
				out[name.Name] = true
			}
			return true
		})
	}
	return out
}

func checkRuleTypeTable(r *repo) ([]finding, error) {
	var declared []string
	var declLine = map[string]int{}
	inTable := map[string]bool{}
	var tablePath string
	var tableLine int

	for _, f := range r.Files {
		if f.Pkg != "internal/core/types" {
			continue
		}
		ast.Inspect(f.File, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.ValueSpec:
				// const RuleTypeXxx RuleType = "..."
				if id, ok := v.Type.(*ast.Ident); !ok || id.Name != "RuleType" {
					return true
				}
				for _, name := range v.Names {
					declared = append(declared, name.Name)
					declLine[name.Name] = f.Fset.Position(name.Pos()).Line
				}
			case *ast.CompositeLit:
				// {Type: RuleTypeXxx, ...} inside the ruleTypes table
				for _, elt := range v.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "Type" {
						continue
					}
					if id, ok := kv.Value.(*ast.Ident); ok {
						inTable[id.Name] = true
						tablePath, tableLine = f.Path, f.Fset.Position(kv.Pos()).Line
					}
				}
			}
			return true
		})
	}

	// No table found at all is itself the failure this check guards.
	if len(inTable) == 0 && len(declared) > 0 {
		return []finding{{
			Check: "rule-type-table",
			Key:   "ruleTypes",
			Path:  "internal/core/types/rule.go",
			Line:  1,
			Msg:   "the ruleTypes table is gone; every derived list is now free to drift again",
		}}, nil
	}

	var out []finding
	for _, name := range declared {
		if inTable[name] {
			continue
		}
		out = append(out, finding{
			Check: "rule-type-table",
			Key:   name,
			Path:  "internal/core/types/rule.go",
			Line:  declLine[name],
			Msg: fmt.Sprintf("%s is declared but missing from the ruleTypes table (%s:%d), so everything deriving from it — ValidRuleTypes, config validation, the CLI — will not know the type exists",
				name, tablePath, tableLine),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
