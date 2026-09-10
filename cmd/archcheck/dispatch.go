package main

import (
	"fmt"
	"go/ast"
	"sort"
	"strings"
)

// ---------- engine-dispatch: callers that ask which engine a rule uses ----------
//
// The evaluation path is polymorphic: RuleEvaluator has Type() and Evaluate(),
// evaluators go into a registry, and adding an engine costs no edit at any call
// site. The validation path never got the same treatment, so the three
// validators have three different signatures —
//
//	JSRuleValidator.ValidateRule(ctx, script string, testCases []JSTestCase)
//	SolidityRuleValidator.ValidateRule(ctx, rule *types.Rule)
//	MessagePatternRuleValidator.ValidateRule(ctx, rule *types.Rule)
//
// — and every caller has to work out which one to call. That is why 15 non-test
// files carry an engine test, and why internal/api/handler has a file named
// solidity_guard.go: the delivery layer knows about one specific engine.
//
// Read the branches and they are all the same three questions, asked of the
// caller instead of the engine:
//
//	if ruleType == RuleTypeEVMJS && len(req.TestCases) > 0   // does it take test cases?
//	if rule.Type == RuleTypeEVMSolidityExpression            // does it need a toolchain?
//	func templateContainsSolidity(tmpl) bool                 // does this template need forge?
//
// ⛔ The fix is never to delete an engine. It is to let the engine answer, the
// way RuleEvaluator already does for evaluation.
//
// # The criterion
//
// A file naming two or more distinct rule-type constants is dispatching. One is
// the shape of an engine declaring its own Type(); the declaration site in
// internal/core/types is exempt because that is where the constants live.
const minTypesForDispatch = 2

var ruleTypeDeclPkg = "internal/core/types"

func checkEngineDispatch(r *repo) ([]finding, error) {
	var out []finding

	for _, f := range r.Files {
		if f.Pkg == ruleTypeDeclPkg {
			continue
		}
		seen := map[string]bool{}
		ast.Inspect(f.File, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.SelectorExpr:
				// types.RuleTypeEVMJS
				if isRuleTypeConst(v.Sel.Name) {
					seen[v.Sel.Name] = true
				}
			case *ast.Ident:
				// RuleTypeEVMJS, in a file that dot-imports or is in the same package
				if isRuleTypeConst(v.Name) {
					seen[v.Name] = true
				}
			}
			return true
		})
		if len(seen) < minTypesForDispatch {
			continue
		}
		names := make([]string, 0, len(seen))
		for k := range seen {
			names = append(names, strings.TrimPrefix(k, "RuleType"))
		}
		sort.Strings(names)
		out = append(out, finding{
			Check: "engine-dispatch",
			Key:   f.Path,
			Path:  f.Path,
			Line:  1,
			Msg:   fmt.Sprintf("branches on %d engines: %s", len(names), strings.Join(names, ",")),
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// isRuleTypeConst matches the RuleTypeXxx constants without hardcoding the list,
// so a new engine's constant is covered the day it is declared.
//
// ⚠️ Deliberately excludes the bare type name "RuleType": that is the type, and
// mentioning it is not dispatch.
func isRuleTypeConst(name string) bool {
	return strings.HasPrefix(name, "RuleType") && len(name) > len("RuleType")
}
