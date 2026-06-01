package rule

import (
	"encoding/json"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// resolveEffectiveRule returns the rule an evaluator should actually see for a
// request on chainID. Instance rules store their Config in TEMPLATE form (with
// ${var} placeholders) and keep their bound values in Variables; Variables is the
// single source of truth. The effective Config is computed live here by
// substituting Variables (overlaid with the per-chain Matrix row and the request
// chain_id) into the template — so editing a rule's Variables takes effect on the
// next evaluation with no rendered snapshot that could drift.
//
// Direct rules (no Variables) are returned unchanged, same pointer. When
// substitution applies, a shallow copy is returned so the repository's rule
// objects (which may be cached/shared) are never mutated.
//
// Substitution is best-effort and chain-agnostic: it only replaces known ${var}
// tokens, leaves any other ${...} (e.g. JS template literals) untouched, and
// never errors — evaluation must not fail closed on a stray placeholder.
// EffectiveRule is the exported entry point to resolveEffectiveRule: it returns
// the rule an evaluator sees for a request on chainID, with Variables
// (+Matrix+chain_id) substituted into the template-form Config. Used by
// validation/tooling that must run a rule's stored (template-form) test cases
// against its resolved config — the same resolution the engine applies at eval.
func EffectiveRule(r *types.Rule, chainID string) *types.Rule {
	return resolveEffectiveRule(r, chainID)
}

func resolveEffectiveRule(r *types.Rule, chainID string) *types.Rule {
	if r == nil || len(r.Variables) == 0 || len(r.Config) == 0 {
		return r
	}
	vars := effectiveVarMap(r, chainID)
	if len(vars) == 0 {
		return r
	}
	eff := *r
	eff.Config = substituteConfigVars(r.Config, vars)
	return &eff
}

// effectiveVarMap builds the variable map used for substitution: the rule's
// Variables, the request chain_id, then the per-chain Matrix row (string values
// only) overlaid on top.
func effectiveVarMap(r *types.Rule, chainID string) map[string]string {
	vars := map[string]string{}
	if len(r.Variables) > 0 {
		if err := json.Unmarshal(r.Variables, &vars); err != nil {
			return nil
		}
	}
	if chainID != "" {
		vars["chain_id"] = chainID
	}
	if len(r.Matrix) > 0 && chainID != "" {
		var matrix []map[string]interface{}
		if json.Unmarshal(r.Matrix, &matrix) == nil {
			for _, row := range matrix {
				if cid, _ := row["chain_id"].(string); cid == chainID {
					for k, v := range row {
						if s, ok := v.(string); ok {
							vars[k] = s
						}
					}
					break
				}
			}
		}
	}
	return vars
}

// substituteConfigVars replaces ${var} and its hex/first variants for each
// variable. It mirrors service.SubstituteVariables but lives here to avoid an
// import cycle (core/service imports core/rule) and is intentionally loose: it
// returns the result without erroring on any leftover ${...} placeholder.
func substituteConfigVars(configJSON []byte, vars map[string]string) []byte {
	result := string(configJSON)
	for k, v := range vars {
		result = strings.ReplaceAll(result, "${"+k+"}", v)
		hexv := strings.TrimPrefix(v, "0x")
		result = strings.ReplaceAll(result, "${hex:"+k+"}", hexv)
		padded := hexv
		if len(hexv) < 64 {
			padded = strings.Repeat("0", 64-len(hexv)) + hexv
		}
		result = strings.ReplaceAll(result, "${paddedhex:"+k+"}", padded)
		first := firstOfList(v)
		result = strings.ReplaceAll(result, "${first:"+k+"}", first)
		result = strings.ReplaceAll(result, "${hex:first:"+k+"}", strings.TrimPrefix(first, "0x"))
	}
	return []byte(result)
}

// firstOfList returns the first non-empty element of a comma-separated list.
func firstOfList(s string) string {
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			return p
		}
	}
	return ""
}
