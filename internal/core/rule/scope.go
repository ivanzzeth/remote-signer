package rule

import (
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// FilterRulesForCaller returns only the rules that apply to the given caller API key ID.
// A rule applies to a caller when:
//   - status = "active"
//   - AND one of:
//     -- "*" is in applied_to (global rule)
//     -- callerKeyID is in applied_to (explicitly targeted)
//     -- "self" is in applied_to AND owner == callerKeyID (self-scoped rule)
//
// If callerKeyID is empty, only global rules (applied_to contains "*") with active status are returned.
func FilterRulesForCaller(rules []*types.Rule, callerKeyID string) []*types.Rule {
	out := make([]*types.Rule, 0, len(rules))
	for _, r := range rules {
		if !ruleAppliesToCaller(r, callerKeyID) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// ruleAppliesToCaller checks whether a single rule applies to the given caller.
func ruleAppliesToCaller(r *types.Rule, callerKeyID string) bool {
	// Status filter: only active rules are evaluated.
	// Zero-value Status ("") is treated as active for backward compatibility
	// with legacy rules that pre-date the ownership model.
	if r.Status != types.RuleStatusActive && r.Status != "" {
		return false
	}

	// Empty AppliedTo is treated as ["*"] (global) for backward compatibility
	// with legacy rules created before the ownership model was added.
	if len(r.AppliedTo) == 0 {
		return true
	}

	for _, target := range r.AppliedTo {
		if target == "*" {
			return true
		}
		if target == callerKeyID && callerKeyID != "" {
			return true
		}
		if target == "self" && r.Owner == callerKeyID && callerKeyID != "" {
			return true
		}
	}
	return false
}
