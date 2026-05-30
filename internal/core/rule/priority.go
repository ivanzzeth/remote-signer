package rule

import (
	"sort"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// sortRulesByPriority sorts rules by Priority (ascending — 1 = highest),
// then by CreatedAt (oldest first) for deterministic tie-breaking.
func sortRulesByPriority(rules []*types.Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return rules[i].CreatedAt.Before(rules[j].CreatedAt)
	})
}
