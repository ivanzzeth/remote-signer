package evm

import "strings"

// isSyntheticBudgetRuleID matches simulation-fallback placeholder rule IDs
// (sim:0x + 40 hex address). These rows exist only to satisfy rule_budgets FK.
func isSyntheticBudgetRuleID(ruleID string) bool {
	return strings.HasPrefix(ruleID, "sim:0x") && len(ruleID) == 46
}

// isRulePathID accepts rule IDs routable on /api/v1/evm/rules/{id}.
// Synthetic sim:* IDs are allowed for read/delete but not create/patch.
func isRulePathID(ruleID string) bool {
	return ruleIDPattern.MatchString(ruleID) || isSyntheticBudgetRuleID(ruleID)
}

// isBudgetCleanupRuleID accepts rule IDs stored on budget rows, including
// synthetic simulation ids (sim:0x...) that normal rule create/patch rejects.
func isBudgetCleanupRuleID(ruleID string) bool {
	return ruleIDPattern.MatchString(ruleID) || isSyntheticBudgetRuleID(ruleID)
}
