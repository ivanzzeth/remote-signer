package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuditRecord_TableName(t *testing.T) {
	assert.Equal(t, "audit_records", AuditRecord{}.TableName())
}

func TestRuleBudget_TableName(t *testing.T) {
	assert.Equal(t, "rule_budgets", RuleBudget{}.TableName())
}

func TestBudgetID(t *testing.T) {
	// Deterministic: same (ruleID, unit) yields same 64-char hex id
	id1 := BudgetID("erc20-transfer-limit", "1:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48:0x0")
	id2 := BudgetID("erc20-transfer-limit", "1:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48:0x0")
	assert.Equal(t, id1, id2)
	assert.Len(t, id1, 64)
	assert.Regexp(t, `^[a-f0-9]{64}$`, id1)
	// Different inputs yield different ids
	id3 := BudgetID("other-rule", "eth")
	assert.NotEqual(t, id1, id3)
}

func TestSignRequest_TableName(t *testing.T) {
	assert.Equal(t, "sign_requests", SignRequest{}.TableName())
}

func TestRule_TableName(t *testing.T) {
	assert.Equal(t, "rules", Rule{}.TableName())
}

func TestRuleTemplate_TableName(t *testing.T) {
	assert.Equal(t, "rule_templates", RuleTemplate{}.TableName())
}
