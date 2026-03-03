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

func TestSignRequest_TableName(t *testing.T) {
	assert.Equal(t, "sign_requests", SignRequest{}.TableName())
}

func TestRule_TableName(t *testing.T) {
	assert.Equal(t, "rules", Rule{}.TableName())
}

func TestRuleTemplate_TableName(t *testing.T) {
	assert.Equal(t, "rule_templates", RuleTemplate{}.TableName())
}
