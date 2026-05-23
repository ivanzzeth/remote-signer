package validate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateTemplateOptionalVarsHaveDefault_AllRequired(t *testing.T) {
	vars := []TemplateVarConfig{
		{Name: "var1", Required: true},
		{Name: "var2", Required: true},
	}
	err := validateTemplateOptionalVarsHaveDefault(vars, "test.yaml")
	assert.NoError(t, err)
}

func TestValidateTemplateOptionalVarsHaveDefault_OptionalWithDefault(t *testing.T) {
	def := "default_val"
	vars := []TemplateVarConfig{
		{Name: "opt", Required: false, Default: &def},
	}
	err := validateTemplateOptionalVarsHaveDefault(vars, "test.yaml")
	assert.NoError(t, err)
}

func TestValidateTemplateOptionalVarsHaveDefault_OptionalMissingDefault(t *testing.T) {
	vars := []TemplateVarConfig{
		{Name: "bad_opt", Required: false, Default: nil},
	}
	err := validateTemplateOptionalVarsHaveDefault(vars, "test.yaml")
	assert.ErrorContains(t, err, "optional variable \"bad_opt\" must declare default")
	assert.ErrorContains(t, err, "test.yaml")
}

func TestValidateExplicitRuleIDsLocal_AllExplicit(t *testing.T) {
	rules := []RuleConfig{
		{Id: "rule_one", Name: "Rule 1"},
		{Id: "rule_two", Name: "Rule 2"},
	}
	err := validateExplicitRuleIDsLocal(rules)
	assert.NoError(t, err)
}

func TestValidateExplicitRuleIDsLocal_MissingIDs(t *testing.T) {
	rules := []RuleConfig{
		{Id: "valid", Name: "Valid"},
		{Id: "", Name: "No ID"},
		{Id: "  ", Name: "Whitespace"},
	}
	err := validateExplicitRuleIDsLocal(rules)
	assert.ErrorContains(t, err, "missing id")
	assert.ErrorContains(t, err, "No ID")
	assert.ErrorContains(t, err, "Whitespace")
}

func TestExtractTestCasesFromConfig_AlreadyAtRuleLevel(t *testing.T) {
	rules := []RuleConfig{
		{
			Name:     "has_test_cases",
			TestCases: []TestCaseConfig{{Name: "tc1"}},
			Config:   map[string]any{},
		},
	}
	extractTestCasesFromConfig(rules)
	assert.Len(t, rules[0].TestCases, 1)
}

func TestExtractTestCasesFromConfig_FromConfigMap(t *testing.T) {
	rules := []RuleConfig{
		{
			Name: "needs_extraction",
			Config: map[string]any{
				"test_cases": []any{
					map[string]any{"name": "tc1", "input": map[string]any{}, "expect_pass": true},
				},
			},
		},
	}
	extractTestCasesFromConfig(rules)
	assert.Len(t, rules[0].TestCases, 1)
	assert.Equal(t, "tc1", rules[0].TestCases[0].Name)
	assert.True(t, rules[0].TestCases[0].ExpectPass)
}

func TestExtractTestCasesFromConfig_NoTestCases(t *testing.T) {
	rules := []RuleConfig{
		{Name: "no_test_cases", Config: map[string]any{"script": "return true"}},
	}
	extractTestCasesFromConfig(rules)
	assert.Len(t, rules[0].TestCases, 0)
}

func TestExtractTestCasesFromConfig_InvalidTestCases(t *testing.T) {
	rules := []RuleConfig{
		{Name: "bad_tc", Config: map[string]any{"test_cases": "not an array"}},
	}
	extractTestCasesFromConfig(rules)
	assert.Len(t, rules[0].TestCases, 0)
}
