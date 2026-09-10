package validate

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
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
			Name:      "has_test_cases",
			TestCases: []TestCaseConfig{{Name: "tc1"}},
			Config:    map[string]any{},
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

// TestValidateTemplateOptionalVarsHaveDefault_RejectsDefaultOutsideItsOwnBound:
// a default the template's own max forbids can never be applied, and saying so
// at validate time beats saying it after the operator has filled in a preset.
func TestValidateTemplateOptionalVarsHaveDefault_RejectsDefaultOutsideItsOwnBound(t *testing.T) {
	max := "1000"
	err := validateTemplateOptionalVarsHaveDefault([]TemplateVarConfig{
		{Name: "cap", Type: types.VarTypeBigInt, Required: false, Default: "5000", Max: &max},
	}, "t.yaml")
	if err == nil {
		t.Fatal("want an error: default 5000 exceeds the declared max 1000")
	}
	if !strings.Contains(err.Error(), "above max") {
		t.Errorf("error should name the bound, got %v", err)
	}
}

func TestValidateTemplateOptionalVarsHaveDefault_AcceptsDefaultInsideItsBound(t *testing.T) {
	max := "1000"
	if err := validateTemplateOptionalVarsHaveDefault([]TemplateVarConfig{
		{Name: "cap", Type: types.VarTypeBigInt, Required: false, Default: "999", Max: &max},
	}, "t.yaml"); err != nil {
		t.Fatalf("want accepted, got %v", err)
	}
}
