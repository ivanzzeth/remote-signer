package validate

import (
	"path/filepath"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
)

// resolvePath resolves path relative to baseDir if path is not absolute.
func resolvePath(baseDir, path string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

// RuleConfig defines a rule in configuration (copied from config package to avoid circular imports)
type RuleConfig struct {
	Id            string                 `yaml:"id,omitempty" json:"id,omitempty"`
	Name          string                 `yaml:"name"`
	Description   string                 `yaml:"description,omitempty"`
	Type          string                 `yaml:"type"`
	Mode          string                 `yaml:"mode"`
	ChainType     string                 `yaml:"chain_type,omitempty"`
	ChainID       string                 `yaml:"chain_id,omitempty"`
	APIKeyID      string                 `yaml:"api_key_id,omitempty"`
	SignerAddress string                 `yaml:"signer_address,omitempty"`
	Config        map[string]any         `yaml:"config"`
	Variables     map[string]interface{} `yaml:"variables,omitempty" json:"variables,omitempty"`           // instance vars (from -config); used for rule.Variables and input substitution
	TestVariables map[string]string      `yaml:"test_variables,omitempty" json:"test_variables,omitempty"` // from template; use for validation so expected-fail cases get template test_variables
	TestCases     []TestCaseConfig       `yaml:"test_cases,omitempty" json:"test_cases,omitempty"`
	Enabled       bool                   `yaml:"enabled"`
}

// TestCaseConfig is a single test case for evm_js (from YAML test_cases).
type TestCaseConfig struct {
	Name               string                 `yaml:"name" json:"name"`
	Input              map[string]interface{} `yaml:"input" json:"input"`
	ExpectPass         bool                   `yaml:"expect_pass" json:"expect_pass"`
	ExpectReason       string                 `yaml:"expect_reason,omitempty" json:"expect_reason,omitempty"`
	ExpectBudgetAmount string                 `yaml:"expect_budget_amount,omitempty" json:"expect_budget_amount,omitempty"`
}

// RuleFile represents a YAML file containing rules (plain rule file)
type RuleFile struct {
	Rules []RuleConfig `yaml:"rules"`
}

// TemplateVarConfig defines a template variable (for template file parsing only).
// Optional variables (Required: false) must declare Default.
type TemplateVarConfig struct {
	Name        string  `yaml:"name"`
	Type        string  `yaml:"type"`
	Description string  `yaml:"description,omitempty"`
	Required    bool    `yaml:"required"`
	Default     *string `yaml:"default,omitempty"` // nil = not declared; optional vars must declare default
}

// TemplateFile represents a YAML template file (variables + test_variables + rules)
// When present, validate-rules substitutes test_variables into rules before validating.
type TemplateFile struct {
	Variables     []TemplateVarConfig `yaml:"variables"`
	TestVariables map[string]string   `yaml:"test_variables"`
	Rules         []RuleConfig        `yaml:"rules"`
}

// ValidationFileResult contains validation result for a single rule
type ValidationFileResult struct {
	RuleName        string               `json:"rule_name"`
	RuleType        string               `json:"rule_type"`
	Valid           bool                 `json:"valid"`
	Error           string               `json:"error,omitempty"`
	SyntaxError     *evm.SyntaxError     `json:"syntax_error,omitempty"`
	TestCaseResults []evm.TestCaseResult `json:"test_case_results,omitempty"`
	FailedTestCases int                  `json:"failed_test_cases,omitempty"`
	Skipped         bool                 `json:"skipped,omitempty"`
	SkipReason      string               `json:"skip_reason,omitempty"`
}

// JSONOutput represents the JSON output format
type JSONOutput struct {
	Files   map[string][]ValidationFileResult `json:"files"`
	Summary Summary                           `json:"summary"`
}

// Summary is the summary section of JSON output.
type Summary struct {
	TotalRules  int  `json:"total_rules"`
	PassedRules int  `json:"passed_rules"`
	FailedRules int  `json:"failed_rules"`
	Success     bool `json:"success"`
}
