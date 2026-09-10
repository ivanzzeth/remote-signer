// Package validate provides the rule-validation CLI logic for remote-signer validate.
// This file contains all shared data types for validation (rule config, test cases, templates).
package validate

import (
	"path/filepath"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
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

// The template-file format has one set of structs, in internal/config, and this
// package aliases them rather than mirroring them.
//
// ⚠️ These were literal copies until 2026-09-10, carrying the note "copied from
// config package to avoid circular imports" — stale, since this package already
// imports config. The copies had drifted: config.RuleConfig grew `priority`,
// which decides whitelist order and therefore which spending authorization
// applies, and this package's copy silently dropped it. `remote-signer validate`
// was checking rules whose ordering it could not see.
//
// ⛔ Do not reintroduce a local struct for any of these. cmd/archcheck's
// mirror-structs check fails on a second struct for the same format.
type (
	RuleConfig        = config.RuleConfig
	TestCaseConfig    = config.TestCaseConfig
	TemplateVarConfig = config.TemplateVarConfig
	TemplateFile      = config.TemplateFile
)

// RuleFile is a plain rule file: rules with no template wrapper.
type RuleFile struct {
	Rules []RuleConfig `yaml:"rules"`
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
