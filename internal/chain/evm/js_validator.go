package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// dangerousJSPatterns contains regex patterns for dangerous JavaScript constructs.
// These are checked before rule execution as a defense-in-depth layer alongside
// the runtime sandbox (removeGlobals()).
var dangerousJSPatterns = []*regexp.Regexp{
	// Prototype pollution / sandbox escape
	regexp.MustCompile(`__proto__`),                          // direct prototype manipulation
	regexp.MustCompile(`constructor\s*\.\s*constructor`),     // sandbox escape via "".constructor.constructor("return this")()
	regexp.MustCompile(`Object\s*\.\s*getPrototypeOf`),       // prototype chain exploration
	regexp.MustCompile(`Object\s*\.\s*setPrototypeOf`),       // prototype chain modification
	regexp.MustCompile(`Object\s*\.\s*defineProperty`),       // property hijacking via getter/setter redefinition

	// Dynamic code execution
	regexp.MustCompile(`\bFunction\s*\(`),  // new Function("...") is equivalent to eval
	regexp.MustCompile(`\bimport\s*\(`),    // dynamic import()

	// Node.js dangerous modules
	regexp.MustCompile(`\bchild_process\b`), // command execution via child_process
}

// ValidateJSCodeSecurity checks JavaScript code for dangerous patterns.
// Returns nil if code is safe, or SecurityError if dangerous patterns are found.
func ValidateJSCodeSecurity(code string) *SecurityError {
	for _, pattern := range dangerousJSPatterns {
		if pattern.MatchString(code) {
			return &SecurityError{
				Pattern: pattern.String(),
				Message: fmt.Sprintf("dangerous pattern detected: %s - this construct is not allowed in JS rules for security reasons", pattern.String()),
			}
		}
	}
	return nil
}

// JSTestCase defines a test case for evm_js rule validation (from YAML test_cases).
type JSTestCase struct {
	Name                string                 `json:"name" yaml:"name"`
	Input               map[string]interface{} `json:"input" yaml:"input"`
	ExpectPass          bool                   `json:"expect_pass" yaml:"expect_pass"`
	ExpectReason        string                 `json:"expect_reason,omitempty" yaml:"expect_reason,omitempty"`
	ExpectBudgetAmount  string                 `json:"expect_budget_amount,omitempty" yaml:"expect_budget_amount,omitempty"` // when set, validateBudget(input) must return this amount
}

// JSRuleValidator validates evm_js rules by running their test_cases.
type JSRuleValidator struct {
	evaluator *JSRuleEvaluator
	logger    *slog.Logger
}

// NewJSRuleValidator creates a validator that runs test cases via the JS evaluator.
func NewJSRuleValidator(evaluator *JSRuleEvaluator, logger *slog.Logger) (*JSRuleValidator, error) {
	if evaluator == nil {
		return nil, fmt.Errorf("evaluator is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	return &JSRuleValidator{evaluator: evaluator, logger: logger}, nil
}

// ValidateRule runs script with each test case (input + config from testVariables), compares result to expect_pass/expect_reason.
// script and testCases are from the rule; testVariables is the config object (e.g. template test_variables).
func (v *JSRuleValidator) ValidateRule(ctx context.Context, script string, testCases []JSTestCase, testVariables map[string]string) (*ValidationResult, error) {
	if script == "" {
		return &ValidationResult{Valid: false, FailedTestCases: 0}, fmt.Errorf("script is empty")
	}

	// Static security check before running any code
	if secErr := ValidateJSCodeSecurity(script); secErr != nil {
		return &ValidationResult{Valid: false}, fmt.Errorf("security check failed: %s", secErr.Message)
	}

	configObj := make(map[string]interface{})
	for k, val := range testVariables {
		configObj[k] = val
	}

	result := &ValidationResult{Valid: true}
	for _, tc := range testCases {
		tcResult := TestCaseResult{
			Name:           tc.Name,
			ExpectedPass:   tc.ExpectPass,
			ExpectedReason: tc.ExpectReason,
		}

		ruleInput, err := MapToRuleInput(tc.Input)
		if err != nil {
			tcResult.Passed = false
			tcResult.Error = fmt.Sprintf("invalid input: %v", err)
			result.TestCaseResults = append(result.TestCaseResults, tcResult)
			result.FailedTestCases++
			result.Valid = false
			continue
		}

		jsResult := v.evaluator.ValidateWithInput(script, ruleInput, configObj)
		tcResult.ActualPass = jsResult.Valid
		tcResult.ActualReason = jsResult.Reason

		if tc.ExpectPass != jsResult.Valid {
			tcResult.Passed = false
			if tc.ExpectPass {
				tcResult.Error = fmt.Sprintf("expected pass but got: %s", jsResult.Reason)
			} else {
				tcResult.Error = fmt.Sprintf("expected fail but passed")
			}
			result.FailedTestCases++
			result.Valid = false
		} else if tc.ExpectReason != "" && !strings.Contains(jsResult.Reason, tc.ExpectReason) {
			tcResult.Passed = false
			tcResult.Error = fmt.Sprintf("expected reason containing %q but got %q", tc.ExpectReason, jsResult.Reason)
			result.FailedTestCases++
			result.Valid = false
		} else {
			tcResult.Passed = true
		}

		// If expect_budget_amount is set, run validateBudget(input) and compare
		if tc.ExpectBudgetAmount != "" && tcResult.Passed {
			cfg := JSRuleConfig{Script: script}
			minimalRule := &types.Rule{
				ID:         "test",
				Type:       types.RuleTypeEVMJS,
				Config:     mustMarshal(cfg),
				Variables:  mustMarshalStringMap(testVariables),
			}
			budgetResult, err := v.evaluator.EvaluateBudgetWithInput(ctx, minimalRule, ruleInput)
			if err != nil {
				tcResult.Passed = false
				tcResult.Error = fmt.Sprintf("validateBudget: %v", err)
				result.FailedTestCases++
				result.Valid = false
			} else {
				expected := new(big.Int)
				if _, ok := expected.SetString(strings.TrimSpace(tc.ExpectBudgetAmount), 10); !ok {
					tcResult.Passed = false
					tcResult.Error = fmt.Sprintf("invalid expect_budget_amount %q", tc.ExpectBudgetAmount)
					result.FailedTestCases++
					result.Valid = false
				} else if budgetResult.Amount.Cmp(expected) != 0 {
					tcResult.Passed = false
					tcResult.Error = fmt.Sprintf("expect_budget_amount %s but got %s", tc.ExpectBudgetAmount, budgetResult.Amount.String())
					result.FailedTestCases++
					result.Valid = false
				}
			}
		}
		result.TestCaseResults = append(result.TestCaseResults, tcResult)
	}
	return result, nil
}

func mustMarshalStringMap(m map[string]string) []byte {
	if m == nil {
		return []byte("{}")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func mustMarshal(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// MapToRuleInput converts a test case input map (YAML/JSON) to RuleInput.
// Exported for use by validate-rules and other callers that need to run EvaluateBudgetWithInput.
func MapToRuleInput(m map[string]interface{}) (*RuleInput, error) {
	if m == nil {
		return nil, fmt.Errorf("input is nil")
	}
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var out RuleInput
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
