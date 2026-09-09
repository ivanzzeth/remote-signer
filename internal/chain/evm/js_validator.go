package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/validate"
)

// ValidateJSCodeSecurity checks JavaScript code for dangerous patterns.
// Returns nil if code is safe, or SecurityError if dangerous patterns are found.
// Delegates to the shared validate.ValidateJSCodeSecurity and wraps the result.
func ValidateJSCodeSecurity(code string) *SecurityError {
	if err := validate.ValidateJSCodeSecurity(code); err != nil {
		return &SecurityError{
			Pattern: "js_security",
			Message: err.Error(),
		}
	}
	return nil
}

// JSTestCase defines a test case for evm_js rule validation (from YAML test_cases).
type JSTestCase struct {
	Name               string                 `json:"name" yaml:"name"`
	Input              map[string]interface{} `json:"input" yaml:"input"`
	Variables          map[string]string      `json:"variables,omitempty" yaml:"variables,omitempty"`
	ExpectPass         bool                   `json:"expect_pass" yaml:"expect_pass"`
	ExpectReason       string                 `json:"expect_reason,omitempty" yaml:"expect_reason,omitempty"`
	ExpectBudgetAmount string                 `json:"expect_budget_amount,omitempty" yaml:"expect_budget_amount,omitempty"` // when set, validateBudget(input) must return this amount
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

	runResults, allPassed := v.evaluator.RunJSTestCases(script, testCases, VarsEvalContext(testVariables))
	result := &ValidationResult{Valid: allPassed}
	for i, tc := range testCases {
		run := runResults[i]
		tcResult := TestCaseResult{
			Name:           tc.Name,
			ExpectedPass:   tc.ExpectPass,
			ExpectedReason: tc.ExpectReason,
			Passed:         run.Passed,
			ActualPass:     run.ActualPass,
			ActualReason:   run.Reason,
		}
		if !run.Passed {
			tcResult.Error = run.Reason
			result.FailedTestCases++
			result.Valid = false
		}

		// If expect_budget_amount is set, run validateBudget(input) and compare
		if tc.ExpectBudgetAmount != "" && tcResult.Passed {
			chainID := ChainIDFromTestInput(tc.Input)
			vars := VarsEvalContext(testVariables).VarsForChain(chainID)
			subInput, subErr := SubstituteTestCaseInput(tc.Input, vars)
			if subErr != nil {
				tcResult.Passed = false
				tcResult.Error = fmt.Sprintf("substitute input: %v", subErr)
				result.FailedTestCases++
				result.Valid = false
				result.TestCaseResults = append(result.TestCaseResults, tcResult)
				continue
			}
			ruleInput, err := MapToRuleInput(subInput)
			if err != nil {
				tcResult.Passed = false
				tcResult.Error = fmt.Sprintf("invalid input: %v", err)
				result.FailedTestCases++
				result.Valid = false
				result.TestCaseResults = append(result.TestCaseResults, tcResult)
				continue
			}
			cfg := JSRuleConfig{Script: script}
			minimalRule := &types.Rule{
				ID:        "test",
				Type:      types.RuleTypeEVMJS,
				Config:    mustMarshal(cfg),
				Variables: mustMarshalStringMap(testVariables),
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

// MapToRuleInputFromTestCase substitutes template-form input then converts to RuleInput.
func MapToRuleInputFromTestCase(input map[string]interface{}, vars map[string]string) (*RuleInput, error) {
	sub, err := SubstituteTestCaseInput(input, vars)
	if err != nil {
		return nil, err
	}
	return MapToRuleInput(sub)
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
