// Package validate implements the `remote-signer validate-rules` CLI command.
// validate_rules_evmjs.go handles evm_js rule test case execution — building the
// per-rule engine, running test cases through it, and checking budget expectations.
package validate

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/service"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// runEVMJSTestCases validates a single evm_js rule by running its test cases
// through the rule engine (full or isolated depending on useFullEngine).
func runEVMJSTestCases(
	ctx context.Context,
	ruleCfg RuleConfig,
	rule *types.Rule,
	ruleEngine *rule.WhitelistRuleEngine,
	fullRepo *storage.MemoryRuleRepository,
	hasSolidity bool,
	validator *evm.SolidityRuleValidator,
	jsEval *evm.JSRuleEvaluator,
	templateTestVariables map[string]string,
	useFullEngine bool,
	log *slog.Logger,
) (ValidationFileResult, int, int) {
	result := ValidationFileResult{
		RuleName: ruleCfg.Name,
		RuleType: ruleCfg.Type,
	}

	validationErr := validateDeclarativeRule(rule)
	if validationErr != nil {
		result.Valid = false
		result.Error = validationErr.Error()
		return result, 0, 1
	}

	if len(ruleCfg.TestCases) < 2 {
		result.Valid = false
		result.Error = fmt.Sprintf("evm_js rules require at least 2 test cases (got %d): need at least one positive and one negative", len(ruleCfg.TestCases))
		return result, 0, 1
	}
	var pos, neg int
	for _, tc := range ruleCfg.TestCases {
		if tc.ExpectPass {
			pos++
		} else {
			neg++
		}
	}
	if err := ruleconfig.ValidateJSRuleTestCasesRequirement(pos, neg); err != nil {
		result.Valid = false
		result.Error = err.Error()
		return result, 0, 1
	}
	if ruleEngine == nil {
		result.Valid = false
		result.Error = "evm_js engine not initialized"
		return result, 0, 1
	}

	// Set Variables on rule so JS script sees config.* Prefer TestVariables for validation.
	var varsToSeed map[string]interface{}
	if len(ruleCfg.TestVariables) > 0 {
		varsToSeed = make(map[string]interface{}, len(ruleCfg.TestVariables))
		for k, v := range ruleCfg.TestVariables {
			varsToSeed[k] = v
		}
	} else if len(ruleCfg.Variables) > 0 {
		varsToSeed = ruleCfg.Variables
	} else if len(templateTestVariables) > 0 {
		varsToSeed = make(map[string]interface{}, len(templateTestVariables))
		for k, v := range templateTestVariables {
			varsToSeed[k] = v
		}
	}
	if len(varsToSeed) > 0 {
		varsJSON, err := json.Marshal(varsToSeed)
		if err != nil {
			result.Valid = false
			result.Error = fmt.Sprintf("marshal rule variables: %v", err)
			return result, 0, 1
		}
		rule.Variables = varsJSON
	}
	if len(ruleCfg.TestVariables) > 0 {
		if v, ok := ruleCfg.TestVariables["chain_id"]; ok && v != "" {
			chainIDVal := v
			rule.ChainID = &chainIDVal
		}
	}

	testEngine := ruleEngine // default: full engine
	if !useFullEngine {
		var buildErr error
		testEngine, buildErr = buildEngineForRuleTest(ctx, fullRepo, rule, hasSolidity, validator, log)
		if buildErr != nil {
			result.Valid = false
			result.Error = fmt.Sprintf("build test engine: %v", buildErr)
			return result, 0, 1
		}
	}

	result.Valid = true // pass unless a test case fails
	for _, tc := range ruleCfg.TestCases {
		tcResult := evm.TestCaseResult{
			Name:           tc.Name,
			ExpectedPass:   tc.ExpectPass,
			ExpectedReason: tc.ExpectReason,
		}
		inputCopy := make(map[string]interface{})
		for k, v := range tc.Input {
			inputCopy[k] = v
		}
		var varsForSubst map[string]string
		if len(ruleCfg.TestVariables) > 0 {
			varsForSubst = ruleCfg.TestVariables
		} else if len(ruleCfg.Variables) > 0 {
			varsForSubst = interfaceMapToStringMap(ruleCfg.Variables)
		} else {
			varsForSubst = templateTestVariables
		}
		if len(varsForSubst) > 0 {
			jsonBytes, _ := json.Marshal(inputCopy)
			subst, err := service.SubstituteString(string(jsonBytes), varsForSubst)
			if err != nil {
				tcResult.Passed = false
				tcResult.Error = fmt.Sprintf("variable substitution: %v", err)
				result.TestCaseResults = append(result.TestCaseResults, tcResult)
				result.FailedTestCases++
				result.Valid = false
				continue
			}
			if err := json.Unmarshal([]byte(subst), &inputCopy); err != nil {
				tcResult.Passed = false
				tcResult.Error = fmt.Sprintf("substituted input invalid: %v", err)
				result.TestCaseResults = append(result.TestCaseResults, tcResult)
				result.FailedTestCases++
				result.Valid = false
				continue
			}
		}
		req, parsed, err := evm.TestCaseInputToSignRequest(inputCopy)
		if err != nil {
			tcResult.Passed = false
			tcResult.Error = fmt.Sprintf("build request: %v", err)
			result.TestCaseResults = append(result.TestCaseResults, tcResult)
			result.FailedTestCases++
			result.Valid = false
			continue
		}
		evalResult, err := testEngine.EvaluateWithResult(ctx, req, parsed)
		if err != nil {
			tcResult.Passed = false
			tcResult.Error = fmt.Sprintf("engine: %v", err)
			result.TestCaseResults = append(result.TestCaseResults, tcResult)
			result.FailedTestCases++
			result.Valid = false
			continue
		}
		if rule.Mode == types.RuleModeBlocklist {
			tcResult.ActualPass = !evalResult.Blocked
		} else {
			tcResult.ActualPass = evalResult.Allowed
		}
		if evalResult.Allowed {
			tcResult.ActualReason = evalResult.AllowReason
		} else if evalResult.Blocked {
			tcResult.ActualReason = evalResult.BlockReason
		} else {
			tcResult.ActualReason = evalResult.NoMatchReason
		}
		if tcResult.ExpectedPass != tcResult.ActualPass {
			tcResult.Passed = false
			if tcResult.ExpectedPass {
				tcResult.Error = fmt.Sprintf("expected pass but got: %s", tcResult.ActualReason)
			} else {
				tcResult.Error = "expected fail but passed"
			}
			result.FailedTestCases++
			result.Valid = false
		} else if tc.ExpectReason != "" && !strings.Contains(tcResult.ActualReason, tc.ExpectReason) {
			isNoMatch := !evalResult.Blocked && !evalResult.Allowed
			isWhitelistRule := rule.Mode != types.RuleModeBlocklist
			if useFullEngine && isNoMatch && isWhitelistRule {
				tcResult.Passed = true
			} else {
				tcResult.Passed = false
				tcResult.Error = fmt.Sprintf("expected reason containing %q but got %q", tc.ExpectReason, tcResult.ActualReason)
				result.FailedTestCases++
				result.Valid = false
			}
		} else {
			tcResult.Passed = true
		}
		// If expect_budget_amount is set, assert validateBudget(input) return value
		if tcResult.Passed && tc.ExpectBudgetAmount != "" && jsEval != nil {
			ruleInput, err := evm.MapToRuleInput(inputCopy)
			if err != nil {
				tcResult.Passed = false
				tcResult.Error = fmt.Sprintf("budget input: %v", err)
				result.FailedTestCases++
				result.Valid = false
			} else {
				budgetResult, err := jsEval.EvaluateBudgetWithInput(ctx, rule, ruleInput)
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
		}
		result.TestCaseResults = append(result.TestCaseResults, tcResult)
	}

	if result.Valid {
		return result, 1, 0
	}
	return result, 0, 1
}
