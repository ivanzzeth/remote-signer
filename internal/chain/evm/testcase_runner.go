package evm

import (
	"fmt"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TestCaseEvalContext resolves variables and the JS config object per test chain_id.
type TestCaseEvalContext struct {
	VarsForChain   func(chainID string) map[string]string
	ConfigForChain func(chainID string) map[string]interface{}
}

// VarsEvalContext builds a flat variable map context (template / preset validation).
func VarsEvalContext(vars map[string]string) TestCaseEvalContext {
	return TestCaseEvalContext{
		VarsForChain: func(chainID string) map[string]string {
			out := make(map[string]string, len(vars)+1)
			for k, v := range vars {
				out[k] = v
			}
			if chainID != "" {
				out["chain_id"] = chainID
			}
			return out
		},
		ConfigForChain: func(chainID string) map[string]interface{} {
			v := VarsEvalContext(vars).VarsForChain(chainID)
			cfg := make(map[string]interface{}, len(v))
			for k, val := range v {
				cfg[k] = val
			}
			return cfg
		},
	}
}

// MatrixRuleEvalContext builds per-chain context from an instance rule (Variables + Matrix).
func MatrixRuleEvalContext(rule *types.Rule) TestCaseEvalContext {
	return TestCaseEvalContext{
		VarsForChain: func(chainID string) map[string]string {
			return RuleVarMapForChain(rule, chainID)
		},
		ConfigForChain: func(chainID string) map[string]interface{} {
			return RuleConfigObjectForChain(rule, chainID)
		},
	}
}

// TestCaseRunResult is the outcome of running one JS rule test case.
type TestCaseRunResult struct {
	Name       string
	Passed     bool
	ActualPass bool
	Reason     string
}

// RunJSTestCases executes evm_js test cases with per-test chain_id variable substitution.
// This is the single validation path used by template validate, preset validate/apply,
// and instance rule validate.
func (e *JSRuleEvaluator) RunJSTestCases(script string, cases []JSTestCase, ctx TestCaseEvalContext) ([]TestCaseRunResult, bool) {
	if e == nil {
		return nil, false
	}
	results := make([]TestCaseRunResult, 0, len(cases))
	allPassed := true
	for _, tc := range cases {
		result := TestCaseRunResult{Name: tc.Name}
		chainID := resolveTestChainID(tc.Input, ctx)
		vars := ctx.VarsForChain(chainID)
		subInput, err := SubstituteTestCaseInput(tc.Input, vars)
		if err != nil {
			result.Reason = fmt.Sprintf("substitute input: %v", err)
			allPassed = false
			results = append(results, result)
			continue
		}
		ruleInput, err := ruleInputFromTestCase(subInput)
		if err != nil {
			if strings.Contains(err.Error(), "payload missing") || strings.Contains(err.Error(), "not derivable") {
				result.Reason = fmt.Sprintf("build input: %v", err)
			} else {
				result.Reason = fmt.Sprintf("invalid input: %v", err)
			}
			allPassed = false
			results = append(results, result)
			continue
		}
		chainID = ChainIDFromTestInput(subInput)
		if chainID == "" || strings.Contains(chainID, "${") {
			chainID = vars["chain_id"]
		}
		cfg := ctx.ConfigForChain(chainID)
		if len(tc.Variables) > 0 {
			merged := make(map[string]interface{}, len(cfg)+len(tc.Variables))
			for k, v := range cfg {
				merged[k] = v
			}
			for k, v := range tc.Variables {
				merged[k] = v
			}
			cfg = merged
		}
		evalResult := e.ValidateWithInput(script, ruleInput, cfg)
		result.ActualPass = evalResult.Valid
		result.Reason = evalResult.Reason
		if evalResult.Valid == tc.ExpectPass {
			if tc.ExpectReason != "" && !strings.Contains(evalResult.Reason, tc.ExpectReason) {
				result.Passed = false
				result.Reason = fmt.Sprintf("expected reason containing %q but got %q", tc.ExpectReason, evalResult.Reason)
				allPassed = false
			} else {
				result.Passed = true
			}
		} else {
			result.Passed = false
			if tc.ExpectPass {
				if result.Reason == "" {
					result.Reason = evalResult.Reason
				}
				if result.Reason == "" {
					result.Reason = "expected pass but got fail"
				} else if !strings.HasPrefix(result.Reason, "expected pass") {
					result.Reason = fmt.Sprintf("expected pass but got: %s", result.Reason)
				}
			} else {
				result.Reason = "expected fail but passed"
			}
			allPassed = false
		}
		results = append(results, result)
	}
	return results, allPassed
}

// ruleInputFromTestCase prefers the full sign-request path (instance/API validation)
// and falls back to direct RuleInput mapping for minimal CLI test cases that only
// carry signer/chain_id without transaction or typed_data blobs.
func ruleInputFromTestCase(input map[string]interface{}) (*RuleInput, error) {
	req, parsed, err := TestCaseInputToSignRequest(input)
	if err != nil {
		return nil, err
	}
	ruleInput, err := BuildRuleInput(req, parsed)
	if err == nil {
		return ruleInput, nil
	}
	if canUseMinimalRuleInput(input, err) {
		return MapToRuleInput(input)
	}
	return nil, err
}

func canUseMinimalRuleInput(input map[string]interface{}, buildErr error) bool {
	msg := buildErr.Error()
	if !strings.Contains(msg, "transaction payload missing") &&
		!strings.Contains(msg, "typed_data payload missing") &&
		!strings.Contains(msg, "message missing") {
		return false
	}
	return stringFromMap(input, "signer") != ""
}

func resolveTestChainID(input map[string]interface{}, ctx TestCaseEvalContext) string {
	raw := ChainIDFromTestInput(input)
	if raw != "" && !strings.Contains(raw, "${") {
		return raw
	}
	if v := ctx.VarsForChain("")["chain_id"]; v != "" {
		return v
	}
	return raw
}
