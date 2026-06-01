// Package evm provides HTTP handlers for EVM signer and rule management API.
// This file validates Solidity and JS rule configurations before persisting them.
package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// validateSolidityRule validates a Solidity expression rule using the validator
func (h *RuleHandler) validateSolidityRule(ctx context.Context, rule *types.Rule) error {
	result, err := h.solidityValidator.ValidateRule(ctx, rule)
	if err != nil {
		return err
	}
	if !result.Valid {
		if result.SyntaxError != nil {
			return fmt.Errorf("syntax error: %s", result.SyntaxError.Message)
		}
		if result.FailedTestCases > 0 {
			return fmt.Errorf("%d test case(s) failed", result.FailedTestCases)
		}
		return fmt.Errorf("validation failed")
	}
	return nil
}

// testCasesFromConfig extracts test_cases from a rule's Config JSON.
func testCasesFromConfig(config []byte) ([]JSRuleTestCase, error) {
	var cfgMap map[string]interface{}
	if err := json.Unmarshal(config, &cfgMap); err != nil {
		return nil, err
	}
	tcRaw, ok := cfgMap["test_cases"]
	if !ok || tcRaw == nil {
		return nil, nil
	}
	tcJSON, err := json.Marshal(tcRaw)
	if err != nil {
		return nil, err
	}
	var cases []JSRuleTestCase
	if err := json.Unmarshal(tcJSON, &cases); err != nil {
		return nil, err
	}
	return cases, nil
}

// validateRule handles POST /api/v1/evm/rules/{id}/validate — runs a single rule's test cases.
func (h *RuleHandler) validateRule(w http.ResponseWriter, r *http.Request, ruleID string) {
	rule, err := h.ruleRepo.Get(r.Context(), types.RuleID(ruleID))
	if err != nil {
		if types.IsNotFound(err) {
			h.writeError(w, "rule not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to get rule", "error", err, "rule_id", ruleID)
		h.writeError(w, "failed to get rule", http.StatusInternalServerError)
		return
	}

	if rule.Type != types.RuleTypeEVMJS {
		h.writeError(w, "validation only supported for evm_js rules", http.StatusBadRequest)
		return
	}

	// Resolve template-form Config so test cases run with concrete variable values.
	effConfig := evmchain.EffectiveConfig(rule)
	testCases, err := testCasesFromConfig(effConfig)
	if err != nil {
		h.writeError(w, fmt.Sprintf("failed to parse test_cases from config: %v", err), http.StatusBadRequest)
		return
	}
	if len(testCases) == 0 {
		h.writeJSON(w, ValidateRuleResponse{
			RuleID:   string(rule.ID),
			RuleName: rule.Name,
			Type:     string(rule.Type),
			Valid:    true,
			Results:  nil,
		}, http.StatusOK)
		return
	}

	results, valid := h.runJSTestCases(rule, effConfig, testCases)
	resp := ValidateRuleResponse{
		RuleID:   string(rule.ID),
		RuleName: rule.Name,
		Type:     string(rule.Type),
		Valid:    valid,
		Results:  results,
	}
	if !valid {
		resp.Error = "one or more test cases failed"
	}
	h.writeJSON(w, resp, http.StatusOK)
}

// runJSTestCases runs test cases against a rule and returns per-case results plus overall validity.
func (h *RuleHandler) runJSTestCases(rule *types.Rule, effConfig []byte, testCases []JSRuleTestCase) ([]ValidateTestResult, bool) {
	if h.jsEvaluator == nil {
		return nil, false
	}

	var cfg evmchain.JSRuleConfig
	if err := json.Unmarshal(effConfig, &cfg); err != nil {
		return nil, false
	}

	results := make([]ValidateTestResult, 0, len(testCases))
	allPassed := true

	for _, tc := range testCases {
		result := ValidateTestResult{Name: tc.Name}
		req, parsed, err := evmchain.TestCaseInputToSignRequest(tc.Input)
		if err != nil {
			result.Passed = false
			result.ActualPass = false
			result.Reason = fmt.Sprintf("invalid input: %v", err)
			allPassed = false
			results = append(results, result)
			continue
		}
		ruleInput, err := evmchain.BuildRuleInput(req, parsed)
		if err != nil {
			result.Passed = false
			result.ActualPass = false
			result.Reason = fmt.Sprintf("build input: %v", err)
			allPassed = false
			results = append(results, result)
			continue
		}

		// The config object must match what the engine builds at runtime: the
		// rule's Variables (+Matrix+chain_id), NOT the stored Config keys. Instance
		// rules keep variable values only in Variables, so resolve here.
		cfgMap := evmchain.RuleConfigObject(rule)
		evalResult := h.jsEvaluator.ValidateWithInput(cfg.Script, ruleInput, cfgMap)

		actualPass := evalResult.Valid
		if rule.Mode == types.RuleModeBlocklist { //nolint:staticcheck
			}

		result.ActualPass = actualPass
		result.Reason = evalResult.Reason

		if actualPass == tc.ExpectPass {
			result.Passed = true
		} else {
			result.Passed = false
			allPassed = false
		}
		results = append(results, result)
	}

	return results, allPassed
}

// validateRules handles POST /api/v1/evm/rules/validate — batch validates all evm_js rules.
// When query param full=true is set, builds a full WhitelistRuleEngine to detect cross-rule interference.
func (h *RuleHandler) validateRules(w http.ResponseWriter, r *http.Request) {
	fullMode := r.URL.Query().Get("full") == "true"

	filter := storage.RuleFilter{
		ChainType:   ptr(types.ChainTypeEVM),
		EnabledOnly: true,
		Limit:       -1,
	}
	allRules, err := h.ruleRepo.List(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list rules for batch validate", "error", err)
		h.writeError(w, "failed to list rules", http.StatusInternalServerError)
		return
	}

	// Filter to evm_js rules only
	var jsRules []*types.Rule
	for _, r := range allRules {
		if r.Type == types.RuleTypeEVMJS {
			jsRules = append(jsRules, r)
		}
	}

	var results []ValidateRuleResponse
	totalPassed := 0
	totalFailed := 0

	if fullMode && h.jsEvaluator != nil {
		// Full engine mode: build a temporary engine with all rules to detect cross-rule interference.
		// Uses the same pattern as buildEngineForRuleTest in the CLI.
		results = h.validateRulesFullEngine(jsRules, allRules)
	} else {
		// Isolated mode: run each rule's test cases independently.
		for _, rule := range jsRules {
			resp := h.validateRuleIsolated(rule)
			results = append(results, resp)
			if resp.Valid {
				totalPassed++
			} else {
				totalFailed++
			}
		}
	}

	h.writeJSON(w, BatchValidateResponse{
		Results: results,
		Total:   len(results),
		Passed:  totalPassed,
		Failed:  totalFailed,
	}, http.StatusOK)
}

// validateRuleIsolated runs a single rule's test cases in isolated mode (no cross-rule interference check).
func (h *RuleHandler) validateRuleIsolated(rule *types.Rule) ValidateRuleResponse {
	resp := ValidateRuleResponse{
		RuleID:   string(rule.ID),
		RuleName: rule.Name,
		Type:     string(rule.Type),
	}

	// Resolve the rule's template-form Config (Variables substituted) so stored
	// test cases — whose inputs use ${var} placeholders like
	// ${first:allowed_safe_addresses} or ${chain_id} — run with concrete values.
	effConfig := evmchain.EffectiveConfig(rule)
	testCases, err := testCasesFromConfig(effConfig)
	if err != nil || len(testCases) == 0 {
		resp.Valid = true
		return resp
	}

	results, valid := h.runJSTestCases(rule, effConfig, testCases)
	resp.Results = results
	resp.Valid = valid
	if !valid {
		resp.Error = "one or more test cases failed"
	}
	return resp
}

// validateRulesFullEngine builds a full WhitelistRuleEngine and runs test cases through it.
// This catches cross-rule interference (e.g., a blocklist rule accidentally blocking a whitelist test).
func (h *RuleHandler) validateRulesFullEngine(jsRules []*types.Rule, allRules []*types.Rule) []ValidateRuleResponse {
	// Build a memory repo with all rules for the test engine
	memRepo := storage.NewMemoryRuleRepository()
	ctx := context.Background()
	for _, r := range allRules {
		if err := memRepo.Create(ctx, r); err != nil {
			h.logger.Warn("validateRulesFullEngine: failed to add rule to test engine repo", "rule_id", r.ID, "error", err)
		}
	}

	engine, err := rule.NewWhitelistRuleEngine(memRepo, h.logger)
	if err != nil {
		results := make([]ValidateRuleResponse, len(jsRules))
		for i, r := range jsRules {
			results[i] = ValidateRuleResponse{
				RuleID:   string(r.ID),
				RuleName: r.Name,
				Type:     string(r.Type),
				Valid:    false,
				Error:    fmt.Sprintf("failed to build test engine: %v", err),
			}
		}
		return results
	}
	engine.RegisterEvaluator(h.jsEvaluator)
	engine.Seal()

	results := make([]ValidateRuleResponse, 0, len(jsRules))
	totalPassed := 0
	totalFailed := 0

	for _, rule := range jsRules {
		resp := ValidateRuleResponse{
			RuleID:   string(rule.ID),
			RuleName: rule.Name,
			Type:     string(rule.Type),
		}

		testCases, tcerr := testCasesFromConfig(evmchain.EffectiveConfig(rule))
		if tcerr != nil || len(testCases) == 0 {
			resp.Valid = true
			results = append(results, resp)
			totalPassed++
			continue
		}

		var allPassed bool
		var tcResults []ValidateTestResult

		for _, tc := range testCases {
			tcr := ValidateTestResult{Name: tc.Name}
			req, parsed, err := evmchain.TestCaseInputToSignRequest(tc.Input)
			if err != nil {
				tcr.Reason = fmt.Sprintf("invalid input: %v", err)
				tcResults = append(tcResults, tcr)
				continue
			}
			// Set API key ID for applied_to scoping
			req.APIKeyID = rule.Owner

			evalResult, evalErr := engine.EvaluateWithResult(ctx, req, parsed)
			if evalErr != nil {
				tcr.Reason = fmt.Sprintf("engine error: %v", evalErr)
				tcResults = append(tcResults, tcr)
				continue
			}

			if rule.Mode == types.RuleModeBlocklist {
				// Blocklist: engine returns Blocked=true when violation detected
				tcr.ActualPass = evalResult.Blocked
				if tc.ExpectPass == evalResult.Blocked {
					tcr.Passed = true
				}
				if evalResult.BlockReason != "" {
					tcr.Reason = evalResult.BlockReason
				}
			} else {
				// Whitelist: engine returns Allowed=true when match found
				tcr.ActualPass = evalResult.Allowed
				if tc.ExpectPass == evalResult.Allowed {
					tcr.Passed = true
				}
				if evalResult.AllowReason != "" {
					tcr.Reason = evalResult.AllowReason
				} else if evalResult.NoMatchReason != "" {
					tcr.Reason = evalResult.NoMatchReason
				}
			}
			tcResults = append(tcResults, tcr)
		}

		resp.Results = tcResults
		allPassed = true
		for _, tcr := range tcResults {
			if !tcr.Passed {
				allPassed = false
				break
			}
		}
		resp.Valid = allPassed
		if !allPassed {
			resp.Error = "one or more test cases failed"
			totalFailed++
		} else {
			totalPassed++
		}
		results = append(results, resp)
	}

	return results
}

// ptr returns a pointer to the given value.
func ptr[T any](v T) *T {
	return &v
}
