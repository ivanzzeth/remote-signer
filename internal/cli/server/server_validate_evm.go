// Package server — server_validate_evm.go validates evm_js rules at startup
// using the same engine path as production (see docs/SECURITY_AUDIT_REPORT.md S4).
// It also builds isolated engines (blocklist + single rule) for expected-fail tests.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// validateEVMJSRulesAtStartup runs evm_js test cases through the same engine path as production
// (see docs/SECURITY_AUDIT_REPORT.md S4). expandedRules must be the same list passed to SyncFromConfig
// so rule IDs and test_cases match. If any test case fails, startup fails.
func validateEVMJSRulesAtStartup(ctx context.Context, expandedRules []config.RuleConfig, ruleRepo storage.RuleRepository, solidityEval *evm.SolidityRuleEvaluator, log *slog.Logger) error {
	var toValidate []struct {
		idx  int
		cfg  config.RuleConfig
		rule *types.Rule
	}
	for i := range expandedRules {
		cfg := &expandedRules[i]
		if cfg.Type != string(types.RuleTypeEVMJS) || !cfg.Enabled {
			continue
		}
		// Fail explicitly (same as validate-rules) when test_cases are missing or insufficient.
		var pos, neg int
		for _, tc := range cfg.TestCases {
			if tc.ExpectPass {
				pos++
			} else {
				neg++
			}
		}
		if err := ruleconfig.ValidateJSRuleTestCasesRequirement(pos, neg); err != nil {
			return fmt.Errorf("rule %q: %w", cfg.Name, err)
		}
		ruleID := config.EffectiveRuleID(i, *cfg)
		rule, err := ruleRepo.Get(ctx, ruleID)
		if err != nil {
			if types.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("get rule %s: %w", ruleID, err)
		}
		toValidate = append(toValidate, struct {
			idx  int
			cfg  config.RuleConfig
			rule *types.Rule
		}{i, *cfg, rule})
	}
	if len(toValidate) == 0 {
		log.Info("No evm_js rules with test_cases to validate at startup")
		return nil
	}

	// List all rules once for building isolated engines (blocklist + delegation targets).
	const listLimit = 10000
	allRules, err := ruleRepo.List(ctx, storage.RuleFilter{EnabledOnly: false, Limit: listLimit})
	if err != nil {
		return fmt.Errorf("list rules for validation: %w", err)
	}
	allRulesMap := make(map[types.RuleID]*types.Rule, len(allRules))
	for _, r := range allRules {
		allRulesMap[r.ID] = r
	}

	jsEval, err := evm.NewJSRuleEvaluator(log)
	if err != nil {
		return fmt.Errorf("js evaluator for validation: %w", err)
	}

	var failed []string
	for _, item := range toValidate {
		cfg := item.cfg
		ruleFromDB := item.rule

		// Use template test_variables for validation so expected-fail cases (e.g. allowed_recipients set) run correctly.
		var varsToSeed map[string]interface{}
		if len(cfg.TestVariables) > 0 {
			varsToSeed = make(map[string]interface{}, len(cfg.TestVariables))
			for k, v := range cfg.TestVariables {
				varsToSeed[k] = v
			}
		} else if len(cfg.Variables) > 0 {
			varsToSeed = cfg.Variables
		}
		ruleForTest := *ruleFromDB
		ruleForTest.Variables = nil
		if len(varsToSeed) > 0 {
			variablesJSON, err := json.Marshal(varsToSeed)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s: marshal test variables: %v", cfg.Name, err))
				continue
			}
			ruleForTest.Variables = variablesJSON
		}
		// When using template test_variables, set rule scope (ChainID, etc.) from them so the rule
		// matches the test case's chain_id and validation passes (e.g. test uses chain_id 1).
		if len(cfg.TestVariables) > 0 {
			if v, ok := cfg.TestVariables["chain_id"]; ok && v != "" {
				chainIDVal := v
				ruleForTest.ChainID = &chainIDVal
			}
		}

		// Build isolated engine (blocklist + this rule only) so expected-fail cases are not allowed by another whitelist rule.
		testEngine, err := buildIsolatedEngineForRule(ctx, allRulesMap, &ruleForTest, solidityEval, log)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: build isolated engine: %v", cfg.Name, err))
			continue
		}
		testEngine.RegisterEvaluator(jsEval)

		varsForSubst := make(map[string]string)
		if len(cfg.TestVariables) > 0 {
			for k, v := range cfg.TestVariables {
				varsForSubst[k] = v
			}
		} else {
			for k, v := range cfg.Variables {
				if v == nil {
					varsForSubst[k] = ""
				} else {
					varsForSubst[k] = fmt.Sprintf("%v", v)
				}
			}
		}
		for _, tc := range cfg.TestCases {
			inputCopy := make(map[string]interface{})
			for k, v := range tc.Input {
				inputCopy[k] = v
			}
			if len(varsForSubst) > 0 {
				jsonBytes, _ := json.Marshal(inputCopy)
				s := string(jsonBytes)
				for k, v := range varsForSubst {
					s = strings.ReplaceAll(s, "${"+k+"}", v)
				}
				if err := json.Unmarshal([]byte(s), &inputCopy); err != nil {
					failed = append(failed, fmt.Sprintf("%s test %q: variable substitution: %v", cfg.Name, tc.Name, err))
					continue
				}
			}
			req, parsed, err := evm.TestCaseInputToSignRequest(inputCopy)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s test %q: build request: %v", cfg.Name, tc.Name, err))
				continue
			}
			evalResult, err := testEngine.EvaluateWithResult(ctx, req, parsed)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s test %q: %v", cfg.Name, tc.Name, err))
				continue
			}
			// For blocklist rules, "pass" means "not blocked"; for whitelist, "pass" means "allowed".
			var actualPass bool
			if ruleFromDB.Mode == types.RuleModeBlocklist {
				actualPass = !evalResult.Blocked
			} else {
				actualPass = evalResult.Allowed
			}
			var actualReason string
			if evalResult.Allowed {
				actualReason = evalResult.AllowReason
			} else if evalResult.Blocked {
				actualReason = evalResult.BlockReason
			} else {
				actualReason = evalResult.NoMatchReason
			}
			if actualPass != tc.ExpectPass {
				if tc.ExpectPass {
					failed = append(failed, fmt.Sprintf("%s test %q: expected pass but got: %s", cfg.Name, tc.Name, actualReason))
				} else {
					failed = append(failed, fmt.Sprintf("%s test %q: expected fail but passed (reason: %s)", cfg.Name, tc.Name, actualReason))
				}
				continue
			}
			if tc.ExpectReason != "" && !strings.Contains(actualReason, tc.ExpectReason) {
				// In isolated engine we only have this rule (+ blocklist), so reason comes from this rule.
				isNoMatch := !evalResult.Blocked && !evalResult.Allowed
				isWhitelistRule := ruleFromDB.Mode != types.RuleModeBlocklist
				if !(isNoMatch && isWhitelistRule) {
					failed = append(failed, fmt.Sprintf("%s test %q: expected reason containing %q but got %q", cfg.Name, tc.Name, tc.ExpectReason, actualReason))
				}
			}
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d evm_js test case(s) failed:\n  - %s", len(failed), strings.Join(failed, "\n  - "))
	}
	log.Info("All evm_js rules validated at startup", "rules", len(toValidate))
	return nil
}

// buildIsolatedEngineForRule builds an engine containing only blocklist rules plus the given rule
// (and its delegation targets). Used so evm_js expected-fail test cases are not allowed by another whitelist rule.
func buildIsolatedEngineForRule(ctx context.Context, allRulesMap map[types.RuleID]*types.Rule, ruleUnderTest *types.Rule, solidityEval *evm.SolidityRuleEvaluator, log *slog.Logger) (*rule.WhitelistRuleEngine, error) {
	minimalRepo := storage.NewMemoryRuleRepository()
	for _, r := range allRulesMap {
		if r.Mode == types.RuleModeBlocklist {
			// Skip evm_dynamic_blocklist — its evaluator depends on runtime DynamicBlocklist
			// which is not available during startup validation. Including it would cause
			// "no evaluator registered" errors in the isolated engine.
			if r.Type == types.RuleTypeEVMDynamicBlocklist {
				continue
			}
			if err := minimalRepo.Create(ctx, r); err != nil {
				return nil, fmt.Errorf("add blocklist rule %s: %w", r.ID, err)
			}
		}
	}
	if ruleUnderTest.Mode != types.RuleModeBlocklist {
		if err := minimalRepo.Create(ctx, ruleUnderTest); err != nil {
			return nil, fmt.Errorf("add rule under test %s: %w", ruleUnderTest.ID, err)
		}
	}
	if err := addDelegationTargetsForValidation(ctx, ruleUnderTest, allRulesMap, minimalRepo, make(map[types.RuleID]bool), log); err != nil {
		return nil, err
	}
	eng, err := rule.NewWhitelistRuleEngine(minimalRepo, log, rule.WithDelegationPayloadConverter(evm.DelegatePayloadToSignRequest))
	if err != nil {
		return nil, err
	}
	eng.RegisterEvaluator(&evm.AddressListEvaluator{})
	eng.RegisterEvaluator(&evm.ContractMethodEvaluator{})
	eng.RegisterEvaluator(&evm.ValueLimitEvaluator{})
	eng.RegisterEvaluator(&evm.SignerRestrictionEvaluator{})
	eng.RegisterEvaluator(&evm.SignTypeRestrictionEvaluator{})
	eng.RegisterEvaluator(&evm.MessagePatternEvaluator{})
	// Internal transfer evaluator: nil repo for validation-only mode
	internalTransferEval, err := evm.NewInternalTransferEvaluator(nil)
	if err != nil {
		return nil, err
	}
	eng.RegisterEvaluator(internalTransferEval)
	if solidityEval != nil {
		eng.RegisterEvaluator(solidityEval)
	}
	return eng, nil
}

// addDelegationTargetsForValidation recursively adds delegation target rules to the minimal repo
// with Enabled=false so they are reachable via Get() but not included in List(EnabledOnly=true).
func addDelegationTargetsForValidation(ctx context.Context, r *types.Rule, allRulesMap map[types.RuleID]*types.Rule, minimalRepo *storage.MemoryRuleRepository, visited map[types.RuleID]bool, log *slog.Logger) error {
	if visited[r.ID] {
		return nil
	}
	visited[r.ID] = true
	var cfg struct {
		DelegateTo string `json:"delegate_to"`
	}
	if err := json.Unmarshal(r.Config, &cfg); err != nil {
		return fmt.Errorf("unmarshal config for rule %q: %w", r.ID, err)
	}
	if cfg.DelegateTo == "" {
		return nil
	}
	for _, part := range strings.Split(cfg.DelegateTo, ",") {
		targetID := types.RuleID(strings.TrimSpace(part))
		if targetID == "" {
			continue
		}
		target, ok := allRulesMap[targetID]
		if !ok {
			return fmt.Errorf("rule %q delegate_to references non-existent target %q", r.ID, targetID)
		}
		clone := *target
		clone.Enabled = false
		if err := minimalRepo.Create(ctx, &clone); err != nil {
			log.Debug("delegation target already in minimal repo", "target", targetID)
		}
		if err := addDelegationTargetsForValidation(ctx, target, allRulesMap, minimalRepo, visited, log); err != nil {
			return err
		}
	}
	return nil
}
