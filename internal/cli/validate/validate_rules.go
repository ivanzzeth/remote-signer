package validate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"path/filepath"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// validateConfig loads config, expands templates and instance/file rules (same as server), then validates.
func validateConfig(ctx context.Context, configPath string, validator *evm.SolidityRuleValidator, msgValidator *evm.MessagePatternRuleValidator, jsValidator *evm.JSRuleValidator, log *slog.Logger, verbose bool) ([]ValidationFileResult, int, int, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("load config: %w", err)
	}
	configDir := filepath.Dir(configPath)

	templates, err := config.ExpandTemplatesFromFiles(cfg.Templates, configDir, log)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("expand templates: %w", err)
	}
	rules, err := config.ExpandInstanceRules(cfg.Rules, templates)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("expand instance rules: %w", err)
	}
	rules, err = config.ExpandFileRules(rules, configDir, log)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("expand file rules: %w", err)
	}
	if err := config.ValidateExplicitRuleIDs(rules); err != nil {
		return nil, 0, 0, fmt.Errorf("rule id validation: %w", err)
	}
	if err := config.ValidateDelegationTargets(rules); err != nil {
		return nil, 0, 0, fmt.Errorf("delegation target validation: %w", err)
	}

	localRules := make([]RuleConfig, 0, len(rules))
	for _, r := range rules {
		// Copy test_cases (from template rules_json), instance variables, and template test_variables for evm_js validation.
		testCases := make([]TestCaseConfig, 0, len(r.TestCases))
		for _, tc := range r.TestCases {
			testCases = append(testCases, TestCaseConfig{
				Name:               tc.Name,
				Input:              tc.Input,
				ExpectPass:         tc.ExpectPass,
				ExpectReason:       tc.ExpectReason,
				ExpectBudgetAmount: tc.ExpectBudgetAmount,
			})
		}
		var testVars map[string]string
		if len(r.TestVariables) > 0 {
			testVars = make(map[string]string, len(r.TestVariables))
			for k, v := range r.TestVariables {
				testVars[k] = v
			}
		}
		localRules = append(localRules, RuleConfig{
			Id: r.Id, Name: r.Name, Description: r.Description, Type: r.Type, Mode: r.Mode,
			ChainType: r.ChainType, ChainID: r.ChainID, APIKeyID: r.APIKeyID, SignerAddress: r.SignerAddress,
			Config: r.Config, Variables: r.Variables, TestVariables: testVars, TestCases: testCases, Enabled: r.Enabled,
		})
	}
	log.Debug("Validating expanded rules from config", "config", configPath, "rules", len(localRules))
	// Validate each rule in isolation (blocklist + rule under test) so template expected-fail cases apply per-rule.
	return validateRules(ctx, localRules, validator, msgValidator, jsValidator, nil, log, verbose, false)
}

// configRuleID returns the deterministic rule ID for a config rule (same formula as internal/config/rule_init.go).
func configRuleID(idx int, name, ruleType string) string {
	data := fmt.Sprintf("config:%d:%s:%s", idx, name, ruleType)
	hash := sha256.Sum256([]byte(data))
	return "cfg_" + hex.EncodeToString(hash[:8])
}

// listConfigRuleIDs loads config, expands rules (templates + instance + file), and prints rule_id and name for each.
// Use this to fill delegate_to in evm_js rules (delegate_to must be the target rule's rule ID).
func listConfigRuleIDs(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	configDir := filepath.Dir(configPath)
	log := slog.Default()

	templates, err := config.ExpandTemplatesFromFiles(cfg.Templates, configDir, log)
	if err != nil {
		return fmt.Errorf("expand templates: %w", err)
	}
	rules, err := config.ExpandInstanceRules(cfg.Rules, templates)
	if err != nil {
		return fmt.Errorf("expand instance rules: %w", err)
	}
	rules, err = config.ExpandFileRules(rules, configDir, log)
	if err != nil {
		return fmt.Errorf("expand file rules: %w", err)
	}

	fmt.Println("# Rule IDs (use as delegate_to in evm_js rules; same order as server)")
	fmt.Println("# Format: rule_id  name  (type); id is custom if set in config, else auto-generated")
	for i, r := range rules {
		effectiveID := strings.TrimSpace(r.Id)
		if effectiveID == "" {
			effectiveID = configRuleID(i, r.Name, r.Type)
		}
		fmt.Printf("%s  %s  (%s)\n", effectiveID, r.Name, r.Type)
	}
	return nil
}

func effectiveRuleID(idx int, cfg RuleConfig) string {
	if s := strings.TrimSpace(cfg.Id); s != "" {
		return s
	}
	return configRuleID(idx, cfg.Name, cfg.Type)
}

// validateRules validates a list of rules. When useFullEngine is true (config instances),
// evm_js test cases run through the full engine with ALL rules to verify combined behavior.
// When useFullEngine is false (template files), each evm_js rule uses an isolated engine
// (blocklist + rule under test only) so other rules don't interfere with template test cases.
func validateRules(ctx context.Context, rules []RuleConfig, validator *evm.SolidityRuleValidator, msgValidator *evm.MessagePatternRuleValidator, jsValidator *evm.JSRuleValidator, templateTestVariables map[string]string, log *slog.Logger, verbose bool, useFullEngine bool) ([]ValidationFileResult, int, int, error) {
	var results []ValidationFileResult
	passed := 0
	failed := 0

	// Build in-memory repo and engine for evm_js when any evm_js rule exists (same path as production: all rule types, delegation + scope).
	var ruleEngine *rule.WhitelistRuleEngine
	hasEVMJS := false
	hasSolidity := false
	for _, c := range rules {
		if c.Type == string(types.RuleTypeEVMJS) && c.Enabled {
			hasEVMJS = true
		}
		if c.Type == string(types.RuleTypeEVMSolidityExpression) && c.Enabled {
			hasSolidity = true
		}
		if hasEVMJS && hasSolidity {
			break
		}
	}
	var fullRepo *storage.MemoryRuleRepository
	var jsEval *evm.JSRuleEvaluator
	if hasEVMJS {
		fullRepo = storage.NewMemoryRuleRepository()
		for i, ruleCfg := range rules {
			if !ruleCfg.Enabled {
				continue
			}
			r, err := configToRuleWithID(i, ruleCfg)
			if err != nil {
				continue
			}
			// So JS script sees config.* (allowed_safe_addresses, etc.) same as production.
			// Prefer template test_variables (from expanded rule) so expected-fail cases validate correctly.
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
					return nil, 0, 0, fmt.Errorf("marshal rule variables: %w", err)
				}
				r.Variables = varsJSON
			}
			if err := fullRepo.Create(ctx, r); err != nil {
				log.Debug("validator repo create skip (duplicate id)", "id", r.ID, "error", err)
			}
		}
		var err error
		ruleEngine, err = rule.NewWhitelistRuleEngine(fullRepo, log, rule.WithDelegationPayloadConverter(evm.DelegatePayloadToSignRequest))
		if err != nil {
			return nil, 0, 0, fmt.Errorf("evm_js engine init: %w", err)
		}
		ruleEngine.RegisterEvaluator(&evm.AddressListEvaluator{})
		ruleEngine.RegisterEvaluator(&evm.ContractMethodEvaluator{})
		ruleEngine.RegisterEvaluator(&evm.ValueLimitEvaluator{})
		ruleEngine.RegisterEvaluator(&evm.SignerRestrictionEvaluator{})
		ruleEngine.RegisterEvaluator(&evm.SignTypeRestrictionEvaluator{})
		ruleEngine.RegisterEvaluator(&evm.MessagePatternEvaluator{})
		// Internal transfer evaluator: nil repo for validation-only mode
		internalTransferEval, err := evm.NewInternalTransferEvaluator(nil)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("internal transfer evaluator: %w", err)
		}
		ruleEngine.RegisterEvaluator(internalTransferEval)
		if hasSolidity && validator != nil {
			if solidityEval := validator.Evaluator(); solidityEval != nil {
				ruleEngine.RegisterEvaluator(solidityEval)
			}
		}
		jsEval, err = evm.NewJSRuleEvaluator(log)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("evm_js evaluator: %w", err)
		}
		ruleEngine.RegisterEvaluator(jsEval)
	}

	// Collect Solidity expression rules for batch validation
	var rulesToValidate []*types.Rule
	for i, ruleCfg := range rules {
		result := ValidationFileResult{
			RuleName: ruleCfg.Name,
			RuleType: ruleCfg.Type,
		}

		// Skip disabled rules
		if !ruleCfg.Enabled {
			result.Skipped = true
			result.SkipReason = "rule is disabled"
			result.Valid = true
			results = append(results, result)
			passed++
			continue
		}

		switch ruleCfg.Type {
		case string(types.RuleTypeEVMSolidityExpression):
			// Solidity expression rules → collect for batch validation
			rule, err := configToRule(i, ruleCfg)
			if err != nil {
				result.Valid = false
				result.Error = fmt.Sprintf("failed to convert rule: %v", err)
				results = append(results, result)
				failed++
				continue
			}
			rulesToValidate = append(rulesToValidate, rule)

		case string(types.RuleTypeMessagePattern):
			// Message pattern rules → validate with MessagePatternRuleValidator
			rule, err := configToRule(i, ruleCfg)
			if err != nil {
				result.Valid = false
				result.Error = fmt.Sprintf("failed to convert rule: %v", err)
				results = append(results, result)
				failed++
				continue
			}
			vResult, err := msgValidator.ValidateRule(ctx, rule)
			if err != nil {
				result.Valid = false
				result.Error = fmt.Sprintf("validation error: %v", err)
				results = append(results, result)
				failed++
				continue
			}
			result.Valid = vResult.Valid
			result.SyntaxError = vResult.SyntaxError
			result.TestCaseResults = vResult.TestCaseResults
			result.FailedTestCases = vResult.FailedTestCases
			results = append(results, result)
			if result.Valid {
				passed++
			} else {
				failed++
			}

		case string(types.RuleTypeEVMJS):
			rule, err := configToRuleWithID(i, ruleCfg)
			if err != nil {
				result.Valid = false
				result.Error = fmt.Sprintf("failed to convert rule: %v", err)
				results = append(results, result)
				failed++
				continue
			}
			validationErr := validateDeclarativeRule(rule)
			if validationErr != nil {
				result.Valid = false
				result.Error = validationErr.Error()
				results = append(results, result)
				failed++
				continue
			}
			// evm_js must have test_cases and be validated through the full engine (same as production).
			if len(ruleCfg.TestCases) < 2 {
				result.Valid = false
				result.Error = fmt.Sprintf("evm_js rules require at least 2 test cases (got %d): need at least one positive and one negative", len(ruleCfg.TestCases))
				results = append(results, result)
				failed++
				continue
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
				results = append(results, result)
				failed++
				continue
			}
			if ruleEngine == nil {
				result.Valid = false
				result.Error = "evm_js engine not initialized"
				results = append(results, result)
				failed++
				continue
			}
			// Set Variables on rule so JS script sees config.* (same as in full repo). Prefer TestVariables for validation.
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
					results = append(results, result)
					failed++
					continue
				}
				rule.Variables = varsJSON
			}
			// When using template test_variables, override rule scope (ChainID)
			// so the rule matches the test case's chain_id (test_cases use
			// test_variables values, not the instance's actual chain_id).
			// This mirrors the same logic in cmd/remote-signer/main.go startup validation.
			if len(ruleCfg.TestVariables) > 0 {
				if v, ok := ruleCfg.TestVariables["chain_id"]; ok && v != "" {
					chainIDVal := v
					rule.ChainID = &chainIDVal
				}
			}
			// Template files: isolated engine (blocklist + rule under test only) so other rules don't interfere.
			// Config instances: full engine (all rules) to validate combined behavior in production context.
			// When using the full engine, if another whitelist rule allows a request that this rule's
			// negative test case expects to reject, the mismatch surfaces as a test failure.
			testEngine := ruleEngine // default: full engine (all rules)
			if !useFullEngine {
				var buildErr error
				testEngine, buildErr = buildEngineForRuleTest(ctx, fullRepo, rule, hasSolidity, validator, log)
				if buildErr != nil {
					result.Valid = false
					result.Error = fmt.Sprintf("build test engine: %v", buildErr)
					results = append(results, result)
					failed++
					continue
				}
			} else {
				log.Debug("Using full engine for rule test", "rule", ruleCfg.Name)
			}
			result.Valid = true // pass unless a test case fails
			// Run each test case through the test engine (blocklist + this rule only).
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
				// Substitute ${var} in test input: prefer per-rule TestVariables (template test_variables) for validation.
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
					subst, err := substituteVarsInString(string(jsonBytes), varsForSubst)
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
				// For blocklist rules, "pass" means "not blocked"; for whitelist, "pass" means "allowed".
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
					// In a multi-rule full engine, the NoMatchReason for whitelist rules depends on
					// evaluation order and may come from a different rule. Only enforce expect_reason
					// when the result is blocked/allowed or when using isolated (non-full) engine.
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
				passed++
			} else {
				failed++
			}
			results = append(results, result)

		case string(types.RuleTypeEVMAddressList), "evm_address_whitelist",
			string(types.RuleTypeEVMContractMethod),
			string(types.RuleTypeEVMValueLimit),
			string(types.RuleTypeSignerRestriction),
			string(types.RuleTypeSignTypeRestriction),
			string(types.RuleTypeChainRestriction),
			string(types.RuleTypeEVMDynamicBlocklist):
			// Declarative rules → JSON deserialization + basic validation
			rule, err := configToRule(i, ruleCfg)
			if err != nil {
				result.Valid = false
				result.Error = fmt.Sprintf("failed to convert rule: %v", err)
				results = append(results, result)
				failed++
				continue
			}
			validationErr := validateDeclarativeRule(rule)
			if validationErr != nil {
				result.Valid = false
				result.Error = validationErr.Error()
				results = append(results, result)
				failed++
			} else {
				result.Valid = true
				results = append(results, result)
				passed++
			}

		default:
			// Unknown rule type → error (not skip!)
			result.Valid = false
			result.Error = fmt.Sprintf("unknown rule type: %s", ruleCfg.Type)
			results = append(results, result)
			failed++
		}
	}

	// Batch validate all rules in the file (automatically groups by mode)
	if len(rulesToValidate) > 0 {
		batchResults, err := validator.ValidateRulesBatch(ctx, rulesToValidate)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("batch validation failed: %w", err)
		}

		for idx, validationResult := range batchResults.Results {
			rule := rulesToValidate[idx]
			result := ValidationFileResult{
				RuleName:        rule.Name,
				RuleType:        string(rule.Type),
				Valid:           validationResult.Valid,
				SyntaxError:     validationResult.SyntaxError,
				TestCaseResults: validationResult.TestCaseResults,
				FailedTestCases: validationResult.FailedTestCases,
			}
			if result.Valid {
				passed++
			} else {
				failed++
			}
			results = append(results, result)
		}
	}

	return results, passed, failed, nil
}
