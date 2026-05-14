// Package validate implements the `remote-signer validate-rules` CLI command.
// validate_rules.go contains the main rule validation orchestration — loading config,
// building engines, and dispatching to rule-type-specific validation functions.
package validate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/config"
	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
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
			result, p, f := runEVMJSTestCases(ctx, ruleCfg, rule, ruleEngine, fullRepo, hasSolidity, validator, jsEval, templateTestVariables, useFullEngine, log)
			results = append(results, result)
			passed += p
			failed += f

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
