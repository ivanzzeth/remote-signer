// Package server provides the daemon entrypoint for `remote-signer server start`.
// server_validate.go contains startup validation for Solidity expression rules
// and message_pattern rules (evm_js validation lives in server_validate_evm.go).
package server

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// validateSolidityRules validates all Solidity expression rules at startup.
// It runs the test cases defined in each rule to ensure they pass.
// If any rule fails validation, the service will not start.
func validateSolidityRules(ctx context.Context, ruleRepo storage.RuleRepository, evaluator *evm.SolidityRuleEvaluator, log *slog.Logger) error {
	// Get all Solidity expression rules
	ruleType := types.RuleTypeEVMSolidityExpression
	rules, err := ruleRepo.List(ctx, storage.RuleFilter{
		Type:        &ruleType,
		EnabledOnly: true,
	})
	if err != nil {
		return fmt.Errorf("failed to list Solidity rules: %w", err)
	}

	if len(rules) == 0 {
		log.Info("No Solidity expression rules to validate")
		return nil
	}

	log.Info("Validating Solidity expression rules", "count", len(rules))
	log.Info("Rule validation may take 1–3 minutes (Forge compiles and runs test cases per batch)")

	// Create validator
	validator, err := evm.NewSolidityRuleValidator(evaluator, log)
	if err != nil {
		return fmt.Errorf("failed to create rule validator: %w", err)
	}

	// Batch validate all rules (automatically groups by mode for optimal performance)
	batchResult, err := validator.ValidateRulesBatch(ctx, rules)
	if err != nil {
		return fmt.Errorf("rule validation failed: %w", err)
	}

	// Report results
	var failedRules []string
	for i, result := range batchResult.Results {
		rule := rules[i]
		if !result.Valid {
			// Collect failure details
			var details string
			if result.SyntaxError != nil {
				details = fmt.Sprintf("syntax error: %s", result.SyntaxError.Message)
			} else if result.FailedTestCases > 0 {
				for _, tc := range result.TestCaseResults {
					if !tc.Passed {
						details = fmt.Sprintf("test case '%s' failed: expected_pass=%v, actual_pass=%v, error=%s",
							tc.Name, tc.ExpectedPass, tc.ActualPass, tc.Error)
						break
					}
				}
			}

			log.Error("Rule validation failed",
				"rule_id", rule.ID,
				"rule_name", rule.Name,
				"details", details,
				"failed_test_cases", result.FailedTestCases,
			)
			failedRules = append(failedRules, fmt.Sprintf("%s (%s): %s", rule.Name, rule.ID, details))
		} else {
			log.Info("Rule validation passed",
				"rule_id", rule.ID,
				"rule_name", rule.Name,
				"test_cases", len(result.TestCaseResults),
			)
		}
	}

	if len(failedRules) > 0 {
		return fmt.Errorf("%d rule(s) failed validation:\n  - %s",
			len(failedRules), strings.Join(failedRules, "\n  - "))
	}

	log.Info("All Solidity expression rules validated successfully", "count", len(rules))
	return nil
}

// validateMessagePatternRulesAtStartup validates all message_pattern rules at startup
// (same as validate-rules: regex compile + test cases). If any fail, startup fails.
func validateMessagePatternRulesAtStartup(ctx context.Context, ruleRepo storage.RuleRepository, log *slog.Logger) error {
	ruleType := types.RuleTypeMessagePattern
	rules, err := ruleRepo.List(ctx, storage.RuleFilter{
		Type:        &ruleType,
		EnabledOnly: true,
	})
	if err != nil {
		return fmt.Errorf("list message_pattern rules: %w", err)
	}
	if len(rules) == 0 {
		log.Info("No message_pattern rules to validate at startup")
		return nil
	}

	msgValidator, err := evm.NewMessagePatternRuleValidator(log)
	if err != nil {
		return fmt.Errorf("create message_pattern validator: %w", err)
	}

	var failed []string
	for _, rule := range rules {
		result, err := msgValidator.ValidateRule(ctx, rule)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s (%s): %v", rule.Name, rule.ID, err))
			continue
		}
		if !result.Valid {
			detail := "invalid config or regex"
			if result.SyntaxError != nil {
				detail = result.SyntaxError.Message
			} else if result.FailedTestCases > 0 {
				for _, tc := range result.TestCaseResults {
					if !tc.Passed {
						detail = fmt.Sprintf("test case %q: %s", tc.Name, tc.Error)
						break
					}
				}
			}
			failed = append(failed, fmt.Sprintf("%s (%s): %s", rule.Name, rule.ID, detail))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d message_pattern rule(s) failed validation:\n  - %s",
			len(failed), strings.Join(failed, "\n  - "))
	}
	log.Info("All message_pattern rules validated at startup", "count", len(rules))
	return nil
}
