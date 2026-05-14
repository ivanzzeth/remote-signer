package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	evmchain "github.com/ivanzzeth/remote-signer/internal/chain/evm"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/ruleconfig"
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

// validateJSRule validates an evm_js rule by running its test cases through the JS evaluator.
// Requires at least 1 positive and 1 negative test case. Runs each test case in isolated mode.
func (h *RuleHandler) validateJSRule(rule *types.Rule, testCases []JSRuleTestCase) error {
	if h.jsEvaluator == nil {
		return fmt.Errorf("JS evaluator not available")
	}

	// Enforce test case requirement
	var pos, neg int
	for _, tc := range testCases {
		if tc.ExpectPass {
			pos++
		} else {
			neg++
		}
	}
	if err := ruleconfig.ValidateJSRuleTestCasesRequirement(pos, neg); err != nil {
		return err
	}

	// Parse the rule config
	var cfg evmchain.JSRuleConfig
	if err := json.Unmarshal(rule.Config, &cfg); err != nil {
		return fmt.Errorf("invalid evm_js config: %w", err)
	}

	// Run each test case
	var failed []string
	for _, tc := range testCases {
		if tc.Name == "" {
			return fmt.Errorf("test case name is required")
		}
		req, parsed, err := evmchain.TestCaseInputToSignRequest(tc.Input)
		if err != nil {
			failed = append(failed, fmt.Sprintf("test %q: invalid input: %v", tc.Name, err))
			continue
		}
		ruleInput, err := evmchain.BuildRuleInput(req, parsed)
		if err != nil {
			failed = append(failed, fmt.Sprintf("test %q: build input: %v", tc.Name, err))
			continue
		}
		// Build config map from the rule's raw JSON config so user-defined keys (e.g. max_message_length)
		// are available to the JS script via the global `config` object.
		var cfgMap map[string]interface{}
		if len(rule.Config) > 0 {
			if err := json.Unmarshal(rule.Config, &cfgMap); err != nil {
				return fmt.Errorf("failed to unmarshal rule config for JS validation: %w", err)
			}
		}
		result := h.jsEvaluator.ValidateWithInput(cfg.Script, ruleInput, cfgMap)

		// For isolated validation: valid=true means pass, valid=false means fail
		actualPass := result.Valid
		if rule.Mode == types.RuleModeBlocklist {
			// Blocklist: script returns valid=false when "violation detected" (should block).
			// A blocklist test case with expect_pass=true means "should NOT be blocked" → valid=true.
			// expect_pass=false means "should be blocked" → valid=false.
			// So actualPass matches result.Valid directly.
		}

		if actualPass != tc.ExpectPass {
			if tc.ExpectPass {
				failed = append(failed, fmt.Sprintf("test %q: expected pass but got: %s", tc.Name, result.Reason))
			} else {
				failed = append(failed, fmt.Sprintf("test %q: expected fail but passed", tc.Name))
			}
			continue
		}

		// Optionally check expect_reason
		if tc.ExpectReason != "" && !tc.ExpectPass {
			if !strings.Contains(result.Reason, tc.ExpectReason) {
				failed = append(failed, fmt.Sprintf("test %q: expected reason containing %q but got %q", tc.Name, tc.ExpectReason, result.Reason))
			}
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("%d test case(s) failed:\n  - %s", len(failed), strings.Join(failed, "\n  - "))
	}
	return nil
}
