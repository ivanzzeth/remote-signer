package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// MessagePatternRuleValidator validates message_pattern rules
type MessagePatternRuleValidator struct {
	evaluator *MessagePatternEvaluator
	logger    *slog.Logger
}

// NewMessagePatternRuleValidator creates a new message pattern rule validator
func NewMessagePatternRuleValidator(logger *slog.Logger) (*MessagePatternRuleValidator, error) {
	eval, err := NewMessagePatternEvaluator()
	if err != nil {
		return nil, err
	}
	return &MessagePatternRuleValidator{evaluator: eval, logger: logger}, nil
}

// ValidateRule validates a single message_pattern rule
func (v *MessagePatternRuleValidator) ValidateRule(ctx context.Context, rule *types.Rule) (*ValidationResult, error) {
	// 1. Parse config
	var config MessagePatternConfig
	if err := json.Unmarshal(rule.Config, &config); err != nil {
		return &ValidationResult{
			Valid:       false,
			SyntaxError: &SyntaxError{Message: fmt.Sprintf("invalid config: %v", err), Severity: "error"},
		}, nil
	}

	// 2. Validate regex patterns compile
	allPatterns := make([]string, 0, len(config.Patterns)+1)
	if config.Pattern != "" {
		allPatterns = append(allPatterns, config.Pattern)
	}
	allPatterns = append(allPatterns, config.Patterns...)
	if len(allPatterns) == 0 {
		return &ValidationResult{
			Valid:       false,
			SyntaxError: &SyntaxError{Message: "no patterns configured", Severity: "error"},
		}, nil
	}
	for _, p := range allPatterns {
		if _, err := regexp.Compile(p); err != nil {
			return &ValidationResult{
				Valid: false,
				SyntaxError: &SyntaxError{
					Message:  fmt.Sprintf("invalid regex pattern '%s': %v", p, err),
					Severity: "error",
				},
			}, nil
		}
	}

	// 3. Check test cases: at least 2 (1 positive + 1 negative)
	if len(config.TestCases) < 2 {
		return nil, fmt.Errorf("rule %s: at least 2 test cases required (got %d)", rule.ID, len(config.TestCases))
	}
	var positiveCount, negativeCount int
	for _, tc := range config.TestCases {
		if tc.ExpectPass {
			positiveCount++
		} else {
			negativeCount++
		}
	}
	if positiveCount == 0 {
		return nil, fmt.Errorf("rule %s: at least one positive test case required", rule.ID)
	}
	if negativeCount == 0 {
		return nil, fmt.Errorf("rule %s: at least one negative test case required", rule.ID)
	}

	// 4. Execute test cases
	result := &ValidationResult{Valid: true}
	for _, tc := range config.TestCases {
		tcResult := TestCaseResult{
			Name:           tc.Name,
			ExpectedPass:   tc.ExpectPass,
			ExpectedReason: tc.ExpectReason,
		}

		// Build SignRequest and ParsedPayload
		signType := tc.Input.SignType
		if signType == "" {
			signType = SignTypePersonal
		}
		req := &types.SignRequest{SignType: signType}
		msg := tc.Input.RawMessage
		parsed := &types.ParsedPayload{Message: &msg}

		// Call evaluator
		matched, reason, err := v.evaluator.Evaluate(ctx, rule, req, parsed)
		if err != nil {
			tcResult.Passed = false
			tcResult.Error = fmt.Sprintf("evaluation error: %v", err)
			result.TestCaseResults = append(result.TestCaseResults, tcResult)
			result.FailedTestCases++
			result.Valid = false
			continue
		}

		tcResult.ActualPass = matched
		tcResult.ActualReason = reason

		// Compare: for whitelist, expect_pass=true means we expect matched=true
		if tc.ExpectPass == matched {
			tcResult.Passed = true
		} else {
			tcResult.Passed = false
			if tc.ExpectPass && !matched {
				tcResult.Error = "expected match but pattern did not match"
			} else {
				tcResult.Error = fmt.Sprintf("expected no match but got: %s", reason)
			}
			result.FailedTestCases++
			result.Valid = false
		}

		result.TestCaseResults = append(result.TestCaseResults, tcResult)
	}

	return result, nil
}
