package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/ivanzzeth/remote-signer/internal/core/rule"
	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// MessagePatternConfig defines the configuration for message pattern matching
type MessagePatternConfig struct {
	// Pattern is a regex pattern that the message must match (whitelist) or must not match (blocklist)
	Pattern string `json:"pattern"`

	// Patterns is a list of regex patterns (any match = rule fires)
	// If both Pattern and Patterns are specified, Pattern is added to Patterns
	Patterns []string `json:"patterns,omitempty"`

	// SignTypes restricts which sign types this rule applies to
	// If empty, applies to "personal" and "eip191" by default
	SignTypes []string `json:"sign_types,omitempty"`

	// Description provides human-readable explanation of what the pattern validates
	Description string `json:"description,omitempty"`

	// TestCases defines validation cases to verify rule correctness
	TestCases []MessagePatternTestCase `json:"test_cases,omitempty"`
}

// MessagePatternTestCase defines a test case for validating a message_pattern rule
type MessagePatternTestCase struct {
	Name         string                  `json:"name"`
	Input        MessagePatternTestInput `json:"input"`
	ExpectPass   bool                    `json:"expect_pass"`
	ExpectReason string                  `json:"expect_reason,omitempty"`
}

// MessagePatternTestInput defines the input for a message pattern test case
type MessagePatternTestInput struct {
	RawMessage string `json:"raw_message"`
	SignType   string `json:"sign_type,omitempty"` // default: "personal"
}

// MessagePatternEvaluator validates personal sign messages against regex patterns
// Behavior depends on rule mode:
// - Whitelist mode: returns true if message matches ANY pattern (allow)
// - Blocklist mode: returns true if message matches ANY pattern (block)
type MessagePatternEvaluator struct{}

// NewMessagePatternEvaluator creates a new message pattern evaluator
func NewMessagePatternEvaluator() (*MessagePatternEvaluator, error) {
	return &MessagePatternEvaluator{}, nil
}

// Type returns the rule type this evaluator handles
func (e *MessagePatternEvaluator) Type() types.RuleType {
	return types.RuleTypeMessagePattern
}

// Evaluate checks if the message matches the configured patterns
// For whitelist mode: returns true if message matches ANY pattern (allow signing)
// For blocklist mode: returns true if message matches ANY pattern (block signing)
func (e *MessagePatternEvaluator) Evaluate(ctx context.Context, r *types.Rule, req *types.SignRequest, parsed *types.ParsedPayload) (bool, string, error) {
	// Check if this sign type should be evaluated
	config, err := e.parseConfig(r.Config)
	if err != nil {
		return false, "", err
	}

	// Check sign type filter
	if !e.shouldEvaluateSignType(req.SignType, config) {
		return false, "", nil
	}

	// Get message from parsed payload
	if parsed == nil || parsed.Message == nil || *parsed.Message == "" {
		// No message to validate
		if r.Mode == types.RuleModeBlocklist {
			// Blocklist: no message means no violation
			return false, "", nil
		}
		// Whitelist: no message means no match
		return false, "", nil
	}

	message := *parsed.Message

	// Collect all patterns
	patterns := config.Patterns
	if config.Pattern != "" {
		patterns = append([]string{config.Pattern}, patterns...)
	}

	if len(patterns) == 0 {
		return false, "", fmt.Errorf("no patterns configured for message_pattern rule")
	}

	// Check each pattern
	for _, patternStr := range patterns {
		re, err := regexp.Compile(patternStr)
		if err != nil {
			return false, "", fmt.Errorf("invalid regex pattern '%s': %w", patternStr, err)
		}

		if re.MatchString(message) {
			if r.Mode == types.RuleModeBlocklist {
				return true, fmt.Sprintf("message matches blocklist pattern: %s", patternStr), nil
			}
			return true, fmt.Sprintf("message matches whitelist pattern: %s", patternStr), nil
		}
	}

	return false, "", nil
}

// parseConfig parses and validates the rule configuration
func (e *MessagePatternEvaluator) parseConfig(configData []byte) (*MessagePatternConfig, error) {
	var config MessagePatternConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("invalid message pattern config: %w", err)
	}

	// Validate patterns are valid regex
	allPatterns := config.Patterns
	if config.Pattern != "" {
		allPatterns = append([]string{config.Pattern}, allPatterns...)
	}

	for _, p := range allPatterns {
		if _, err := regexp.Compile(p); err != nil {
			return nil, fmt.Errorf("invalid regex pattern '%s': %w", p, err)
		}
	}

	return &config, nil
}

// shouldEvaluateSignType checks if the rule applies to the given sign type
func (e *MessagePatternEvaluator) shouldEvaluateSignType(signType string, config *MessagePatternConfig) bool {
	// Default sign types if not specified
	targetTypes := config.SignTypes
	if len(targetTypes) == 0 {
		targetTypes = []string{SignTypePersonal, SignTypeEIP191}
	}

	for _, t := range targetTypes {
		if t == signType {
			return true
		}
	}
	return false
}

// Compile-time check
var _ rule.RuleEvaluator = (*MessagePatternEvaluator)(nil)
