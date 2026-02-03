package evm

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestMessagePatternEvaluator_Type(t *testing.T) {
	evaluator, err := NewMessagePatternEvaluator()
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	if evaluator.Type() != types.RuleTypeMessagePattern {
		t.Errorf("expected type %s, got %s", types.RuleTypeMessagePattern, evaluator.Type())
	}
}

func TestMessagePatternEvaluator_WhitelistMode(t *testing.T) {
	evaluator, err := NewMessagePatternEvaluator()
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	tests := []struct {
		name        string
		pattern     string
		message     string
		expectMatch bool
		expectErr   bool
	}{
		{
			name:        "simple pattern match",
			pattern:     `^Hello World$`,
			message:     "Hello World",
			expectMatch: true,
		},
		{
			name:        "simple pattern no match",
			pattern:     `^Hello World$`,
			message:     "Goodbye World",
			expectMatch: false,
		},
		{
			name:        "regex with special chars",
			pattern:     `^app\.example\.com wants you to sign in`,
			message:     "app.example.com wants you to sign in",
			expectMatch: true,
		},
		{
			name:        "ethereum address pattern",
			pattern:     `0x[a-fA-F0-9]{40}`,
			message:     "Sign in with 0x1234567890abcdef1234567890abcdef12345678",
			expectMatch: true,
		},
		{
			name:        "invalid ethereum address",
			pattern:     `^0x[a-fA-F0-9]{40}$`,
			message:     "0x123", // too short
			expectMatch: false,
		},
		{
			name:        "multiline message",
			pattern:     `(?s)app\.opinion\.trade wants you to sign in.*Welcome`,
			message:     "app.opinion.trade wants you to sign in with your account\n\nWelcome to the platform",
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := MessagePatternConfig{
				Pattern:   tt.pattern,
				SignTypes: []string{SignTypePersonal},
			}
			configBytes, _ := json.Marshal(config)

			rule := &types.Rule{
				Name:   "test-rule",
				Mode:   types.RuleModeWhitelist,
				Config: configBytes,
			}

			req := &types.SignRequest{
				SignType: SignTypePersonal,
			}

			parsed := &types.ParsedPayload{
				Message: &tt.message,
			}

			matched, reason, err := evaluator.Evaluate(context.Background(), rule, req, parsed)

			if tt.expectErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if matched != tt.expectMatch {
				t.Errorf("expected match=%v, got match=%v, reason=%s", tt.expectMatch, matched, reason)
			}
		})
	}
}

func TestMessagePatternEvaluator_BlocklistMode(t *testing.T) {
	evaluator, err := NewMessagePatternEvaluator()
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	tests := []struct {
		name        string
		pattern     string
		message     string
		expectMatch bool
	}{
		{
			name:        "blocklist pattern match - should block",
			pattern:     `dangerous\.site\.com`,
			message:     "dangerous.site.com wants you to sign in",
			expectMatch: true, // matches blocklist = should block
		},
		{
			name:        "blocklist pattern no match - should allow",
			pattern:     `dangerous\.site\.com`,
			message:     "safe.site.com wants you to sign in",
			expectMatch: false, // no match = should allow
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := MessagePatternConfig{
				Pattern:   tt.pattern,
				SignTypes: []string{SignTypePersonal},
			}
			configBytes, _ := json.Marshal(config)

			rule := &types.Rule{
				Name:   "test-blocklist-rule",
				Mode:   types.RuleModeBlocklist,
				Config: configBytes,
			}

			req := &types.SignRequest{
				SignType: SignTypePersonal,
			}

			parsed := &types.ParsedPayload{
				Message: &tt.message,
			}

			matched, reason, err := evaluator.Evaluate(context.Background(), rule, req, parsed)

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if matched != tt.expectMatch {
				t.Errorf("expected match=%v, got match=%v, reason=%s", tt.expectMatch, matched, reason)
			}
		})
	}
}

func TestMessagePatternEvaluator_MultiplePatterns(t *testing.T) {
	evaluator, err := NewMessagePatternEvaluator()
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	config := MessagePatternConfig{
		Pattern:   `^pattern1$`,
		Patterns:  []string{`^pattern2$`, `^pattern3$`},
		SignTypes: []string{SignTypePersonal},
	}
	configBytes, _ := json.Marshal(config)

	rule := &types.Rule{
		Name:   "multi-pattern-rule",
		Mode:   types.RuleModeWhitelist,
		Config: configBytes,
	}

	req := &types.SignRequest{
		SignType: SignTypePersonal,
	}

	tests := []struct {
		name        string
		message     string
		expectMatch bool
	}{
		{"matches first pattern", "pattern1", true},
		{"matches second pattern", "pattern2", true},
		{"matches third pattern", "pattern3", true},
		{"matches none", "pattern4", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := &types.ParsedPayload{
				Message: &tt.message,
			}

			matched, _, err := evaluator.Evaluate(context.Background(), rule, req, parsed)

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if matched != tt.expectMatch {
				t.Errorf("expected match=%v, got match=%v", tt.expectMatch, matched)
			}
		})
	}
}

func TestMessagePatternEvaluator_SignTypeFiltering(t *testing.T) {
	evaluator, err := NewMessagePatternEvaluator()
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	config := MessagePatternConfig{
		Pattern:   `^test message$`,
		SignTypes: []string{SignTypePersonal}, // only personal sign
	}
	configBytes, _ := json.Marshal(config)

	rule := &types.Rule{
		Name:   "sign-type-filter-rule",
		Mode:   types.RuleModeWhitelist,
		Config: configBytes,
	}

	message := "test message"
	parsed := &types.ParsedPayload{
		Message: &message,
	}

	tests := []struct {
		name        string
		signType    string
		expectMatch bool
	}{
		{"personal sign - should evaluate", SignTypePersonal, true},
		{"eip191 sign - should not evaluate", SignTypeEIP191, false},
		{"typed data - should not evaluate", SignTypeTypedData, false},
		{"transaction - should not evaluate", SignTypeTransaction, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.SignRequest{
				SignType: tt.signType,
			}

			matched, _, err := evaluator.Evaluate(context.Background(), rule, req, parsed)

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if matched != tt.expectMatch {
				t.Errorf("expected match=%v, got match=%v", tt.expectMatch, matched)
			}
		})
	}
}

func TestMessagePatternEvaluator_DefaultSignTypes(t *testing.T) {
	evaluator, err := NewMessagePatternEvaluator()
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	// No sign types specified - should default to personal and eip191
	config := MessagePatternConfig{
		Pattern: `^test$`,
		// SignTypes not specified
	}
	configBytes, _ := json.Marshal(config)

	rule := &types.Rule{
		Name:   "default-sign-types-rule",
		Mode:   types.RuleModeWhitelist,
		Config: configBytes,
	}

	message := "test"
	parsed := &types.ParsedPayload{
		Message: &message,
	}

	tests := []struct {
		name        string
		signType    string
		expectMatch bool
	}{
		{"personal sign - should evaluate", SignTypePersonal, true},
		{"eip191 sign - should evaluate", SignTypeEIP191, true},
		{"typed data - should not evaluate", SignTypeTypedData, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.SignRequest{
				SignType: tt.signType,
			}

			matched, _, err := evaluator.Evaluate(context.Background(), rule, req, parsed)

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if matched != tt.expectMatch {
				t.Errorf("expected match=%v, got match=%v", tt.expectMatch, matched)
			}
		})
	}
}

func TestMessagePatternEvaluator_EmptyMessage(t *testing.T) {
	evaluator, err := NewMessagePatternEvaluator()
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	config := MessagePatternConfig{
		Pattern:   `^test$`,
		SignTypes: []string{SignTypePersonal},
	}
	configBytes, _ := json.Marshal(config)

	req := &types.SignRequest{
		SignType: SignTypePersonal,
	}

	tests := []struct {
		name        string
		mode        types.RuleMode
		parsed      *types.ParsedPayload
		expectMatch bool
	}{
		// Whitelist mode - empty message should not match
		{"whitelist - nil parsed payload", types.RuleModeWhitelist, nil, false},
		{"whitelist - nil message", types.RuleModeWhitelist, &types.ParsedPayload{Message: nil}, false},
		{"whitelist - empty message", types.RuleModeWhitelist, &types.ParsedPayload{Message: strPtr("")}, false},
		// Blocklist mode - empty message should not trigger (no violation)
		{"blocklist - nil parsed payload", types.RuleModeBlocklist, nil, false},
		{"blocklist - nil message", types.RuleModeBlocklist, &types.ParsedPayload{Message: nil}, false},
		{"blocklist - empty message", types.RuleModeBlocklist, &types.ParsedPayload{Message: strPtr("")}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &types.Rule{
				Name:   "empty-message-rule",
				Mode:   tt.mode,
				Config: configBytes,
			}

			matched, _, err := evaluator.Evaluate(context.Background(), rule, req, tt.parsed)

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if matched != tt.expectMatch {
				t.Errorf("expected match=%v, got match=%v", tt.expectMatch, matched)
			}
		})
	}
}

func TestMessagePatternEvaluator_InvalidRegex(t *testing.T) {
	evaluator, err := NewMessagePatternEvaluator()
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	config := MessagePatternConfig{
		Pattern:   `[invalid regex`, // unclosed bracket
		SignTypes: []string{SignTypePersonal},
	}
	configBytes, _ := json.Marshal(config)

	rule := &types.Rule{
		Name:   "invalid-regex-rule",
		Mode:   types.RuleModeWhitelist,
		Config: configBytes,
	}

	req := &types.SignRequest{
		SignType: SignTypePersonal,
	}

	message := "test"
	parsed := &types.ParsedPayload{
		Message: &message,
	}

	_, _, err = evaluator.Evaluate(context.Background(), rule, req, parsed)

	if err == nil {
		t.Error("expected error for invalid regex, got nil")
	}
}

func TestMessagePatternEvaluator_NoPatterns(t *testing.T) {
	evaluator, err := NewMessagePatternEvaluator()
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	config := MessagePatternConfig{
		// No pattern specified
		SignTypes: []string{SignTypePersonal},
	}
	configBytes, _ := json.Marshal(config)

	rule := &types.Rule{
		Name:   "no-pattern-rule",
		Mode:   types.RuleModeWhitelist,
		Config: configBytes,
	}

	req := &types.SignRequest{
		SignType: SignTypePersonal,
	}

	message := "test"
	parsed := &types.ParsedPayload{
		Message: &message,
	}

	_, _, err = evaluator.Evaluate(context.Background(), rule, req, parsed)

	if err == nil {
		t.Error("expected error for no patterns, got nil")
	}
}

func TestMessagePatternEvaluator_OpinionLoginMessage(t *testing.T) {
	evaluator, err := NewMessagePatternEvaluator()
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	// Pattern from opinion.example.yaml
	pattern := `^app\.opinion\.trade wants you to sign in with your Ethereum account:\n0x[a-fA-F0-9]{40}\n\nWelcome to opinion\.trade! By proceeding, you agree to our Privacy Policy and Terms of Use\.\n\nURI: https://app\.opinion\.trade\nVersion: 1\nChain ID: 56\nNonce: \d+\nIssued At: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`

	config := MessagePatternConfig{
		Pattern:   pattern,
		SignTypes: []string{SignTypePersonal, SignTypeEIP191},
	}
	configBytes, _ := json.Marshal(config)

	rule := &types.Rule{
		Name:   "opinion-login-rule",
		Mode:   types.RuleModeWhitelist,
		Config: configBytes,
	}

	req := &types.SignRequest{
		SignType: SignTypePersonal,
	}

	tests := []struct {
		name        string
		message     string
		expectMatch bool
	}{
		{
			name: "valid opinion login message",
			message: `app.opinion.trade wants you to sign in with your Ethereum account:
0x88eD75e9eCE373997221E3c0229e74007C1AD718

Welcome to opinion.trade! By proceeding, you agree to our Privacy Policy and Terms of Use.

URI: https://app.opinion.trade
Version: 1
Chain ID: 56
Nonce: 4821202891733693881
Issued At: 2026-01-23T08:46:20.000Z`,
			expectMatch: true,
		},
		{
			name: "invalid domain",
			message: `app.fake.trade wants you to sign in with your Ethereum account:
0x88eD75e9eCE373997221E3c0229e74007C1AD718

Welcome to opinion.trade! By proceeding, you agree to our Privacy Policy and Terms of Use.

URI: https://app.opinion.trade
Version: 1
Chain ID: 56
Nonce: 4821202891733693881
Issued At: 2026-01-23T08:46:20.000Z`,
			expectMatch: false,
		},
		{
			name: "invalid address format",
			message: `app.opinion.trade wants you to sign in with your Ethereum account:
0x123

Welcome to opinion.trade! By proceeding, you agree to our Privacy Policy and Terms of Use.

URI: https://app.opinion.trade
Version: 1
Chain ID: 56
Nonce: 4821202891733693881
Issued At: 2026-01-23T08:46:20.000Z`,
			expectMatch: false,
		},
		{
			name: "wrong chain ID",
			message: `app.opinion.trade wants you to sign in with your Ethereum account:
0x88eD75e9eCE373997221E3c0229e74007C1AD718

Welcome to opinion.trade! By proceeding, you agree to our Privacy Policy and Terms of Use.

URI: https://app.opinion.trade
Version: 1
Chain ID: 1
Nonce: 4821202891733693881
Issued At: 2026-01-23T08:46:20.000Z`,
			expectMatch: false,
		},
		{
			name: "wrong URI",
			message: `app.opinion.trade wants you to sign in with your Ethereum account:
0x88eD75e9eCE373997221E3c0229e74007C1AD718

Welcome to opinion.trade! By proceeding, you agree to our Privacy Policy and Terms of Use.

URI: https://app.fake.trade
Version: 1
Chain ID: 56
Nonce: 4821202891733693881
Issued At: 2026-01-23T08:46:20.000Z`,
			expectMatch: false,
		},
		{
			name:        "completely different message",
			message:     "Please sign this random message",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := &types.ParsedPayload{
				Message: &tt.message,
			}

			matched, reason, err := evaluator.Evaluate(context.Background(), rule, req, parsed)

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if matched != tt.expectMatch {
				t.Errorf("expected match=%v, got match=%v, reason=%s", tt.expectMatch, matched, reason)
			}
		})
	}
}

func TestMessagePatternEvaluator_InvalidConfig(t *testing.T) {
	evaluator, err := NewMessagePatternEvaluator()
	if err != nil {
		t.Fatalf("failed to create evaluator: %v", err)
	}

	rule := &types.Rule{
		Name:   "invalid-config-rule",
		Mode:   types.RuleModeWhitelist,
		Config: []byte(`{invalid json`),
	}

	req := &types.SignRequest{
		SignType: SignTypePersonal,
	}

	message := "test"
	parsed := &types.ParsedPayload{
		Message: &message,
	}

	_, _, err = evaluator.Evaluate(context.Background(), rule, req, parsed)

	if err == nil {
		t.Error("expected error for invalid config JSON, got nil")
	}
}
