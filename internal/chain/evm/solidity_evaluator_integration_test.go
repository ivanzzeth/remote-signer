//go:build integration

package evm

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// TestIntegration_SolidityRuleEvaluator_ValueLimit tests actual forge execution
// with a simple value limit rule
func TestIntegration_SolidityRuleEvaluator_ValueLimit(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	expression := `require(value <= 1000000000000000000, "value exceeds 1 ETH");`

	tests := []struct {
		name        string
		value       string
		expectPass  bool
		expectMatch string // substring to match in reason
	}{
		{
			name:       "pass for 0.5 ETH",
			value:      "500000000000000000",
			expectPass: true,
		},
		{
			name:       "pass for exactly 1 ETH",
			value:      "1000000000000000000",
			expectPass: true,
		},
		{
			name:        "reject for 1.5 ETH",
			value:       "1500000000000000000",
			expectPass:  false,
			expectMatch: "value exceeds 1 ETH",
		},
		{
			name:        "reject for 10 ETH",
			value:       "10000000000000000000",
			expectPass:  false,
			expectMatch: "value exceeds 1 ETH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.SignRequest{
				ChainID:       "1",
				SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4", // Checksummed
			}
			parsed := &types.ParsedPayload{
				Value: &tt.value,
			}

			passed, reason, err := evaluator.evaluateExpression(context.Background(), expression, req, parsed)
			require.NoError(t, err)
			assert.Equal(t, tt.expectPass, passed, "pass/fail mismatch")

			if !tt.expectPass && tt.expectMatch != "" {
				assert.Contains(t, reason, tt.expectMatch, "reason should contain expected substring")
			}
		})
	}
}

// TestIntegration_SolidityRuleEvaluator_AddressCheck tests address-based rules
func TestIntegration_SolidityRuleEvaluator_AddressCheck(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	expression := `require(to != address(0), "cannot send to zero address");`

	// Use checksummed addresses for Solidity compatibility
	tests := []struct {
		name       string
		to         string
		expectPass bool
	}{
		{
			name:       "pass for valid address",
			to:         "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4", // Checksummed address
			expectPass: true,
		},
		{
			name:       "reject for zero address",
			to:         "0x0000000000000000000000000000000000000000",
			expectPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.SignRequest{
				ChainID:       "1",
				SignerAddress: "0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2", // Checksummed
			}
			parsed := &types.ParsedPayload{
				Recipient: &tt.to,
			}

			passed, _, err := evaluator.evaluateExpression(context.Background(), expression, req, parsed)
			require.NoError(t, err)
			assert.Equal(t, tt.expectPass, passed)
		})
	}
}

// TestIntegration_SolidityRuleEvaluator_SelectorCheck tests method selector rules
func TestIntegration_SolidityRuleEvaluator_SelectorCheck(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	// Only allow ERC20 transfer
	expression := `require(selector == bytes4(0xa9059cbb), "only transfer allowed");`

	transferSig := "0xa9059cbb"
	approveSig := "0x095ea7b3"

	tests := []struct {
		name       string
		selector   string
		expectPass bool
	}{
		{
			name:       "pass for transfer",
			selector:   transferSig,
			expectPass: true,
		},
		{
			name:       "reject for approve",
			selector:   approveSig,
			expectPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.SignRequest{
				ChainID:       "1",
				SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4", // Checksummed
			}
			parsed := &types.ParsedPayload{
				MethodSig: &tt.selector,
			}

			passed, _, err := evaluator.evaluateExpression(context.Background(), expression, req, parsed)
			require.NoError(t, err)
			assert.Equal(t, tt.expectPass, passed)
		})
	}
}

// TestIntegration_SolidityRuleValidator_SyntaxValidation tests syntax checking
func TestIntegration_SolidityRuleValidator_SyntaxValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	validator, err := NewSolidityRuleValidator(evaluator, logger)
	require.NoError(t, err)

	tests := []struct {
		name        string
		expression  string
		expectValid bool
	}{
		{
			name:        "valid simple require",
			expression:  `require(value <= 1 ether, "limit");`,
			expectValid: true,
		},
		{
			name:        "valid multiple requires",
			expression:  `require(value <= 1 ether, "limit1"); require(to != address(0), "limit2");`,
			expectValid: true,
		},
		{
			name:        "invalid missing semicolon",
			expression:  `require(value <= 1 ether, "limit")`,
			expectValid: false,
		},
		{
			name:        "invalid syntax",
			expression:  `require value <= 1 ether, "limit";`,
			expectValid: false,
		},
		{
			name:        "invalid undefined variable",
			expression:  `require(undefined_var <= 1, "limit");`,
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := SolidityExpressionConfig{
				Expression: tt.expression,
				TestCases: []SolidityTestCase{
					{
						Name:       "dummy test",
						Input:      SolidityTestInput{Value: "0"},
						ExpectPass: true,
					},
				},
			}

			configBytes, err := json.Marshal(config)
			require.NoError(t, err)

			rule := &types.Rule{
				ID:     "test-rule",
				Type:   types.RuleTypeEVMSolidityExpression,
				Config: configBytes,
			}

			result, err := validator.ValidateRule(context.Background(), rule)
			require.NoError(t, err)

			if tt.expectValid {
				if result.SyntaxError != nil {
					t.Errorf("expected valid syntax, got error: %s", result.SyntaxError.Message)
				}
			} else {
				assert.NotNil(t, result.SyntaxError, "expected syntax error")
			}
		})
	}
}

// TestIntegration_SolidityRuleValidator_TestCaseExecution tests full validation
func TestIntegration_SolidityRuleValidator_TestCaseExecution(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	validator, err := NewSolidityRuleValidator(evaluator, logger)
	require.NoError(t, err)

	config := SolidityExpressionConfig{
		Expression: `require(value <= 1000000000000000000, "exceeds 1 ETH limit");`,
		TestCases: []SolidityTestCase{
			{
				Name:       "should pass for 0.5 ETH",
				Input:      SolidityTestInput{Value: "500000000000000000"},
				ExpectPass: true,
			},
			{
				Name:         "should reject for 2 ETH",
				Input:        SolidityTestInput{Value: "2000000000000000000"},
				ExpectPass:   false,
				ExpectReason: "exceeds 1 ETH limit",
			},
		},
	}

	configBytes, err := json.Marshal(config)
	require.NoError(t, err)

	rule := &types.Rule{
		ID:     "test-rule",
		Type:   types.RuleTypeEVMSolidityExpression,
		Config: configBytes,
	}

	result, err := validator.ValidateRule(context.Background(), rule)
	require.NoError(t, err)

	assert.True(t, result.Valid, "rule should be valid")
	assert.Nil(t, result.SyntaxError, "should have no syntax error")
	assert.Len(t, result.TestCaseResults, 2, "should have 2 test case results")
	assert.Equal(t, 0, result.FailedTestCases, "should have no failed test cases")

	for _, tcr := range result.TestCaseResults {
		assert.True(t, tcr.Passed, "test case %s should pass", tcr.Name)
	}
}

// TestIntegration_SolidityRuleValidator_FailingTestCase tests detection of failing test cases
func TestIntegration_SolidityRuleValidator_FailingTestCase(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	validator, err := NewSolidityRuleValidator(evaluator, logger)
	require.NoError(t, err)

	// This test case is wrong - expects pass for 2 ETH but rule rejects it
	config := SolidityExpressionConfig{
		Expression: `require(value <= 1000000000000000000, "exceeds limit");`,
		TestCases: []SolidityTestCase{
			{
				Name:       "wrong expectation - expects pass for 2 ETH",
				Input:      SolidityTestInput{Value: "2000000000000000000"},
				ExpectPass: true, // This is wrong - should be false
			},
		},
	}

	configBytes, err := json.Marshal(config)
	require.NoError(t, err)

	rule := &types.Rule{
		ID:     "test-rule",
		Type:   types.RuleTypeEVMSolidityExpression,
		Config: configBytes,
	}

	result, err := validator.ValidateRule(context.Background(), rule)
	require.NoError(t, err)

	assert.False(t, result.Valid, "rule should be invalid due to failing test case")
	assert.Equal(t, 1, result.FailedTestCases, "should have 1 failed test case")
	assert.Len(t, result.TestCaseResults, 1)
	assert.False(t, result.TestCaseResults[0].Passed, "test case should fail")
	assert.Contains(t, result.TestCaseResults[0].Error, "expected pass but got revert")
}

// TestIntegration_SolidityRuleEvaluator_Evaluate tests the full Evaluate method
func TestIntegration_SolidityRuleEvaluator_Evaluate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	config := SolidityExpressionConfig{
		Expression:  `require(value <= 1000000000000000000, "exceeds limit");`,
		Description: "Max 1 ETH transfer",
		TestCases: []SolidityTestCase{
			{
				Name:       "pass case",
				Input:      SolidityTestInput{Value: "500000000000000000"},
				ExpectPass: true,
			},
		},
	}

	configBytes, err := json.Marshal(config)
	require.NoError(t, err)

	rule := &types.Rule{
		ID:     "test-rule",
		Type:   types.RuleTypeEVMSolidityExpression,
		Config: configBytes,
	}

	// Test passing case
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4", // Checksummed
	}
	value := "500000000000000000"
	parsed := &types.ParsedPayload{
		Value: &value,
	}

	passed, reason, err := evaluator.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.True(t, passed, "should pass for 0.5 ETH")
	assert.Empty(t, reason)

	// Test failing case
	value = "2000000000000000000"
	parsed.Value = &value

	passed, reason, err = evaluator.Evaluate(context.Background(), rule, req, parsed)
	require.NoError(t, err)
	assert.False(t, passed, "should reject for 2 ETH")
	assert.Contains(t, reason, "exceeds limit")
}

