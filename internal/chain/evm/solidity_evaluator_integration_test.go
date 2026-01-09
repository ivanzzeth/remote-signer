//go:build integration

package evm

import (
	"context"
	"encoding/hex"
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

// =============================================================================
// Function Mode Tests
// =============================================================================

// TestIntegration_FunctionMode_ERC20Transfer tests function-based rules with ERC20 transfer
func TestIntegration_FunctionMode_ERC20Transfer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	// User defines transfer function - when tx selector matches, it's called with decoded params
	functions := `
    function transfer(address to, uint256 amount) external {
        require(amount <= 10000000000, "exceeds 10k limit");
        require(to != address(0), "invalid recipient");
    }
    `

	// ERC20 transfer calldata: transfer(0x5B38Da6a701c568545dCfcB03FcB875f56beddC4, 5000000000)
	// Selector: 0xa9059cbb
	// to: 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4 (padded to 32 bytes)
	// amount: 5000000000 (padded to 32 bytes)
	transferCalldata, _ := hex.DecodeString("a9059cbb0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc400000000000000000000000000000000000000000000000000000001dcd65000")

	tests := []struct {
		name        string
		data        []byte
		expectPass  bool
		expectMatch string
	}{
		{
			name:       "pass for 5k transfer",
			data:       transferCalldata,
			expectPass: true,
		},
		{
			name: "reject for 20k transfer",
			// transfer(0x5B38Da6a701c568545dCfcB03FcB875f56beddC4, 20000000000)
			data: func() []byte {
				d, _ := hex.DecodeString("a9059cbb0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc40000000000000000000000000000000000000000000000000000000ba43b7400")
				return d
			}(),
			expectPass:  false,
			expectMatch: "exceeds 10k limit",
		},
		{
			name: "reject for zero address",
			// transfer(0x0000000000000000000000000000000000000000, 1000000000)
			data: func() []byte {
				d, _ := hex.DecodeString("a9059cbb000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b2d05e00")
				return d
			}(),
			expectPass:  false,
			expectMatch: "invalid recipient",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.SignRequest{
				ChainID:       "1",
				SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
			}
			parsed := &types.ParsedPayload{
				RawData: tt.data,
			}

			passed, reason, err := evaluator.evaluateFunctions(context.Background(), functions, req, parsed)
			require.NoError(t, err)
			assert.Equal(t, tt.expectPass, passed, "pass/fail mismatch")

			if !tt.expectPass && tt.expectMatch != "" {
				assert.Contains(t, reason, tt.expectMatch, "reason should contain expected substring")
			}
		})
	}
}

// TestIntegration_FunctionMode_MultipleSelectors tests multiple function definitions
func TestIntegration_FunctionMode_MultipleSelectors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	// Define multiple functions for different selectors
	functions := `
    function transfer(address to, uint256 amount) external {
        require(amount <= 1000000000000000000, "transfer exceeds 1 ETH");
    }

    function approve(address spender, uint256 amount) external {
        require(spender != address(0), "cannot approve zero address");
    }
    `

	tests := []struct {
		name       string
		data       []byte
		expectPass bool
	}{
		{
			name: "pass for transfer 0.5 ETH",
			// transfer(0x5B38Da6a701c568545dCfcB03FcB875f56beddC4, 500000000000000000)
			data: func() []byte {
				d, _ := hex.DecodeString("a9059cbb0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc400000000000000000000000000000000000000000000000006f05b59d3b20000")
				return d
			}(),
			expectPass: true,
		},
		{
			name: "reject transfer exceeds limit",
			// transfer(0x5B38Da6a701c568545dCfcB03FcB875f56beddC4, 2000000000000000000) - 2 ETH
			data: func() []byte {
				d, _ := hex.DecodeString("a9059cbb0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc4000000000000000000000000000000000000000000000000ade68d5bb8d90000")
				return d
			}(),
			expectPass: false,
		},
		{
			name: "pass for approve valid spender",
			// approve(0x5B38Da6a701c568545dCfcB03FcB875f56beddC4, 1000000000000000000)
			data: func() []byte {
				d, _ := hex.DecodeString("095ea7b30000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc40000000000000000000000000000000000000000000000000de0b6b3a7640000")
				return d
			}(),
			expectPass: true,
		},
		{
			name: "reject approve zero address",
			// approve(0x0000000000000000000000000000000000000000, 1000000000000000000)
			data: func() []byte {
				d, _ := hex.DecodeString("095ea7b300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000de0b6b3a7640000")
				return d
			}(),
			expectPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.SignRequest{
				ChainID:       "1",
				SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
			}
			parsed := &types.ParsedPayload{
				RawData: tt.data,
			}

			passed, _, err := evaluator.evaluateFunctions(context.Background(), functions, req, parsed)
			require.NoError(t, err)
			assert.Equal(t, tt.expectPass, passed, "pass/fail mismatch")
		})
	}
}

// TestIntegration_FunctionMode_AccessTxContext tests accessing tx context from functions
func TestIntegration_FunctionMode_AccessTxContext(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	// Function that accesses txValue and txSigner from context
	functions := `
    function transfer(address to, uint256 amount) external view {
        // Can access transaction context
        require(txValue == 0, "no ETH should be sent with transfer");
        require(txSigner != address(0), "signer must be set");
    }
    `

	// transfer(0x5B38Da6a701c568545dCfcB03FcB875f56beddC4, 1000)
	transferCalldata, _ := hex.DecodeString("a9059cbb0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc400000000000000000000000000000000000000000000000000000000000003e8")

	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	}
	value := "0"
	parsed := &types.ParsedPayload{
		RawData: transferCalldata,
		Value:   &value,
	}

	passed, _, err := evaluator.evaluateFunctions(context.Background(), functions, req, parsed)
	require.NoError(t, err)
	assert.True(t, passed, "should pass when txValue is 0")
}

// TestIntegration_FunctionMode_Validator tests validation of function-based rules
func TestIntegration_FunctionMode_Validator(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	validator, err := NewSolidityRuleValidator(evaluator, logger)
	require.NoError(t, err)

	config := SolidityExpressionConfig{
		Functions: `
        function transfer(address to, uint256 amount) external {
            require(amount <= 10000000000, "exceeds limit");
        }
        `,
		Description: "ERC20 transfer limit",
		TestCases: []SolidityTestCase{
			{
				Name: "should pass for 5k",
				Input: SolidityTestInput{
					// transfer(0x5B38Da6a701c568545dCfcB03FcB875f56beddC4, 5000000000)
					Data: "0xa9059cbb0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc400000000000000000000000000000000000000000000000000000001dcd65000",
				},
				ExpectPass: true,
			},
			{
				Name: "should reject for 20k",
				Input: SolidityTestInput{
					// transfer(0x5B38Da6a701c568545dCfcB03FcB875f56beddC4, 20000000000)
					Data: "0xa9059cbb0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc40000000000000000000000000000000000000000000000000000000ba43b7400",
				},
				ExpectPass:   false,
				ExpectReason: "exceeds limit",
			},
		},
	}

	configBytes, err := json.Marshal(config)
	require.NoError(t, err)

	rule := &types.Rule{
		ID:     "test-function-rule",
		Type:   types.RuleTypeEVMSolidityExpression,
		Config: configBytes,
	}

	result, err := validator.ValidateRule(context.Background(), rule)
	require.NoError(t, err)

	assert.True(t, result.Valid, "rule should be valid")
	assert.Nil(t, result.SyntaxError, "should have no syntax error")
	assert.Len(t, result.TestCaseResults, 2, "should have 2 test case results")
	assert.Equal(t, 0, result.FailedTestCases, "should have no failed test cases")
}

// TestIntegration_FunctionMode_SyntaxError tests syntax error detection in function mode
func TestIntegration_FunctionMode_SyntaxError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	validator, err := NewSolidityRuleValidator(evaluator, logger)
	require.NoError(t, err)

	config := SolidityExpressionConfig{
		Functions: `
        function transfer(address to, uint256 amount) external {
            // Missing semicolon
            require(amount <= 10000000000, "exceeds limit")
        }
        `,
		TestCases: []SolidityTestCase{
			{
				Name:       "dummy",
				Input:      SolidityTestInput{},
				ExpectPass: true,
			},
		},
	}

	configBytes, err := json.Marshal(config)
	require.NoError(t, err)

	rule := &types.Rule{
		ID:     "test-syntax-error-rule",
		Type:   types.RuleTypeEVMSolidityExpression,
		Config: configBytes,
	}

	result, err := validator.ValidateRule(context.Background(), rule)
	require.NoError(t, err)

	assert.False(t, result.Valid, "rule should be invalid due to syntax error")
	assert.NotNil(t, result.SyntaxError, "should have syntax error")
}

// =============================================================================
// EIP-712 TypedDataExpression Mode Tests
// =============================================================================

// TestIntegration_TypedDataExpression_PermitValidation tests EIP-712 Permit validation
func TestIntegration_TypedDataExpression_PermitValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	// Validate Permit: limit value and check spender is not zero address
	expression := `
		require(value <= 1000000000000000000000, "permit value exceeds 1000 token limit");
		require(spender != address(0), "cannot permit zero address spender");
	`

	tests := []struct {
		name        string
		value       string
		spender     string
		expectPass  bool
		expectMatch string
	}{
		{
			name:       "pass for 100 tokens",
			value:      "100000000000000000000", // 100 tokens (18 decimals)
			spender:    "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
			expectPass: true,
		},
		{
			name:        "reject for 2000 tokens",
			value:       "2000000000000000000000", // 2000 tokens
			spender:     "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
			expectPass:  false,
			expectMatch: "permit value exceeds 1000 token limit",
		},
		{
			name:        "reject for zero address spender",
			value:       "100000000000000000000",
			spender:     "0x0000000000000000000000000000000000000000",
			expectPass:  false,
			expectMatch: "cannot permit zero address spender",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typedData := &TypedDataPayload{
				PrimaryType: "Permit",
				Domain: TypedDataDomain{
					Name:              "TestToken",
					Version:           "1",
					ChainId:           "1",
					VerifyingContract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
				},
				Types: map[string][]TypedDataField{
					"Permit": {
						{Name: "owner", Type: "address"},
						{Name: "spender", Type: "address"},
						{Name: "value", Type: "uint256"},
						{Name: "nonce", Type: "uint256"},
						{Name: "deadline", Type: "uint256"},
					},
				},
				Message: map[string]interface{}{
					"owner":    "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
					"spender":  tt.spender,
					"value":    tt.value,
					"nonce":    "0",
					"deadline": "1735689600", // Future timestamp
				},
			}

			req := &types.SignRequest{
				ChainID:       "1",
				SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
			}

			passed, reason, err := evaluator.evaluateTypedDataExpression(context.Background(), expression, req, typedData)
			require.NoError(t, err)
			assert.Equal(t, tt.expectPass, passed, "pass/fail mismatch")

			if !tt.expectPass && tt.expectMatch != "" {
				assert.Contains(t, reason, tt.expectMatch, "reason should contain expected substring")
			}
		})
	}
}

// TestIntegration_TypedDataExpression_DomainValidation tests domain parameter validation
func TestIntegration_TypedDataExpression_DomainValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	// Only allow specific domain contract
	expression := `
		require(domainContract == 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, "invalid contract");
		require(domainChainId == 1, "invalid chain");
	`

	tests := []struct {
		name        string
		contract    string
		chainId     string
		expectPass  bool
		expectMatch string
	}{
		{
			name:       "pass for correct contract and chain",
			contract:   "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
			chainId:    "1",
			expectPass: true,
		},
		{
			name:        "reject for wrong contract",
			contract:    "0xdAC17F958D2ee523a2206206994597C13D831ec7",
			chainId:     "1",
			expectPass:  false,
			expectMatch: "invalid contract",
		},
		{
			name:        "reject for wrong chain",
			contract:    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
			chainId:     "137",
			expectPass:  false,
			expectMatch: "invalid chain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typedData := &TypedDataPayload{
				PrimaryType: "Permit",
				Domain: TypedDataDomain{
					Name:              "TestToken",
					Version:           "1",
					ChainId:           tt.chainId,
					VerifyingContract: tt.contract,
				},
				Types: map[string][]TypedDataField{
					"Permit": {
						{Name: "owner", Type: "address"},
						{Name: "spender", Type: "address"},
						{Name: "value", Type: "uint256"},
					},
				},
				Message: map[string]interface{}{
					"owner":   "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
					"spender": "0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2",
					"value":   "1000000000000000000",
				},
			}

			req := &types.SignRequest{
				ChainID:       "1",
				SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
			}

			passed, reason, err := evaluator.evaluateTypedDataExpression(context.Background(), expression, req, typedData)
			require.NoError(t, err)
			assert.Equal(t, tt.expectPass, passed, "pass/fail mismatch")

			if !tt.expectPass && tt.expectMatch != "" {
				assert.Contains(t, reason, tt.expectMatch, "reason should contain expected substring")
			}
		})
	}
}

// TestIntegration_TypedDataExpression_Validator tests full validation with test cases
func TestIntegration_TypedDataExpression_Validator(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	validator, err := NewSolidityRuleValidator(evaluator, logger)
	require.NoError(t, err)

	config := SolidityExpressionConfig{
		TypedDataExpression: `
			require(value <= 1000000000000000000, "exceeds 1 token limit");
			require(spender != address(0), "invalid spender");
		`,
		SignTypeFilter: "typed_data",
		Description:    "Permit validation: max 1 token, no zero address spender",
		TestCases: []SolidityTestCase{
			{
				Name: "should pass for 0.5 tokens",
				Input: SolidityTestInput{
					TypedData: &TypedDataTestInput{
						PrimaryType: "Permit",
						Domain: &TypedDataDomainInput{
							Name:              "TestToken",
							Version:           "1",
							ChainID:           "1",
							VerifyingContract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
						},
						Message: map[string]interface{}{
							"owner":    "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
							"spender":  "0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2",
							"value":    "500000000000000000",
							"nonce":    "0",
							"deadline": "1735689600",
						},
					},
				},
				ExpectPass: true,
			},
			{
				Name: "should reject for 2 tokens",
				Input: SolidityTestInput{
					TypedData: &TypedDataTestInput{
						PrimaryType: "Permit",
						Domain: &TypedDataDomainInput{
							Name:              "TestToken",
							Version:           "1",
							ChainID:           "1",
							VerifyingContract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
						},
						Message: map[string]interface{}{
							"owner":    "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
							"spender":  "0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2",
							"value":    "2000000000000000000",
							"nonce":    "0",
							"deadline": "1735689600",
						},
					},
				},
				ExpectPass:   false,
				ExpectReason: "exceeds 1 token limit",
			},
			{
				Name: "should reject zero address spender",
				Input: SolidityTestInput{
					TypedData: &TypedDataTestInput{
						PrimaryType: "Permit",
						Domain: &TypedDataDomainInput{
							Name:              "TestToken",
							Version:           "1",
							ChainID:           "1",
							VerifyingContract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
						},
						Message: map[string]interface{}{
							"owner":    "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
							"spender":  "0x0000000000000000000000000000000000000000",
							"value":    "500000000000000000",
							"nonce":    "0",
							"deadline": "1735689600",
						},
					},
				},
				ExpectPass:   false,
				ExpectReason: "invalid spender",
			},
		},
	}

	configBytes, err := json.Marshal(config)
	require.NoError(t, err)

	rule := &types.Rule{
		ID:     "test-typed-data-rule",
		Type:   types.RuleTypeEVMSolidityExpression,
		Config: configBytes,
	}

	result, err := validator.ValidateRule(context.Background(), rule)
	require.NoError(t, err)

	assert.True(t, result.Valid, "rule should be valid")
	assert.Nil(t, result.SyntaxError, "should have no syntax error")
	assert.Len(t, result.TestCaseResults, 3, "should have 3 test case results")
	assert.Equal(t, 0, result.FailedTestCases, "should have no failed test cases")

	for _, tcr := range result.TestCaseResults {
		assert.True(t, tcr.Passed, "test case %s should pass", tcr.Name)
	}
}

// TestIntegration_TypedDataExpression_SyntaxError tests syntax error detection
func TestIntegration_TypedDataExpression_SyntaxError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	validator, err := NewSolidityRuleValidator(evaluator, logger)
	require.NoError(t, err)

	config := SolidityExpressionConfig{
		TypedDataExpression: `
			// Missing semicolon
			require(value <= 1000000000000000000, "exceeds limit")
		`,
		TestCases: []SolidityTestCase{
			{
				Name: "dummy",
				Input: SolidityTestInput{
					TypedData: &TypedDataTestInput{
						PrimaryType: "Permit",
						Message: map[string]interface{}{
							"value": "100",
						},
					},
				},
				ExpectPass: true,
			},
		},
	}

	configBytes, err := json.Marshal(config)
	require.NoError(t, err)

	rule := &types.Rule{
		ID:     "test-syntax-error-rule",
		Type:   types.RuleTypeEVMSolidityExpression,
		Config: configBytes,
	}

	result, err := validator.ValidateRule(context.Background(), rule)
	require.NoError(t, err)

	assert.False(t, result.Valid, "rule should be invalid due to syntax error")
	assert.NotNil(t, result.SyntaxError, "should have syntax error")
}

// TestIntegration_TypedDataExpression_Evaluate tests the full Evaluate method path
func TestIntegration_TypedDataExpression_Evaluate(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	evaluator, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{
		Timeout: 60 * time.Second,
	}, logger)
	require.NoError(t, err)

	config := SolidityExpressionConfig{
		TypedDataExpression: `require(value <= 1000000000000000000, "exceeds limit");`,
		SignTypeFilter:      "typed_data",
		Description:         "Max 1 token permit",
		TestCases: []SolidityTestCase{
			{
				Name: "pass case",
				Input: SolidityTestInput{
					TypedData: &TypedDataTestInput{
						PrimaryType: "Permit",
						Message:     map[string]interface{}{"value": "500000000000000000"},
					},
				},
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

	// Build typed data payload
	typedData := &TypedDataPayload{
		PrimaryType: "Permit",
		Domain: TypedDataDomain{
			Name:              "TestToken",
			Version:           "1",
			ChainId:           "1",
			VerifyingContract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
		},
		Types: map[string][]TypedDataField{
			"Permit": {
				{Name: "value", Type: "uint256"},
			},
		},
		Message: map[string]interface{}{
			"value": "500000000000000000",
		},
	}

	evmPayload := EVMSignPayload{TypedData: typedData}
	payload, _ := json.Marshal(evmPayload)

	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
		SignType:      "typed_data",
		Payload:       payload,
	}

	// Test passing case
	passed, reason, err := evaluator.Evaluate(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.True(t, passed, "should pass for 0.5 tokens")
	assert.Empty(t, reason)

	// Test failing case
	typedData.Message["value"] = "2000000000000000000"
	evmPayload.TypedData = typedData
	payload, _ = json.Marshal(evmPayload)
	req.Payload = payload

	passed, reason, err = evaluator.Evaluate(context.Background(), rule, req, nil)
	require.NoError(t, err)
	assert.False(t, passed, "should reject for 2 tokens")
	assert.Contains(t, reason, "exceeds limit")
}

