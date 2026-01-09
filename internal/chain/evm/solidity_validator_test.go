package evm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestSolidityRuleValidator_CompareTestResult(t *testing.T) {
	// Create a validator without evaluator for unit testing
	// We're testing the comparison logic only
	v := &SolidityRuleValidator{}

	tests := []struct {
		name         string
		expectPass   bool
		actualPass   bool
		expectReason string
		actualReason string
		shouldPass   bool
	}{
		{
			name:         "pass expected, pass actual",
			expectPass:   true,
			actualPass:   true,
			expectReason: "",
			actualReason: "",
			shouldPass:   true,
		},
		{
			name:         "pass expected, fail actual",
			expectPass:   true,
			actualPass:   false,
			expectReason: "",
			actualReason: "some error",
			shouldPass:   false,
		},
		{
			name:         "fail expected, fail actual with matching reason",
			expectPass:   false,
			actualPass:   false,
			expectReason: "limit",
			actualReason: "exceeds limit",
			shouldPass:   true,
		},
		{
			name:         "fail expected, fail actual with wrong reason",
			expectPass:   false,
			actualPass:   false,
			expectReason: "limit",
			actualReason: "blocked",
			shouldPass:   false,
		},
		{
			name:         "fail expected, pass actual",
			expectPass:   false,
			actualPass:   true,
			expectReason: "",
			actualReason: "",
			shouldPass:   false,
		},
		{
			name:         "fail expected with no reason specified, any fail is ok",
			expectPass:   false,
			actualPass:   false,
			expectReason: "",
			actualReason: "any random error",
			shouldPass:   true,
		},
		{
			name:         "fail expected with partial match",
			expectPass:   false,
			actualPass:   false,
			expectReason: "exceeds",
			actualReason: "value exceeds maximum",
			shouldPass:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.compareTestResult(tt.expectPass, tt.actualPass, tt.expectReason, tt.actualReason)
			assert.Equal(t, tt.shouldPass, result)
		})
	}
}

func TestSolidityRuleValidator_TestInputToRequest(t *testing.T) {
	v := &SolidityRuleValidator{}

	tests := []struct {
		name           string
		input          SolidityTestInput
		expectedChain  string
		expectedSigner string
		expectedTo     *string
		expectedValue  *string
	}{
		{
			name:           "empty input uses defaults",
			input:          SolidityTestInput{},
			expectedChain:  "1",
			expectedSigner: "0x0000000000000000000000000000000000000000",
			expectedTo:     nil,
			expectedValue:  nil,
		},
		{
			name: "full input",
			input: SolidityTestInput{
				To:      "0x1234567890123456789012345678901234567890",
				Value:   "1000000000000000000",
				ChainID: "137",
				Signer:  "0xabcdef1234567890abcdef1234567890abcdef12",
			},
			expectedChain:  "137",
			expectedSigner: "0xabcdef1234567890abcdef1234567890abcdef12",
			expectedTo:     strPtr("0x1234567890123456789012345678901234567890"),
			expectedValue:  strPtr("1000000000000000000"),
		},
		{
			name: "with selector",
			input: SolidityTestInput{
				Selector: "0xa9059cbb",
			},
			expectedChain:  "1",
			expectedSigner: "0x0000000000000000000000000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, parsed := v.testInputToRequest(tt.input)

			assert.Equal(t, tt.expectedChain, req.ChainID)
			assert.Equal(t, tt.expectedSigner, req.SignerAddress)

			if tt.expectedTo == nil {
				assert.Nil(t, parsed.Recipient)
			} else {
				require.NotNil(t, parsed.Recipient)
				assert.Equal(t, *tt.expectedTo, *parsed.Recipient)
			}

			if tt.expectedValue == nil {
				assert.Nil(t, parsed.Value)
			} else {
				require.NotNil(t, parsed.Value)
				assert.Equal(t, *tt.expectedValue, *parsed.Value)
			}
		})
	}
}

func TestSolidityRuleValidator_TestInputToRequest_DataParsing(t *testing.T) {
	v := &SolidityRuleValidator{}

	// Test hex data parsing
	input := SolidityTestInput{
		Data: "0xa9059cbb0000000000000000000000001234567890123456789012345678901234567890",
	}

	_, parsed := v.testInputToRequest(input)
	require.NotNil(t, parsed.RawData)
	assert.Equal(t, 36, len(parsed.RawData)) // 4 bytes selector + 32 bytes address

	// Verify first 4 bytes are the selector
	assert.Equal(t, byte(0xa9), parsed.RawData[0])
	assert.Equal(t, byte(0x05), parsed.RawData[1])
	assert.Equal(t, byte(0x9c), parsed.RawData[2])
	assert.Equal(t, byte(0xbb), parsed.RawData[3])
}

func TestParseSolidityError(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		hasError bool
		severity string
	}{
		{
			name:     "Error with code",
			output:   "Error (1234): Expected ';' but got '}'",
			hasError: true,
			severity: "error",
		},
		{
			name:     "ParserError",
			output:   "ParserError: Invalid token",
			hasError: true,
			severity: "error",
		},
		{
			name:     "TypeError",
			output:   "TypeError: Type mismatch",
			hasError: true,
			severity: "error",
		},
		{
			name:     "success output (empty)",
			output:   "",
			hasError: true, // still returns error struct with "unknown" message
			severity: "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSolidityError(tt.output)
			if tt.hasError {
				assert.NotNil(t, result)
				assert.Equal(t, tt.severity, result.Severity)
				assert.NotEmpty(t, result.Message)
			}
		})
	}
}

func TestValidationResult_Fields(t *testing.T) {
	result := ValidationResult{
		Valid: true,
		TestCaseResults: []TestCaseResult{
			{
				Name:           "test1",
				Passed:         true,
				ExpectedPass:   true,
				ActualPass:     true,
				ExpectedReason: "",
				ActualReason:   "",
			},
		},
		FailedTestCases: 0,
	}

	assert.True(t, result.Valid)
	assert.Nil(t, result.SyntaxError)
	assert.Len(t, result.TestCaseResults, 1)
	assert.Equal(t, 0, result.FailedTestCases)
}

func TestValidationResult_WithSyntaxError(t *testing.T) {
	result := ValidationResult{
		Valid: false,
		SyntaxError: &SyntaxError{
			Message:  "Expected ';'",
			Line:     10,
			Column:   5,
			Severity: "error",
		},
	}

	assert.False(t, result.Valid)
	assert.NotNil(t, result.SyntaxError)
	assert.Equal(t, "Expected ';'", result.SyntaxError.Message)
	assert.Equal(t, 10, result.SyntaxError.Line)
	assert.Equal(t, "error", result.SyntaxError.Severity)
}

func TestTestCaseResult_Fields(t *testing.T) {
	// Test case that passed
	passedResult := TestCaseResult{
		Name:           "should pass",
		Passed:         true,
		ExpectedPass:   true,
		ActualPass:     true,
		ExpectedReason: "",
		ActualReason:   "",
		Error:          "",
	}
	assert.True(t, passedResult.Passed)
	assert.Empty(t, passedResult.Error)

	// Test case that failed
	failedResult := TestCaseResult{
		Name:           "should fail",
		Passed:         false,
		ExpectedPass:   true,
		ActualPass:     false,
		ExpectedReason: "",
		ActualReason:   "exceeded limit",
		Error:          "expected pass but got revert: exceeded limit",
	}
	assert.False(t, failedResult.Passed)
	assert.NotEmpty(t, failedResult.Error)
}

func TestSolidityRuleValidator_Type(t *testing.T) {
	// Verify the rule type constant
	assert.Equal(t, types.RuleType("evm_solidity_expression"), types.RuleTypeEVMSolidityExpression)
}
