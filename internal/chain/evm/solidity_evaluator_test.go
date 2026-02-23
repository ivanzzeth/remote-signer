package evm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestProcessInOperatorToMappings(t *testing.T) {
	tests := []struct {
		name            string
		source          string
		inMappingArrays map[string][]string
		wantModified    string
		wantDecl        string
		wantInit        string
	}{
		{
			name:            "in(expr, varName) with nil arrays still replaces for syntax check",
			source:          "require(in(txTo, allowed_safe_addresses), \"bad\");",
			inMappingArrays: nil,
			wantModified:    "require(allowed_safe_addresses_mapping[txTo], \"bad\");",
			wantDecl:        "mapping(address => bool) private allowed_safe_addresses_mapping;",
			wantInit:        "",
		},
		{
			name:            "in(expr, varName) with arrays",
			source:          "require(in(txTo, allowed_safe_addresses), \"bad\");",
			inMappingArrays: map[string][]string{"allowed_safe_addresses": {"0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"}},
			wantModified:    "require(allowed_safe_addresses_mapping[txTo], \"bad\");",
			wantDecl:        "mapping(address => bool) private allowed_safe_addresses_mapping;",
			wantInit:        "allowed_safe_addresses_mapping[0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837] = true;",
		},
		{
			name:            "in(expr, varName) no array leaves for preprocessInOperator",
			source:          "require(in(txTo, 0xa, 0xb), \"bad\");",
			inMappingArrays: map[string][]string{},
			wantModified:    "require(in(txTo, 0xa, 0xb), \"bad\");",
			wantDecl:        "",
			wantInit:        "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := processInOperatorToMappings(tt.source, tt.inMappingArrays)
			assert.Equal(t, tt.wantModified, got.Modified)
			assert.Equal(t, tt.wantDecl, got.Declarations)
			assert.Equal(t, tt.wantInit, got.ConstructorInit)
		})
	}
}

func TestPreprocessInOperator(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single value",
			input:    "in(x, 0xAAA)",
			expected: "(x == 0xAAA)",
		},
		{
			name:     "multiple values",
			input:    "in(eip712_domainContract, 0xAAA, 0xBBB, 0xCCC)",
			expected: "(eip712_domainContract == 0xAAA || eip712_domainContract == 0xBBB || eip712_domainContract == 0xCCC)",
		},
		{
			name:     "with spaces",
			input:    "in( txTo , 0x1 , 0x2 )",
			expected: "(txTo == 0x1 || txTo == 0x2)",
		},
		{
			name:     "no match unchanged",
			input:    "txTo == 0xOnly",
			expected: "txTo == 0xOnly",
		},
		{
			name:     "empty expression unchanged",
			input:    "",
			expected: "",
		},
		{
			name:     "empty list expands to false",
			input:    "in(txTo, )",
			expected: "false",
		},
		{
			name:     "empty list no space expands to false",
			input:    "in(txTo,)",
			expected: "false",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := preprocessInOperator(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestFormatAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    *string
		expected string
	}{
		{
			name:     "nil address",
			input:    nil,
			expected: "address(0)",
		},
		{
			name:     "empty address",
			input:    strPtr(""),
			expected: "address(0)",
		},
		{
			name:     "valid address",
			input:    strPtr("0x1234567890123456789012345678901234567890"),
			expected: "0x1234567890123456789012345678901234567890",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatAddress(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatWei(t *testing.T) {
	tests := []struct {
		name     string
		input    *string
		expected string
	}{
		{
			name:     "nil value",
			input:    nil,
			expected: "0",
		},
		{
			name:     "empty value",
			input:    strPtr(""),
			expected: "0",
		},
		{
			name:     "valid value",
			input:    strPtr("1000000000000000000"),
			expected: "1000000000000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatWei(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatSelector(t *testing.T) {
	tests := []struct {
		name     string
		input    *string
		expected string
	}{
		{
			name:     "nil selector",
			input:    nil,
			expected: "bytes4(0)",
		},
		{
			name:     "empty selector",
			input:    strPtr(""),
			expected: "bytes4(0)",
		},
		{
			name:     "with 0x prefix",
			input:    strPtr("0xa9059cbb"),
			expected: "bytes4(0xa9059cbb)",
		},
		{
			name:     "without 0x prefix",
			input:    strPtr("a9059cbb"),
			expected: "bytes4(0xa9059cbb)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatSelector(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty bytes",
			input:    []byte{},
			expected: `hex""`,
		},
		{
			name:     "nil bytes",
			input:    nil,
			expected: `hex""`,
		},
		{
			name:     "valid bytes",
			input:    []byte{0xa9, 0x05, 0x9c, 0xbb},
			expected: `hex"a9059cbb"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatBytes(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatChainID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty chain ID",
			input:    "",
			expected: "1",
		},
		{
			name:     "valid chain ID",
			input:    "137",
			expected: "137",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatChainID(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseRevertReason(t *testing.T) {
	tests := []struct {
		name     string
		output   []byte
		expected string
	}{
		{
			name:     "empty output",
			output:   []byte{},
			expected: "",
		},
		{
			name:     "JSON return_data pattern",
			output:   []byte(`{"success":false,"traces":[],"decoded":{"return_data":"value exceeds 1 ETH"}}`),
			expected: "value exceeds 1 ETH",
		},
		{
			name:     "Error script failed pattern",
			output:   []byte("Error: script failed: exceeds limit\nsome other output"),
			expected: "exceeds limit",
		},
		{
			name:     "revert with reason",
			output:   []byte("revert: exceeds limit\nsome other output"),
			expected: "exceeds limit",
		},
		{
			name:     "general Error pattern",
			output:   []byte("Error: value too high"),
			expected: "value too high",
		},
		{
			name:     "panic pattern",
			output:   []byte("Panic(0x11)"),
			expected: "panic: 0x11",
		},
		{
			name:     "compiler error should be empty",
			output:   []byte("Error: Compiler run failed\nsome error"),
			expected: "",
		},
		{
			name:     "no revert reason",
			output:   []byte("some random output"),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseRevertReason(tt.output)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSolidityRuleEvaluator_Type(t *testing.T) {
	// This test doesn't require Foundry
	// We can't create a real evaluator without forge, but we can test the Type constant
	assert.Equal(t, types.RuleType("evm_solidity_expression"), types.RuleTypeEVMSolidityExpression)
}

func TestSolidityExpressionConfig_JSON(t *testing.T) {
	// Test JSON marshaling/unmarshaling of config
	config := SolidityExpressionConfig{
		Expression:  `require(value <= 1 ether, "exceeds limit");`,
		Description: "Test rule",
		TestCases: []SolidityTestCase{
			{
				Name: "should pass for 0.5 ETH",
				Input: SolidityTestInput{
					Value: "500000000000000000",
					To:    "0x1234567890123456789012345678901234567890",
				},
				ExpectPass: true,
			},
			{
				Name: "should fail for 2 ETH",
				Input: SolidityTestInput{
					Value: "2000000000000000000",
					To:    "0x1234567890123456789012345678901234567890",
				},
				ExpectPass:   false,
				ExpectReason: "exceeds limit",
			},
		},
	}

	require.NotEmpty(t, config.Expression)
	require.Len(t, config.TestCases, 2)
	require.True(t, config.TestCases[0].ExpectPass)
	require.False(t, config.TestCases[1].ExpectPass)
	require.Equal(t, "exceeds limit", config.TestCases[1].ExpectReason)
}

func TestSolidityTestInput_Defaults(t *testing.T) {
	input := SolidityTestInput{}

	// Empty input should result in default values
	assert.Empty(t, input.To)
	assert.Empty(t, input.Value)
	assert.Empty(t, input.Selector)
	assert.Empty(t, input.Data)
	assert.Empty(t, input.ChainID)
	assert.Empty(t, input.Signer)
}

// Helper function
func strPtr(s string) *string {
	return &s
}
