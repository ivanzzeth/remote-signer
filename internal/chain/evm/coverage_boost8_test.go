package evm

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

var bgCtx = context.Background()

// ─────────────────────────────────────────────────────────────────────────────
// generateExpressionScript / generateFunctionScript (solidity_script_gen.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestGenerateExpressionScript(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	script, err := e.generateExpressionScript("require(value <= 1 ether, \"exceeds\");", nil)
	require.NoError(t, err)
	assert.Contains(t, script, "pragma solidity")
	assert.Contains(t, script, "RuleEvaluator is Script")
	assert.Contains(t, script, "require(value <= 1 ether, \"exceeds\");")
}

func TestGenerateExpressionScript_WithMappingArrays(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	// Expression must use in() to trigger mapping generation
	script, err := e.generateExpressionScript("require(in(txTo, addrs), \"bad\");", map[string][]string{
		"addrs": {"0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"},
	})
	require.NoError(t, err)
	assert.Contains(t, script, "addrs_mapping")
	assert.Contains(t, script, "mapping(address => bool)")
}

func TestGenerateFunctionScript(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	script, err := e.generateFunctionScript("function transfer(address,uint256) external { require(true); }", nil)
	require.NoError(t, err)
	assert.Contains(t, script, "RuleContract")
	assert.Contains(t, script, "RuleEvaluatorTest is Test")
	assert.Contains(t, script, "function transfer")
}

func TestGenerateFunctionScript_WithMappingArrays(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	// Functions must include in() to trigger mapping generation
	script, err := e.generateFunctionScript("function check(address to) external { require(in(to, addrs), \"bad\"); }", map[string][]string{
		"addrs": {"0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"},
	})
	require.NoError(t, err)
	assert.Contains(t, script, "addrs_mapping")
	assert.Contains(t, script, "mapping(address => bool)")
}

// ─────────────────────────────────────────────────────────────────────────────
// GenerateSyntaxCheckScript / GenerateFunctionSyntaxCheckScript
// ─────────────────────────────────────────────────────────────────────────────

func TestGenerateSyntaxCheckScript(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	script := e.GenerateSyntaxCheckScript("require(true);")
	assert.Contains(t, script, "SyntaxCheck")
	assert.Contains(t, script, "require(true);")
	assert.Contains(t, script, "contract SyntaxCheck")
}

func TestGenerateSyntaxCheckScript_WithMappingArrays(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	// SyntaxCheck script does NOT embed mapping declarations; the expression is preprocessed but only the
	// modified expression (e.g., addrs_mapping[txTo]) is included. Verifying the mapping reference is present
	// rather than the declaration, since GenerateSyntaxCheckScript only includes the expression body.
	script := e.GenerateSyntaxCheckScript("require(in(txTo, addrs),\"bad\");", map[string][]string{
		"addrs": {"0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"},
	})
	assert.Contains(t, script, "addrs_mapping")
	assert.NotContains(t, script, "addrs_mapping_mapping")
}

func TestGenerateFunctionSyntaxCheckScript(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	script := e.GenerateFunctionSyntaxCheckScript("function foo() external pure {}")
	assert.Contains(t, script, "contract RuleContract")
	assert.Contains(t, script, "contract RuleEvaluatorTest")
	assert.Contains(t, script, "function foo()")
}

func TestGenerateFunctionSyntaxCheckScript_WithMapping(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	script := e.GenerateFunctionSyntaxCheckScript("function check(address to) external { require(in(to, addrs), \"bad\"); }", map[string][]string{
		"addrs": {"0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"},
	})
	assert.Contains(t, script, "addrs_mapping")
}

// ─────────────────────────────────────────────────────────────────────────────
// generateTypedDataExpressionScript / generateTypedDataFunctionsScript (solidity_typed_data.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestGenerateTypedDataExpressionScript(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	req := &types.SignRequest{
		SignerAddress: "0x1234567890123456789012345678901234567890",
		ChainID:       "1",
	}
	typedData := &TypedDataPayload{
		PrimaryType: "Order",
		Domain: TypedDataDomain{
			Name:    "Test",
			Version: "1",
			ChainId: "1",
		},
		Message: map[string]interface{}{
			"maker": "0x1234567890123456789012345678901234567890",
		},
		Types: map[string][]TypedDataField{
			"Order": {
				{Name: "maker", Type: "address"},
			},
		},
	}
	structDef := &StructDefinition{
		Name: "Order",
		Fields: []TypedDataField{
			{Name: "maker", Type: "address"},
		},
	}

	script, err := e.generateTypedDataExpressionScript(
		"require(order.maker != address(0), \"no maker\");",
		req, typedData, structDef, nil,
	)
	require.NoError(t, err)
	assert.Contains(t, script, "order.maker")
	assert.Contains(t, script, "struct Order")
	assert.Contains(t, script, "maker")
}

func TestGenerateTypedDataExpressionScript_NoStruct(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	req := &types.SignRequest{
		SignerAddress: "0x1234567890123456789012345678901234567890",
		ChainID:       "1",
	}
	typedData := &TypedDataPayload{
		PrimaryType: "Permit",
		Domain: TypedDataDomain{
			Name:    "Test",
			Version: "1",
			ChainId: "1",
		},
		Message: map[string]interface{}{
			"owner": "0x1234567890123456789012345678901234567890",
		},
		Types: map[string][]TypedDataField{
			"Permit": {
				{Name: "owner", Type: "address"},
			},
		},
	}

	script, err := e.generateTypedDataExpressionScript(
		"require(owner != address(0), \"no owner\");",
		req, typedData, nil, nil,
	)
	require.NoError(t, err)
	assert.Contains(t, script, "address owner")
	assert.NotContains(t, script, "struct Permit")
}

func TestGenerateTypedDataExpressionScript_WithMappingArrays(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	req := &types.SignRequest{
		SignerAddress: "0x1234567890123456789012345678901234567890",
		ChainID:       "1",
	}
	typedData := &TypedDataPayload{
		PrimaryType: "Order",
		Domain:      TypedDataDomain{Name: "Test", Version: "1", ChainId: "1"},
		Message:     map[string]interface{}{"maker": "0x1234567890123456789012345678901234567890"},
		Types: map[string][]TypedDataField{
			"Order": {{Name: "maker", Type: "address"}},
		},
	}
	structDef := &StructDefinition{Name: "Order", Fields: []TypedDataField{{Name: "maker", Type: "address"}}}

	// Expression must use in() to trigger mapping generation
	script, err := e.generateTypedDataExpressionScript(
		"require(in(order.maker, addrs), \"bad\");",
		req, typedData, structDef,
		map[string][]string{"addrs": {"0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"}},
	)
	require.NoError(t, err)
	assert.Contains(t, script, "addrs_mapping")
}

func TestGenerateTypedDataFunctionsScript(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	req := &types.SignRequest{
		SignerAddress: "0x1234567890123456789012345678901234567890",
		ChainID:       "1",
	}
	typedData := &TypedDataPayload{
		PrimaryType: "Order",
		Domain:      TypedDataDomain{Name: "Test", Version: "1", ChainId: "1"},
		Message:     map[string]interface{}{"maker": "0x1234567890123456789012345678901234567890"},
		Types: map[string][]TypedDataField{
			"Order": {{Name: "maker", Type: "address"}},
		},
	}

	script, err := e.generateTypedDataFunctionsScript(
		"function _validateMessage() internal override {}",
		req, typedData, nil,
	)
	require.NoError(t, err)
	assert.Contains(t, script, "messageData")
	assert.Contains(t, script, "_validateMessage")
	assert.Contains(t, script, "hex\"")
}

// ─────────────────────────────────────────────────────────────────────────────
// GenerateTypedDataExpressionSyntaxCheckScript / WithStruct / Functions
// ─────────────────────────────────────────────────────────────────────────────

func TestGenerateTypedDataExpressionSyntaxCheckScript(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	script := e.GenerateTypedDataExpressionSyntaxCheckScript("require(true);")
	assert.Contains(t, script, "SyntaxCheck")
	assert.Contains(t, script, "eip712_primaryType")
	assert.Contains(t, script, "require(true);")
	// Check that no Solidity struct declaration exists (the variable name "typed_data_struct" in comments is fine)
	assert.NotContains(t, script, "struct Order")
}

func TestGenerateTypedDataExpressionSyntaxCheckScript_WithStruct(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	structDef := &StructDefinition{
		Name: "Order",
		Fields: []TypedDataField{
			{Name: "maker", Type: "address"},
			{Name: "salt", Type: "uint256"},
		},
	}
	script := e.GenerateTypedDataExpressionSyntaxCheckScriptWithStruct(
		"require(order.maker != address(0));",
		structDef,
	)
	assert.Contains(t, script, "struct Order")
	assert.Contains(t, script, "address maker")
	assert.Contains(t, script, "uint256 salt")
	assert.Contains(t, script, "order.maker")
}

func TestGenerateTypedDataExpressionSyntaxCheckScript_WithStructAndMapping(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	structDef := &StructDefinition{
		Name:   "Order",
		Fields: []TypedDataField{{Name: "maker", Type: "address"}},
	}
	script := e.GenerateTypedDataExpressionSyntaxCheckScriptWithStruct(
		"require(in(order.maker, addrs), \"bad\");",
		structDef,
		map[string][]string{"addrs": {"0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"}},
	)
	assert.Contains(t, script, "struct Order")
	assert.Contains(t, script, "addrs_mapping")
}

func TestGenerateTypedDataExpressionSyntaxCheckScript_NoStruct(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	script := e.GenerateTypedDataExpressionSyntaxCheckScriptWithStruct("require(true);", nil)
	assert.NotContains(t, script, "struct Order")
}

func TestGenerateTypedDataFunctionsSyntaxCheckScript(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	script := e.GenerateTypedDataFunctionsSyntaxCheckScript("function _validateMessage() internal override {}")
	assert.Contains(t, script, "messageData")
	assert.Contains(t, script, "_validateMessage")
	assert.Contains(t, script, "ctx_signer")
}

func TestGenerateTypedDataFunctionsSyntaxCheckScript_WithMapping(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	script := e.GenerateTypedDataFunctionsSyntaxCheckScript("function check(address to) external { require(in(to, addrs), \"bad\"); }", map[string][]string{
		"addrs": {"0xaC52BebecA7f5FA1561fa9Ab8DA136602D21b837"},
	})
	assert.Contains(t, script, "addrs_mapping")
}

// ─────────────────────────────────────────────────────────────────────────────
// encodeMessageData (solidity_typed_data_format.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestEncodeMessageData(t *testing.T) {
	result := encodeMessageData(nil)
	assert.Equal(t, `hex""`, result)

	result = encodeMessageData(&TypedDataPayload{Message: nil})
	assert.Equal(t, `hex""`, result)

	result = encodeMessageData(&TypedDataPayload{
		Message: map[string]interface{}{"name": "test", "value": "123"},
	})
	assert.Contains(t, result, `hex"`)
	assert.True(t, len(result) > 10)
}

// ─────────────────────────────────────────────────────────────────────────────
// GetFoundryPath / GetCacheDir / GetTimeout (solidity_execution.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestSolidityRuleEvaluator_Getters(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	assert.NotEmpty(t, e.GetTempDir())
	assert.NotEmpty(t, e.GetFoundryPath())
	assert.NotEmpty(t, e.GetCacheDir())
	assert.Equal(t, 30*time.Second, e.GetTimeout())
}

// ─────────────────────────────────────────────────────────────────────────────
// AppliesToSignType (solidity_evaluator.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestSolidityRuleEvaluator_AppliesToSignType(t *testing.T) {
	e := newTestSolidityEvaluator(t)

	rule := &types.Rule{
		Config: mustJSONMarshal(t, SolidityExpressionConfig{Expression: "require(true);"}),
	}
	assert.True(t, e.AppliesToSignType(rule, "transaction"))
	assert.True(t, e.AppliesToSignType(rule, "typed_data"))

	rule2 := &types.Rule{
		Config: mustJSONMarshal(t, SolidityExpressionConfig{
			Expression:     "require(true);",
			SignTypeFilter: "transaction",
		}),
	}
	assert.True(t, e.AppliesToSignType(rule2, "transaction"))
	assert.False(t, e.AppliesToSignType(rule2, "typed_data"))

	rule3 := &types.Rule{Config: []byte("not valid json")}
	assert.True(t, e.AppliesToSignType(rule3, "transaction"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Evaluate with SignTypeFilter skip (solidity_evaluator.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestSolidityRuleEvaluator_Evaluate_SignTypeFilterSkip(t *testing.T) {
	e := newTestSolidityEvaluator(t)
	rule := &types.Rule{
		ID:   "skip-test",
		Mode: types.RuleModeWhitelist,
		Config: mustJSONMarshal(t, SolidityExpressionConfig{
			Expression:     "require(true);",
			SignTypeFilter: "transaction",
		}),
	}
	req := &types.SignRequest{
		SignType:       "typed_data",
		SignerAddress:  "0x1234567890123456789012345678901234567890",
		ChainID:        "1",
		Payload:        []byte(`{"typed_data":{"types":{"EIP712Domain":[]},"primaryType":"EIP712Domain","domain":{},"message":{}}}`),
	}

	passed, reason, err := e.Evaluate(bgCtx, rule, req, nil)
	require.NoError(t, err)
	assert.False(t, passed)
	assert.Empty(t, reason)
}

// ─────────────────────────────────────────────────────────────────────────────
// sanitizeEmptyComparisons (solidity_script_gen.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestSanitizeEmptyComparisons(t *testing.T) {
	tests := []struct {
		input    string
		contains string
	}{
		{"x == )", "x == address(0)"},
		{"chainId == )", "chainId == 0"},
		{"x == , ", "x == address(0), "},
		{"x == ||", "x == address(0) ||"},
		{"x == &&", "x == address(0) &&"},
		{"x == ;", "x == address(0);"},
		{"x != )", "x != address(0)"},
		{" != , ", " != address(0), "},
		{" != ||", " != address(0) ||"},
		{" != &&", " != address(0) &&"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeEmptyComparisons(tt.input)
			assert.Contains(t, result, tt.contains)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// format helpers (solidity_typed_data_format.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestFormatString(t *testing.T) {
	assert.Equal(t, `""`, formatString(""))
	assert.Equal(t, `"hello"`, formatString("hello"))
	assert.Equal(t, `"hello \"world\""`, formatString(`hello "world"`))
	assert.Equal(t, `"back\\slash"`, formatString(`back\slash`))
}

func TestFormatDomainChainId(t *testing.T) {
	assert.Equal(t, "0", formatDomainChainId(""))
	assert.Equal(t, "1", formatDomainChainId("1"))
	assert.Equal(t, "137", formatDomainChainId("137"))
	assert.Equal(t, "0", formatDomainChainId("abc"))
	assert.Equal(t, "0", formatDomainChainId("1; DROP TABLE"))
}

func TestFormatDomainContract(t *testing.T) {
	assert.Equal(t, "address(0)", formatDomainContract(""))
	validAddr := "0x0000000000000000000000000000000000000000"
	assert.Equal(t, validAddr, formatDomainContract(validAddr))
	assert.Equal(t, "address(0)", formatDomainContract("not_an_address"))
}

func TestFormatInterfaceAsAddress(t *testing.T) {
	assert.Equal(t, "address(0)", formatInterfaceAsAddress(nil))
	assert.Equal(t, "address(0)", formatInterfaceAsAddress(""))
	assert.Equal(t, "address(0)", formatInterfaceAsAddress(123))
	assert.Equal(t, "address(0)", formatInterfaceAsAddress("not_addr"))
	valid := "0x1234567890123456789012345678901234567890"
	assert.Equal(t, "0x1234567890123456789012345678901234567890", formatInterfaceAsAddress(valid))
}

func TestFormatInterfaceAsUint(t *testing.T) {
	assert.Equal(t, "0", formatInterfaceAsUint(nil))
	assert.Equal(t, "0", formatInterfaceAsUint(""))
	assert.Equal(t, "0", formatInterfaceAsUint("abc"))
	assert.Equal(t, "42", formatInterfaceAsUint("42"))
	assert.Equal(t, "42", formatInterfaceAsUint(42))
	assert.Equal(t, "42", formatInterfaceAsUint(int64(42)))
	assert.Equal(t, "42", formatInterfaceAsUint(uint64(42)))
	assert.Equal(t, "42", formatInterfaceAsUint(42.0))
}

func TestFormatInterfaceAsInt(t *testing.T) {
	assert.Equal(t, "0", formatInterfaceAsInt(nil))
	assert.Equal(t, "0", formatInterfaceAsInt(""))
	assert.Equal(t, "0", formatInterfaceAsInt("abc"))
	assert.Equal(t, "42", formatInterfaceAsInt("42"))
	assert.Equal(t, "-42", formatInterfaceAsInt("-42"))
	assert.Equal(t, "0", formatInterfaceAsInt("-"))
}

func TestFormatInterfaceAsBool(t *testing.T) {
	assert.Equal(t, "false", formatInterfaceAsBool(nil))
	assert.Equal(t, "true", formatInterfaceAsBool(true))
	assert.Equal(t, "false", formatInterfaceAsBool(false))
	assert.Equal(t, "true", formatInterfaceAsBool("true"))
	assert.Equal(t, "false", formatInterfaceAsBool("false"))
	assert.Equal(t, "false", formatInterfaceAsBool("other"))
}

func TestFormatInterfaceAsBytes32(t *testing.T) {
	assert.Equal(t, "bytes32(0)", formatInterfaceAsBytes32(nil))
	assert.Equal(t, "bytes32(0)", formatInterfaceAsBytes32(""))
	assert.Equal(t, "bytes32(0)", formatInterfaceAsBytes32("short"))
	validHex := "0x" + strings.Repeat("ab", 32)
	assert.Equal(t, validHex, formatInterfaceAsBytes32(validHex))
}

func TestFormatInterfaceAsBytes(t *testing.T) {
	assert.Equal(t, `hex""`, formatInterfaceAsBytes(nil))
	assert.Equal(t, `hex""`, formatInterfaceAsBytes(""))
	assert.Equal(t, `hex"dead"`, formatInterfaceAsBytes("0xdead"))
	assert.Equal(t, `hex"dead"`, formatInterfaceAsBytes([]byte{0xde, 0xad}))
	result := formatInterfaceAsBytes("hello")
	assert.Contains(t, result, `hex"`)
	assert.True(t, len(result) > 6)
}

func TestFormatInterfaceAsString(t *testing.T) {
	assert.Equal(t, `""`, formatInterfaceAsString(nil))
	assert.Equal(t, `"hello"`, formatInterfaceAsString("hello"))
	assert.Equal(t, `""`, formatInterfaceAsString(42))
}

func TestFormatInterfaceAsFixedBytes(t *testing.T) {
	assert.Equal(t, "bytes8(0)", formatInterfaceAsFixedBytes(nil, "bytes8"))
	assert.Equal(t, "bytes8(0)", formatInterfaceAsFixedBytes("", "bytes8"))
	assert.Equal(t, "0xdead", formatInterfaceAsFixedBytes("0xdead", "bytes8"))
	assert.Equal(t, "bytes8(0)", formatInterfaceAsFixedBytes("0xZZ", "bytes8"))
}

// ─────────────────────────────────────────────────────────────────────────────
// escapeReservedKeyword (solidity_typed_data_format.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestEscapeReservedKeyword(t *testing.T) {
	assert.Equal(t, "_address", escapeReservedKeyword("address"))
	assert.Equal(t, "_bool", escapeReservedKeyword("bool"))
	assert.Equal(t, "_string", escapeReservedKeyword("string"))
	assert.Equal(t, "_for", escapeReservedKeyword("for"))
	assert.Equal(t, "myField", escapeReservedKeyword("myField"))
	assert.Equal(t, "normalName", escapeReservedKeyword("normalName"))
}

// ─────────────────────────────────────────────────────────────────────────────
// parseTypedDataFromPayload (solidity_typed_data_format.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestParseTypedDataFromPayload(t *testing.T) {
	payload := []byte(`{"typed_data":{"types":{"EIP712Domain":[]},"primaryType":"EIP712Domain","domain":{},"message":{}}}`)
	td, err := parseTypedDataFromPayload(payload)
	require.NoError(t, err)
	assert.NotNil(t, td)
	assert.Equal(t, "EIP712Domain", td.PrimaryType)

	_, err = parseTypedDataFromPayload([]byte(`{}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "typed_data field is required")

	_, err = parseTypedDataFromPayload([]byte(`not json`))
	require.Error(t, err)
}

// ─────────────────────────────────────────────────────────────────────────────
// generateMessageFieldDeclarations / generateFieldDeclaration
// ─────────────────────────────────────────────────────────────────────────────

func TestGenerateMessageFieldDeclarations(t *testing.T) {
	assert.Equal(t, "", generateMessageFieldDeclarations(nil))

	result := generateMessageFieldDeclarations(&TypedDataPayload{
		PrimaryType: "Order",
		Types: map[string][]TypedDataField{
			"Order": {
				{Name: "maker", Type: "address"},
				{Name: "amount", Type: "uint256"},
				{Name: "active", Type: "bool"},
			},
		},
		Message: map[string]interface{}{
			"maker":  "0x1234567890123456789012345678901234567890",
			"amount": "1000",
			"active": true,
		},
	})
	assert.Contains(t, result, "address maker")
	assert.Contains(t, result, "uint256 amount")
	assert.Contains(t, result, "bool active")
}

func TestGenerateFieldDeclaration(t *testing.T) {
	result := generateFieldDeclaration("123bad", "address", "0x1234")
	assert.Contains(t, result, "Skipped")

	result = generateFieldDeclaration("myfield", "imaginary_type", "val")
	assert.Contains(t, result, "Skipped")

	result = generateFieldDeclaration("myaddr", "address", "0x1234567890123456789012345678901234567890")
	assert.Contains(t, result, "address myaddr")

	result = generateFieldDeclaration("address", "address", "0x1234567890123456789012345678901234567890")
	assert.Contains(t, result, "_address")

	result = generateFieldDeclaration("name", "string", "hello")
	assert.Contains(t, result, "string memory name")

	result = generateFieldDeclaration("data", "bytes", "0xdead")
	assert.Contains(t, result, "bytes memory data")

	result = generateFieldDeclaration("hash", "bytes32", "0x"+strings.Repeat("ab", 32))
	assert.Contains(t, result, "bytes32 hash")

	result = generateFieldDeclaration("small", "uint8", "42")
	assert.Contains(t, result, "uint8 small = 42")

	result = generateFieldDeclaration("neg", "int256", "-1")
	assert.Contains(t, result, "int256 neg")
}

// ─────────────────────────────────────────────────────────────────────────────
// buildRequestEnv (solidity_env.go) - new coverage
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildRequestEnv_NilInputs(t *testing.T) {
	assert.Nil(t, buildRequestEnv(nil, nil))
	assert.Nil(t, buildRequestEnv(&types.SignRequest{}, nil))
}

func TestBuildRequestEnv_WithData(t *testing.T) {
	req := &types.SignRequest{
		SignerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		ChainID:       "137",
	}
	selector := "0xa9059cbb"
	parsed := &types.ParsedPayload{
		Recipient: strPtr("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
		MethodSig: &selector,
		RawData:   []byte{0xa9, 0x05, 0x9c, 0xbb, 0x00},
		Value:     strPtr("1000000"),
	}
	env := buildRequestEnv(req, parsed)
	require.NotNil(t, env)
	assert.Len(t, env, 6)
	found := false
	for _, e := range env {
		if strings.HasPrefix(e, "RULE_CHAIN_ID=137") {
			found = true
		}
	}
	assert.True(t, found, "expected RULE_CHAIN_ID=137 in env")
}

// ─────────────────────────────────────────────────────────────────────────────
// addressForEnv (solidity_env.go)
// ─────────────────────────────────────────────────────────────────────────────

func TestAddressForEnv(t *testing.T) {
	zero := "0x0000000000000000000000000000000000000000"
	assert.Equal(t, zero, addressForEnv(nil))
	assert.Equal(t, zero, addressForEnv(strPtr("")))
	assert.Equal(t, zero, addressForEnv(strPtr("not_valid")))
	valid := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	assert.Equal(t, valid, addressForEnv(strPtr(valid)))
}

// ─────────────────────────────────────────────────────────────────────────────
// newTestSolidityEvaluator helper (only for forge-dependent tests)
// ─────────────────────────────────────────────────────────────────────────────

func newTestSolidityEvaluator(t *testing.T) *SolidityRuleEvaluator {
	t.Helper()
	e, err := NewSolidityRuleEvaluator(SolidityEvaluatorConfig{}, newTestLogger())
	if err != nil {
		t.Skipf("forge not available: %v", err)
	}
	return e
}
