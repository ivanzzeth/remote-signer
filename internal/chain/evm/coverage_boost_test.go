package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// =============================================================================
// test_case_input.go: TestCaseInputToSignRequest and stringFromMap (0% -> ~100%)
// =============================================================================

func TestStringFromMap_StringValue_CB(t *testing.T) {
	m := map[string]interface{}{"key": "hello"}
	assert.Equal(t, "hello", stringFromMap(m, "key"))
}

func TestStringFromMap_Float64WholeNumber_CB(t *testing.T) {
	m := map[string]interface{}{"chain_id": float64(137)}
	assert.Equal(t, "137", stringFromMap(m, "chain_id"))
}

func TestStringFromMap_Float64Fractional_CB(t *testing.T) {
	m := map[string]interface{}{"val": float64(1.5)}
	assert.Equal(t, "1.5", stringFromMap(m, "val"))
}

func TestStringFromMap_IntValue_CB(t *testing.T) {
	m := map[string]interface{}{"val": int(42)}
	assert.Equal(t, "42", stringFromMap(m, "val"))
}

func TestStringFromMap_Int64Value_CB(t *testing.T) {
	m := map[string]interface{}{"val": int64(999)}
	assert.Equal(t, "999", stringFromMap(m, "val"))
}

func TestStringFromMap_OtherType_CB(t *testing.T) {
	m := map[string]interface{}{"val": true}
	assert.Equal(t, "true", stringFromMap(m, "val"))
}

func TestStringFromMap_MissingKey_CB(t *testing.T) {
	m := map[string]interface{}{}
	assert.Equal(t, "", stringFromMap(m, "missing"))
}

func TestStringFromMap_NilValue_CB(t *testing.T) {
	m := map[string]interface{}{"key": nil}
	assert.Equal(t, "", stringFromMap(m, "key"))
}

func TestTestCaseInputToSignRequest_NilInput_CB(t *testing.T) {
	_, _, err := TestCaseInputToSignRequest(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "input is nil")
}

func TestTestCaseInputToSignRequest_DefaultChainIDAndSignType_CB(t *testing.T) {
	input := map[string]interface{}{
		"signer": "0x1234567890123456789012345678901234567890",
		"transaction": map[string]interface{}{
			"to":    "0xaabbccddaabbccddaabbccddaabbccddaabbccdd",
			"value": "1000000000000000000",
			"data":  "0xa9059cbb0001020304050607",
		},
	}
	req, parsed, err := TestCaseInputToSignRequest(input)
	require.NoError(t, err)
	assert.Equal(t, "1", req.ChainID)
	assert.Equal(t, SignTypeTransaction, req.SignType)
	assert.Equal(t, "0x1234567890123456789012345678901234567890", req.SignerAddress)
	assert.NotNil(t, parsed.Recipient)
	assert.NotNil(t, parsed.Value)
	assert.NotNil(t, parsed.MethodSig)
	assert.Equal(t, "0xa9059cbb", *parsed.MethodSig)
}

func TestTestCaseInputToSignRequest_TransactionWithShortData_CB(t *testing.T) {
	input := map[string]interface{}{
		"signer": "0x1234567890123456789012345678901234567890",
		"transaction": map[string]interface{}{
			"to":    "0xaabbccddaabbccddaabbccddaabbccddaabbccdd",
			"value": "",
			"data":  "0xabcd", // too short for method selector (< 8 hex chars after 0x)
		},
	}
	req, parsed, err := TestCaseInputToSignRequest(input)
	require.NoError(t, err)
	assert.NotNil(t, req)
	assert.Nil(t, parsed.MethodSig, "short data should not produce method sig")
}

func TestTestCaseInputToSignRequest_TransactionNoData_CB(t *testing.T) {
	input := map[string]interface{}{
		"signer": "0x1234567890123456789012345678901234567890",
		"transaction": map[string]interface{}{
			"to":    "0xaabbccddaabbccddaabbccddaabbccddaabbccdd",
			"value": "0",
		},
	}
	req, _, err := TestCaseInputToSignRequest(input)
	require.NoError(t, err)
	assert.NotNil(t, req.Payload)
}

func TestTestCaseInputToSignRequest_TransactionMissing_CB(t *testing.T) {
	// Transaction sign type but no transaction field
	input := map[string]interface{}{
		"signer":    "0x1234567890123456789012345678901234567890",
		"sign_type": "transaction",
	}
	req, _, err := TestCaseInputToSignRequest(input)
	require.NoError(t, err)
	assert.NotNil(t, req)
}

func TestTestCaseInputToSignRequest_TypedData_CB(t *testing.T) {
	input := map[string]interface{}{
		"signer":    "0x1234567890123456789012345678901234567890",
		"sign_type": "typed_data",
		"typed_data": map[string]interface{}{
			"primaryType": "Permit",
			"types": map[string]interface{}{
				"Permit": []interface{}{
					map[string]interface{}{"name": "owner", "type": "address"},
				},
			},
			"domain": map[string]interface{}{
				"name": "Test",
			},
			"message": map[string]interface{}{
				"owner": "0x1234567890123456789012345678901234567890",
			},
		},
	}
	req, _, err := TestCaseInputToSignRequest(input)
	require.NoError(t, err)
	assert.Equal(t, SignTypeTypedData, req.SignType)
	assert.NotNil(t, req.Payload)
}

func TestTestCaseInputToSignRequest_PersonalSignWithMessage_CB(t *testing.T) {
	input := map[string]interface{}{
		"signer":    "0x1234567890123456789012345678901234567890",
		"sign_type": "personal",
		"message":   "Hello, World!",
	}
	req, parsed, err := TestCaseInputToSignRequest(input)
	require.NoError(t, err)
	assert.Equal(t, SignTypePersonal, req.SignType)
	assert.NotNil(t, parsed.Message)
	assert.Equal(t, "Hello, World!", *parsed.Message)
}

func TestTestCaseInputToSignRequest_PersonalSignFromPersonalSignMap_CB(t *testing.T) {
	input := map[string]interface{}{
		"signer":    "0x1234567890123456789012345678901234567890",
		"sign_type": "personal",
		"personal_sign": map[string]interface{}{
			"message": "Nested message",
		},
	}
	req, parsed, err := TestCaseInputToSignRequest(input)
	require.NoError(t, err)
	assert.Equal(t, SignTypePersonal, req.SignType)
	assert.NotNil(t, parsed.Message)
	assert.Equal(t, "Nested message", *parsed.Message)
}

func TestTestCaseInputToSignRequest_PersonalSignNoMessage_CB(t *testing.T) {
	input := map[string]interface{}{
		"signer":    "0x1234567890123456789012345678901234567890",
		"sign_type": "personal",
	}
	req, _, err := TestCaseInputToSignRequest(input)
	require.NoError(t, err)
	assert.NotNil(t, req)
	// No message set, payload should be empty
	assert.Empty(t, req.Payload)
}

func TestTestCaseInputToSignRequest_EIP191_CB(t *testing.T) {
	input := map[string]interface{}{
		"signer":    "0x1234567890123456789012345678901234567890",
		"sign_type": "eip191",
		"message":   "EIP191 message",
	}
	req, parsed, err := TestCaseInputToSignRequest(input)
	require.NoError(t, err)
	assert.Equal(t, SignTypeEIP191, req.SignType)
	assert.NotNil(t, parsed.Message)
}

func TestTestCaseInputToSignRequest_ExplicitChainID_CB(t *testing.T) {
	input := map[string]interface{}{
		"signer":    "0x1234567890123456789012345678901234567890",
		"chain_id":  float64(137), // JSON numbers are float64
		"sign_type": "transaction",
		"transaction": map[string]interface{}{
			"to":    "0xaabbccddaabbccddaabbccddaabbccddaabbccdd",
			"value": "0",
		},
	}
	req, _, err := TestCaseInputToSignRequest(input)
	require.NoError(t, err)
	assert.Equal(t, "137", req.ChainID)
}

// =============================================================================
// js_helpers.go: exportStringSlice (0% -> ~100%)
// =============================================================================

func TestExportStringSlice_Nil_CB(t *testing.T) {
	result, ok := exportStringSlice(nil)
	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestExportStringSlice_Undefined_CB(t *testing.T) {
	result, ok := exportStringSlice(sobek.Undefined())
	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestExportStringSlice_ValidStringArray_CB(t *testing.T) {
	vm := sobek.New()
	val, _ := vm.RunString(`["address", "uint256", "bool"]`)
	result, ok := exportStringSlice(val)
	assert.True(t, ok)
	assert.Equal(t, []string{"address", "uint256", "bool"}, result)
}

func TestExportStringSlice_NonArrayValue_CB(t *testing.T) {
	vm := sobek.New()
	val, _ := vm.RunString(`"just a string"`)
	result, ok := exportStringSlice(val)
	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestExportStringSlice_MixedArray_CB(t *testing.T) {
	vm := sobek.New()
	val, _ := vm.RunString(`["address", 42]`)
	result, ok := exportStringSlice(val)
	assert.False(t, ok, "array with non-string should fail")
	assert.Nil(t, result)
}

func TestExportStringSlice_EmptyArray_CB(t *testing.T) {
	vm := sobek.New()
	val, _ := vm.RunString(`[]`)
	result, ok := exportStringSlice(val)
	assert.True(t, ok)
	assert.Equal(t, []string{}, result)
}

// =============================================================================
// js_abi_tuple.go: marshalComponents edge cases (47.8% -> higher)
// =============================================================================

func TestMarshalComponents_NonObjectElement_CB(t *testing.T) {
	comps := []interface{}{"not_an_object"}
	_, err := marshalComponents(comps)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "component must be object")
}

func TestMarshalComponents_MissingType_CB(t *testing.T) {
	comps := []interface{}{
		map[string]interface{}{"name": "myField"},
	}
	_, err := marshalComponents(comps)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "component missing type")
}

func TestMarshalComponents_SimpleField_CB(t *testing.T) {
	comps := []interface{}{
		map[string]interface{}{"name": "amount", "type": "uint256"},
	}
	result, err := marshalComponents(comps)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "amount", result[0].Name)
	assert.Equal(t, "uint256", result[0].Type)
}

func TestMarshalComponents_NestedTuple_CB(t *testing.T) {
	comps := []interface{}{
		map[string]interface{}{
			"name": "inner",
			"type": "tuple",
			"components": []interface{}{
				map[string]interface{}{"name": "x", "type": "uint256"},
				map[string]interface{}{"name": "y", "type": "address"},
			},
		},
	}
	result, err := marshalComponents(comps)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "tuple", result[0].Type)
	require.Len(t, result[0].Components, 2)
	assert.Equal(t, "x", result[0].Components[0].Name)
}

func TestMarshalComponents_TupleMissingComponents_CB(t *testing.T) {
	comps := []interface{}{
		map[string]interface{}{"name": "inner", "type": "tuple"},
	}
	_, err := marshalComponents(comps)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tuple component missing components")
}

func TestMarshalComponents_TupleComponentsNotArray_CB(t *testing.T) {
	comps := []interface{}{
		map[string]interface{}{"name": "inner", "type": "tuple", "components": "not_array"},
	}
	_, err := marshalComponents(comps)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tuple components must be array")
}

func TestMarshalComponents_TupleArrayType_CB(t *testing.T) {
	comps := []interface{}{
		map[string]interface{}{
			"name": "items",
			"type": "tuple[]",
			"components": []interface{}{
				map[string]interface{}{"name": "val", "type": "uint256"},
			},
		},
	}
	result, err := marshalComponents(comps)
	require.NoError(t, err)
	assert.Equal(t, "tuple[]", result[0].Type)
	require.Len(t, result[0].Components, 1)
}

// =============================================================================
// js_abi_tuple.go: typeSpecToArgument edge cases (66.7% -> higher)
// =============================================================================

func TestTypeSpecToArgument_UnsupportedTypeSpec_CB(t *testing.T) {
	_, err := typeSpecToArgument(42) // neither string nor map
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "type spec must be string or tuple object")
}

func TestTypeSpecToArgument_MapNonTupleType_CB(t *testing.T) {
	spec := map[string]interface{}{"type": "uint256"}
	_, err := typeSpecToArgument(spec)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported type spec")
}

func TestTypeSpecToArgument_StringType_CB(t *testing.T) {
	arg, err := typeSpecToArgument("address")
	require.NoError(t, err)
	assert.Equal(t, "address", arg.Type.String())
}

func TestTypeSpecToArgument_InvalidStringType_CB(t *testing.T) {
	_, err := typeSpecToArgument("invalid_abi_type")
	assert.Error(t, err)
}

// =============================================================================
// js_abi_tuple.go: exportTypesSpecs edge cases (71.4% -> higher)
// =============================================================================

func TestExportTypesSpecs_Nil_CB(t *testing.T) {
	result, ok := exportTypesSpecs(nil)
	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestExportTypesSpecs_Undefined_CB(t *testing.T) {
	result, ok := exportTypesSpecs(sobek.Undefined())
	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestExportTypesSpecs_NonArray_CB(t *testing.T) {
	vm := sobek.New()
	val, _ := vm.RunString(`"not an array"`)
	result, ok := exportTypesSpecs(val)
	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestExportTypesSpecs_ValidArray_CB(t *testing.T) {
	vm := sobek.New()
	val, _ := vm.RunString(`["address", "uint256"]`)
	result, ok := exportTypesSpecs(val)
	assert.True(t, ok)
	assert.Len(t, result, 2)
}

// =============================================================================
// js_helpers.go: toBigIntOrUint edge cases (95% -> 100%)
// =============================================================================

func TestToBigIntOrUint_UnsupportedType_CB(t *testing.T) {
	result, err := toBigIntOrUint(true, "uint256") // bool is not supported
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestToBigIntOrUint_Uint8Overflow_CB(t *testing.T) {
	result, err := toBigIntOrUint("256", "uint8") // exceeds 0xff
	require.NoError(t, err)
	assert.NotNil(t, result) // returns big.NewInt(0)
}

func TestToBigIntOrUint_Uint16Overflow_CB(t *testing.T) {
	result, err := toBigIntOrUint("65536", "uint16") // exceeds 0xffff
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestToBigIntOrUint_Uint32Overflow_CB(t *testing.T) {
	result, err := toBigIntOrUint("4294967296", "uint32") // exceeds 0xffffffff
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestToBigIntOrUint_Uint64Overflow_CB(t *testing.T) {
	result, err := toBigIntOrUint("18446744073709551616", "uint64") // exceeds max uint64
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestToBigIntOrUint_InvalidString_CB(t *testing.T) {
	result, err := toBigIntOrUint("not_a_number", "uint256")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestToBigIntOrUint_Float64_CB(t *testing.T) {
	result, err := toBigIntOrUint(float64(42), "uint256")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

// =============================================================================
// solidity_validator.go: inferSolidityType (53.3% -> ~100%)
// =============================================================================

func TestInferSolidityType_Address_CB(t *testing.T) {
	assert.Equal(t, "address", inferSolidityType("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
}

func TestInferSolidityType_Bytes32_CB(t *testing.T) {
	assert.Equal(t, "bytes32", inferSolidityType("0x"+strings.Repeat("ab", 32)))
}

func TestInferSolidityType_NumericString_CB(t *testing.T) {
	assert.Equal(t, "uint256", inferSolidityType("1000000000000000000"))
}

func TestInferSolidityType_NegativeNumericString_CB(t *testing.T) {
	assert.Equal(t, "int256", inferSolidityType("-42"))
}

func TestInferSolidityType_PlainString_CB(t *testing.T) {
	assert.Equal(t, "string", inferSolidityType("hello world"))
}

func TestInferSolidityType_Float64_CB(t *testing.T) {
	assert.Equal(t, "uint256", inferSolidityType(float64(42)))
}

func TestInferSolidityType_Int_CB(t *testing.T) {
	assert.Equal(t, "uint256", inferSolidityType(int(99)))
}

func TestInferSolidityType_Int64_CB(t *testing.T) {
	assert.Equal(t, "uint256", inferSolidityType(int64(999)))
}

func TestInferSolidityType_Uint64_CB(t *testing.T) {
	assert.Equal(t, "uint256", inferSolidityType(uint64(888)))
}

func TestInferSolidityType_Bool_CB(t *testing.T) {
	assert.Equal(t, "bool", inferSolidityType(true))
	assert.Equal(t, "bool", inferSolidityType(false))
}

func TestInferSolidityType_ByteSlice_CB(t *testing.T) {
	assert.Equal(t, "bytes", inferSolidityType([]byte{0x01, 0x02}))
}

func TestInferSolidityType_DefaultType_CB(t *testing.T) {
	assert.Equal(t, "bytes", inferSolidityType(struct{}{}))
}

func TestInferSolidityType_HexStringNotAddress_CB(t *testing.T) {
	// 0x + 20 hex chars (not 40) - not an address, not bytes32
	assert.Equal(t, "string", inferSolidityType("0xabcdef1234567890abcd"))
}

func TestInferSolidityType_ZeroString_CB(t *testing.T) {
	assert.Equal(t, "uint256", inferSolidityType("0"))
}

func TestInferSolidityType_NegativeZero_CB(t *testing.T) {
	assert.Equal(t, "int256", inferSolidityType("-0"))
}

func TestInferSolidityType_JustDash_CB(t *testing.T) {
	// "-" -> TrimPrefix("-") -> "" -> isDecimalString("") = false
	assert.Equal(t, "string", inferSolidityType("-"))
}

// =============================================================================
// solidity_validator.go: sanitizeFunctionName (71.4% -> ~100%)
// =============================================================================

func TestSanitizeFunctionName_Simple_CB(t *testing.T) {
	assert.Equal(t, "myRule", sanitizeFunctionName("myRule"))
}

func TestSanitizeFunctionName_WithInvalidChars_CB(t *testing.T) {
	assert.Equal(t, "my_rule_name", sanitizeFunctionName("my-rule name"))
}

func TestSanitizeFunctionName_StartsWithDigit_CB(t *testing.T) {
	result := sanitizeFunctionName("123rule")
	assert.True(t, strings.HasPrefix(result, "_"))
}

func TestSanitizeFunctionName_TooLong_CB(t *testing.T) {
	longName := strings.Repeat("a", 100)
	result := sanitizeFunctionName(longName)
	assert.LessOrEqual(t, len(result), 50)
}

func TestSanitizeFunctionName_SpecialChars_CB(t *testing.T) {
	assert.Equal(t, "rule__test_", sanitizeFunctionName("rule::test!"))
}

func TestSanitizeFunctionName_AllUnderscores_CB(t *testing.T) {
	assert.Equal(t, "___", sanitizeFunctionName("___"))
}

func TestSanitizeFunctionName_Empty_CB(t *testing.T) {
	assert.Equal(t, "", sanitizeFunctionName(""))
}

// =============================================================================
// solidity_validator.go: parseSolidityError (75% -> ~100%)
// =============================================================================

func TestParseSolidityError_WithError_CB(t *testing.T) {
	output := "Error (1234): something went wrong\nother line"
	result := parseSolidityError(output)
	assert.NotNil(t, result)
	assert.Contains(t, result.Message, "Error")
	assert.Equal(t, "error", result.Severity)
}

func TestParseSolidityError_ParserError_CB(t *testing.T) {
	output := "ParserError: unexpected token"
	result := parseSolidityError(output)
	assert.NotNil(t, result)
	assert.Contains(t, result.Message, "ParserError")
}

func TestParseSolidityError_TypeError_CB(t *testing.T) {
	output := "TypeError: type mismatch"
	result := parseSolidityError(output)
	assert.NotNil(t, result)
	assert.Contains(t, result.Message, "TypeError")
}

func TestParseSolidityError_EmptyOutput_CB(t *testing.T) {
	result := parseSolidityError("")
	assert.NotNil(t, result)
	assert.Equal(t, "unknown compilation error", result.Message)
}

func TestParseSolidityError_WhitespaceOnly_CB(t *testing.T) {
	result := parseSolidityError("   \n   \t   ")
	assert.NotNil(t, result)
	assert.Equal(t, "unknown compilation error", result.Message)
}

func TestParseSolidityError_NonErrorOutput_CB(t *testing.T) {
	// Output with no error patterns returns the whole output
	result := parseSolidityError("some random output")
	assert.NotNil(t, result)
	assert.Equal(t, "some random output", result.Message)
}

// =============================================================================
// solidity_evaluator.go: parseRevertReason edge cases (85.4% -> higher)
// =============================================================================

func TestParseRevertReason_FAILPattern_CB(t *testing.T) {
	output := "[FAIL: value exceeds limit] testMyRule()"
	reason := parseRevertReason([]byte(output))
	assert.Equal(t, "value exceeds limit", reason)
}

func TestParseRevertReason_ReturnData_CB(t *testing.T) {
	output := `some output before "return_data": "forbidden operation" more output`
	reason := parseRevertReason([]byte(output))
	assert.Equal(t, "forbidden operation", reason)
}

func TestParseRevertReason_ReturnDataNull_CB(t *testing.T) {
	output := `"return_data": "null"`
	reason := parseRevertReason([]byte(output))
	assert.Equal(t, "", reason, "null return_data should produce empty reason")
}

func TestParseRevertReason_ReturnDataEmpty_CB(t *testing.T) {
	output := `"return_data": ""`
	reason := parseRevertReason([]byte(output))
	assert.Equal(t, "", reason, "empty return_data should produce empty reason")
}

func TestParseRevertReason_ScriptFailed_CB(t *testing.T) {
	output := "Error: script failed: invalid recipient"
	reason := parseRevertReason([]byte(output))
	assert.Equal(t, "invalid recipient", reason)
}

func TestParseRevertReason_ScriptFailedNoNewline_CB(t *testing.T) {
	output := "Error: script failed: rule violation"
	reason := parseRevertReason([]byte(output))
	assert.Equal(t, "rule violation", reason)
}

func TestParseRevertReason_RevertPattern_CB(t *testing.T) {
	output := "revert: exceeds max value\nsome stack trace"
	reason := parseRevertReason([]byte(output))
	assert.Equal(t, "exceeds max value", reason)
}

func TestParseRevertReason_RevertNoNewline_CB(t *testing.T) {
	output := "revert: amount too large"
	reason := parseRevertReason([]byte(output))
	assert.Equal(t, "amount too large", reason)
}

func TestParseRevertReason_GeneralError_CB(t *testing.T) {
	output := "Error: something failed badly"
	reason := parseRevertReason([]byte(output))
	assert.Contains(t, reason, "something failed badly")
}

func TestParseRevertReason_CompilerRunFailedSkipped_CB(t *testing.T) {
	output := "Error: Compiler run failed\nsome details"
	reason := parseRevertReason([]byte(output))
	// Should skip "Compiler run failed" and try remaining patterns
	assert.NotEqual(t, "Compiler run failed", reason)
}

func TestParseRevertReason_PanicCode_CB(t *testing.T) {
	output := "Panic(0x01) at some location"
	reason := parseRevertReason([]byte(output))
	assert.Equal(t, "panic: 0x01", reason)
}

func TestParseRevertReason_EmptyOutput_CB(t *testing.T) {
	reason := parseRevertReason([]byte(""))
	assert.Equal(t, "", reason)
}

// =============================================================================
// js_evaluator.go: removeGlobals (75% -> ~100%)
// =============================================================================

func TestRemoveGlobals_CB(t *testing.T) {
	vm := sobek.New()
	err := removeGlobals(vm)
	require.NoError(t, err)

	// Verify that dangerous globals are undefined
	for _, name := range []string{"eval", "Function", "Date", "console", "require", "global", "globalThis"} {
		val := vm.Get(name)
		assert.True(t, val.Equals(sobek.Undefined()), "expected %s to be undefined", name)
	}
}

func TestRemoveGlobals_MathRandomUndefined_CB(t *testing.T) {
	vm := sobek.New()
	err := removeGlobals(vm)
	require.NoError(t, err)

	// Math.random should be undefined
	val, err := vm.RunString("typeof Math.random")
	require.NoError(t, err)
	assert.Equal(t, "undefined", val.String())
}

// =============================================================================
// js_evaluator.go: trySetUndefined edge cases (66.7% -> ~100%)
// =============================================================================

func TestTrySetUndefined_NilTop_CB(t *testing.T) {
	vm := sobek.New()
	// Set a global to nil/undefined; trySetUndefined panics because
	// sobek.Undefined().ToObject() panics with a TypeError.
	_ = vm.Set("nonexistent", sobek.Undefined())
	assert.Panics(t, func() {
		_ = trySetUndefined(vm, "nonexistent", "key")
	})
}

func TestTrySetUndefined_ValidObject_CB(t *testing.T) {
	vm := sobek.New()
	err := trySetUndefined(vm, "Math", "random")
	assert.NoError(t, err)

	val, err := vm.RunString("typeof Math.random")
	require.NoError(t, err)
	assert.Equal(t, "undefined", val.String())
}

func TestTrySetUndefined_MissingTop_CB(t *testing.T) {
	vm := sobek.New()
	// Try on a global that doesn't exist at all
	err := trySetUndefined(vm, "NonexistentGlobal", "key")
	assert.NoError(t, err)
}

// =============================================================================
// adapter.go: NewEVMAdapter error path (66.7% -> 100%)
// =============================================================================

func TestNewEVMAdapter_NilRegistry_CB(t *testing.T) {
	_, err := NewEVMAdapter(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signer registry is required")
}

func TestNewEVMAdapter_ValidRegistry_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)

	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)
	assert.NotNil(t, adapter)
	assert.Equal(t, types.ChainTypeEVM, adapter.Type())
}

// =============================================================================
// adapter.go: ListSigners and HasSigner (0% -> ~100%)
// =============================================================================

func TestEVMAdapter_ListSigners_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)

	signers, err := adapter.ListSigners(context.Background())
	require.NoError(t, err)
	assert.Len(t, signers, 1)
	assert.Equal(t, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", signers[0].Address)
}

func TestEVMAdapter_HasSigner_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)

	assert.True(t, adapter.HasSigner(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"))
	assert.False(t, adapter.HasSigner(context.Background(), "0x0000000000000000000000000000000000000001"))
}

// =============================================================================
// adapter.go: Sign (0% -> partial)
// Uses real private key signer so no external tools needed
// =============================================================================

func TestEVMAdapter_Sign_Hash_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)

	payload, _ := json.Marshal(EVMSignPayload{
		Hash: "0x" + strings.Repeat("ab", 32),
	})

	result, err := adapter.Sign(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", SignTypeHash, "1", payload)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Signature, 65)
	assert.Equal(t, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", result.SignerUsed)
}

func TestEVMAdapter_Sign_RawMessage_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)

	payload, _ := json.Marshal(EVMSignPayload{
		RawMessage: []byte("test message"),
	})

	result, err := adapter.Sign(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", SignTypeRawMessage, "1", payload)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Signature, 65)
}

func TestEVMAdapter_Sign_EIP191_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)

	// "Hello EIP191" lacks the required EIP-191 prefix ("\x19Ethereum Signed Message:\n"),
	// so the ethsig library rejects it.
	payload, _ := json.Marshal(EVMSignPayload{
		Message: "Hello EIP191",
	})

	_, err = adapter.Sign(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", SignTypeEIP191, "1", payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "EIP-191")
}

func TestEVMAdapter_Sign_Personal_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)

	payload, _ := json.Marshal(EVMSignPayload{
		Message: "Hello Personal",
	})

	result, err := adapter.Sign(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", SignTypePersonal, "1", payload)
	require.NoError(t, err)
	assert.Len(t, result.Signature, 65)
}

func TestEVMAdapter_Sign_TypedData_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)

	payload, _ := json.Marshal(EVMSignPayload{
		TypedData: &TypedDataPayload{
			Types: map[string][]TypedDataField{
				"EIP712Domain": {
					{Name: "name", Type: "string"},
				},
				"Test": {
					{Name: "value", Type: "uint256"},
				},
			},
			PrimaryType: "Test",
			Domain: TypedDataDomain{
				Name: "TestDomain",
			},
			Message: map[string]interface{}{
				"value": "42",
			},
		},
	})

	result, err := adapter.Sign(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", SignTypeTypedData, "1", payload)
	require.NoError(t, err)
	assert.Len(t, result.Signature, 65)
}

func TestEVMAdapter_Sign_Transaction_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)

	toAddr := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	payload, _ := json.Marshal(EVMSignPayload{
		Transaction: &TransactionPayload{
			To:       &toAddr,
			Value:    "1000000000000000000",
			Data:     "0x",
			Gas:      21000,
			GasPrice: "20000000000",
			TxType:   "legacy",
		},
	})

	result, err := adapter.Sign(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", SignTypeTransaction, "1", payload)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Signature, 65)
	assert.NotEmpty(t, result.SignedData)
}

func TestEVMAdapter_Sign_TransactionEIP1559_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)

	toAddr := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	payload, _ := json.Marshal(EVMSignPayload{
		Transaction: &TransactionPayload{
			To:        &toAddr,
			Value:     "0",
			Data:      "0x",
			Gas:       21000,
			GasTipCap: "1000000000",
			GasFeeCap: "20000000000",
			TxType:    "eip1559",
		},
	})

	result, err := adapter.Sign(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", SignTypeTransaction, "1", payload)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Signature)
	assert.NotEmpty(t, result.SignedData)
}

func TestEVMAdapter_Sign_TransactionEIP2930_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)

	toAddr := "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	payload, _ := json.Marshal(EVMSignPayload{
		Transaction: &TransactionPayload{
			To:       &toAddr,
			Value:    "0",
			Data:     "0x",
			Gas:      21000,
			GasPrice: "20000000000",
			TxType:   "eip2930",
		},
	})

	result, err := adapter.Sign(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", SignTypeTransaction, "1", payload)
	require.NoError(t, err)
	assert.NotEmpty(t, result.Signature)
}

func TestEVMAdapter_Sign_UnsupportedType_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)

	payload, _ := json.Marshal(EVMSignPayload{})
	_, err = adapter.Sign(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "unknown_type", "1", payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported sign type")
}

func TestEVMAdapter_Sign_InvalidPayload_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)

	_, err = adapter.Sign(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", SignTypeHash, "1", []byte(`{invalid`))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid payload")
}

func TestEVMAdapter_Sign_SignerNotFound_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)

	payload, _ := json.Marshal(EVMSignPayload{Hash: "0x" + strings.Repeat("ab", 32)})
	_, err = adapter.Sign(context.Background(), "0x0000000000000000000000000000000000000001", SignTypeHash, "1", payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get signer")
}

func TestEVMAdapter_Sign_InvalidHash_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)

	// Hash too short
	payload, _ := json.Marshal(EVMSignPayload{Hash: "0xabcd"})
	_, err = adapter.Sign(context.Background(), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", SignTypeHash, "1", payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hash")
}

// =============================================================================
// signer.go: resolvePrivateKey (66.7% -> ~100%)
// =============================================================================

func TestResolvePrivateKey_DirectHexWith0x_CB(t *testing.T) {
	key := "0x" + strings.Repeat("ab", 32)
	result := resolvePrivateKey(key)
	assert.Equal(t, strings.Repeat("ab", 32), result)
}

func TestResolvePrivateKey_DirectHexWithout0x_CB(t *testing.T) {
	key := strings.Repeat("ab", 32) // 64 hex chars
	result := resolvePrivateKey(key)
	assert.Equal(t, key, result)
}

func TestResolvePrivateKey_EnvVar_CB(t *testing.T) {
	envKey := "TEST_RESOLVE_PRIV_KEY_1234"
	expectedKey := strings.Repeat("cd", 32)
	os.Setenv(envKey, expectedKey)
	defer os.Unsetenv(envKey)

	result := resolvePrivateKey(envKey)
	assert.Equal(t, expectedKey, result)
}

func TestResolvePrivateKey_EnvVarNotSet_CB(t *testing.T) {
	result := resolvePrivateKey("NONEXISTENT_KEY_VAR_12345")
	assert.Equal(t, "", result)
}

func TestResolvePrivateKey_NonHex64Chars_CB(t *testing.T) {
	// 64 chars but not all hex
	key := strings.Repeat("z", 64)
	result := resolvePrivateKey(key)
	// Should treat as env var, which doesn't exist
	assert.Equal(t, "", result)
}

func TestResolvePrivateKey_128HexChars_CB(t *testing.T) {
	key := strings.Repeat("ab", 64) // 128 hex chars (64 bytes full key)
	result := resolvePrivateKey(key)
	assert.Equal(t, key, result)
}

func TestResolvePrivateKey_128NonHexChars_CB(t *testing.T) {
	key := strings.Repeat("zz", 64) // 128 chars but not hex
	result := resolvePrivateKey(key)
	assert.Equal(t, "", result) // treated as env var
}

func TestResolvePrivateKey_ShortString_CB(t *testing.T) {
	// Not 64 or 128 chars, not a hex key, treated as env var
	result := resolvePrivateKey("short")
	assert.Equal(t, "", result)
}

// =============================================================================
// signer.go: NewSignerRegistryWithProvider edge cases (47.4% -> higher)
// =============================================================================

func TestNewSignerRegistryWithProvider_NilProvider_CB(t *testing.T) {
	_, err := NewSignerRegistryWithProvider(SignerConfig{}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password provider is required")
}

func TestNewSignerRegistryWithProvider_NoSigners_CB(t *testing.T) {
	provider, _ := NewEnvPasswordProvider()
	registry, err := NewSignerRegistryWithProvider(SignerConfig{}, provider)
	assert.NoError(t, err)
	assert.Equal(t, 0, registry.SignerCount())
}

func TestNewSignerRegistryWithProvider_DisabledSignersOnly_CB(t *testing.T) {
	provider, _ := NewEnvPasswordProvider()
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   false,
			},
		},
	}
	registry, err := NewSignerRegistryWithProvider(cfg, provider)
	assert.NoError(t, err)
	assert.Equal(t, 0, registry.SignerCount())
}

func TestNewSignerRegistryWithProvider_EmptyPrivateKey_CB(t *testing.T) {
	provider, _ := NewEnvPasswordProvider()
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "NONEXISTENT_ENV_VAR_FOR_TEST_12345",
				Enabled:   true,
			},
		},
	}
	_, err := NewSignerRegistryWithProvider(cfg, provider)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private key is empty")
}

func TestNewSignerRegistryWithProvider_AddressMismatch_CB(t *testing.T) {
	provider, _ := NewEnvPasswordProvider()
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				// Wrong address for this key
				Address:   "0x0000000000000000000000000000000000000001",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	_, err := NewSignerRegistryWithProvider(cfg, provider)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "address mismatch")
}

func TestNewSignerRegistryWithProvider_KeystorePasswordError_CB(t *testing.T) {
	// Mock provider that always returns an error
	provider := &mockPasswordProvider{err: fmt.Errorf("password unavailable")}
	cfg := SignerConfig{
		Keystores: []KeystoreConfig{
			{
				Address:     "0x1234567890123456789012345678901234567890",
				Path:        "/nonexistent/keystore.json",
				PasswordEnv: "WHATEVER",
				Enabled:     true,
			},
		},
	}
	_, err := NewSignerRegistryWithProvider(cfg, provider)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get password")
}

func TestNewSignerRegistryWithProvider_DisabledKeystoreSkipped_CB(t *testing.T) {
	provider, _ := NewEnvPasswordProvider()
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
		Keystores: []KeystoreConfig{
			{
				Address: "0x1234567890123456789012345678901234567890",
				Path:    "/nonexistent/file.json",
				Enabled: false, // disabled, should be skipped
			},
		},
	}
	registry, err := NewSignerRegistryWithProvider(cfg, provider)
	require.NoError(t, err)
	assert.NotNil(t, registry)
	// Only the private key signer should be registered
	signers := registry.ListSigners()
	assert.Len(t, signers, 1)
}

// mockPasswordProvider for testing
type mockPasswordProvider struct {
	password []byte
	err      error
}

func (m *mockPasswordProvider) GetPassword(address string, config KeystoreConfig) ([]byte, error) {
	return m.password, m.err
}

// =============================================================================
// signer.go: ListSigners and GetSigner (0% -> covered)
// =============================================================================

func TestSignerRegistry_GetSigner_NotFound_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)

	_, err = registry.GetSigner("0x0000000000000000000000000000000000000001")
	assert.Error(t, err)
}

func TestSignerRegistry_GetSigner_Found_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)

	signer, err := registry.GetSigner("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

func TestSignerRegistry_ListSigners_CB(t *testing.T) {
	cfg := SignerConfig{
		PrivateKeys: []PrivateKeyConfig{
			{
				Address:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				KeyEnvVar: "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
				Enabled:   true,
			},
		},
	}
	registry, err := NewSignerRegistry(cfg)
	require.NoError(t, err)

	signers := registry.ListSigners()
	assert.Len(t, signers, 1)
	assert.Equal(t, "private_key", signers[0].Type)
}

// =============================================================================
// js_rule_input_map.go: ruleInputToMap (77.8% -> ~100%)
// =============================================================================

func TestRuleInputToMap_Nil_CB(t *testing.T) {
	result, err := ruleInputToMap(nil)
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestRuleInputToMap_Transaction_CB(t *testing.T) {
	input := &RuleInput{
		SignType: "transaction",
		ChainID:  1,
		Signer:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		Transaction: &RuleInputTransaction{
			From:     "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
			To:       "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			Value:    "0x0",
			Data:     "0x",
			MethodID: "0xa9059cbb",
		},
	}
	m, err := ruleInputToMap(input)
	require.NoError(t, err)
	assert.Equal(t, "transaction", m["sign_type"])
	assert.Equal(t, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", m["signer"])
	assert.NotNil(t, m["transaction"])
}

func TestRuleInputToMap_PersonalSign_CB(t *testing.T) {
	input := &RuleInput{
		SignType: "personal_sign",
		ChainID:  56,
		Signer:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		PersonalSign: &RuleInputPersonalSign{
			Message: "Hello World",
		},
	}
	m, err := ruleInputToMap(input)
	require.NoError(t, err)
	assert.Equal(t, "personal_sign", m["sign_type"])
	ps, ok := m["personal_sign"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "Hello World", ps["message"])
}

// =============================================================================
// delegation_convert.go: DelegatePayloadToSignRequest edge cases (75% -> higher)
// =============================================================================

func TestDelegatePayloadToSignRequest_NilPayload_CB(t *testing.T) {
	_, _, err := DelegatePayloadToSignRequest(context.Background(), nil, "single")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "delegation payload is nil")
}

func TestDelegatePayloadToSignRequest_MapPayload_CB(t *testing.T) {
	payload := map[string]interface{}{
		"sign_type": "transaction",
		"chain_id":  float64(1),
		"signer":    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		"transaction": map[string]interface{}{
			"to":    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			"value": "0x0",
			"data":  "0x",
		},
	}
	req, parsed, err := DelegatePayloadToSignRequest(context.Background(), payload, "single")
	require.NoError(t, err)
	assert.Equal(t, SignTypeTransaction, req.SignType)
	assert.NotNil(t, parsed.Recipient)
}

func TestDelegatePayloadToSignRequest_RuleInputPayload_CB(t *testing.T) {
	input := &RuleInput{
		SignType: "transaction",
		ChainID:  137,
		Signer:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		Transaction: &RuleInputTransaction{
			From:  "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
			To:    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			Value: "0x0",
			Data:  "0x",
		},
	}
	req, _, err := DelegatePayloadToSignRequest(context.Background(), input, "single")
	require.NoError(t, err)
	assert.Equal(t, "137", req.ChainID)
}

func TestDelegatePayloadToSignRequest_StructPayload_CB(t *testing.T) {
	// Test with a generic struct that gets marshaled to JSON
	type customPayload struct {
		SignType string                 `json:"sign_type"`
		ChainID  float64                `json:"chain_id"`
		Signer   string                 `json:"signer"`
	}
	payload := customPayload{
		SignType: "personal_sign",
		ChainID:  56,
		Signer:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
	}
	req, _, err := DelegatePayloadToSignRequest(context.Background(), payload, "single")
	require.NoError(t, err)
	assert.Equal(t, SignTypePersonal, req.SignType)
}

func TestDelegatePayloadToSignRequest_MissingSigner_CB(t *testing.T) {
	payload := map[string]interface{}{
		"sign_type": "transaction",
		"chain_id":  float64(1),
		// no signer
	}
	_, _, err := DelegatePayloadToSignRequest(context.Background(), payload, "single")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing signer")
}

// =============================================================================
// delegation_convert.go: mapRuleInputSignTypeToEVM
// =============================================================================

func TestMapRuleInputSignTypeToEVM_CB(t *testing.T) {
	assert.Equal(t, SignTypeTransaction, mapRuleInputSignTypeToEVM("transaction"))
	assert.Equal(t, SignTypeTypedData, mapRuleInputSignTypeToEVM("typed_data"))
	assert.Equal(t, SignTypePersonal, mapRuleInputSignTypeToEVM("personal_sign"))
	assert.Equal(t, "custom", mapRuleInputSignTypeToEVM("custom"))
}

// =============================================================================
// delegation_convert.go: hexWeiToDecimal edge cases
// =============================================================================

func TestHexWeiToDecimal_Valid_CB(t *testing.T) {
	assert.Equal(t, "255", hexWeiToDecimal("0xff"))
	assert.Equal(t, "1000000000000000000", hexWeiToDecimal("0xDE0B6B3A7640000"))
}

func TestHexWeiToDecimal_EmptyAndZero_CB(t *testing.T) {
	assert.Equal(t, "0", hexWeiToDecimal(""))
	assert.Equal(t, "0", hexWeiToDecimal("0x0"))
	assert.Equal(t, "0", hexWeiToDecimal("0x"))
}

func TestHexWeiToDecimal_InvalidHex_CB(t *testing.T) {
	assert.Equal(t, "0", hexWeiToDecimal("0xZZZZ"))
}

func TestHexWeiToDecimal_CapitalPrefix_CB(t *testing.T) {
	assert.Equal(t, "255", hexWeiToDecimal("0Xff"))
}

// =============================================================================
// delegation_convert.go: chainIDFromInterface edge cases
// =============================================================================

func TestChainIDFromInterface_Float64_CB(t *testing.T) {
	assert.Equal(t, float64(137), chainIDFromInterface(float64(137)))
}

func TestChainIDFromInterface_Int64_CB(t *testing.T) {
	assert.Equal(t, float64(56), chainIDFromInterface(int64(56)))
}

func TestChainIDFromInterface_Int_CB(t *testing.T) {
	assert.Equal(t, float64(1), chainIDFromInterface(int(1)))
}

func TestChainIDFromInterface_JsonNumber_CB(t *testing.T) {
	assert.Equal(t, float64(42161), chainIDFromInterface(json.Number("42161")))
}

func TestChainIDFromInterface_String_CB(t *testing.T) {
	assert.Equal(t, float64(10), chainIDFromInterface("10"))
}

func TestChainIDFromInterface_InvalidString_CB(t *testing.T) {
	assert.Equal(t, float64(0), chainIDFromInterface("not_a_number"))
}

func TestChainIDFromInterface_Nil_CB(t *testing.T) {
	assert.Equal(t, float64(0), chainIDFromInterface(nil))
}

func TestChainIDFromInterface_UnknownType_CB(t *testing.T) {
	assert.Equal(t, float64(0), chainIDFromInterface(true))
}

// =============================================================================
// struct_parser.go: formatFieldValue additional edge cases (63.8% -> higher)
// =============================================================================

func TestFormatFieldValue_BytesNonHexString_CB(t *testing.T) {
	// Non-hex string for bytes type -> encode as hex
	result := formatFieldValue("bytes", "hello")
	assert.Contains(t, result, "hex\"")
}

func TestFormatFieldValue_BytesFromByteSlice_CB(t *testing.T) {
	result := formatFieldValue("bytes", []byte{0xde, 0xad})
	assert.Equal(t, `hex"dead"`, result)
}

func TestFormatFieldValue_BytesNonStringNonBytes_CB(t *testing.T) {
	result := formatFieldValue("bytes", 42)
	assert.Equal(t, `""`, result)
}

func TestFormatFieldValue_Uint256_IntType_CB(t *testing.T) {
	assert.Equal(t, "99", formatFieldValue("uint256", int(99)))
}

func TestFormatFieldValue_Uint256_Int64Type_CB(t *testing.T) {
	assert.Equal(t, "999", formatFieldValue("uint256", int64(999)))
}

func TestFormatFieldValue_Uint256_Uint64Type_CB(t *testing.T) {
	assert.Equal(t, "888", formatFieldValue("uint256", uint64(888)))
}

func TestFormatFieldValue_Uint256_JsonNumber_CB(t *testing.T) {
	assert.Equal(t, "42", formatFieldValue("uint256", json.Number("42")))
}

func TestFormatFieldValue_Uint256_JsonNumberFloat_CB(t *testing.T) {
	result := formatFieldValue("uint256", json.Number("3.14"))
	assert.Equal(t, "3", result)
}

func TestFormatFieldValue_Uint256_JsonNumberInvalid_CB(t *testing.T) {
	result := formatFieldValue("uint256", json.Number("not_a_number"))
	assert.Equal(t, "0", result)
}

func TestFormatFieldValue_Int256_NegativeFloat_CB(t *testing.T) {
	assert.Equal(t, "-42", formatFieldValue("int256", float64(-42)))
}

func TestFormatFieldValue_FixedBytes_ValidHex_CB(t *testing.T) {
	// bytes4 with valid 0x-prefixed hex
	result := formatFieldValue("bytes4", "0xdeadbeef")
	assert.Equal(t, "0xdeadbeef", result)
}

func TestFormatFieldValue_FixedBytes_ValidHexNot0x_CB(t *testing.T) {
	result := formatFieldValue("bytes4", "deadbeef")
	// Should still work through the fixed bytes branch
	assert.NotEqual(t, `""`, result)
}

func TestFormatFieldValue_FixedBytes_InvalidHex_CB(t *testing.T) {
	result := formatFieldValue("bytes4", "not_hex")
	assert.Equal(t, "bytes4(0)", result)
}

func TestFormatFieldValue_FixedBytes_NonString_CB(t *testing.T) {
	result := formatFieldValue("bytes4", 42)
	assert.Equal(t, "bytes4(0)", result)
}

func TestFormatFieldValue_Uint8_Numeric_CB(t *testing.T) {
	assert.Equal(t, "255", formatFieldValue("uint8", "255"))
}

func TestFormatFieldValue_Int8_Negative_CB(t *testing.T) {
	assert.Equal(t, "-128", formatFieldValue("int8", "-128"))
}

func TestFormatFieldValue_UnknownType_Nil_CB(t *testing.T) {
	// Unknown type with nil value
	result := formatFieldValue("tuple", nil)
	assert.Equal(t, "0", result) // getDefaultValue for unknown type
}

func TestFormatFieldValue_String_WithBackslash_CB(t *testing.T) {
	result := formatFieldValue("string", `hello\world`)
	assert.Equal(t, `"hello\\world"`, result)
}

func TestFormatFieldValue_Address_NonString_CB(t *testing.T) {
	result := formatFieldValue("address", 42)
	assert.Equal(t, "address(0)", result)
}

func TestFormatFieldValue_Bool_NonBool_CB(t *testing.T) {
	result := formatFieldValue("bool", "not_a_bool")
	assert.Equal(t, "false", result)
}

func TestFormatFieldValue_Bytes32_NonString_CB(t *testing.T) {
	result := formatFieldValue("bytes32", 42)
	assert.Equal(t, "bytes32(0)", result)
}

func TestFormatFieldValue_Bytes32_InvalidHex_CB(t *testing.T) {
	// Right length but invalid hex chars
	result := formatFieldValue("bytes32", "0x"+strings.Repeat("zz", 32))
	assert.Equal(t, "bytes32(0)", result)
}

// =============================================================================
// struct_parser.go: parseStructFields edge cases (80% -> higher)
// =============================================================================

func TestParseStructFields_InvalidFieldDeclaration_CB(t *testing.T) {
	_, err := parseStructFields("justOnePart")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid field declaration")
}

func TestParseStructFields_InvalidIdentifier_CB(t *testing.T) {
	_, err := parseStructFields("uint256 1invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid field name")
}

func TestParseStructFields_EmptyLines_CB(t *testing.T) {
	fields, err := parseStructFields("uint256 x;\n\n  \n uint256 y;")
	require.NoError(t, err)
	assert.Len(t, fields, 2)
}

func TestParseStructFields_InlineComments_CB(t *testing.T) {
	// parseStructFields splits by ";" so an inline comment after the first ";"
	// absorbs everything until the next ";" - only 1 field is parsed here.
	fields, err := parseStructFields("uint256 amount; // the amount\naddress owner;")
	require.NoError(t, err)
	assert.Len(t, fields, 1)
	assert.Equal(t, "amount", fields[0].Name)
}

// =============================================================================
// struct_parser.go: parseFieldDeclaration edge cases (84.6% -> higher)
// =============================================================================

func TestParseFieldDeclaration_WithStorageModifier_CB(t *testing.T) {
	field, err := parseFieldDeclaration("bytes storage data")
	require.NoError(t, err)
	assert.Equal(t, "bytes", field.Type)
	assert.Equal(t, "data", field.Name)
}

func TestParseFieldDeclaration_WithCalldataModifier_CB(t *testing.T) {
	field, err := parseFieldDeclaration("bytes calldata data")
	require.NoError(t, err)
	assert.Equal(t, "bytes", field.Type)
	assert.Equal(t, "data", field.Name)
}

func TestParseFieldDeclaration_ArrayType_CB(t *testing.T) {
	field, err := parseFieldDeclaration("uint256[] amounts")
	require.NoError(t, err)
	assert.Equal(t, "uint256[]", field.Type)
	assert.Equal(t, "amounts", field.Name)
}

func TestParseFieldDeclaration_UintNormalization_CB(t *testing.T) {
	field, err := parseFieldDeclaration("uint amount")
	require.NoError(t, err)
	assert.Equal(t, "uint256", field.Type)
}

func TestParseFieldDeclaration_IntNormalization_CB(t *testing.T) {
	field, err := parseFieldDeclaration("int amount")
	require.NoError(t, err)
	assert.Equal(t, "int256", field.Type)
}

// =============================================================================
// struct_parser.go: generateStructInstance edge cases (92.9% -> ~100%)
// =============================================================================

func TestGenerateStructInstance_MissingFieldUsesDefault_CB(t *testing.T) {
	def := &StructDefinition{
		Name: "Token",
		Fields: []TypedDataField{
			{Name: "name", Type: "string"},
			{Name: "amount", Type: "uint256"},
		},
	}
	// Only provide "name", "amount" is missing
	message := map[string]interface{}{
		"name": "TestToken",
	}
	code := generateStructInstance(def, message)
	assert.Contains(t, code, `name: "TestToken"`)
	assert.Contains(t, code, "amount: 0") // default for uint256
}

// =============================================================================
// password_provider.go: additional edge cases
// =============================================================================

func TestCompositePasswordProvider_GetPassword_EnvFallback_CB(t *testing.T) {
	// Create composite without stdin
	p, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)

	envKey := "TEST_COMP_PASS_FALLBACK"
	os.Setenv(envKey, "test_password")
	defer os.Unsetenv(envKey)

	// When PasswordStdin is false, should use env provider
	pwd, err := p.GetPassword("0x123", KeystoreConfig{PasswordEnv: envKey, PasswordStdin: false})
	require.NoError(t, err)
	assert.Equal(t, []byte("test_password"), pwd)
}

// =============================================================================
// solidity_evaluator.go: formatChainID
// =============================================================================

func TestFormatChainID_Empty_CB(t *testing.T) {
	assert.Equal(t, "1", formatChainID(""))
}

func TestFormatChainID_Valid_CB(t *testing.T) {
	assert.Equal(t, "137", formatChainID("137"))
}

func TestFormatChainID_NonDecimal_CB(t *testing.T) {
	assert.Equal(t, "1", formatChainID("not_a_number"))
}

func TestFormatChainID_Hex_CB(t *testing.T) {
	assert.Equal(t, "1", formatChainID("0x89"))
}

// =============================================================================
// solidity_evaluator.go: formatAddress
// =============================================================================

func TestFormatAddress_InjectionAttemptOther_CB(t *testing.T) {
	s := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\"); attack()"
	result := formatAddress(&s)
	assert.Equal(t, "address(0)", result)
}

// =============================================================================
// solidity_evaluator.go: formatWei
// =============================================================================

func TestFormatWei_NilValue_CB(t *testing.T) {
	assert.Equal(t, "0", formatWei(nil))
}

func TestFormatWei_EmptyString_CB(t *testing.T) {
	s := ""
	assert.Equal(t, "0", formatWei(&s))
}

func TestFormatWei_ValidDecimal_CB(t *testing.T) {
	s := "1000000000000000000"
	assert.Equal(t, "1000000000000000000", formatWei(&s))
}

func TestFormatWei_NonDecimal_CB(t *testing.T) {
	s := "not_a_number"
	assert.Equal(t, "0", formatWei(&s))
}

// =============================================================================
// solidity_evaluator.go: formatSelector
// =============================================================================

func TestFormatSelector_Nil_CB(t *testing.T) {
	assert.Equal(t, "bytes4(0)", formatSelector(nil))
}

func TestFormatSelector_Empty_CB(t *testing.T) {
	s := ""
	assert.Equal(t, "bytes4(0)", formatSelector(&s))
}

func TestFormatSelector_Valid_CB(t *testing.T) {
	s := "0xa9059cbb"
	result := formatSelector(&s)
	assert.Contains(t, result, "a9059cbb")
}

func TestFormatSelector_InvalidHex_CB(t *testing.T) {
	s := "0xZZZZ"
	assert.Equal(t, "bytes4(0)", formatSelector(&s))
}

// =============================================================================
// solidity_evaluator.go: formatBytes
// =============================================================================

func TestFormatBytes_Empty_CB(t *testing.T) {
	assert.Equal(t, `hex""`, formatBytes(nil))
	assert.Equal(t, `hex""`, formatBytes([]byte{}))
}

func TestFormatBytes_Data_CB(t *testing.T) {
	assert.Equal(t, `hex"deadbeef"`, formatBytes([]byte{0xde, 0xad, 0xbe, 0xef}))
}

// =============================================================================
// solidity_evaluator.go: formatString
// =============================================================================

func TestFormatString_Normal_CB(t *testing.T) {
	assert.Equal(t, `"hello"`, formatString("hello"))
}

func TestFormatString_Empty_CB(t *testing.T) {
	assert.Equal(t, `""`, formatString(""))
}

func TestFormatString_WithQuotes_CB(t *testing.T) {
	result := formatString(`say "hello"`)
	assert.Contains(t, result, `\"`)
}

// =============================================================================
// solidity_evaluator.go: formatDomainChainId
// =============================================================================

func TestFormatDomainChainId_Empty_CB(t *testing.T) {
	assert.Equal(t, "0", formatDomainChainId(""))
}

func TestFormatDomainChainId_Valid_CB(t *testing.T) {
	assert.Equal(t, "1", formatDomainChainId("1"))
}

func TestFormatDomainChainId_Invalid_CB(t *testing.T) {
	assert.Equal(t, "0", formatDomainChainId("not_number"))
}

// =============================================================================
// solidity_evaluator.go: formatDomainContract
// =============================================================================

func TestFormatDomainContract_Empty_CB(t *testing.T) {
	assert.Equal(t, "address(0)", formatDomainContract(""))
}

func TestFormatDomainContract_Valid_CB(t *testing.T) {
	result := formatDomainContract("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
	assert.Contains(t, result, "0x")
	assert.Len(t, result, 42)
}

func TestFormatDomainContract_Invalid_CB(t *testing.T) {
	assert.Equal(t, "address(0)", formatDomainContract("not_address"))
}

// =============================================================================
// solidity_evaluator.go: safeForgeEnv
// =============================================================================

func TestSafeForgeEnv_ContainsSecurityDefaults_CB(t *testing.T) {
	env := safeForgeEnv()
	assert.NotEmpty(t, env)

	envMap := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	assert.Equal(t, "false", envMap["FOUNDRY_FFI"])
	assert.Equal(t, "[]", envMap["FOUNDRY_FS_PERMISSIONS"])
}

func TestSafeForgeEnv_ForwardsPathAndHome_CB(t *testing.T) {
	env := safeForgeEnv()
	envStr := strings.Join(env, "\n")
	// PATH and HOME should be forwarded if set
	if os.Getenv("PATH") != "" {
		assert.Contains(t, envStr, "PATH=")
	}
	if os.Getenv("HOME") != "" {
		assert.Contains(t, envStr, "HOME=")
	}
}

// =============================================================================
// solidity_evaluator.go: processInOperatorToMappings edge cases (95.7% -> ~100%)
// =============================================================================

func TestProcessInOperatorToMappings_BasicReplacement_CB(t *testing.T) {
	source := "in(txTo, allowed_addresses)"
	arrays := map[string][]string{
		"allowed_addresses": {"0x1234567890123456789012345678901234567890"},
	}
	result := processInOperatorToMappings(source, arrays)
	assert.Contains(t, result.Modified, "allowed_addresses_mapping[txTo]")
	assert.NotEmpty(t, result.Declarations)
	assert.NotEmpty(t, result.ConstructorInit)
}

func TestProcessInOperatorToMappings_NoMatch_CB(t *testing.T) {
	source := "require(value > 0)"
	result := processInOperatorToMappings(source, nil)
	assert.Equal(t, source, result.Modified)
	assert.Empty(t, result.Declarations)
}

func TestProcessInOperatorToMappings_NumericSecondArg_CB(t *testing.T) {
	// Second arg starting with digit should not be replaced
	source := "in(txTo, 0x123)"
	result := processInOperatorToMappings(source, nil)
	assert.Equal(t, source, result.Modified)
}

// =============================================================================
// solidity_evaluator.go: preprocessInOperator edge cases
// =============================================================================

func TestPreprocessInOperator_LiteralList_CB(t *testing.T) {
	source := `in(txTo, 0x1234567890123456789012345678901234567890, 0xaabbccddaabbccddaabbccddaabbccddaabbccdd)`
	result := preprocessInOperator(source)
	// Should replace with OR chain
	assert.Contains(t, result, "||")
}

func TestPreprocessInOperator_NoInOperator_CB(t *testing.T) {
	source := "require(value > 0)"
	result := preprocessInOperator(source)
	assert.Equal(t, source, result)
}

// =============================================================================
// solidity_evaluator.go: CanBatchEvaluate
// =============================================================================

func TestCanBatchEvaluate_EmptyRules_CB(t *testing.T) {
	eval := &SolidityRuleEvaluator{}
	assert.False(t, eval.CanBatchEvaluate(nil))
	assert.False(t, eval.CanBatchEvaluate([]*types.Rule{}))
}

func TestCanBatchEvaluate_SingleRule_CB(t *testing.T) {
	eval := &SolidityRuleEvaluator{}
	config, _ := json.Marshal(SolidityExpressionConfig{Expression: "require(true);"})
	rules := []*types.Rule{
		{ID: "r1", Type: "evm_solidity", Config: config},
	}
	assert.True(t, eval.CanBatchEvaluate(rules))
}

// =============================================================================
// solidity_validator.go: modeString (66.7% -> ~100%)
// =============================================================================

func TestModeString_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	assert.Equal(t, "expression", v.modeString(ValidationModeExpression))
	assert.Equal(t, "functions", v.modeString(ValidationModeFunctions))
	assert.Equal(t, "typed_data_expression", v.modeString(ValidationModeTypedDataExpression))
	assert.Equal(t, "typed_data_functions", v.modeString(ValidationModeTypedDataFunctions))
	assert.Equal(t, "unknown", v.modeString(ValidationMode(999)))
}

// =============================================================================
// solidity_validator.go: determineValidationMode (85.7% -> ~100%)
// =============================================================================

func TestDetermineValidationMode_Expression_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	mode, code := v.determineValidationMode(&SolidityExpressionConfig{
		Expression: "require(true);",
	})
	assert.Equal(t, ValidationModeExpression, mode)
	assert.Equal(t, "require(true);", code)
}

func TestDetermineValidationMode_Functions_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	mode, code := v.determineValidationMode(&SolidityExpressionConfig{
		Functions: "function foo() {}",
	})
	assert.Equal(t, ValidationModeFunctions, mode)
	assert.Equal(t, "function foo() {}", code)
}

func TestDetermineValidationMode_TypedDataExpression_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	mode, code := v.determineValidationMode(&SolidityExpressionConfig{
		TypedDataExpression: "require(order.amount > 0);",
	})
	assert.Equal(t, ValidationModeTypedDataExpression, mode)
	assert.Equal(t, "require(order.amount > 0);", code)
}

func TestDetermineValidationMode_TypedDataFunctions_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	mode, code := v.determineValidationMode(&SolidityExpressionConfig{
		TypedDataFunctions: "function validatePermit(Permit memory p) {}",
	})
	assert.Equal(t, ValidationModeTypedDataFunctions, mode)
	assert.Equal(t, "function validatePermit(Permit memory p) {}", code)
}

func TestDetermineValidationMode_Priority_CB(t *testing.T) {
	// TypedDataExpression takes priority over Functions and Expression
	v := &SolidityRuleValidator{}
	mode, _ := v.determineValidationMode(&SolidityExpressionConfig{
		Expression:          "require(true);",
		Functions:           "function foo() {}",
		TypedDataExpression: "require(order.amount > 0);",
	})
	assert.Equal(t, ValidationModeTypedDataExpression, mode)
}

// =============================================================================
// solidity_validator.go: compareTestResult (100% but let's add context)
// =============================================================================

func TestCompareTestResult_Pass_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	result := v.compareTestResult(true, true, "", "")
	assert.True(t, result)
}

func TestCompareTestResult_ExpectedPassGotFail_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	result := v.compareTestResult(true, false, "", "some reason")
	assert.False(t, result)
}

func TestCompareTestResult_ExpectedFailGotPass_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	result := v.compareTestResult(false, true, "expected reason", "")
	assert.False(t, result)
}

func TestCompareTestResult_ExpectedFailGotFailReasonMatch_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	result := v.compareTestResult(false, false, "too large", "value too large")
	assert.True(t, result) // reason contains expected substring
}

func TestCompareTestResult_ExpectedFailGotFailReasonMismatch_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	result := v.compareTestResult(false, false, "specific reason", "different reason")
	assert.False(t, result)
}

// =============================================================================
// solidity_validator.go: testInputToRequest (94.4% -> ~100%)
// =============================================================================

func TestTestInputToRequest_WithData_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	input := SolidityTestInput{
		To:       "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
		Value:    "1000000000000000000",
		Selector: "0xa9059cbb",
		Data:     "0xa9059cbb0000000000000000000000000000000000000001",
		ChainID:  "1",
		Signer:   "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
	}
	req, parsed, err := v.testInputToRequest(input)
	require.NoError(t, err)
	assert.NotNil(t, req)
	assert.NotNil(t, parsed)
	assert.Equal(t, "1", req.ChainID)
	assert.NotNil(t, parsed.Recipient)
	assert.NotNil(t, parsed.Value)
	assert.NotNil(t, parsed.MethodSig)
	assert.NotEmpty(t, parsed.RawData)
}

func TestTestInputToRequest_Defaults_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	input := SolidityTestInput{}
	req, _, err := v.testInputToRequest(input)
	require.NoError(t, err)
	assert.Equal(t, "1", req.ChainID)
	assert.Equal(t, "0x0000000000000000000000000000000000000000", req.SignerAddress)
}

func TestTestInputToRequest_InvalidData_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	input := SolidityTestInput{
		Data: "0xZZZZ", // invalid hex
	}
	_, _, err := v.testInputToRequest(input)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hex data")
}

// =============================================================================
// solidity_validator.go: testInputToTypedDataRequest
// =============================================================================

func TestTestInputToTypedDataRequest_Defaults_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	input := SolidityTestInput{}
	typedData := &TypedDataPayload{
		PrimaryType: "Permit",
		Types:       map[string][]TypedDataField{},
	}
	req := v.testInputToTypedDataRequest(input, typedData)
	assert.Equal(t, "1", req.ChainID)
	assert.Equal(t, "0x0000000000000000000000000000000000000000", req.SignerAddress)
	assert.Equal(t, SignTypeTypedData, req.SignType)
}

func TestTestInputToTypedDataRequest_WithValues_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	input := SolidityTestInput{
		ChainID: "137",
		Signer:  "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
	}
	typedData := &TypedDataPayload{
		PrimaryType: "Permit",
		Types:       map[string][]TypedDataField{},
		Message:     map[string]interface{}{"owner": "0x123"},
	}
	req := v.testInputToTypedDataRequest(input, typedData)
	assert.Equal(t, "137", req.ChainID)
	assert.Equal(t, "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", req.SignerAddress)
	assert.NotEmpty(t, req.Payload)
}

// =============================================================================
// solidity_validator.go: buildTypedDataFromInput (85.7% -> ~100%)
// =============================================================================

func TestBuildTypedDataFromInput_NilTypedData_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	_, err := v.buildTypedDataFromInput(SolidityTestInput{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "typed_data field is required")
}

func TestBuildTypedDataFromInput_WithMessage_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	input := SolidityTestInput{
		TypedData: &TypedDataTestInput{
			PrimaryType: "Order",
			Domain: &TypedDataDomainInput{
				Name:    "TestDomain",
				Version: "1",
				ChainID: "1",
			},
			Message: map[string]interface{}{
				"amount": "42",
				"to":     "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			},
		},
	}
	result, err := v.buildTypedDataFromInput(input)
	require.NoError(t, err)
	assert.Equal(t, "Order", result.PrimaryType)
	assert.Equal(t, "TestDomain", result.Domain.Name)
	assert.NotEmpty(t, result.Types["Order"])
}

func TestBuildTypedDataFromInput_DefaultPrimaryType_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	input := SolidityTestInput{
		TypedData: &TypedDataTestInput{
			// No PrimaryType set
			Message: map[string]interface{}{
				"owner": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
			},
		},
	}
	result, err := v.buildTypedDataFromInput(input)
	require.NoError(t, err)
	assert.Equal(t, "Permit", result.PrimaryType) // default
}

func TestBuildTypedDataFromInput_NoDomain_CB(t *testing.T) {
	v := &SolidityRuleValidator{}
	input := SolidityTestInput{
		TypedData: &TypedDataTestInput{
			PrimaryType: "Test",
			Message: map[string]interface{}{
				"value": float64(42),
			},
		},
	}
	result, err := v.buildTypedDataFromInput(input)
	require.NoError(t, err)
	assert.Equal(t, "Test", result.PrimaryType)
	assert.Equal(t, "", result.Domain.Name)
}

// =============================================================================
// js_evaluator.go: isUndefined
// =============================================================================

func TestIsUndefined_Nil_CB(t *testing.T) {
	assert.True(t, isUndefined(nil))
}

func TestIsUndefined_Undefined_CB(t *testing.T) {
	assert.True(t, isUndefined(sobek.Undefined()))
}

func TestIsUndefined_DefinedValue_CB(t *testing.T) {
	vm := sobek.New()
	val := vm.ToValue("hello")
	assert.False(t, isUndefined(val))
}

// =============================================================================
// js_evaluator.go: sanitizeReason
// =============================================================================

func TestSanitizeReason_EmptyCodeAndDetail_CB(t *testing.T) {
	assert.Equal(t, "", sanitizeReason("", "", true))
	assert.Equal(t, "script_error", sanitizeReason("", "", false))
}

func TestSanitizeReason_CodeOnly_CB(t *testing.T) {
	assert.Equal(t, "timeout", sanitizeReason("timeout", "", true))
	assert.Equal(t, "timeout", sanitizeReason("timeout", "", false))
}

func TestSanitizeReason_DetailOnly_IsReason_CB(t *testing.T) {
	assert.Equal(t, "value too large", sanitizeReason("", "value too large", true))
}

func TestSanitizeReason_CodeAndDetail_NotReason_CB(t *testing.T) {
	result := sanitizeReason("script_error", "TypeError: x is not defined", false)
	assert.Equal(t, "script_error: TypeError: x is not defined", result)
}

func TestSanitizeReason_ControlCharsStripped_CB(t *testing.T) {
	result := sanitizeReason("", "hello\x00world", true)
	assert.Equal(t, "helloworld", result)
}

func TestSanitizeReason_NewlinesEscaped_CB(t *testing.T) {
	result := sanitizeReason("", "line1\nline2", true)
	assert.Equal(t, "line1\\nline2", result)
}

func TestSanitizeReason_Truncation_CB(t *testing.T) {
	longDetail := strings.Repeat("a", 2000)
	result := sanitizeReason("", longDetail, true)
	assert.LessOrEqual(t, len(result), 1024) // jsRuleMaxReasonLen
}

// =============================================================================
// js_evaluator.go: parseDelegateToIDs
// =============================================================================

func TestParseDelegateToIDs_Single_CB(t *testing.T) {
	ids := parseDelegateToIDs("rule-1")
	assert.Equal(t, []types.RuleID{"rule-1"}, ids)
}

func TestParseDelegateToIDs_Multiple_CB(t *testing.T) {
	ids := parseDelegateToIDs("rule-1,rule-2,rule-3")
	assert.Equal(t, []types.RuleID{"rule-1", "rule-2", "rule-3"}, ids)
}

func TestParseDelegateToIDs_WithSpaces_CB(t *testing.T) {
	ids := parseDelegateToIDs(" rule-1 , rule-2 ")
	assert.Equal(t, []types.RuleID{"rule-1", "rule-2"}, ids)
}

func TestParseDelegateToIDs_Empty_CB(t *testing.T) {
	ids := parseDelegateToIDs("")
	assert.Empty(t, ids)
}

func TestParseDelegateToIDs_OnlyCommas_CB(t *testing.T) {
	ids := parseDelegateToIDs(",,")
	assert.Empty(t, ids)
}

// =============================================================================
// encodeSignature (100% but test correctness)
// =============================================================================

func TestEncodeSignature_Standard_CB(t *testing.T) {
	r := new(big.Int).SetBytes([]byte{0x01, 0x02})
	s := new(big.Int).SetBytes([]byte{0x03, 0x04})
	v := new(big.Int).SetInt64(27) // standard v=27

	sig := encodeSignature(r, s, v)
	assert.Len(t, sig, 65)
	assert.Equal(t, byte(0), sig[64]) // v=27 -> 27-27=0
}

func TestEncodeSignature_V28_CB(t *testing.T) {
	r := new(big.Int).SetBytes([]byte{0x01})
	s := new(big.Int).SetBytes([]byte{0x02})
	v := new(big.Int).SetInt64(28)

	sig := encodeSignature(r, s, v)
	assert.Len(t, sig, 65)
	assert.Equal(t, byte(1), sig[64]) // v=28 -> 28-27=1
}

func TestEncodeSignature_LowV_CB(t *testing.T) {
	r := new(big.Int).SetBytes([]byte{0x01})
	s := new(big.Int).SetBytes([]byte{0x02})
	v := new(big.Int).SetInt64(0) // EIP-155 style v=0

	sig := encodeSignature(r, s, v)
	assert.Len(t, sig, 65)
	assert.Equal(t, byte(0), sig[64])
}
