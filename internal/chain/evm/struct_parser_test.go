package evm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─────────────────────────────────────────────────────────────────────────────
// parseStructDefinition
// ─────────────────────────────────────────────────────────────────────────────

func TestParseStructDefinition_Basic(t *testing.T) {
	input := `struct Order {
		uint256 salt;
		address maker;
		address taker;
	}`
	def, err := parseStructDefinition(input)
	require.NoError(t, err)
	assert.Equal(t, "Order", def.Name)
	assert.Len(t, def.Fields, 3)
	assert.Equal(t, "uint256", def.Fields[0].Type)
	assert.Equal(t, "salt", def.Fields[0].Name)
	assert.Equal(t, "address", def.Fields[1].Type)
	assert.Equal(t, "maker", def.Fields[1].Name)
}

func TestParseStructDefinition_WithComments(t *testing.T) {
	input := `
	// This is a test struct
	struct Permit {
		address owner; // the permit owner
		address spender;
		/* multi-line
		comment */
		uint256 value;
	}`
	def, err := parseStructDefinition(input)
	require.NoError(t, err)
	assert.Equal(t, "Permit", def.Name)
	assert.Len(t, def.Fields, 3)
}

func TestParseStructDefinition_Empty(t *testing.T) {
	_, err := parseStructDefinition("struct Empty { }")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no fields")
}

func TestParseStructDefinition_Invalid(t *testing.T) {
	_, err := parseStructDefinition("not a struct")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no struct found")
}

func TestParseStructDefinition_MemoryModifier(t *testing.T) {
	input := `struct Data {
		string memory message;
		bytes memory data;
	}`
	def, err := parseStructDefinition(input)
	require.NoError(t, err)
	assert.Equal(t, "string", def.Fields[0].Type)
	assert.Equal(t, "message", def.Fields[0].Name)
	assert.Equal(t, "bytes", def.Fields[1].Type)
}

// ─────────────────────────────────────────────────────────────────────────────
// isValidIdentifier
// ─────────────────────────────────────────────────────────────────────────────

func TestIsValidIdentifier(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"salt", true},
		{"_private", true},
		{"x1", true},
		{"camelCase", true},
		{"ALL_CAPS", true},
		{"", false},
		{"1start", false},
		{"with-dash", false},
		{"with space", false},
		{"with.dot", false},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.valid, isValidIdentifier(tc.input))
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// normalizeType
// ─────────────────────────────────────────────────────────────────────────────

func TestNormalizeType(t *testing.T) {
	assert.Equal(t, "uint256", normalizeType("uint"))
	assert.Equal(t, "int256", normalizeType("int"))
	assert.Equal(t, "uint8", normalizeType("uint8"))
	assert.Equal(t, "address", normalizeType("address"))
	assert.Equal(t, "string", normalizeType(" string "))
}

// ─────────────────────────────────────────────────────────────────────────────
// formatFieldValue
// ─────────────────────────────────────────────────────────────────────────────

func TestFormatFieldValue_Address(t *testing.T) {
	// Valid address
	assert.Contains(t, formatFieldValue("address", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	// Invalid address
	assert.Equal(t, "address(0)", formatFieldValue("address", "not_an_address"))
	// Nil
	assert.Equal(t, "address(0)", formatFieldValue("address", nil))
}

func TestFormatFieldValue_String(t *testing.T) {
	assert.Equal(t, `"hello"`, formatFieldValue("string", "hello"))
	assert.Equal(t, `"with \"quotes\""`, formatFieldValue("string", `with "quotes"`))
	assert.Equal(t, `""`, formatFieldValue("string", nil))
	assert.Equal(t, `""`, formatFieldValue("string", 42)) // non-string
}

func TestFormatFieldValue_Bool(t *testing.T) {
	assert.Equal(t, "true", formatFieldValue("bool", true))
	assert.Equal(t, "false", formatFieldValue("bool", false))
	assert.Equal(t, "false", formatFieldValue("bool", nil))
	assert.Equal(t, "false", formatFieldValue("bool", "true")) // non-bool type
}

func TestFormatFieldValue_Uint256(t *testing.T) {
	assert.Equal(t, "42", formatFieldValue("uint256", "42"))
	assert.Equal(t, "1000000000000000000", formatFieldValue("uint256", "1000000000000000000"))
	assert.Equal(t, "0", formatFieldValue("uint256", "not_a_number"))
	assert.Equal(t, "0", formatFieldValue("uint256", nil))
	assert.Equal(t, "42", formatFieldValue("uint256", float64(42)))
	assert.Equal(t, "0", formatFieldValue("uint256", "-1")) // negative not allowed for uint
}

func TestFormatFieldValue_Int256(t *testing.T) {
	assert.Equal(t, "42", formatFieldValue("int256", "42"))
	assert.Equal(t, "-42", formatFieldValue("int256", "-42"))
}

func TestFormatFieldValue_Bytes32(t *testing.T) {
	validBytes32 := "0x0000000000000000000000000000000000000000000000000000000000000001"
	assert.Equal(t, validBytes32, formatFieldValue("bytes32", validBytes32))
	assert.Equal(t, "bytes32(0)", formatFieldValue("bytes32", "short"))
	assert.Equal(t, "bytes32(0)", formatFieldValue("bytes32", nil))
}

func TestFormatFieldValue_Bytes(t *testing.T) {
	assert.Equal(t, `hex"abcd"`, formatFieldValue("bytes", "0xabcd"))
	assert.Equal(t, `hex""`, formatFieldValue("bytes", "0xZZZZ")) // invalid hex
	assert.Equal(t, `""`, formatFieldValue("bytes", nil))
}

// ─────────────────────────────────────────────────────────────────────────────
// getDefaultValue
// ─────────────────────────────────────────────────────────────────────────────

func TestGetDefaultValue(t *testing.T) {
	assert.Equal(t, "address(0)", getDefaultValue("address"))
	assert.Equal(t, `""`, getDefaultValue("string"))
	assert.Equal(t, `""`, getDefaultValue("bytes"))
	assert.Equal(t, "bytes32(0)", getDefaultValue("bytes32"))
	assert.Equal(t, "false", getDefaultValue("bool"))
	assert.Equal(t, "0", getDefaultValue("uint256"))
	assert.Equal(t, "0", getDefaultValue("int256"))
	assert.Equal(t, `""`, getDefaultValue("bytes4"))
	assert.Equal(t, "0", getDefaultValue("unknown"))
}

// ─────────────────────────────────────────────────────────────────────────────
// generateStructDefinition
// ─────────────────────────────────────────────────────────────────────────────

func TestGenerateStructDefinition(t *testing.T) {
	def := &StructDefinition{
		Name: "Order",
		Fields: []TypedDataField{
			{Name: "salt", Type: "uint256"},
			{Name: "maker", Type: "address"},
		},
	}
	code := generateStructDefinition(def)
	assert.Contains(t, code, "struct Order")
	assert.Contains(t, code, "uint256 salt;")
	assert.Contains(t, code, "address maker;")
}

func TestGenerateStructDefinition_Nil(t *testing.T) {
	assert.Equal(t, "", generateStructDefinition(nil))
	assert.Equal(t, "", generateStructDefinition(&StructDefinition{Name: "Empty"}))
}

// ─────────────────────────────────────────────────────────────────────────────
// generateStructInstance
// ─────────────────────────────────────────────────────────────────────────────

func TestGenerateStructInstance(t *testing.T) {
	def := &StructDefinition{
		Name: "Order",
		Fields: []TypedDataField{
			{Name: "salt", Type: "uint256"},
			{Name: "maker", Type: "address"},
		},
	}
	message := map[string]interface{}{
		"salt":  "42",
		"maker": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
	}
	code := generateStructInstance(def, message)
	assert.Contains(t, code, "Order memory order")
	assert.Contains(t, code, "salt: 42")
}

func TestGenerateStructInstance_Nil(t *testing.T) {
	assert.Equal(t, "", generateStructInstance(nil, nil))
}

func TestGenerateStructInstance_UnderscoreFieldMapping(t *testing.T) {
	def := &StructDefinition{
		Name: "Data",
		Fields: []TypedDataField{
			{Name: "address_", Type: "address"}, // underscore suffix for reserved word
		},
	}
	message := map[string]interface{}{
		"address": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", // key without underscore
	}
	code := generateStructInstance(def, message)
	assert.Contains(t, code, "address_:")
}

// ─────────────────────────────────────────────────────────────────────────────
// removeComments
// ─────────────────────────────────────────────────────────────────────────────

func TestRemoveComments(t *testing.T) {
	input := `line1 // comment
line2
/* multi
line */
line3`
	result := removeComments(input)
	assert.Contains(t, result, "line1")
	assert.Contains(t, result, "line2")
	assert.Contains(t, result, "line3")
	assert.NotContains(t, result, "comment")
	assert.NotContains(t, result, "multi")
}

// ─────────────────────────────────────────────────────────────────────────────
// Template injection defense
// ─────────────────────────────────────────────────────────────────────────────

func TestFormatFieldValue_AddressInjection(t *testing.T) {
	// Attempt to inject Solidity code through an address field
	malicious := "0x0000000000000000000000000000000000000001); revert(\"hacked"
	result := formatFieldValue("address", malicious)
	assert.Equal(t, "address(0)", result, "injection attempt should be sanitized to default")
}

func TestFormatFieldValue_Uint256Injection(t *testing.T) {
	// Attempt to inject through numeric field
	malicious := "42); revert(\"hacked"
	result := formatFieldValue("uint256", malicious)
	assert.Equal(t, "0", result, "injection attempt should be sanitized to default")
}

func TestFormatFieldValue_Bytes32Injection(t *testing.T) {
	// Too short to be valid bytes32
	malicious := "0x01); revert(\"hacked"
	result := formatFieldValue("bytes32", malicious)
	assert.Equal(t, "bytes32(0)", result)
}
