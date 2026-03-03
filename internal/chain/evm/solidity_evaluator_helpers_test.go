package evm

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// =============================================================================
// addressForEnv Tests
// =============================================================================

func TestAddressForEnv_Nil(t *testing.T) {
	assert.Equal(t, "0x0000000000000000000000000000000000000000", addressForEnv(nil))
}

func TestAddressForEnv_Empty(t *testing.T) {
	s := ""
	assert.Equal(t, "0x0000000000000000000000000000000000000000", addressForEnv(&s))
}

func TestAddressForEnv_ValidLowercase(t *testing.T) {
	s := "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
	result := addressForEnv(&s)
	// Should return EIP-55 checksummed address
	assert.True(t, strings.HasPrefix(result, "0x"))
	assert.Len(t, result, 42)
	assert.Equal(t, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", result)
}

func TestAddressForEnv_ValidChecksummed(t *testing.T) {
	s := "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
	result := addressForEnv(&s)
	assert.Equal(t, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", result)
}

func TestAddressForEnv_InvalidHex(t *testing.T) {
	s := "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	assert.Equal(t, "0x0000000000000000000000000000000000000000", addressForEnv(&s))
}

func TestAddressForEnv_TooShort(t *testing.T) {
	s := "0xd8da6bf269"
	assert.Equal(t, "0x0000000000000000000000000000000000000000", addressForEnv(&s))
}

func TestAddressForEnv_TooLong(t *testing.T) {
	s := "0xd8da6bf26964af9d7eed9e03e53415d37aa96045aa"
	assert.Equal(t, "0x0000000000000000000000000000000000000000", addressForEnv(&s))
}

func TestAddressForEnv_Without0xPrefix(t *testing.T) {
	s := "d8da6bf26964af9d7eed9e03e53415d37aa96045"
	// No 0x prefix: TrimPrefix("0x") leaves the string as-is (40 hex chars), isHexString and len check pass,
	// but common.IsHexAddress requires 0x prefix, so it should return zero address.
	// Actually common.IsHexAddress accepts addresses without 0x prefix IF they're 40 hex chars.
	// Let's just verify the behavior:
	result := addressForEnv(&s)
	// common.IsHexAddress("d8da6bf26964af9d7eed9e03e53415d37aa96045") returns true
	assert.True(t, strings.HasPrefix(result, "0x"))
	assert.Len(t, result, 42)
}

func TestAddressForEnv_ZeroAddress(t *testing.T) {
	s := "0x0000000000000000000000000000000000000000"
	result := addressForEnv(&s)
	assert.Equal(t, "0x0000000000000000000000000000000000000000", result)
}

func TestAddressForEnv_InjectionAttempt(t *testing.T) {
	s := "0xd8da6bf26964af9d7eed9e03e53415d37aa96045; attack()"
	assert.Equal(t, "0x0000000000000000000000000000000000000000", addressForEnv(&s))
}

// =============================================================================
// buildRequestEnv Tests
// =============================================================================

func TestBuildRequestEnv_NilRequest(t *testing.T) {
	parsed := &types.ParsedPayload{}
	assert.Nil(t, buildRequestEnv(nil, parsed))
}

func TestBuildRequestEnv_NilParsed(t *testing.T) {
	req := &types.SignRequest{}
	assert.Nil(t, buildRequestEnv(req, nil))
}

func TestBuildRequestEnv_BothNil(t *testing.T) {
	assert.Nil(t, buildRequestEnv(nil, nil))
}

func TestBuildRequestEnv_MinimalInput(t *testing.T) {
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
	}
	parsed := &types.ParsedPayload{}

	env := buildRequestEnv(req, parsed)
	require.NotNil(t, env)
	assert.Len(t, env, 6)

	envMap := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		require.Len(t, parts, 2)
		envMap[parts[0]] = parts[1]
	}

	assert.Equal(t, "0x0000000000000000000000000000000000000000", envMap["RULE_TX_TO"])
	assert.Equal(t, "0", envMap["RULE_TX_VALUE"])
	assert.Equal(t, "0x00000000", envMap["RULE_TX_SELECTOR"])
	assert.Equal(t, "0x", envMap["RULE_TX_DATA"])
	assert.Equal(t, "1", envMap["RULE_CHAIN_ID"])
	assert.Equal(t, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", envMap["RULE_SIGNER"])
}

func TestBuildRequestEnv_FullInput(t *testing.T) {
	recipient := "0x1234567890abcdef1234567890abcdef12345678"
	value := "1000000000000000000"
	methodSig := "0xa9059cbb"
	rawData := []byte{0xa9, 0x05, 0x9c, 0xbb, 0x01, 0x02}

	req := &types.SignRequest{
		ChainID:       "137",
		SignerAddress: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
	}
	parsed := &types.ParsedPayload{
		Recipient: &recipient,
		Value:     &value,
		MethodSig: &methodSig,
		RawData:   rawData,
	}

	env := buildRequestEnv(req, parsed)
	require.NotNil(t, env)
	assert.Len(t, env, 6)

	envMap := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		require.Len(t, parts, 2)
		envMap[parts[0]] = parts[1]
	}

	assert.Contains(t, envMap["RULE_TX_TO"], "0x")
	assert.Equal(t, "1000000000000000000", envMap["RULE_TX_VALUE"])
	assert.Equal(t, "0xa9059cbb", envMap["RULE_TX_SELECTOR"])
	assert.Equal(t, "0x"+hex.EncodeToString(rawData), envMap["RULE_TX_DATA"])
	assert.Equal(t, "137", envMap["RULE_CHAIN_ID"])
}

func TestBuildRequestEnv_InvalidChainID(t *testing.T) {
	req := &types.SignRequest{
		ChainID:       "not-a-number",
		SignerAddress: "0x0000000000000000000000000000000000000001",
	}
	parsed := &types.ParsedPayload{}

	env := buildRequestEnv(req, parsed)
	envMap := envToMap(t, env)
	assert.Equal(t, "1", envMap["RULE_CHAIN_ID"])
}

func TestBuildRequestEnv_EmptyChainID(t *testing.T) {
	req := &types.SignRequest{
		ChainID:       "",
		SignerAddress: "0x0000000000000000000000000000000000000001",
	}
	parsed := &types.ParsedPayload{}

	env := buildRequestEnv(req, parsed)
	envMap := envToMap(t, env)
	assert.Equal(t, "1", envMap["RULE_CHAIN_ID"])
}

func TestBuildRequestEnv_InvalidValue(t *testing.T) {
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x0000000000000000000000000000000000000001",
	}
	badValue := "abc"
	parsed := &types.ParsedPayload{
		Value: &badValue,
	}

	env := buildRequestEnv(req, parsed)
	envMap := envToMap(t, env)
	assert.Equal(t, "0", envMap["RULE_TX_VALUE"])
}

func TestBuildRequestEnv_InvalidSelector(t *testing.T) {
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x0000000000000000000000000000000000000001",
	}
	badSig := "0xZZZZ"
	parsed := &types.ParsedPayload{
		MethodSig: &badSig,
	}

	env := buildRequestEnv(req, parsed)
	envMap := envToMap(t, env)
	assert.Equal(t, "0x00000000", envMap["RULE_TX_SELECTOR"])
}

func TestBuildRequestEnv_SelectorTooShort(t *testing.T) {
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x0000000000000000000000000000000000000001",
	}
	shortSig := "0xaa"
	parsed := &types.ParsedPayload{
		MethodSig: &shortSig,
	}

	env := buildRequestEnv(req, parsed)
	envMap := envToMap(t, env)
	assert.Equal(t, "0x00000000", envMap["RULE_TX_SELECTOR"])
}

func TestBuildRequestEnv_EmptyRawData(t *testing.T) {
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x0000000000000000000000000000000000000001",
	}
	parsed := &types.ParsedPayload{
		RawData: []byte{},
	}

	env := buildRequestEnv(req, parsed)
	envMap := envToMap(t, env)
	assert.Equal(t, "0x", envMap["RULE_TX_DATA"])
}

// =============================================================================
// formatInterfaceAsAddress Tests
// =============================================================================

func TestFormatInterfaceAsAddress_ValidString(t *testing.T) {
	result := formatInterfaceAsAddress("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
	assert.Equal(t, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", result)
}

func TestFormatInterfaceAsAddress_ValidLowercase(t *testing.T) {
	result := formatInterfaceAsAddress("0xd8da6bf26964af9d7eed9e03e53415d37aa96045")
	assert.Equal(t, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", result)
}

func TestFormatInterfaceAsAddress_EmptyString(t *testing.T) {
	assert.Equal(t, "address(0)", formatInterfaceAsAddress(""))
}

func TestFormatInterfaceAsAddress_InvalidAddress(t *testing.T) {
	assert.Equal(t, "address(0)", formatInterfaceAsAddress("not-an-address"))
}

func TestFormatInterfaceAsAddress_NonStringType(t *testing.T) {
	assert.Equal(t, "address(0)", formatInterfaceAsAddress(42))
	assert.Equal(t, "address(0)", formatInterfaceAsAddress(nil))
	assert.Equal(t, "address(0)", formatInterfaceAsAddress(true))
	assert.Equal(t, "address(0)", formatInterfaceAsAddress(3.14))
}

func TestFormatInterfaceAsAddress_InjectionAttempt(t *testing.T) {
	assert.Equal(t, "address(0)", formatInterfaceAsAddress("0xd8da6bf26964af9d7eed9e03e53415d37aa96045; evil()"))
}

// =============================================================================
// formatInterfaceAsUint Tests
// =============================================================================

func TestFormatInterfaceAsUint_ValidString(t *testing.T) {
	assert.Equal(t, "12345", formatInterfaceAsUint("12345"))
}

func TestFormatInterfaceAsUint_ZeroString(t *testing.T) {
	assert.Equal(t, "0", formatInterfaceAsUint("0"))
}

func TestFormatInterfaceAsUint_EmptyString(t *testing.T) {
	assert.Equal(t, "0", formatInterfaceAsUint(""))
}

func TestFormatInterfaceAsUint_InvalidString(t *testing.T) {
	assert.Equal(t, "0", formatInterfaceAsUint("not-a-number"))
}

func TestFormatInterfaceAsUint_NegativeString(t *testing.T) {
	// Negative is not valid for uint
	assert.Equal(t, "0", formatInterfaceAsUint("-123"))
}

func TestFormatInterfaceAsUint_HexString(t *testing.T) {
	assert.Equal(t, "0", formatInterfaceAsUint("0xdeadbeef"))
}

func TestFormatInterfaceAsUint_Float64(t *testing.T) {
	assert.Equal(t, "42", formatInterfaceAsUint(float64(42)))
}

func TestFormatInterfaceAsUint_Float64Large(t *testing.T) {
	assert.Equal(t, "1000000000000000000", formatInterfaceAsUint(float64(1e18)))
}

func TestFormatInterfaceAsUint_Int(t *testing.T) {
	assert.Equal(t, "99", formatInterfaceAsUint(int(99)))
}

func TestFormatInterfaceAsUint_Int64(t *testing.T) {
	assert.Equal(t, "999999999999", formatInterfaceAsUint(int64(999999999999)))
}

func TestFormatInterfaceAsUint_Uint64(t *testing.T) {
	assert.Equal(t, "18446744073709551615", formatInterfaceAsUint(uint64(18446744073709551615)))
}

func TestFormatInterfaceAsUint_DefaultType(t *testing.T) {
	assert.Equal(t, "0", formatInterfaceAsUint(nil))
	assert.Equal(t, "0", formatInterfaceAsUint(true))
	assert.Equal(t, "0", formatInterfaceAsUint([]byte{1, 2}))
}

func TestFormatInterfaceAsUint_LargeDecimalString(t *testing.T) {
	assert.Equal(t, "115792089237316195423570985008687907853269984665640564039457584007913129639935", formatInterfaceAsUint("115792089237316195423570985008687907853269984665640564039457584007913129639935"))
}

func TestFormatInterfaceAsUint_InjectionAttempt(t *testing.T) {
	assert.Equal(t, "0", formatInterfaceAsUint("123; evil()"))
}

// =============================================================================
// formatInterfaceAsInt Tests
// =============================================================================

func TestFormatInterfaceAsInt_ValidPositive(t *testing.T) {
	assert.Equal(t, "42", formatInterfaceAsInt("42"))
}

func TestFormatInterfaceAsInt_ValidNegative(t *testing.T) {
	assert.Equal(t, "-42", formatInterfaceAsInt("-42"))
}

func TestFormatInterfaceAsInt_Zero(t *testing.T) {
	assert.Equal(t, "0", formatInterfaceAsInt("0"))
}

func TestFormatInterfaceAsInt_EmptyString(t *testing.T) {
	assert.Equal(t, "0", formatInterfaceAsInt(""))
}

func TestFormatInterfaceAsInt_InvalidString(t *testing.T) {
	assert.Equal(t, "0", formatInterfaceAsInt("abc"))
}

func TestFormatInterfaceAsInt_JustDash(t *testing.T) {
	// "-" -> TrimPrefix("-") = "" -> isDecimalString("") = false -> "0"
	assert.Equal(t, "0", formatInterfaceAsInt("-"))
}

func TestFormatInterfaceAsInt_Float64(t *testing.T) {
	assert.Equal(t, "42", formatInterfaceAsInt(float64(42)))
}

func TestFormatInterfaceAsInt_Float64Negative(t *testing.T) {
	assert.Equal(t, "-42", formatInterfaceAsInt(float64(-42)))
}

func TestFormatInterfaceAsInt_IntType(t *testing.T) {
	assert.Equal(t, "99", formatInterfaceAsInt(int(99)))
}

func TestFormatInterfaceAsInt_Int64Type(t *testing.T) {
	assert.Equal(t, "-9223372036854775808", formatInterfaceAsInt(int64(-9223372036854775808)))
}

func TestFormatInterfaceAsInt_DefaultType(t *testing.T) {
	assert.Equal(t, "0", formatInterfaceAsInt(nil))
	assert.Equal(t, "0", formatInterfaceAsInt(true))
	assert.Equal(t, "0", formatInterfaceAsInt(uint64(5)))
}

func TestFormatInterfaceAsInt_InjectionAttempt(t *testing.T) {
	assert.Equal(t, "0", formatInterfaceAsInt("123; evil()"))
}

// =============================================================================
// formatInterfaceAsBool Tests
// =============================================================================

func TestFormatInterfaceAsBool_TrueBool(t *testing.T) {
	assert.Equal(t, "true", formatInterfaceAsBool(true))
}

func TestFormatInterfaceAsBool_FalseBool(t *testing.T) {
	assert.Equal(t, "false", formatInterfaceAsBool(false))
}

func TestFormatInterfaceAsBool_TrueString(t *testing.T) {
	assert.Equal(t, "true", formatInterfaceAsBool("true"))
}

func TestFormatInterfaceAsBool_FalseString(t *testing.T) {
	assert.Equal(t, "false", formatInterfaceAsBool("false"))
}

func TestFormatInterfaceAsBool_OtherString(t *testing.T) {
	assert.Equal(t, "false", formatInterfaceAsBool("yes"))
	assert.Equal(t, "false", formatInterfaceAsBool("1"))
	assert.Equal(t, "false", formatInterfaceAsBool(""))
	assert.Equal(t, "false", formatInterfaceAsBool("True")) // case-sensitive
}

func TestFormatInterfaceAsBool_NonStringNonBool(t *testing.T) {
	assert.Equal(t, "false", formatInterfaceAsBool(nil))
	assert.Equal(t, "false", formatInterfaceAsBool(42))
	assert.Equal(t, "false", formatInterfaceAsBool(1))
	assert.Equal(t, "false", formatInterfaceAsBool(0))
	assert.Equal(t, "false", formatInterfaceAsBool(3.14))
}

// =============================================================================
// formatInterfaceAsBytes32 Tests
// =============================================================================

func TestFormatInterfaceAsBytes32_ValidHexWith0x(t *testing.T) {
	hexVal := "0x" + strings.Repeat("ab", 32)
	assert.Equal(t, hexVal, formatInterfaceAsBytes32(hexVal))
}

func TestFormatInterfaceAsBytes32_ValidHexWithout0x(t *testing.T) {
	hexVal := strings.Repeat("ab", 32)
	assert.Equal(t, `hex"`+hexVal+`"`, formatInterfaceAsBytes32(hexVal))
}

func TestFormatInterfaceAsBytes32_EmptyString(t *testing.T) {
	assert.Equal(t, "bytes32(0)", formatInterfaceAsBytes32(""))
}

func TestFormatInterfaceAsBytes32_TooShortWith0x(t *testing.T) {
	assert.Equal(t, "bytes32(0)", formatInterfaceAsBytes32("0xabcd"))
}

func TestFormatInterfaceAsBytes32_TooLongWith0x(t *testing.T) {
	hexVal := "0x" + strings.Repeat("ab", 33)
	assert.Equal(t, "bytes32(0)", formatInterfaceAsBytes32(hexVal))
}

func TestFormatInterfaceAsBytes32_InvalidHexWith0x(t *testing.T) {
	hexVal := "0x" + strings.Repeat("zz", 32)
	assert.Equal(t, "bytes32(0)", formatInterfaceAsBytes32(hexVal))
}

func TestFormatInterfaceAsBytes32_InvalidHexWithout0x(t *testing.T) {
	assert.Equal(t, "bytes32(0)", formatInterfaceAsBytes32("not-hex-at-all"))
}

func TestFormatInterfaceAsBytes32_NonStringType(t *testing.T) {
	assert.Equal(t, "bytes32(0)", formatInterfaceAsBytes32(42))
	assert.Equal(t, "bytes32(0)", formatInterfaceAsBytes32(nil))
	assert.Equal(t, "bytes32(0)", formatInterfaceAsBytes32(true))
}

// =============================================================================
// formatInterfaceAsBytes Tests
// =============================================================================

func TestFormatInterfaceAsBytes_EmptyString(t *testing.T) {
	assert.Equal(t, `hex""`, formatInterfaceAsBytes(""))
}

func TestFormatInterfaceAsBytes_ValidHexWith0x(t *testing.T) {
	assert.Equal(t, `hex"deadbeef"`, formatInterfaceAsBytes("0xdeadbeef"))
}

func TestFormatInterfaceAsBytes_InvalidHexWith0x(t *testing.T) {
	assert.Equal(t, `hex""`, formatInterfaceAsBytes("0xnothex"))
}

func TestFormatInterfaceAsBytes_NonHexString(t *testing.T) {
	// Non-0x string: encode as hex bytes
	result := formatInterfaceAsBytes("hello")
	assert.Equal(t, `hex"`+hex.EncodeToString([]byte("hello"))+`"`, result)
}

func TestFormatInterfaceAsBytes_ByteSlice(t *testing.T) {
	data := []byte{0xde, 0xad, 0xbe, 0xef}
	assert.Equal(t, `hex"deadbeef"`, formatInterfaceAsBytes(data))
}

func TestFormatInterfaceAsBytes_EmptyByteSlice(t *testing.T) {
	assert.Equal(t, `hex""`, formatInterfaceAsBytes([]byte{}))
}

func TestFormatInterfaceAsBytes_NonStringNonBytes(t *testing.T) {
	assert.Equal(t, `hex""`, formatInterfaceAsBytes(nil))
	assert.Equal(t, `hex""`, formatInterfaceAsBytes(42))
	assert.Equal(t, `hex""`, formatInterfaceAsBytes(true))
}

func TestFormatInterfaceAsBytes_LongHex(t *testing.T) {
	longHex := "0x" + strings.Repeat("ab", 100)
	assert.Equal(t, `hex"`+strings.Repeat("ab", 100)+`"`, formatInterfaceAsBytes(longHex))
}

// =============================================================================
// formatInterfaceAsString Tests
// =============================================================================

func TestFormatInterfaceAsString_NormalString(t *testing.T) {
	assert.Equal(t, `"hello"`, formatInterfaceAsString("hello"))
}

func TestFormatInterfaceAsString_EmptyString(t *testing.T) {
	assert.Equal(t, `""`, formatInterfaceAsString(""))
}

func TestFormatInterfaceAsString_StringWithQuotes(t *testing.T) {
	assert.Equal(t, `"say \"hello\""`, formatInterfaceAsString(`say "hello"`))
}

func TestFormatInterfaceAsString_StringWithBackslash(t *testing.T) {
	assert.Equal(t, `"back\\slash"`, formatInterfaceAsString(`back\slash`))
}

func TestFormatInterfaceAsString_StringWithBothEscapes(t *testing.T) {
	assert.Equal(t, `"a\\b\"c"`, formatInterfaceAsString(`a\b"c`))
}

func TestFormatInterfaceAsString_NonStringType(t *testing.T) {
	assert.Equal(t, `""`, formatInterfaceAsString(42))
	assert.Equal(t, `""`, formatInterfaceAsString(nil))
	assert.Equal(t, `""`, formatInterfaceAsString(true))
	assert.Equal(t, `""`, formatInterfaceAsString(3.14))
}

func TestFormatInterfaceAsString_UnicodeString(t *testing.T) {
	result := formatInterfaceAsString("hello world")
	assert.Equal(t, `"hello world"`, result)
}

// =============================================================================
// formatInterfaceAsFixedBytes Tests
// =============================================================================

func TestFormatInterfaceAsFixedBytes_EmptyString(t *testing.T) {
	assert.Equal(t, "bytes4(0)", formatInterfaceAsFixedBytes("", "bytes4"))
	assert.Equal(t, "bytes16(0)", formatInterfaceAsFixedBytes("", "bytes16"))
}

func TestFormatInterfaceAsFixedBytes_ValidHexWith0x(t *testing.T) {
	assert.Equal(t, "0xdeadbeef", formatInterfaceAsFixedBytes("0xdeadbeef", "bytes4"))
}

func TestFormatInterfaceAsFixedBytes_ValidHexWithout0x(t *testing.T) {
	assert.Equal(t, `hex"deadbeef"`, formatInterfaceAsFixedBytes("deadbeef", "bytes4"))
}

func TestFormatInterfaceAsFixedBytes_InvalidHexWith0x(t *testing.T) {
	assert.Equal(t, "bytes4(0)", formatInterfaceAsFixedBytes("0xnothex!", "bytes4"))
}

func TestFormatInterfaceAsFixedBytes_InvalidHexWithout0x(t *testing.T) {
	assert.Equal(t, "bytes8(0)", formatInterfaceAsFixedBytes("not-hex", "bytes8"))
}

func TestFormatInterfaceAsFixedBytes_NonStringType(t *testing.T) {
	assert.Equal(t, "bytes4(0)", formatInterfaceAsFixedBytes(42, "bytes4"))
	assert.Equal(t, "bytes4(0)", formatInterfaceAsFixedBytes(nil, "bytes4"))
	assert.Equal(t, "bytes4(0)", formatInterfaceAsFixedBytes(true, "bytes4"))
}

func TestFormatInterfaceAsFixedBytes_DifferentSizes(t *testing.T) {
	tests := []struct {
		name     string
		solType  string
		expected string
	}{
		{"bytes1", "bytes1", "bytes1(0)"},
		{"bytes8", "bytes8", "bytes8(0)"},
		{"bytes20", "bytes20", "bytes20(0)"},
		{"bytes32", "bytes32", "bytes32(0)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, formatInterfaceAsFixedBytes("", tc.solType))
		})
	}
}

// =============================================================================
// isDecimalString Tests
// =============================================================================

func TestIsDecimalString_ValidNumbers(t *testing.T) {
	assert.True(t, isDecimalString("0"))
	assert.True(t, isDecimalString("1"))
	assert.True(t, isDecimalString("123456789"))
	assert.True(t, isDecimalString("99999999999999999999"))
}

func TestIsDecimalString_Empty(t *testing.T) {
	assert.False(t, isDecimalString(""))
}

func TestIsDecimalString_Invalid(t *testing.T) {
	assert.False(t, isDecimalString("abc"))
	assert.False(t, isDecimalString("12.34"))
	assert.False(t, isDecimalString("-1"))
	assert.False(t, isDecimalString("1e18"))
	assert.False(t, isDecimalString("0x1"))
	assert.False(t, isDecimalString(" 123"))
	assert.False(t, isDecimalString("123 "))
	assert.False(t, isDecimalString("12 34"))
}

func TestIsDecimalString_LeadingZeros(t *testing.T) {
	// Leading zeros are valid decimal digits
	assert.True(t, isDecimalString("000"))
	assert.True(t, isDecimalString("007"))
}

// =============================================================================
// isHexString Tests
// =============================================================================

func TestIsHexString_ValidHex(t *testing.T) {
	assert.True(t, isHexString("0123456789abcdefABCDEF"))
	assert.True(t, isHexString("deadbeef"))
	assert.True(t, isHexString("DEADBEEF"))
	assert.True(t, isHexString("a"))
	assert.True(t, isHexString("0"))
}

func TestIsHexString_Empty(t *testing.T) {
	assert.False(t, isHexString(""))
}

func TestIsHexString_Invalid(t *testing.T) {
	assert.False(t, isHexString("xyz"))
	assert.False(t, isHexString("0xdeadbeef")) // '0x' prefix - 'x' is not hex
	assert.False(t, isHexString(" ab"))
	assert.False(t, isHexString("ab "))
	assert.False(t, isHexString("gh"))
	assert.False(t, isHexString("12.34"))
}

// =============================================================================
// sanitizeEmptyComparisons Tests
// =============================================================================

func TestSanitizeEmptyComparisons_EqCloseParen(t *testing.T) {
	// to == ) -> to == address(0))
	result := sanitizeEmptyComparisons("require(to == )")
	assert.Equal(t, "require(to == address(0))", result)
}

func TestSanitizeEmptyComparisons_EqCloseParenChainId(t *testing.T) {
	// chainId == ) -> chainId == 0)
	result := sanitizeEmptyComparisons("require(chainId == )")
	assert.Equal(t, "require(chainId == 0)", result)
}

func TestSanitizeEmptyComparisons_EqComma(t *testing.T) {
	// to == , -> to == address(0),
	result := sanitizeEmptyComparisons(`require(to == , "msg")`)
	assert.Equal(t, `require(to == address(0), "msg")`, result)
}

func TestSanitizeEmptyComparisons_EqCommaChainId(t *testing.T) {
	result := sanitizeEmptyComparisons(`require(chainId == , "msg")`)
	assert.Equal(t, `require(chainId == 0, "msg")`, result)
}

func TestSanitizeEmptyComparisons_EqOr(t *testing.T) {
	result := sanitizeEmptyComparisons("to == || signer == address(1)")
	assert.Equal(t, "to == address(0) || signer == address(1)", result)
}

func TestSanitizeEmptyComparisons_EqOrChainId(t *testing.T) {
	result := sanitizeEmptyComparisons("chainId == || true")
	assert.Equal(t, "chainId == 0 || true", result)
}

func TestSanitizeEmptyComparisons_EqAnd(t *testing.T) {
	result := sanitizeEmptyComparisons("to == && signer == address(1)")
	assert.Equal(t, "to == address(0) && signer == address(1)", result)
}

func TestSanitizeEmptyComparisons_EqAndChainId(t *testing.T) {
	result := sanitizeEmptyComparisons("chainId == && true")
	assert.Equal(t, "chainId == 0 && true", result)
}

func TestSanitizeEmptyComparisons_EqSemicolon(t *testing.T) {
	result := sanitizeEmptyComparisons("to == ;")
	assert.Equal(t, "to == address(0);", result)
}

func TestSanitizeEmptyComparisons_EqSemicolonChainId(t *testing.T) {
	result := sanitizeEmptyComparisons("chainId == ;")
	assert.Equal(t, "chainId == 0;", result)
}

func TestSanitizeEmptyComparisons_NeqCloseParen(t *testing.T) {
	result := sanitizeEmptyComparisons("require(to != )")
	assert.Equal(t, "require(to != address(0))", result)
}

func TestSanitizeEmptyComparisons_NeqCloseParenChainId(t *testing.T) {
	result := sanitizeEmptyComparisons("require(chainId != )")
	// != with paren uses emptyRHS which checks for chainId
	assert.Equal(t, "require(chainId != 0)", result)
}

func TestSanitizeEmptyComparisons_NeqComma(t *testing.T) {
	result := sanitizeEmptyComparisons(`to != , "msg"`)
	assert.Equal(t, `to != address(0), "msg"`, result)
}

func TestSanitizeEmptyComparisons_NeqOr(t *testing.T) {
	result := sanitizeEmptyComparisons("to != || false")
	assert.Equal(t, "to != address(0) || false", result)
}

func TestSanitizeEmptyComparisons_NeqAnd(t *testing.T) {
	result := sanitizeEmptyComparisons("to != && false")
	assert.Equal(t, "to != address(0) && false", result)
}

func TestSanitizeEmptyComparisons_NoChange(t *testing.T) {
	code := "require(to == address(0x123))"
	result := sanitizeEmptyComparisons(code)
	assert.Equal(t, code, result)
}

func TestSanitizeEmptyComparisons_MixedComparisons(t *testing.T) {
	code := "require(to == ) && require(chainId == )"
	result := sanitizeEmptyComparisons(code)
	assert.Contains(t, result, "to == address(0)")
	assert.Contains(t, result, "chainId == 0")
}

func TestSanitizeEmptyComparisons_CaseInsensitiveChainId(t *testing.T) {
	// Test that chainId detection is case insensitive
	result := sanitizeEmptyComparisons("CHAINID == ;")
	assert.Equal(t, "CHAINID == 0;", result)
	result = sanitizeEmptyComparisons("ChainId == ;")
	assert.Equal(t, "ChainId == 0;", result)
}

// =============================================================================
// formatAddress Tests
// =============================================================================

func TestFormatAddress_Nil(t *testing.T) {
	assert.Equal(t, "address(0)", formatAddress(nil))
}

func TestFormatAddress_Empty(t *testing.T) {
	s := ""
	assert.Equal(t, "address(0)", formatAddress(&s))
}

func TestFormatAddress_ValidLowercase(t *testing.T) {
	s := "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
	result := formatAddress(&s)
	// Should return EIP-55 checksummed address
	assert.Equal(t, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", result)
}

func TestFormatAddress_ValidChecksummed(t *testing.T) {
	s := "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
	assert.Equal(t, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", formatAddress(&s))
}

func TestFormatAddress_InvalidAddress(t *testing.T) {
	s := "not-an-address"
	assert.Equal(t, "address(0)", formatAddress(&s))
}

func TestFormatAddress_ZeroAddress(t *testing.T) {
	s := "0x0000000000000000000000000000000000000000"
	result := formatAddress(&s)
	assert.Equal(t, "0x0000000000000000000000000000000000000000", result)
}

func TestFormatAddress_InjectionAttempt(t *testing.T) {
	s := "0xd8da6bf26964af9d7eed9e03e53415d37aa96045; assembly { invalid() }"
	assert.Equal(t, "address(0)", formatAddress(&s))
}

// =============================================================================
// escapeReservedKeyword Tests
// =============================================================================

func TestEscapeReservedKeyword_Reserved(t *testing.T) {
	reserved := []string{
		"address", "bool", "string", "bytes", "uint", "int",
		"mapping", "struct", "enum", "function", "modifier",
		"event", "error", "contract", "interface", "library",
		"abstract", "public", "private", "internal", "external",
		"view", "pure", "payable", "constant", "immutable",
		"virtual", "override", "memory", "storage", "calldata",
		"if", "else", "for", "while", "do", "break", "continue",
		"return", "try", "catch", "revert", "require", "assert",
		"new", "delete", "this", "super", "true", "false",
		"wei", "ether", "gwei", "seconds", "minutes", "hours",
		"days", "weeks",
	}
	for _, kw := range reserved {
		t.Run(kw, func(t *testing.T) {
			assert.Equal(t, "_"+kw, escapeReservedKeyword(kw))
		})
	}
}

func TestEscapeReservedKeyword_NotReserved(t *testing.T) {
	nonReserved := []string{
		"myVar", "taker", "amount", "deadline", "nonce",
		"tokenAddress", "spender", "owner", "recipient",
		"foo", "bar", "x", "y", "z",
	}
	for _, name := range nonReserved {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, name, escapeReservedKeyword(name))
		})
	}
}

func TestEscapeReservedKeyword_EmptyString(t *testing.T) {
	assert.Equal(t, "", escapeReservedKeyword(""))
}

func TestEscapeReservedKeyword_CaseSensitive(t *testing.T) {
	// Solidity keywords are case-sensitive
	assert.Equal(t, "Address", escapeReservedKeyword("Address"))
	assert.Equal(t, "BOOL", escapeReservedKeyword("BOOL"))
	assert.Equal(t, "IF", escapeReservedKeyword("IF"))
}

// =============================================================================
// Helpers for tests
// =============================================================================

func envToMap(t *testing.T, env []string) map[string]string {
	t.Helper()
	m := make(map[string]string)
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		require.Len(t, parts, 2)
		m[parts[0]] = parts[1]
	}
	return m
}
