package evm

import (
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/grafana/sobek"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// =============================================================================
// parseUintStrict — additional edge cases (41.7% -> >80%)
// =============================================================================

func TestParseUintStrict_StringEmpty(t *testing.T) {
	_, ok := parseUintStrict("")
	assert.False(t, ok)
}

func TestParseUintStrict_StringTooLong(t *testing.T) {
	s := "123456789012345678901234567890123" // 33 chars > rsMaxIntInputLen (32)
	_, ok := parseUintStrict(s)
	assert.False(t, ok)
}

func TestParseUintStrict_StringNonDigit(t *testing.T) {
	_, ok := parseUintStrict("12a45")
	assert.False(t, ok)
}

func TestParseUintStrict_NegativeInt(t *testing.T) {
	_, ok := parseUintStrict(-1)
	assert.False(t, ok)
}

func TestParseUintStrict_NegativeInt64(t *testing.T) {
	_, ok := parseUintStrict(int64(-42))
	assert.False(t, ok)
}

func TestParseUintStrict_Float64NaN(t *testing.T) {
	_, ok := parseUintStrict(math.NaN())
	assert.False(t, ok)
}

func TestParseUintStrict_Float64Inf(t *testing.T) {
	_, ok := parseUintStrict(math.Inf(1))
	assert.False(t, ok)
}

func TestParseUintStrict_Float64Negative(t *testing.T) {
	_, ok := parseUintStrict(-3.14)
	assert.False(t, ok)
}

func TestParseUintStrict_Float64TooLarge(t *testing.T) {
	_, ok := parseUintStrict(float64(1 << 54)) // > 2^53
	assert.False(t, ok)
}

func TestParseUintStrict_Float64Trunc(t *testing.T) {
	_, ok := parseUintStrict(3.14)
	assert.False(t, ok)
}

func TestParseUintStrict_DefaultCase(t *testing.T) {
	_, ok := parseUintStrict(true)
	assert.False(t, ok)
}

func TestParseUintStrict_Float64Valid(t *testing.T) {
	u, ok := parseUintStrict(float64(42))
	assert.True(t, ok)
	assert.Equal(t, uint64(42), u)
}

func TestParseUintStrict_StringValid(t *testing.T) {
	u, ok := parseUintStrict("  99  ")
	assert.True(t, ok)
	assert.Equal(t, uint64(99), u)
}

// =============================================================================
// parseBigIntStrict — additional edge cases (61.5% -> >80%)
// =============================================================================

func TestParseBigIntStrict_Float64NaN(t *testing.T) {
	_, ok := parseBigIntStrict(math.NaN())
	assert.False(t, ok)
}

func TestParseBigIntStrict_Float64Inf(t *testing.T) {
	_, ok := parseBigIntStrict(math.Inf(1))
	assert.False(t, ok)
}

func TestParseBigIntStrict_EmptyString(t *testing.T) {
	_, ok := parseBigIntStrict("  ")
	assert.False(t, ok)
}

func TestParseBigIntStrict_EmptyHex(t *testing.T) {
	_, ok := parseBigIntStrict("0x")
	assert.False(t, ok)
}

func TestParseBigIntStrict_HexTooLong(t *testing.T) {
	// 65 hex chars > 64 max
	s := "0x" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01"
	_, ok := parseBigIntStrict(s)
	assert.False(t, ok)
}

func TestParseBigIntStrict_HexNonHexChars(t *testing.T) {
	_, ok := parseBigIntStrict("0xGGG")
	assert.False(t, ok)
}

func TestParseBigIntStrict_DecimalJustPlus(t *testing.T) {
	_, ok := parseBigIntStrict("+")
	assert.False(t, ok)
}

func TestParseBigIntStrict_DecimalJustMinus(t *testing.T) {
	_, ok := parseBigIntStrict("-")
	assert.False(t, ok)
}

func TestParseBigIntStrict_DecimalNonDigit(t *testing.T) {
	_, ok := parseBigIntStrict("12a34")
	assert.False(t, ok)
}

func TestParseBigIntStrict_Float64NonInteger(t *testing.T) {
	_, ok := parseBigIntStrict(float64(3.14))
	assert.False(t, ok)
}

func TestParseBigIntStrict_Float64TooLarge(t *testing.T) {
	_, ok := parseBigIntStrict(float64(1 << 62)) // still fits in float64 exactly
	assert.True(t, ok) // (1<<62) is representable exactly
}

func TestParseBigIntStrict_DefaultCase(t *testing.T) {
	_, ok := parseBigIntStrict(struct{}{})
	assert.False(t, ok)
}

func TestParseBigIntStrict_ValidHex(t *testing.T) {
	n, ok := parseBigIntStrict("0xff")
	assert.True(t, ok)
	assert.Equal(t, big.NewInt(255), n)
}

func TestParseBigIntStrict_ValidDecimal(t *testing.T) {
	n, ok := parseBigIntStrict("42")
	assert.True(t, ok)
	assert.Equal(t, big.NewInt(42), n)
}

func TestParseBigIntStrict_Uint64(t *testing.T) {
	n, ok := parseBigIntStrict(uint64(100))
	assert.True(t, ok)
	assert.Equal(t, big.NewInt(100), n)
}

// =============================================================================
// parseUint256HexToUint64Strict — missing edge cases (68.8% -> >80%)
// =============================================================================

func TestParseUint256HexToUint64Strict_Empty(t *testing.T) {
	_, ok := parseUint256HexToUint64Strict("")
	assert.False(t, ok)
}

func TestParseUint256HexToUint64Strict_TooLong(t *testing.T) {
	_, ok := parseUint256HexToUint64Strict("0x" + "ff1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	assert.False(t, ok) // > 64 hex chars
}

func TestParseUint256HexToUint64Strict_ExceedsUint64(t *testing.T) {
	// value > max uint64 (the first 48 chars aren't all zero)
	_, ok := parseUint256HexToUint64Strict("0x0000000000000001000000000000000000000000000000000000000000000000")
	assert.False(t, ok)
}

func TestParseUint256HexToUint64Strict_InvalidHex(t *testing.T) {
	_, ok := parseUint256HexToUint64Strict("0xGG")
	assert.False(t, ok)
}

func TestParseUint256HexToUint64Strict_Valid(t *testing.T) {
	v, ok := parseUint256HexToUint64Strict("0x00000000000000000000000000000000000000000000000000000000000000ff")
	assert.True(t, ok)
	assert.Equal(t, uint64(255), v)
}

// =============================================================================
// decodeStringFromHex — remaining branches (71.4% -> >80%)
// =============================================================================

func TestDecodeStringFromHex_TooShort(t *testing.T) {
	_, err := decodeStringFromHex("0xabcd")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestDecodeStringFromHex_InvalidABIOffset(t *testing.T) {
	// ABI string with offset pointing past the data
	// offset(32 bytes = 0xffffffff...) where offset+32 > len(data)
	hexStr := "0x" +
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" + // offset = huge
		"0000000000000000000000000000000000000000000000000000000000000020" + // length = 32
		"48656c6c6f20576f726c6421" // data
	_, err := decodeStringFromHex(hexStr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ABI string offset")
}

func TestDecodeStringFromHex_InvalidHex(t *testing.T) {
	// Must be >128 hex chars to pass the length check before hex decode
	hexStr := "0x" + strings.Repeat("GG", 65) // 130 chars with invalid hex
	_, err := decodeStringFromHex(hexStr)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode hex")
}

func TestDecodeStringFromHex_Valid(t *testing.T) {
	// ABI-encoded "Hello World"
	result, err := decodeStringFromHex(
		"0x" +
			"0000000000000000000000000000000000000000000000000000000000000020" + // offset
			"000000000000000000000000000000000000000000000000000000000000000b" + // length = 11
			"48656c6c6f20576f726c64000000000000000000000000000000000000000000", // "Hello World"
	)
	require.NoError(t, err)
	assert.Equal(t, "Hello World", result)
}

// =============================================================================
// decodeBoolFromHex — remaining branches (85.7% -> >80%)
// =============================================================================

func TestDecodeBoolFromHex_Empty(t *testing.T) {
	assert.False(t, decodeBoolFromHex("0x"))
	assert.False(t, decodeBoolFromHex(""))
}

func TestDecodeBoolFromHex_InvalidHex(t *testing.T) {
	assert.False(t, decodeBoolFromHex("0xGG"))
}

func TestDecodeBoolFromHex_True(t *testing.T) {
	assert.True(t, decodeBoolFromHex("0x0000000000000000000000000000000000000000000000000000000000000001"))
}

func TestDecodeBoolFromHex_False(t *testing.T) {
	assert.False(t, decodeBoolFromHex("0x0000000000000000000000000000000000000000000000000000000000000000"))
}

// =============================================================================
// decodeUint8FromHex — remaining branches (88.9% -> >80%)
// =============================================================================

func TestDecodeUint8FromHex_Empty(t *testing.T) {
	_, err := decodeUint8FromHex("0x")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestDecodeUint8FromHex_InvalidHex(t *testing.T) {
	_, err := decodeUint8FromHex("0xGG")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hex")
}

func TestDecodeUint8FromHex_TooLarge(t *testing.T) {
	_, err := decodeUint8FromHex("0xff")
	assert.Error(t, err)                                   // > 77
	assert.Contains(t, err.Error(), "out of valid range")  // > maxValidDecimals
}

func TestDecodeUint8FromHex_Valid(t *testing.T) {
	v, err := decodeUint8FromHex("0x12")
	require.NoError(t, err)
	assert.Equal(t, 18, v)
}

func TestDecodeUint8FromHex_Negative(t *testing.T) {
	// A large hex value that when parsed as big.Int is > maxValidDecimals
	_, _ = decodeUint8FromHex("0x4a") // 74 > 77? no, 74 > 77 is false
	// Let's test with a value that's actually > 77
	_, err := decodeUint8FromHex("0x4e") // 78 > 77
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "out of valid range")
}

// =============================================================================
// InternalTransferEvaluator.Type() (0% -> 100%)
// =============================================================================

func TestInternalTransferEvaluator_Type(t *testing.T) {
	e, err := NewInternalTransferEvaluator(nil)
	require.NoError(t, err)
	assert.Equal(t, types.RuleTypeEVMInternalTransfer, e.Type())
}

// =============================================================================
// InternalTransferEvaluator.extractRecipientFromCalldata — more branches
// (13.3% -> >80%)
// =============================================================================

func TestExtractRecipientFromCalldata_NilParsed(t *testing.T) {
	e, _ := NewInternalTransferEvaluator(nil)
	// MethodSig is nil -> early return
	result := e.extractRecipientFromCalldata(&types.ParsedPayload{})
	assert.Empty(t, result)
}

func TestExtractRecipientFromCalldata_NilMethodSig(t *testing.T) {
	e, _ := NewInternalTransferEvaluator(nil)
	result := e.extractRecipientFromCalldata(&types.ParsedPayload{
		MethodSig: nil,
		RawData:   []byte{1, 2, 3},
	})
	assert.Empty(t, result)
}

func TestExtractRecipientFromCalldata_NilRawData(t *testing.T) {
	e, _ := NewInternalTransferEvaluator(nil)
	sig := "0xa9059cbb"
	result := e.extractRecipientFromCalldata(&types.ParsedPayload{
		MethodSig: &sig,
		RawData:   nil,
	})
	assert.Empty(t, result)
}

func TestExtractRecipientFromCalldata_UnknownSelector(t *testing.T) {
	e, _ := NewInternalTransferEvaluator(nil)
	sig := "0xdeadbeef"
	result := e.extractRecipientFromCalldata(&types.ParsedPayload{
		MethodSig: &sig,
		RawData:   []byte("some data here"),
	})
	assert.Empty(t, result)
}

func TestExtractRecipientFromCalldata_ShortCalldata(t *testing.T) {
	e, _ := NewInternalTransferEvaluator(nil)
	sig := "0xa9059cbb"
	result := e.extractRecipientFromCalldata(&types.ParsedPayload{
		MethodSig: &sig,
		RawData:   []byte{0, 1, 2, 3}, // too short for offset(4) + 32 = 36
	})
	assert.Empty(t, result)
}

func TestExtractRecipientFromCalldata_ZeroAddress(t *testing.T) {
	e, _ := NewInternalTransferEvaluator(nil)
	sig := "0xa9059cbb"
	// Build calldata: selector(4 bytes) + 32-byte padded zero address
	data := make([]byte, 4+32) // all zeros
	result := e.extractRecipientFromCalldata(&types.ParsedPayload{
		MethodSig: &sig,
		RawData:   data,
	})
	assert.Empty(t, result)
}

func TestExtractRecipientFromCalldata_ValidTransfer(t *testing.T) {
	e, _ := NewInternalTransferEvaluator(nil)
	sig := "0xa9059cbb"
	// Build calldata: selector(4 bytes) + 0x00...f39F... address
	data := make([]byte, 4+32)
	// Put a recognizable address at offset 4+12=16 (address starts at offset 4+12)
	// Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
	addrBytes := []byte{
		0xf3, 0x9F, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xF6,
		0xF4, 0xce, 0x6a, 0xB8, 0x82, 0x72, 0x79, 0xcf,
		0xfF, 0xb9, 0x22, 0x66,
	}
	copy(data[4+12:4+12+20], addrBytes)
	result := e.extractRecipientFromCalldata(&types.ParsedPayload{
		MethodSig: &sig,
		RawData:   data,
	})
	assert.Equal(t, "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", result)
}

// =============================================================================
// SetRPCProvider on EVMAdapter (0% -> 100%)
// =============================================================================

func TestEVMAdapter_SetRPCProvider(t *testing.T) {
	registry, err := NewSignerRegistry(SignerConfig{})
	require.NoError(t, err)
	adapter, err := NewEVMAdapter(registry)
	require.NoError(t, err)
	// Just verify it doesn't panic
	adapter.SetRPCProvider(nil)
	assert.NotNil(t, adapter)
}

// =============================================================================
// dedupeAndSort — pure utility (should already be tested, add edge cases)
// =============================================================================

func TestDedupeAndSort_Empty(t *testing.T) {
	assert.Nil(t, dedupeAndSort(nil))
	assert.Empty(t, dedupeAndSort([]uint32{}))
}

func TestDedupeAndSort_Duplicates(t *testing.T) {
	result := dedupeAndSort([]uint32{3, 1, 2, 1, 3, 2})
	assert.Equal(t, []uint32{1, 2, 3}, result)
}

func TestDedupeAndSort_AlreadySorted(t *testing.T) {
	result := dedupeAndSort([]uint32{1, 2, 3, 4, 5})
	assert.Equal(t, []uint32{1, 2, 3, 4, 5}, result)
}

// =============================================================================
// NewCompositePasswordProvider — error path (hasStdinKeystores=true on non-tty)
// (55.6% -> >80%)
// =============================================================================

func TestNewCompositePasswordProvider_StdinError(t *testing.T) {
	// When stdin is not a terminal, hasStdinKeystores=true should cause an error
	p, err := NewCompositePasswordProvider(true)
	if err != nil {
		assert.Nil(t, p)
		assert.Contains(t, err.Error(), "stdin")
	} else {
		// If stdin happens to be a terminal (running interactively), we can't test
		t.Skip("stdin is a terminal, cannot test non-tty error path")
	}
}

// =============================================================================
// CompositePasswordProvider.GetPassword — stdin path on nil provider
// (80% -> >80%)
// =============================================================================

func TestCompositePasswordProvider_GetPassword_StdinNil(t *testing.T) {
	p, err := NewCompositePasswordProvider(false)
	require.NoError(t, err)
	// PasswordStdin=true but stdin provider was not initialized
	_, err = p.GetPassword("0xabc", KeystoreConfig{PasswordStdin: true})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "stdin password provider not initialized")
}

// =============================================================================
// EnvPasswordProvider — empty password_env (already at 100% but verify)
// =============================================================================

func TestEnvPasswordProvider_GetPassword_EmptyEnv(t *testing.T) {
	p := &EnvPasswordProvider{}
	_, err := p.GetPassword("0xabc", KeystoreConfig{PasswordEnv: ""})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "password_env not configured")
}

// =============================================================================
// DerivationStateStore.Delete — edge cases
// =============================================================================

func TestDerivationStateStore_Delete_EmptyAddr(t *testing.T) {
	s, err := NewDerivationStateStore("/tmp/nonexistent-dir/test-state.json")
	require.NoError(t, err)
	err = s.Delete("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "primary address is required")
}

// Test the Type() method on InternalTransferEvaluator differently to make sure
func TestInternalTransferEvaluator_TypeConstant(t *testing.T) {
	e, err := NewInternalTransferEvaluator(nil)
	require.NoError(t, err)
	assert.Equal(t, types.RuleType("evm_internal_transfer"), e.Type())
	assert.Equal(t, types.RuleTypeEVMInternalTransfer, e.Type())
}

// =============================================================================
// exportedToBigInt — additional branches (21.1% -> >80%)
// =============================================================================

func TestExportedToBigInt_NegativeInt64(t *testing.T) {
	_, err := exportedToBigInt(int64(-1))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "negative")
}

func TestExportedToBigInt_NegativeInt(t *testing.T) {
	_, err := exportedToBigInt(-1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "negative")
}

func TestExportedToBigInt_Uint64(t *testing.T) {
	n, err := exportedToBigInt(uint64(42))
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(42), n)
}

func TestExportedToBigInt_StringNegative(t *testing.T) {
	_, err := exportedToBigInt("-42")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "negative")
}

func TestExportedToBigInt_StringInvalid(t *testing.T) {
	_, err := exportedToBigInt("not-a-number")
	assert.Error(t, err)
}

func TestExportedToBigInt_StringValid(t *testing.T) {
	n, err := exportedToBigInt("100")
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(100), n)
}

func TestExportedToBigInt_BigIntValid(t *testing.T) {
	n, err := exportedToBigInt(big.NewInt(42))
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(42), n)
}

func TestExportedToBigInt_BigIntNegative(t *testing.T) {
	_, err := exportedToBigInt(big.NewInt(-1))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "negative")
}

func TestExportedToBigInt_DefaultType(t *testing.T) {
	_, err := exportedToBigInt(struct{}{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported type")
}

// =============================================================================
// removeGlobals — smoke test (66.7% -> >80%)
// =============================================================================

func TestRemoveGlobals_NoError(t *testing.T) {
	vm := sobek.New()
	err := removeGlobals(vm)
	assert.NoError(t, err)
}

// =============================================================================
// NewDecimalsQuerierAdapter — error paths (0% -> >80%)
// =============================================================================

func TestNewDecimalsQuerierAdapter_NilCache(t *testing.T) {
	_, err := NewDecimalsQuerierAdapter(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token metadata cache is required")
}

// =============================================================================
// parseNonNegativeBigInt — additional branches (90.9% -> >80%)
// =============================================================================

func TestParseNonNegativeBigInt_Hex(t *testing.T) {
	n, err := parseNonNegativeBigInt("0x0a", "test")
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(10), n)
}

func TestParseNonNegativeBigInt_Empty(t *testing.T) {
	n, err := parseNonNegativeBigInt("", "test")
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(0), n)
}

func TestParseNonNegativeBigInt_NegativeDecimal(t *testing.T) {
	_, err := parseNonNegativeBigInt("-10", "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must not be negative")
}

// =============================================================================
// parseNonNegativeBigInt — invalid decimal
// =============================================================================

func TestParseNonNegativeBigInt_InvalidDecimal(t *testing.T) {
	_, err := parseNonNegativeBigInt("not_a_number", "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestParseNonNegativeBigInt_InvalidHex(t *testing.T) {
	_, err := parseNonNegativeBigInt("0xZZ", "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

// =============================================================================
// fmt import needed for error assertions — unused import check
// =============================================================================
