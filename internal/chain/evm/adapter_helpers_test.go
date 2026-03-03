package evm

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// decodeHexData
// ---------------------------------------------------------------------------

func TestDecodeHexData_ValidWithPrefix(t *testing.T) {
	got, err := decodeHexData("0xdeadbeef")
	require.NoError(t, err)
	assert.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, got)
}

func TestDecodeHexData_ValidWithoutPrefix(t *testing.T) {
	// The function strips "0x" if present, but if the caller passes raw hex
	// without the prefix the hex package should still decode it.
	got, err := decodeHexData("abcd1234")
	require.NoError(t, err)
	assert.Equal(t, []byte{0xab, 0xcd, 0x12, 0x34}, got)
}

func TestDecodeHexData_EmptyString(t *testing.T) {
	got, err := decodeHexData("")
	require.NoError(t, err)
	assert.Nil(t, got, "empty string should return nil bytes")
}

func TestDecodeHexData_Only0x(t *testing.T) {
	got, err := decodeHexData("0x")
	require.NoError(t, err)
	assert.Nil(t, got, `"0x" should return nil bytes`)
}

func TestDecodeHexData_InvalidHexCharacters(t *testing.T) {
	_, err := decodeHexData("0xZZZZ")
	require.Error(t, err)
}

func TestDecodeHexData_OddLength(t *testing.T) {
	// hex.DecodeString requires even-length input
	_, err := decodeHexData("0xabc")
	require.Error(t, err)
}

func TestDecodeHexData_LongValidData(t *testing.T) {
	// 32 bytes of zeros
	input := "0x" + strings.Repeat("00", 32)
	got, err := decodeHexData(input)
	require.NoError(t, err)
	assert.Len(t, got, 32)
	assert.Equal(t, make([]byte, 32), got)
}

// ---------------------------------------------------------------------------
// hexToHash
// ---------------------------------------------------------------------------

func TestHexToHash_Valid32Bytes(t *testing.T) {
	hexStr := "0x" + strings.Repeat("ab", 32)
	got, err := hexToHash(hexStr)
	require.NoError(t, err)

	expected := common.BytesToHash([]byte{
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
		0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
	})
	assert.Equal(t, expected, got)
}

func TestHexToHash_ValidWithout0xPrefix(t *testing.T) {
	hexStr := strings.Repeat("ff", 32)
	got, err := hexToHash(hexStr)
	require.NoError(t, err)

	expected := common.BytesToHash([]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	})
	assert.Equal(t, expected, got)
}

func TestHexToHash_TooShort(t *testing.T) {
	hexStr := "0x" + strings.Repeat("ab", 16) // 16 bytes
	_, err := hexToHash(hexStr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected 32 bytes")
}

func TestHexToHash_TooLong(t *testing.T) {
	hexStr := "0x" + strings.Repeat("ab", 33) // 33 bytes
	_, err := hexToHash(hexStr)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected 32 bytes")
}

func TestHexToHash_InvalidHex(t *testing.T) {
	hexStr := "0x" + strings.Repeat("zz", 32)
	_, err := hexToHash(hexStr)
	require.Error(t, err)
}

func TestHexToHash_EmptyString(t *testing.T) {
	// Empty string after stripping "0x" -> hex.DecodeString("") returns empty
	// -> length check should fail (0 != 32).
	_, err := hexToHash("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected 32 bytes")
}

func TestHexToHash_ZeroHash(t *testing.T) {
	hexStr := "0x" + strings.Repeat("00", 32)
	got, err := hexToHash(hexStr)
	require.NoError(t, err)
	assert.Equal(t, common.Hash{}, got)
}

// ---------------------------------------------------------------------------
// parseChainID
// ---------------------------------------------------------------------------

func TestParseChainID_Valid(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int64
	}{
		{"mainnet", "1", 1},
		{"polygon", "137", 137},
		{"bsc", "56", 56},
		{"arbitrum", "42161", 42161},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseChainID(tt.input)
			require.NoError(t, err)
			assert.Equal(t, big.NewInt(tt.expected), got)
		})
	}
}

func TestParseChainID_VeryLargeValid(t *testing.T) {
	// Chain IDs can be arbitrarily large; make sure big.Int handles it.
	largeID := "999999999999999999999999999999"
	got, err := parseChainID(largeID)
	require.NoError(t, err)
	expected := new(big.Int)
	expected.SetString(largeID, 10)
	assert.Equal(t, expected, got)
}

func TestParseChainID_EmptyString(t *testing.T) {
	_, err := parseChainID("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

func TestParseChainID_Zero(t *testing.T) {
	_, err := parseChainID("0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "positive")
}

func TestParseChainID_Negative(t *testing.T) {
	_, err := parseChainID("-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "positive")
}

func TestParseChainID_NotANumber(t *testing.T) {
	_, err := parseChainID("abc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid chain ID")
}

func TestParseChainID_HexNotAccepted(t *testing.T) {
	// parseChainID uses base 10; hex input should fail.
	_, err := parseChainID("0x1")
	require.Error(t, err)
}

func TestParseChainID_FloatingPoint(t *testing.T) {
	_, err := parseChainID("1.5")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// parseNonNegativeBigInt
// ---------------------------------------------------------------------------

func TestParseNonNegativeBigInt_EmptyReturnsZero(t *testing.T) {
	got, err := parseNonNegativeBigInt("", "value")
	require.NoError(t, err)
	assert.Equal(t, new(big.Int), got)
}

func TestParseNonNegativeBigInt_Zero(t *testing.T) {
	got, err := parseNonNegativeBigInt("0", "value")
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(0), got)
}

func TestParseNonNegativeBigInt_PositiveValues(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *big.Int
	}{
		{"small", "100", big.NewInt(100)},
		{"one wei", "1", big.NewInt(1)},
		{"1 ether in wei", "1000000000000000000", new(big.Int).SetUint64(1_000_000_000_000_000_000)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNonNegativeBigInt(tt.input, "value")
			require.NoError(t, err)
			assert.Equal(t, 0, tt.expected.Cmp(got), "expected %s, got %s", tt.expected, got)
		})
	}
}

func TestParseNonNegativeBigInt_VeryLargePositive(t *testing.T) {
	huge := strings.Repeat("9", 78) // 78-digit number
	got, err := parseNonNegativeBigInt(huge, "gasPrice")
	require.NoError(t, err)
	expected := new(big.Int)
	expected.SetString(huge, 10)
	assert.Equal(t, 0, expected.Cmp(got))
}

func TestParseNonNegativeBigInt_Negative(t *testing.T) {
	_, err := parseNonNegativeBigInt("-1", "value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be negative")
	assert.Contains(t, err.Error(), "value")
}

func TestParseNonNegativeBigInt_LargeNegative(t *testing.T) {
	_, err := parseNonNegativeBigInt("-99999999999999999999", "gasPrice")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be negative")
	assert.Contains(t, err.Error(), "gasPrice")
}

func TestParseNonNegativeBigInt_InvalidString(t *testing.T) {
	_, err := parseNonNegativeBigInt("not_a_number", "value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid value")
}

func TestParseNonNegativeBigInt_HexStringRejected(t *testing.T) {
	// The function uses base 10; hex strings should fail.
	_, err := parseNonNegativeBigInt("0xff", "gasPrice")
	require.Error(t, err)
}

func TestParseNonNegativeBigInt_FloatRejected(t *testing.T) {
	_, err := parseNonNegativeBigInt("1.5", "value")
	require.Error(t, err)
}

func TestParseNonNegativeBigInt_FieldNameInError(t *testing.T) {
	_, err := parseNonNegativeBigInt("xyz", "gasTipCap")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gasTipCap")
}

// ---------------------------------------------------------------------------
// ValidateBasicRequest  (additional cases beyond adapter_test.go)
// ---------------------------------------------------------------------------

func TestValidateBasicRequest_AllSignTypes(t *testing.T) {
	adapter := &EVMAdapter{}
	validAddr := "0x88eD75e9eCE373997221E3c0229e74007C1AD718"

	tests := []struct {
		name     string
		signType string
		payload  interface{}
	}{
		{
			name:     "hash",
			signType: SignTypeHash,
			payload:  EVMSignPayload{Hash: "0x" + strings.Repeat("ab", 32)},
		},
		{
			name:     "raw_message",
			signType: SignTypeRawMessage,
			payload:  EVMSignPayload{RawMessage: []byte("raw bytes")},
		},
		{
			name:     "eip191",
			signType: SignTypeEIP191,
			payload:  EVMSignPayload{Message: "hello"},
		},
		{
			name:     "personal",
			signType: SignTypePersonal,
			payload:  EVMSignPayload{Message: "hello"},
		},
		{
			name:     "typed_data",
			signType: SignTypeTypedData,
			payload: EVMSignPayload{
				TypedData: &TypedDataPayload{
					Types:       map[string][]TypedDataField{"EIP712Domain": {}},
					PrimaryType: "Test",
					Message:     map[string]interface{}{"key": "val"},
				},
			},
		},
		{
			name:     "transaction",
			signType: SignTypeTransaction,
			payload: EVMSignPayload{
				Transaction: &TransactionPayload{
					Gas:    21000,
					Value:  "0",
					TxType: "legacy",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloadBytes, err := json.Marshal(tt.payload)
			require.NoError(t, err)
			err = adapter.ValidateBasicRequest("1", validAddr, tt.signType, payloadBytes)
			assert.NoError(t, err)
		})
	}
}

func TestValidateBasicRequest_MissingPayloadFieldPerSignType(t *testing.T) {
	adapter := &EVMAdapter{}
	validAddr := "0x88eD75e9eCE373997221E3c0229e74007C1AD718"

	// For each sign_type, an empty JSON object {} should fail because the
	// required top-level field is absent.
	emptyPayload := []byte(`{}`)

	tests := []struct {
		signType    string
		errContains string
	}{
		{SignTypeHash, "hash is required"},
		{SignTypeRawMessage, "raw_message is required"},
		{SignTypeEIP191, "message is required"},
		{SignTypePersonal, "message is required"},
		{SignTypeTypedData, "typed_data is required"},
		{SignTypeTransaction, "transaction is required"},
	}
	for _, tt := range tests {
		t.Run(tt.signType, func(t *testing.T) {
			err := adapter.ValidateBasicRequest("1", validAddr, tt.signType, emptyPayload)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestValidateBasicRequest_ChainIDEdgeCases(t *testing.T) {
	adapter := &EVMAdapter{}
	validAddr := "0x88eD75e9eCE373997221E3c0229e74007C1AD718"
	payload := []byte(`{"message":"hello"}`)

	tests := []struct {
		name        string
		chainID     string
		wantErr     bool
		errContains string
	}{
		// ValidateBasicRequest uses strconv.ParseUint which accepts 0;
		// the stricter positivity check is in parseChainID (used at sign time).
		{"decimal zero", "0", false, ""},
		{"negative", "-1", true, "positive decimal integer"},
		{"hex format", "0xff", true, "positive decimal integer"},
		{"float", "1.5", true, "positive decimal integer"},
		{"leading zeros accepted", "01", false, ""},
		{"max uint64", "18446744073709551615", false, ""},
		{"overflow uint64", "18446744073709551616", true, "positive decimal integer"},
		{"spaces", " 1 ", true, "positive decimal integer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := adapter.ValidateBasicRequest(tt.chainID, validAddr, SignTypePersonal, payload)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateBasicRequest_SignerAddressEdgeCases(t *testing.T) {
	adapter := &EVMAdapter{}
	payload := []byte(`{"message":"hello"}`)

	tests := []struct {
		name        string
		addr        string
		wantErr     bool
		errContains string
	}{
		{"valid checksummed", "0x88eD75e9eCE373997221E3c0229e74007C1AD718", false, ""},
		{"valid all lowercase", "0x88ed75e9ece373997221e3c0229e74007c1ad718", false, ""},
		{"valid all uppercase", "0x88ED75E9ECE373997221E3C0229E74007C1AD718", false, ""},
		{"too short", "0x1234", true, "signer_address"},
		{"too long", "0x88eD75e9eCE373997221E3c0229e74007C1AD71800", true, "signer_address"},
		{"missing 0x", "88eD75e9eCE373997221E3c0229e74007C1AD718", true, "signer_address"},
		{"empty", "", true, "signer_address is required"},
		{"non-hex chars", "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG", true, "signer_address"},
		{"just 0x", "0x", true, "signer_address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := adapter.ValidateBasicRequest("1", tt.addr, SignTypePersonal, payload)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateBasicRequest_PayloadNotValidJSON(t *testing.T) {
	adapter := &EVMAdapter{}
	validAddr := "0x88eD75e9eCE373997221E3c0229e74007C1AD718"

	err := adapter.ValidateBasicRequest("1", validAddr, SignTypePersonal, []byte(`not json`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid JSON")
}

func TestValidateBasicRequest_PayloadMaxBoundary(t *testing.T) {
	adapter := &EVMAdapter{}
	validAddr := "0x88eD75e9eCE373997221E3c0229e74007C1AD718"

	// Exactly at max size -- the content needs to be valid JSON containing the
	// required field. We build a JSON object with a message string that fills
	// up to maxPayloadSize.
	// Overhead: `{"message":"` + `"}` = 14 bytes
	overhead := len(`{"message":""}`)
	msgLen := maxPayloadSize - overhead
	if msgLen < 1 {
		t.Skip("maxPayloadSize too small for this test")
	}
	bigPayload := []byte(`{"message":"` + strings.Repeat("a", msgLen) + `"}`)
	assert.Equal(t, maxPayloadSize, len(bigPayload))

	err := adapter.ValidateBasicRequest("1", validAddr, SignTypePersonal, bigPayload)
	assert.NoError(t, err, "payload exactly at max size should be accepted")

	// One byte over
	overPayload := []byte(`{"message":"` + strings.Repeat("a", msgLen+1) + `"}`)
	err = adapter.ValidateBasicRequest("1", validAddr, SignTypePersonal, overPayload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "payload exceeds")
}
