package rule

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// ExtractAmount
// ─────────────────────────────────────────────────────────────────────────────

func TestExtractAmount_CountOnly(t *testing.T) {
	metering := types.BudgetMetering{Method: "count_only"}
	amount, err := ExtractAmount(metering, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(1), amount)
}

func TestExtractAmount_TxValue(t *testing.T) {
	val := "1000000000000000000" // 1 ETH
	metering := types.BudgetMetering{Method: "tx_value"}
	amount, err := ExtractAmount(metering, nil, &types.ParsedPayload{Value: &val})
	require.NoError(t, err)
	expected, _ := new(big.Int).SetString("1000000000000000000", 10)
	assert.Equal(t, expected, amount)
}

func TestExtractAmount_Default(t *testing.T) {
	metering := types.BudgetMetering{Method: "unknown_method"}
	_, err := ExtractAmount(metering, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown metering method")
}

// ─────────────────────────────────────────────────────────────────────────────
// extractTxValue
// ─────────────────────────────────────────────────────────────────────────────

func TestExtractTxValue_NilParsed(t *testing.T) {
	_, err := extractTxValue(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tx_value metering requires a transaction value")
}

func TestExtractTxValue_NilValue(t *testing.T) {
	_, err := extractTxValue(&types.ParsedPayload{Value: nil})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tx_value metering requires a transaction value")
}

func TestExtractTxValue_Decimal(t *testing.T) {
	val := "500000000000000000"
	amount, err := extractTxValue(&types.ParsedPayload{Value: &val})
	require.NoError(t, err)
	expected, _ := new(big.Int).SetString("500000000000000000", 10)
	assert.Equal(t, expected, amount)
}

func TestExtractTxValue_Hex(t *testing.T) {
	val := "0xDE0B6B3A7640000" // 1 ETH in hex
	amount, err := extractTxValue(&types.ParsedPayload{Value: &val})
	require.NoError(t, err)
	expected, _ := new(big.Int).SetString("1000000000000000000", 10)
	assert.Equal(t, expected, amount)
}

func TestExtractTxValue_Invalid(t *testing.T) {
	val := "not_a_number"
	_, err := extractTxValue(&types.ParsedPayload{Value: &val})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot parse")
}

// ─────────────────────────────────────────────────────────────────────────────
// extractCalldataParam
// ─────────────────────────────────────────────────────────────────────────────

func TestExtractCalldataParam_NilParsed(t *testing.T) {
	_, err := extractCalldataParam(types.BudgetMetering{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "calldata_param metering requires raw transaction data")
}

func TestExtractCalldataParam_EmptyData(t *testing.T) {
	_, err := extractCalldataParam(types.BudgetMetering{}, &types.ParsedPayload{RawData: []byte{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "calldata_param metering requires raw transaction data")
}

func TestExtractCalldataParam_ShortCalldata(t *testing.T) {
	_, err := extractCalldataParam(types.BudgetMetering{}, &types.ParsedPayload{RawData: []byte{0x01, 0x02}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "calldata_param metering requires at least 4 bytes")
}

func TestExtractCalldataParam_ExtractParam0(t *testing.T) {
	// transfer(address to, uint256 amount)
	// selector: 4 bytes + param0 (address, 32 bytes) + param1 (amount, 32 bytes)
	data := make([]byte, 4+64) // selector + 2 params
	data[0] = 0xa9
	data[1] = 0x05
	data[2] = 0x9c
	data[3] = 0xbb
	// param0: address (last 20 bytes of 32-byte slot)
	data[4+31] = 0x01 // address 0x...01

	metering := types.BudgetMetering{Method: "calldata_param", ParamIndex: 0}
	amount, err := extractCalldataParam(metering, &types.ParsedPayload{RawData: data})
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(1), amount)
}

func TestExtractCalldataParam_ExtractParam1(t *testing.T) {
	// param1 at offset 32
	data := make([]byte, 4+64) // selector + 2 params
	// Set param1 (at offset 4+32) to value 42
	data[4+32+31] = 42

	metering := types.BudgetMetering{Method: "calldata_param", ParamIndex: 1}
	amount, err := extractCalldataParam(metering, &types.ParsedPayload{RawData: data})
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(42), amount)
}

func TestExtractCalldataParam_IndexTooHigh(t *testing.T) {
	data := make([]byte, 4+32) // only 1 param
	metering := types.BudgetMetering{Method: "calldata_param", ParamIndex: 1}
	_, err := extractCalldataParam(metering, &types.ParsedPayload{RawData: data})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "calldata too short")
}

// ─────────────────────────────────────────────────────────────────────────────
// extractTypedDataField
// ─────────────────────────────────────────────────────────────────────────────

func TestExtractTypedDataField_NilParsed(t *testing.T) {
	_, err := extractTypedDataField(types.BudgetMetering{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "typed_data_field metering requires raw data")
}

func TestExtractTypedDataField_EmptyFieldPath(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"amount": "100"})
	_, err := extractTypedDataField(types.BudgetMetering{FieldPath: ""},
		&types.ParsedPayload{RawData: data})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "typed_data_field metering requires field_path")
}

func TestExtractTypedDataField_SimpleField(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"amount": "1000"})
	metering := types.BudgetMetering{Method: "typed_data_field", FieldPath: "amount"}
	amount, err := extractTypedDataField(metering, &types.ParsedPayload{RawData: data})
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(1000), amount)
}

func TestExtractTypedDataField_NestedField(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{
		"message": map[string]interface{}{
			"amount": "5000",
		},
	})
	metering := types.BudgetMetering{Method: "typed_data_field", FieldPath: "message.amount"}
	amount, err := extractTypedDataField(metering, &types.ParsedPayload{RawData: data})
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(5000), amount)
}

func TestExtractTypedDataField_FieldNotFound(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{"other": "100"})
	metering := types.BudgetMetering{Method: "typed_data_field", FieldPath: "amount"}
	_, err := extractTypedDataField(metering, &types.ParsedPayload{RawData: data})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestExtractTypedDataField_InvalidJSON(t *testing.T) {
	metering := types.BudgetMetering{Method: "typed_data_field", FieldPath: "amount"}
	_, err := extractTypedDataField(metering, &types.ParsedPayload{RawData: []byte(`{invalid}`)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse")
}

func TestExtractTypedDataField_NonMapNavigation(t *testing.T) {
	data, _ := json.Marshal(map[string]interface{}{
		"amount": "not_a_map",
	})
	metering := types.BudgetMetering{Method: "typed_data_field", FieldPath: "amount.nested"}
	_, err := extractTypedDataField(metering, &types.ParsedPayload{RawData: data})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot navigate")
}

// ─────────────────────────────────────────────────────────────────────────────
// valueToBigInt
// ─────────────────────────────────────────────────────────────────────────────

func TestValueToBigInt_String_Decimal(t *testing.T) {
	n, err := valueToBigInt("1000000000000000000")
	require.NoError(t, err)
	expected, _ := new(big.Int).SetString("1000000000000000000", 10)
	assert.Equal(t, expected, n)
}

func TestValueToBigInt_String_Hex(t *testing.T) {
	n, err := valueToBigInt("0xff")
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(255), n)
}

func TestValueToBigInt_String_Invalid(t *testing.T) {
	_, err := valueToBigInt("not_a_number")
	assert.Error(t, err)
}

func TestValueToBigInt_Float64(t *testing.T) {
	n, err := valueToBigInt(float64(42))
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(42), n)
}

func TestValueToBigInt_Int64(t *testing.T) {
	n, err := valueToBigInt(int64(99))
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(99), n)
}

func TestValueToBigInt_JSONNumber(t *testing.T) {
	n, err := valueToBigInt(json.Number("12345"))
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(12345), n)
}

func TestValueToBigInt_JSONNumber_Invalid(t *testing.T) {
	_, err := valueToBigInt(json.Number("not_valid"))
	assert.Error(t, err)
}

func TestValueToBigInt_UnsupportedType(t *testing.T) {
	_, err := valueToBigInt([]string{"array"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported type")
}
