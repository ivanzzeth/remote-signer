package evm

import (
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─────────────────────────────────────────────────────────────────────────────
// ValidatePayload
// ─────────────────────────────────────────────────────────────────────────────

func adapterForTest() *EVMAdapter {
	// We can't create a full registry easily, but ValidatePayload doesn't use signerRegistry
	return &EVMAdapter{}
}

func TestValidatePayload_InvalidJSON(t *testing.T) {
	a := adapterForTest()
	err := a.ValidatePayload(context.Background(), SignTypeHash, []byte(`{invalid`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid EVM payload JSON")
}

func TestValidatePayload_Hash_Valid(t *testing.T) {
	a := adapterForTest()
	hash := "0x" + strings.Repeat("ab", 32) // 66 chars
	payload, _ := json.Marshal(EVMSignPayload{Hash: hash})
	err := a.ValidatePayload(context.Background(), SignTypeHash, payload)
	require.NoError(t, err)
}

func TestValidatePayload_Hash_Empty(t *testing.T) {
	a := adapterForTest()
	payload, _ := json.Marshal(EVMSignPayload{})
	err := a.ValidatePayload(context.Background(), SignTypeHash, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hash is required")
}

func TestValidatePayload_Hash_NoPrefix(t *testing.T) {
	a := adapterForTest()
	payload, _ := json.Marshal(EVMSignPayload{Hash: strings.Repeat("ab", 32)}) // no 0x
	err := a.ValidatePayload(context.Background(), SignTypeHash, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "0x-prefixed")
}

func TestValidatePayload_Hash_WrongLength(t *testing.T) {
	a := adapterForTest()
	payload, _ := json.Marshal(EVMSignPayload{Hash: "0x" + strings.Repeat("ab", 16)}) // 34 chars, not 66
	err := a.ValidatePayload(context.Background(), SignTypeHash, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "0x-prefixed 32-byte")
}

func TestValidatePayload_Hash_InvalidHex(t *testing.T) {
	a := adapterForTest()
	payload, _ := json.Marshal(EVMSignPayload{Hash: "0x" + strings.Repeat("gg", 32)})
	err := a.ValidatePayload(context.Background(), SignTypeHash, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hex characters")
}

func TestValidatePayload_RawMessage_Valid(t *testing.T) {
	a := adapterForTest()
	payload, _ := json.Marshal(EVMSignPayload{RawMessage: []byte("hello")})
	err := a.ValidatePayload(context.Background(), SignTypeRawMessage, payload)
	require.NoError(t, err)
}

func TestValidatePayload_RawMessage_Empty(t *testing.T) {
	a := adapterForTest()
	payload, _ := json.Marshal(EVMSignPayload{})
	err := a.ValidatePayload(context.Background(), SignTypeRawMessage, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "raw_message is required")
}

func TestValidatePayload_RawMessage_TooLarge(t *testing.T) {
	a := adapterForTest()
	bigMsg := make([]byte, maxRawMessageSize+1)
	payload, _ := json.Marshal(EVMSignPayload{RawMessage: bigMsg})
	err := a.ValidatePayload(context.Background(), SignTypeRawMessage, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size")
}

func TestValidatePayload_Personal_Valid(t *testing.T) {
	a := adapterForTest()
	payload, _ := json.Marshal(EVMSignPayload{Message: "Hello World"})
	err := a.ValidatePayload(context.Background(), SignTypePersonal, payload)
	require.NoError(t, err)
}

func TestValidatePayload_EIP191_Valid(t *testing.T) {
	a := adapterForTest()
	payload, _ := json.Marshal(EVMSignPayload{Message: "Hello World"})
	err := a.ValidatePayload(context.Background(), SignTypeEIP191, payload)
	require.NoError(t, err)
}

func TestValidatePayload_Personal_Empty(t *testing.T) {
	a := adapterForTest()
	payload, _ := json.Marshal(EVMSignPayload{})
	err := a.ValidatePayload(context.Background(), SignTypePersonal, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "message is required")
}

func TestValidatePayload_Personal_TooLarge(t *testing.T) {
	a := adapterForTest()
	bigMsg := strings.Repeat("a", maxMessageSize+1)
	payload, _ := json.Marshal(EVMSignPayload{Message: bigMsg})
	err := a.ValidatePayload(context.Background(), SignTypePersonal, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size")
}

func TestValidatePayload_TypedData_Valid(t *testing.T) {
	a := adapterForTest()
	td := &TypedDataPayload{
		PrimaryType: "Permit",
		Types: map[string][]TypedDataField{
			"Permit": {{Name: "owner", Type: "address"}},
		},
		Message: map[string]interface{}{"owner": "0x123"},
	}
	payload, _ := json.Marshal(EVMSignPayload{TypedData: td})
	err := a.ValidatePayload(context.Background(), SignTypeTypedData, payload)
	require.NoError(t, err)
}

func TestValidatePayload_TypedData_Nil(t *testing.T) {
	a := adapterForTest()
	payload, _ := json.Marshal(EVMSignPayload{})
	err := a.ValidatePayload(context.Background(), SignTypeTypedData, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "typed_data is required")
}

func TestValidatePayload_TypedData_NoPrimaryType(t *testing.T) {
	a := adapterForTest()
	td := &TypedDataPayload{
		Types: map[string][]TypedDataField{
			"Permit": {{Name: "owner", Type: "address"}},
		},
	}
	payload, _ := json.Marshal(EVMSignPayload{TypedData: td})
	err := a.ValidatePayload(context.Background(), SignTypeTypedData, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "primaryType is required")
}

func TestValidatePayload_TypedData_NoTypes(t *testing.T) {
	a := adapterForTest()
	td := &TypedDataPayload{PrimaryType: "Permit"}
	payload, _ := json.Marshal(EVMSignPayload{TypedData: td})
	err := a.ValidatePayload(context.Background(), SignTypeTypedData, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "types is required")
}

func TestValidatePayload_Transaction_Valid_Legacy(t *testing.T) {
	a := adapterForTest()
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:       &to,
		Value:    "0",
		Gas:      21000,
		GasPrice: "20000000000",
		TxType:   "legacy",
	}
	payload, _ := json.Marshal(EVMSignPayload{Transaction: tx})
	err := a.ValidatePayload(context.Background(), SignTypeTransaction, payload)
	require.NoError(t, err)
}

func TestValidatePayload_Transaction_Nil(t *testing.T) {
	a := adapterForTest()
	payload, _ := json.Marshal(EVMSignPayload{})
	err := a.ValidatePayload(context.Background(), SignTypeTransaction, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transaction is required")
}

func TestValidatePayload_Transaction_InvalidTo(t *testing.T) {
	a := adapterForTest()
	to := "not_an_address"
	tx := &TransactionPayload{
		To:       &to,
		Value:    "0",
		Gas:      21000,
		GasPrice: "0",
		TxType:   "legacy",
	}
	payload, _ := json.Marshal(EVMSignPayload{Transaction: tx})
	err := a.ValidatePayload(context.Background(), SignTypeTransaction, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid 'to' address")
}

func TestValidatePayload_Transaction_ZeroGas(t *testing.T) {
	a := adapterForTest()
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:       &to,
		Value:    "0",
		Gas:      0, // zero gas
		GasPrice: "0",
		TxType:   "legacy",
	}
	payload, _ := json.Marshal(EVMSignPayload{Transaction: tx})
	err := a.ValidatePayload(context.Background(), SignTypeTransaction, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gas is required")
}

func TestValidatePayload_Transaction_InvalidDataHex(t *testing.T) {
	a := adapterForTest()
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:       &to,
		Value:    "0",
		Data:     "0xGGGG",
		Gas:      21000,
		GasPrice: "0",
		TxType:   "legacy",
	}
	payload, _ := json.Marshal(EVMSignPayload{Transaction: tx})
	err := a.ValidatePayload(context.Background(), SignTypeTransaction, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid transaction data hex")
}

func TestValidatePayload_Transaction_DataTooLarge(t *testing.T) {
	a := adapterForTest()
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	bigData := "0x" + strings.Repeat("ab", maxTransactionDataSize+1)
	tx := &TransactionPayload{
		To:       &to,
		Value:    "0",
		Data:     bigData,
		Gas:      21000,
		GasPrice: "0",
		TxType:   "legacy",
	}
	payload, _ := json.Marshal(EVMSignPayload{Transaction: tx})
	err := a.ValidatePayload(context.Background(), SignTypeTransaction, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size")
}

func TestValidatePayload_Transaction_Legacy_NoGasPrice(t *testing.T) {
	a := adapterForTest()
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:     &to,
		Value:  "0",
		Gas:    21000,
		TxType: "legacy",
		// missing GasPrice
	}
	payload, _ := json.Marshal(EVMSignPayload{Transaction: tx})
	err := a.ValidatePayload(context.Background(), SignTypeTransaction, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gasPrice is required for legacy")
}

func TestValidatePayload_Transaction_EIP1559_Valid(t *testing.T) {
	a := adapterForTest()
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:        &to,
		Value:     "0",
		Gas:       21000,
		GasFeeCap: "50000000000",
		GasTipCap: "1000000000",
		TxType:    "eip1559",
	}
	payload, _ := json.Marshal(EVMSignPayload{Transaction: tx})
	err := a.ValidatePayload(context.Background(), SignTypeTransaction, payload)
	require.NoError(t, err)
}

func TestValidatePayload_Transaction_EIP1559_MissingFees(t *testing.T) {
	a := adapterForTest()
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:     &to,
		Value:  "0",
		Gas:    21000,
		TxType: "eip1559",
	}
	payload, _ := json.Marshal(EVMSignPayload{Transaction: tx})
	err := a.ValidatePayload(context.Background(), SignTypeTransaction, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gasFeeCap and gasTipCap are required")
}

func TestValidatePayload_Transaction_EIP2930_Valid(t *testing.T) {
	a := adapterForTest()
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:       &to,
		Value:    "0",
		Gas:      21000,
		GasPrice: "20000000000",
		TxType:   "eip2930",
	}
	payload, _ := json.Marshal(EVMSignPayload{Transaction: tx})
	err := a.ValidatePayload(context.Background(), SignTypeTransaction, payload)
	require.NoError(t, err)
}

func TestValidatePayload_Transaction_EIP2930_NoGasPrice(t *testing.T) {
	a := adapterForTest()
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:     &to,
		Value:  "0",
		Gas:    21000,
		TxType: "eip2930",
	}
	payload, _ := json.Marshal(EVMSignPayload{Transaction: tx})
	err := a.ValidatePayload(context.Background(), SignTypeTransaction, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gasPrice is required for EIP-2930")
}

func TestValidatePayload_Transaction_UnsupportedType(t *testing.T) {
	a := adapterForTest()
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:     &to,
		Value:  "0",
		Gas:    21000,
		TxType: "eip4844",
	}
	payload, _ := json.Marshal(EVMSignPayload{Transaction: tx})
	err := a.ValidatePayload(context.Background(), SignTypeTransaction, payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported transaction type")
}

func TestValidatePayload_UnsupportedSignType(t *testing.T) {
	a := adapterForTest()
	payload, _ := json.Marshal(EVMSignPayload{})
	err := a.ValidatePayload(context.Background(), "unknown_sign_type", payload)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported sign type")
}

// ─────────────────────────────────────────────────────────────────────────────
// convertToEIP712TypedData
// ─────────────────────────────────────────────────────────────────────────────

func TestConvertToEIP712TypedData_Nil(t *testing.T) {
	_, err := convertToEIP712TypedData(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "typed data payload is nil")
}

func TestConvertToEIP712TypedData_Valid(t *testing.T) {
	td := &TypedDataPayload{
		PrimaryType: "Permit",
		Types: map[string][]TypedDataField{
			"EIP712Domain": {{Name: "name", Type: "string"}},
			"Permit":       {{Name: "owner", Type: "address"}, {Name: "spender", Type: "address"}},
		},
		Domain: TypedDataDomain{
			Name:    "Test",
			Version: "1",
			ChainId: "1",
		},
		Message: map[string]interface{}{
			"owner":   "0x123",
			"spender": "0x456",
		},
	}
	result, err := convertToEIP712TypedData(td)
	require.NoError(t, err)
	assert.Equal(t, "Permit", result.PrimaryType)
	assert.Equal(t, "Test", result.Domain.Name)
	assert.Len(t, result.Types["Permit"], 2)
}

// ─────────────────────────────────────────────────────────────────────────────
// convertToEthTransaction
// ─────────────────────────────────────────────────────────────────────────────

func TestConvertToEthTransaction_Nil(t *testing.T) {
	_, err := convertToEthTransaction(nil, big.NewInt(1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transaction payload is nil")
}

func TestConvertToEthTransaction_Legacy_Valid(t *testing.T) {
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	nonce := uint64(5)
	tx := &TransactionPayload{
		To:       &to,
		Value:    "1000000000000000000",
		Data:     "0x",
		Gas:      21000,
		GasPrice: "20000000000",
		TxType:   "legacy",
		Nonce:    &nonce,
	}
	result, err := convertToEthTransaction(tx, big.NewInt(1))
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, uint64(21000), result.Gas())
}

func TestConvertToEthTransaction_Legacy_NoTo(t *testing.T) {
	// Contract creation: no "to"
	tx := &TransactionPayload{
		Value:    "0",
		Data:     "0x6080604052",
		Gas:      100000,
		GasPrice: "20000000000",
		TxType:   "legacy",
	}
	result, err := convertToEthTransaction(tx, big.NewInt(1))
	require.NoError(t, err)
	assert.Nil(t, result.To())
}

func TestConvertToEthTransaction_InvalidTo(t *testing.T) {
	to := "not_address"
	tx := &TransactionPayload{
		To:       &to,
		Value:    "0",
		Gas:      21000,
		GasPrice: "0",
		TxType:   "legacy",
	}
	_, err := convertToEthTransaction(tx, big.NewInt(1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid 'to' address")
}

func TestConvertToEthTransaction_InvalidValue(t *testing.T) {
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:       &to,
		Value:    "not_a_number",
		Gas:      21000,
		GasPrice: "0",
		TxType:   "legacy",
	}
	_, err := convertToEthTransaction(tx, big.NewInt(1))
	require.Error(t, err)
}

func TestConvertToEthTransaction_InvalidDataHex(t *testing.T) {
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:       &to,
		Value:    "0",
		Data:     "0xGGGG",
		Gas:      21000,
		GasPrice: "0",
		TxType:   "legacy",
	}
	_, err := convertToEthTransaction(tx, big.NewInt(1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid transaction data hex")
}

func TestConvertToEthTransaction_EIP1559_Valid(t *testing.T) {
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	nonce := uint64(10)
	tx := &TransactionPayload{
		To:        &to,
		Value:     "0",
		Gas:       21000,
		GasFeeCap: "50000000000",
		GasTipCap: "1000000000",
		TxType:    "eip1559",
		Nonce:     &nonce,
	}
	result, err := convertToEthTransaction(tx, big.NewInt(1))
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestConvertToEthTransaction_EIP1559_InvalidTipCap(t *testing.T) {
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:        &to,
		Value:     "0",
		Gas:       21000,
		GasFeeCap: "50000000000",
		GasTipCap: "not_valid",
		TxType:    "eip1559",
	}
	_, err := convertToEthTransaction(tx, big.NewInt(1))
	require.Error(t, err)
}

func TestConvertToEthTransaction_EIP1559_InvalidFeeCap(t *testing.T) {
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:        &to,
		Value:     "0",
		Gas:       21000,
		GasFeeCap: "not_valid",
		GasTipCap: "1000000000",
		TxType:    "eip1559",
	}
	_, err := convertToEthTransaction(tx, big.NewInt(1))
	require.Error(t, err)
}

func TestConvertToEthTransaction_EIP2930_Valid(t *testing.T) {
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	nonce := uint64(0)
	tx := &TransactionPayload{
		To:       &to,
		Value:    "0",
		Gas:      21000,
		GasPrice: "20000000000",
		TxType:   "eip2930",
		Nonce:    &nonce,
	}
	result, err := convertToEthTransaction(tx, big.NewInt(1))
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestConvertToEthTransaction_UnsupportedType(t *testing.T) {
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:     &to,
		Value:  "0",
		Gas:    21000,
		TxType: "eip4844",
	}
	_, err := convertToEthTransaction(tx, big.NewInt(1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported transaction type")
}

func TestConvertToEthTransaction_Legacy_InvalidGasPrice(t *testing.T) {
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:       &to,
		Value:    "0",
		Gas:      21000,
		GasPrice: "not_valid",
		TxType:   "legacy",
	}
	_, err := convertToEthTransaction(tx, big.NewInt(1))
	require.Error(t, err)
}

func TestConvertToEthTransaction_EIP2930_InvalidGasPrice(t *testing.T) {
	to := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
	tx := &TransactionPayload{
		To:       &to,
		Value:    "0",
		Gas:      21000,
		GasPrice: "not_valid",
		TxType:   "eip2930",
	}
	_, err := convertToEthTransaction(tx, big.NewInt(1))
	require.Error(t, err)
}

// ─────────────────────────────────────────────────────────────────────────────
// encodeSignature
// ─────────────────────────────────────────────────────────────────────────────

func TestEncodeSignature_Standard(t *testing.T) {
	r := new(big.Int).SetBytes([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32})
	s := new(big.Int).SetBytes([]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	v := big.NewInt(27) // standard v value

	sig := encodeSignature(r, s, v)
	assert.Len(t, sig, 65)
	assert.Equal(t, byte(0), sig[64]) // 27 - 27 = 0
}

func TestEncodeSignature_V28(t *testing.T) {
	r := big.NewInt(1)
	s := big.NewInt(2)
	v := big.NewInt(28)

	sig := encodeSignature(r, s, v)
	assert.Len(t, sig, 65)
	assert.Equal(t, byte(1), sig[64]) // 28 - 27 = 1
}

func TestEncodeSignature_V0(t *testing.T) {
	r := big.NewInt(1)
	s := big.NewInt(2)
	v := big.NewInt(0)

	sig := encodeSignature(r, s, v)
	assert.Len(t, sig, 65)
	assert.Equal(t, byte(0), sig[64]) // < 27, so raw v
}

func TestEncodeSignature_V1(t *testing.T) {
	r := big.NewInt(1)
	s := big.NewInt(2)
	v := big.NewInt(1)

	sig := encodeSignature(r, s, v)
	assert.Len(t, sig, 65)
	assert.Equal(t, byte(1), sig[64]) // < 27, so raw v
}

// ─────────────────────────────────────────────────────────────────────────────
// NewEVMAdapter / Type
// ─────────────────────────────────────────────────────────────────────────────

func TestNewEVMAdapter_NilRegistry(t *testing.T) {
	_, err := NewEVMAdapter(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signer registry is required")
}

func TestEVMAdapter_Type(t *testing.T) {
	a := adapterForTest()
	assert.Equal(t, "evm", string(a.Type()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Transaction: empty "to" is contract creation
// ─────────────────────────────────────────────────────────────────────────────

func TestValidatePayload_Transaction_EmptyTo(t *testing.T) {
	a := adapterForTest()
	emptyTo := ""
	tx := &TransactionPayload{
		To:       &emptyTo,
		Value:    "0",
		Gas:      21000,
		GasPrice: "0",
		TxType:   "legacy",
	}
	payload, _ := json.Marshal(EVMSignPayload{Transaction: tx})
	// Empty "to" → not checked by IsHexAddress (contract creation)
	err := a.ValidatePayload(context.Background(), SignTypeTransaction, payload)
	require.NoError(t, err)
}

func TestConvertToEthTransaction_EmptyTo(t *testing.T) {
	emptyTo := ""
	tx := &TransactionPayload{
		To:       &emptyTo,
		Value:    "0",
		Gas:      21000,
		GasPrice: "0",
		TxType:   "legacy",
	}
	result, err := convertToEthTransaction(tx, big.NewInt(1))
	require.NoError(t, err)
	assert.Nil(t, result.To())
}
