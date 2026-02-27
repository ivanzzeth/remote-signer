package evm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// parseChainIDForRuleInput
// ─────────────────────────────────────────────────────────────────────────────

func TestParseChainIDForRuleInput_Valid(t *testing.T) {
	n, err := parseChainIDForRuleInput("137")
	require.NoError(t, err)
	assert.Equal(t, int64(137), n)
}

func TestParseChainIDForRuleInput_Empty(t *testing.T) {
	_, err := parseChainIDForRuleInput("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chain_id is required")
}

func TestParseChainIDForRuleInput_Invalid(t *testing.T) {
	_, err := parseChainIDForRuleInput("not_a_number")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid chain_id")
}

func TestParseChainIDForRuleInput_Negative(t *testing.T) {
	_, err := parseChainIDForRuleInput("-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid chain_id")
}

func TestParseChainIDForRuleInput_Zero(t *testing.T) {
	n, err := parseChainIDForRuleInput("0")
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}

// ─────────────────────────────────────────────────────────────────────────────
// mapEVMSignTypeToRuleInput
// ─────────────────────────────────────────────────────────────────────────────

func TestMapEVMSignTypeToRuleInput(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{SignTypeTransaction, "transaction"},
		{SignTypeTypedData, "typed_data"},
		{SignTypePersonal, "personal_sign"},
		{SignTypeEIP191, "personal_sign"},
		{SignTypeHash, "hash"},       // default passthrough
		{"custom", "custom"},         // default passthrough
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.expected, mapEVMSignTypeToRuleInput(tc.input))
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// toHexWei
// ─────────────────────────────────────────────────────────────────────────────

func TestToHexWei(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", "0x0"},
		{"zero", "0", "0x0"},
		{"one ETH", "1000000000000000000", "0xde0b6b3a7640000"},
		{"invalid", "not_a_number", "0x0"},
		{"small", "255", "0xff"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, toHexWei(tc.input))
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// normalizeHex
// ─────────────────────────────────────────────────────────────────────────────

func TestNormalizeHex(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "0x"},
		{"0x", "0x"},
		{"0X", "0x"},
		{"0xabcdef", "0xabcdef"},
		{"0Xabcdef", "0xabcdef"},
		{"abcdef", "0xabcdef"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.expected, normalizeHex(tc.input))
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// BuildRuleInput edge cases
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildRuleInput_NilRequest(t *testing.T) {
	_, err := BuildRuleInput(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request is required")
}

func TestBuildRuleInput_EmptyChainID(t *testing.T) {
	req := &types.SignRequest{
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
	}
	_, err := BuildRuleInput(req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chain_id is required")
}

func TestBuildRuleInput_InvalidPayloadJSON(t *testing.T) {
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{invalid`),
	}
	_, err := BuildRuleInput(req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid payload JSON")
}

func TestBuildRuleInput_TransactionMissingPayload(t *testing.T) {
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       []byte(`{}`), // no transaction
	}
	_, err := BuildRuleInput(req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "transaction payload missing")
}

func TestBuildRuleInput_TypedData_MissingPayload(t *testing.T) {
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTypedData,
		Payload:       []byte(`{}`),
	}
	_, err := BuildRuleInput(req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "typed_data payload missing")
}

func TestBuildRuleInput_Personal_MissingMessage(t *testing.T) {
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypePersonal,
		Payload:       []byte(`{}`),
	}
	_, err := BuildRuleInput(req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "message payload missing")
}

func TestBuildRuleInput_Hash_NoFields(t *testing.T) {
	// hash sign_type → no transaction/typed_data/personal_sign fields, just basic info
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeHash,
		Payload:       []byte(`{"hash":"0x` + "ab" + `"}`),
	}
	out, err := BuildRuleInput(req, nil)
	require.NoError(t, err)
	assert.Equal(t, "hash", out.SignType)
	assert.Nil(t, out.Transaction)
	assert.Nil(t, out.TypedData)
	assert.Nil(t, out.PersonalSign)
}

func TestBuildRuleInput_Transaction_NoTo(t *testing.T) {
	// Contract creation: no "to" field
	payload := []byte(`{"transaction":{"value":"0","data":"0x6080604052","gas":100000,"gasPrice":"0","txType":"legacy"}}`)
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       payload,
	}
	out, err := BuildRuleInput(req, nil)
	require.NoError(t, err)
	// When To is nil, the code sets to = "" (contract creation)
	assert.Equal(t, "", out.Transaction.To)
}

func TestBuildRuleInput_EmptyPayload(t *testing.T) {
	// Empty payload but sign_type is hash (which doesn't require structured payload)
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeHash,
	}
	out, err := BuildRuleInput(req, nil)
	require.NoError(t, err)
	assert.Equal(t, "hash", out.SignType)
}

func TestBuildRuleInput_Transaction_ZeroGas(t *testing.T) {
	// Gas=0 should result in empty gas string
	payload := []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":0,"gasPrice":"0","txType":"legacy"}}`)
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       payload,
	}
	out, err := BuildRuleInput(req, nil)
	require.NoError(t, err)
	assert.Equal(t, "", out.Transaction.Gas)
}
