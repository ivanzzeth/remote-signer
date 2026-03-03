package evm

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// DelegatePayloadToSignRequest
// ─────────────────────────────────────────────────────────────────────────────

func TestDelegatePayloadToSignRequest_NilPayload(t *testing.T) {
	_, _, err := DelegatePayloadToSignRequest(context.Background(), nil, "single")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delegation payload is nil")
}

func TestDelegatePayloadToSignRequest_MapPayload(t *testing.T) {
	payload := map[string]interface{}{
		"sign_type": "transaction",
		"chain_id":  float64(1),
		"signer":    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		"transaction": map[string]interface{}{
			"from":  "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			"to":    "0x742d35cc6634c0532925a3b844bc454e4438f44e",
			"value": "0xDE0B6B3A7640000",
			"data":  "0xa9059cbb",
		},
	}
	req, parsed, err := DelegatePayloadToSignRequest(context.Background(), payload, "single")
	require.NoError(t, err)
	require.NotNil(t, req)
	require.NotNil(t, parsed)
	assert.Equal(t, types.ChainTypeEVM, req.ChainType)
	assert.Equal(t, "1", req.ChainID)
	assert.Equal(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", req.SignerAddress)
	assert.Equal(t, SignTypeTransaction, req.SignType)
	// parsed should have recipient
	require.NotNil(t, parsed.Recipient)
	assert.Equal(t, "0x742d35cc6634c0532925a3b844bc454e4438f44e", *parsed.Recipient)
	// parsed should have value (hex→decimal)
	require.NotNil(t, parsed.Value)
	assert.Equal(t, "1000000000000000000", *parsed.Value)
}

func TestDelegatePayloadToSignRequest_RuleInputPayload(t *testing.T) {
	to := "0x742d35cc6634c0532925a3b844bc454e4438f44e"
	payload := &RuleInput{
		SignType: "transaction",
		ChainID:  1,
		Signer:   "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Transaction: &RuleInputTransaction{
			From:  "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			To:    to,
			Value: "0x0",
			Data:  "0x",
		},
	}
	req, _, err := DelegatePayloadToSignRequest(context.Background(), payload, "single")
	require.NoError(t, err)
	require.NotNil(t, req)
	assert.Equal(t, "1", req.ChainID)
	assert.Equal(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", req.SignerAddress)
}

func TestDelegatePayloadToSignRequest_StructPayload(t *testing.T) {
	// Any struct that marshals to a map with signer/sign_type/chain_id
	type customPayload struct {
		SignType string  `json:"sign_type"`
		ChainID  float64 `json:"chain_id"`
		Signer   string  `json:"signer"`
	}
	payload := customPayload{SignType: "transaction", ChainID: 1, Signer: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
	req, _, err := DelegatePayloadToSignRequest(context.Background(), payload, "single")
	require.NoError(t, err)
	require.NotNil(t, req)
	assert.Equal(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", req.SignerAddress)
}

func TestDelegatePayloadToSignRequest_MissingSigner(t *testing.T) {
	payload := map[string]interface{}{
		"sign_type": "transaction",
		"chain_id":  float64(1),
	}
	_, _, err := DelegatePayloadToSignRequest(context.Background(), payload, "single")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing signer")
}

// ─────────────────────────────────────────────────────────────────────────────
// mapRuleInputSignTypeToEVM
// ─────────────────────────────────────────────────────────────────────────────

func TestMapRuleInputSignTypeToEVM(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"transaction", SignTypeTransaction},
		{"typed_data", SignTypeTypedData},
		{"personal_sign", SignTypePersonal},
		{"unknown_type", "unknown_type"}, // default passthrough
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.expected, mapRuleInputSignTypeToEVM(tc.input))
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// buildEVMPayloadFromRuleInputMap
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildEVMPayloadFromRuleInputMap_Transaction(t *testing.T) {
	m := map[string]interface{}{
		"sign_type": "transaction",
		"transaction": map[string]interface{}{
			"to":    "0x742d35cc6634c0532925a3b844bc454e4438f44e",
			"value": "0xDE0B6B3A7640000",
			"data":  "0xa9059cbb",
		},
	}
	payload, err := buildEVMPayloadFromRuleInputMap(m)
	require.NoError(t, err)
	assert.Contains(t, string(payload), "transaction")
	assert.Contains(t, string(payload), "1000000000000000000")
	assert.Contains(t, string(payload), "0xa9059cbb")
}

func TestBuildEVMPayloadFromRuleInputMap_TypedData(t *testing.T) {
	m := map[string]interface{}{
		"sign_type": "typed_data",
		"typed_data": map[string]interface{}{
			"primaryType": "Permit",
			"message":     map[string]interface{}{"owner": "0x123"},
		},
	}
	payload, err := buildEVMPayloadFromRuleInputMap(m)
	require.NoError(t, err)
	assert.Contains(t, string(payload), "typed_data")
	assert.Contains(t, string(payload), "Permit")
}

func TestBuildEVMPayloadFromRuleInputMap_PersonalSign(t *testing.T) {
	m := map[string]interface{}{
		"sign_type": "personal_sign",
		"personal_sign": map[string]interface{}{
			"message": "Hello World",
		},
	}
	payload, err := buildEVMPayloadFromRuleInputMap(m)
	require.NoError(t, err)
	assert.Contains(t, string(payload), "Hello World")
}

func TestBuildEVMPayloadFromRuleInputMap_NoTransaction(t *testing.T) {
	m := map[string]interface{}{
		"sign_type": "transaction",
		// missing transaction key
	}
	payload, err := buildEVMPayloadFromRuleInputMap(m)
	require.NoError(t, err)
	assert.Equal(t, "{}", string(payload))
}

func TestBuildEVMPayloadFromRuleInputMap_NoTypedData(t *testing.T) {
	m := map[string]interface{}{
		"sign_type": "typed_data",
		// missing typed_data key
	}
	payload, err := buildEVMPayloadFromRuleInputMap(m)
	require.NoError(t, err)
	assert.Equal(t, "{}", string(payload))
}

func TestBuildEVMPayloadFromRuleInputMap_NoPersonalSign(t *testing.T) {
	m := map[string]interface{}{
		"sign_type": "personal_sign",
		// missing personal_sign key
	}
	payload, err := buildEVMPayloadFromRuleInputMap(m)
	require.NoError(t, err)
	assert.Equal(t, "{}", string(payload))
}

func TestBuildEVMPayloadFromRuleInputMap_UnknownSignType(t *testing.T) {
	m := map[string]interface{}{
		"sign_type": "raw_hash",
	}
	payload, err := buildEVMPayloadFromRuleInputMap(m)
	require.NoError(t, err)
	assert.Equal(t, "{}", string(payload))
}

func TestBuildEVMPayloadFromRuleInputMap_TransactionMissingData(t *testing.T) {
	// data is absent → firstStr should return default "0x"
	m := map[string]interface{}{
		"sign_type": "transaction",
		"transaction": map[string]interface{}{
			"to":    "0x742d35cc6634c0532925a3b844bc454e4438f44e",
			"value": "0x0",
		},
	}
	payload, err := buildEVMPayloadFromRuleInputMap(m)
	require.NoError(t, err)
	assert.Contains(t, string(payload), `"data":"0x"`)
}

func TestBuildEVMPayloadFromRuleInputMap_PersonalSignNoMessage(t *testing.T) {
	m := map[string]interface{}{
		"sign_type": "personal_sign",
		"personal_sign": map[string]interface{}{
			"not_message": 42,
		},
	}
	payload, err := buildEVMPayloadFromRuleInputMap(m)
	require.NoError(t, err)
	// No "message" key in payload since it's not a string
	assert.Equal(t, "{}", string(payload))
}

// ─────────────────────────────────────────────────────────────────────────────
// hexWeiToDecimal
// ─────────────────────────────────────────────────────────────────────────────

func TestHexWeiToDecimal(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", "0"},
		{"0x0", "0x0", "0"},
		{"bare 0x", "0x", "0"},
		{"1 ETH", "0xDE0B6B3A7640000", "1000000000000000000"},
		{"uppercase prefix", "0XDE0B6B3A7640000", "1000000000000000000"},
		{"invalid hex", "0xGGGG", "0"},
		{"small value", "0xa", "10"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, hexWeiToDecimal(tc.input))
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// firstStr
// ─────────────────────────────────────────────────────────────────────────────

func TestFirstStr(t *testing.T) {
	assert.Equal(t, "hello", firstStr("hello", "default"))
	assert.Equal(t, "default", firstStr(nil, "default"))
	assert.Equal(t, "default", firstStr(42, "default"))
	assert.Equal(t, "", firstStr("", "default")) // empty string IS a string
}

// ─────────────────────────────────────────────────────────────────────────────
// chainIDFromInterface
// ─────────────────────────────────────────────────────────────────────────────

func TestChainIDFromInterface(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected float64
	}{
		{"nil", nil, 0},
		{"float64", float64(137), 137},
		{"int64", int64(1), 1},
		{"int", int(42), 42},
		{"json.Number", json.Number("137"), 137},
		{"string", "137", 137},
		{"string invalid", "not_a_number", 0},
		{"bool (unsupported)", true, 0},
		{"slice (unsupported)", []int{1}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := chainIDFromInterface(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// parsedPayloadFromRuleInputMap
// ─────────────────────────────────────────────────────────────────────────────

func TestParsedPayloadFromRuleInputMap_Transaction(t *testing.T) {
	m := map[string]interface{}{
		"transaction": map[string]interface{}{
			"to":       "0x742d35cc6634c0532925a3b844bc454e4438f44e",
			"value":    "0xDE0B6B3A7640000",
			"methodId": "0xa9059cbb",
		},
	}
	parsed := parsedPayloadFromRuleInputMap(m)
	require.NotNil(t, parsed.Recipient)
	assert.Equal(t, "0x742d35cc6634c0532925a3b844bc454e4438f44e", *parsed.Recipient)
	require.NotNil(t, parsed.Value)
	assert.Equal(t, "1000000000000000000", *parsed.Value)
	require.NotNil(t, parsed.MethodSig)
	assert.Equal(t, "0xa9059cbb", *parsed.MethodSig)
	// Contract should be set to recipient when methodId present
	require.NotNil(t, parsed.Contract)
	assert.Equal(t, "0x742d35cc6634c0532925a3b844bc454e4438f44e", *parsed.Contract)
}

func TestParsedPayloadFromRuleInputMap_NoTransaction(t *testing.T) {
	m := map[string]interface{}{}
	parsed := parsedPayloadFromRuleInputMap(m)
	assert.Nil(t, parsed.Recipient)
	assert.Nil(t, parsed.Value)
}

func TestParsedPayloadFromRuleInputMap_PersonalSign(t *testing.T) {
	m := map[string]interface{}{
		"personal_sign": map[string]interface{}{
			"message": "Hello",
		},
	}
	parsed := parsedPayloadFromRuleInputMap(m)
	require.NotNil(t, parsed.Message)
	assert.Equal(t, "Hello", *parsed.Message)
}

func TestParsedPayloadFromRuleInputMap_TransactionEmptyTo(t *testing.T) {
	m := map[string]interface{}{
		"transaction": map[string]interface{}{
			"to":    "",
			"value": "0x0",
		},
	}
	parsed := parsedPayloadFromRuleInputMap(m)
	assert.Nil(t, parsed.Recipient) // empty "to" should not set recipient
	require.NotNil(t, parsed.Value)
	assert.Equal(t, "0", *parsed.Value)
}

func TestParsedPayloadFromRuleInputMap_TransactionNoMethodId(t *testing.T) {
	m := map[string]interface{}{
		"transaction": map[string]interface{}{
			"to":    "0x742d35cc6634c0532925a3b844bc454e4438f44e",
			"value": "0x0",
		},
	}
	parsed := parsedPayloadFromRuleInputMap(m)
	assert.Nil(t, parsed.MethodSig)
	assert.Nil(t, parsed.Contract)
}

func TestParsedPayloadFromRuleInputMap_PersonalSignNoMessage(t *testing.T) {
	m := map[string]interface{}{
		"personal_sign": map[string]interface{}{
			"not_message": 42,
		},
	}
	parsed := parsedPayloadFromRuleInputMap(m)
	assert.Nil(t, parsed.Message)
}

// ─────────────────────────────────────────────────────────────────────────────
// ruleInputToMap
// ─────────────────────────────────────────────────────────────────────────────

func TestRuleInputToMap_Nil(t *testing.T) {
	m, err := ruleInputToMap(nil)
	require.NoError(t, err)
	assert.Nil(t, m)
}

func TestRuleInputToMap_Basic(t *testing.T) {
	input := &RuleInput{
		SignType: "transaction",
		ChainID:  1,
		Signer:   "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
	}
	m, err := ruleInputToMap(input)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, "transaction", m["sign_type"])
	assert.Equal(t, float64(1), m["chain_id"])
	assert.Equal(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", m["signer"])
}
