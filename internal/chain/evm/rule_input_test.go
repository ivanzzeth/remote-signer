package evm

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func TestBuildRuleInput_Transaction(t *testing.T) {
	payload := []byte(`{
		"transaction": {
			"to": "0x742d35cc6634c0532925a3b844bc454e4438f44e",
			"value": "1000000000000000000",
			"data": "0x",
			"gas": 21000,
			"gasPrice": "20000000000",
			"txType": "legacy"
		}
	}`)
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTransaction,
		Payload:       payload,
	}
	parsed := &types.ParsedPayload{
		Recipient: strPtrForRuleInput("0x742d35cc6634c0532925a3b844bc454e4438f44e"),
		Value:     strPtrForRuleInput("1000000000000000000"),
		MethodSig: strPtrForRuleInput("0xa9059cbb"),
	}

	out, err := BuildRuleInput(req, parsed)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, "transaction", out.SignType)
	assert.Equal(t, int64(1), out.ChainID)
	assert.Equal(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", out.Signer)
	require.NotNil(t, out.Transaction)
	assert.Equal(t, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", out.Transaction.From)
	assert.Equal(t, common.HexToAddress("0x742d35cc6634c0532925a3b844bc454e4438f44e").Hex(), out.Transaction.To)
	assert.Equal(t, "0xde0b6b3a7640000", out.Transaction.Value)
	assert.Equal(t, "0x", out.Transaction.Data)
	assert.Equal(t, "21000", out.Transaction.Gas)
	assert.Equal(t, "0xa9059cbb", out.Transaction.MethodID)
}

func TestBuildRuleInput_FromNotDerivable(t *testing.T) {
	payload := []byte(`{"transaction":{"to":"0x742d35cc6634c0532925a3b844bc454e4438f44e","value":"0","data":"0x","gas":21000,"gasPrice":"0","txType":"legacy"}}`)
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "",
		SignType:      SignTypeTransaction,
		Payload:       payload,
	}
	_, err := BuildRuleInput(req, nil)
	assert.ErrorIs(t, err, ErrFromNotDerivable)
}

func TestBuildRuleInput_PersonalSign(t *testing.T) {
	payload := []byte(`{"message":"Hello world"}`)
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypePersonal,
		Payload:       payload,
	}
	out, err := BuildRuleInput(req, nil)
	require.NoError(t, err)
	require.NotNil(t, out.PersonalSign)
	assert.Equal(t, "Hello world", out.PersonalSign.Message)
}

func strPtrForRuleInput(s string) *string { return &s }

func TestBuildRuleInput_TypedData(t *testing.T) {
	payload := []byte(`{
		"typed_data": {
			"types": {"EIP712Domain":[{"name":"name","type":"string"}],"Permit":[{"name":"owner","type":"address"}]},
			"primaryType": "Permit",
			"domain": {"name":"Test","version":"1","chainId":"1"},
			"message": {"owner":"0x70997970C51812dc3A010C7d01b50e0d17dc79C8"}
		}
	}`)
	req := &types.SignRequest{
		ChainID:       "1",
		SignerAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		SignType:      SignTypeTypedData,
		Payload:       payload,
	}
	out, err := BuildRuleInput(req, nil)
	require.NoError(t, err)
	require.NotNil(t, out.TypedData)
	assert.Equal(t, "Permit", out.TypedData.PrimaryType)
}
