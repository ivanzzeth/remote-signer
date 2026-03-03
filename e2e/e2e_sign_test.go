//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ivanzzeth/ethsig/eip712"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

func TestSign_PersonalSign(t *testing.T) {
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	sig, err := signer.PersonalSign("Hello, Remote Signer!")
	require.NoError(t, err)
	require.NotEmpty(t, sig)
	assert.Len(t, sig, 65)
	assert.Equal(t, address, signer.GetAddress())
}

func TestSign_Hash(t *testing.T) {
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	hash := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	sig, err := signer.SignHash(hash)
	require.NoError(t, err)
	require.NotEmpty(t, sig)
	assert.Len(t, sig, 65)
}

func TestSign_RawMessage(t *testing.T) {
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	sig, err := signer.SignRawMessage([]byte("raw message bytes"))
	require.NoError(t, err)
	require.NotEmpty(t, sig)
	assert.Len(t, sig, 65)
}

func TestSign_EIP191Message(t *testing.T) {
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	rawMessage := "Hello, EIP-191!"
	eip191Message := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(rawMessage), rawMessage)
	sig, err := signer.SignEIP191Message(eip191Message)
	require.NoError(t, err)
	require.NotEmpty(t, sig)
	assert.Len(t, sig, 65)
}

func TestSign_TypedData(t *testing.T) {
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	typedData := eip712.TypedData{
		Types: eip712.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"Mail": {
				{Name: "from", Type: "string"},
				{Name: "to", Type: "string"},
				{Name: "contents", Type: "string"},
			},
		},
		PrimaryType: "Mail",
		Domain: eip712.TypedDataDomain{
			Name:              "Test App",
			Version:           "1",
			ChainId:           "1",
			VerifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
		},
		Message: map[string]interface{}{
			"from":     "Alice",
			"to":       "Bob",
			"contents": "Hello, Bob!",
		},
	}
	sig, err := signer.SignTypedData(typedData)
	require.NoError(t, err)
	require.NotEmpty(t, sig)
	assert.Len(t, sig, 65)
}

func TestSign_LegacyTransaction(t *testing.T) {
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	to := common.HexToAddress(treasuryAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(500000000000000000),
		Data:     nil,
	})
	chainIDBig := big.NewInt(1)
	signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err)
	require.NotNil(t, signedTx)
	v, r, s := signedTx.RawSignatureValues()
	assert.NotNil(t, v)
	assert.NotNil(t, r)
	assert.NotNil(t, s)
}

func TestSign_EIP1559Transaction(t *testing.T) {
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	to := common.HexToAddress(treasuryAddress)
	chainIDBig := big.NewInt(1)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainIDBig,
		Nonce:     1,
		GasTipCap: big.NewInt(1000000000),
		GasFeeCap: big.NewInt(20000000000),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(500000000000000000),
		Data:      nil,
	})
	signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err)
	require.NotNil(t, signedTx)
	v, r, s := signedTx.RawSignatureValues()
	assert.NotNil(t, v)
	assert.NotNil(t, r)
	assert.NotNil(t, s)
}

func TestSign_SignerNotFound(t *testing.T) {
	unknownAddress := common.HexToAddress("0x0000000000000000000000000000000000000001")
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, unknownAddress, testChainID)
	_, err := signer.PersonalSign("test message")
	require.Error(t, err)
}

func TestSign_ContextCancellation(t *testing.T) {
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := signer.PersonalSignWithContext(ctx, "test message")
	require.Error(t, err)
}

func TestSign_MultipleRequests(t *testing.T) {
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	for _, msg := range []string{"Message 1", "Message 2", "Message 3"} {
		sig, err := signer.PersonalSign(msg)
		require.NoError(t, err)
		assert.Len(t, sig, 65)
	}
}

func TestSign_DirectSignAPI(t *testing.T) {
	ctx := context.Background()
	resp, err := adminClient.EVM.Sign.Execute(ctx, &evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      evm.SignTypePersonal,
		Payload:       []byte(`{"message":"Direct API test"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Signature)
}
