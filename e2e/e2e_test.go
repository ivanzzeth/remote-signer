//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ivanzzeth/ethsig/eip712"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
)

const (
	// Well-known test private key (Hardhat/Foundry first account)
	// Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
	testSignerPrivateKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	testSignerAddress    = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	testChainID          = "1"

	// Default API port for e2e tests
	defaultAPIPort = 8548
)

var (
	testServer    *TestServer
	testClient    *client.Client
	testAPIKeyID  string
	testAPIKeyHex string
)

func TestMain(m *testing.M) {
	// Get port from environment or use default
	port := defaultAPIPort
	if portStr := os.Getenv("E2E_API_PORT"); portStr != "" {
		// Parse port if needed
		port = defaultAPIPort
	}

	// Generate Ed25519 API key for tests
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic("failed to generate API key: " + err.Error())
	}
	testAPIKeyID = "test-api-key-e2e"
	testAPIKeyHex = hex.EncodeToString(privKey)

	// Start test server
	testServer, err = NewTestServer(TestServerConfig{
		Port:             port,
		SignerPrivateKey: testSignerPrivateKey,
		SignerAddress:    testSignerAddress,
		APIKeyID:         testAPIKeyID,
		APIKeyPublicKey:  pubKey,
	})
	if err != nil {
		panic("failed to create test server: " + err.Error())
	}

	if err := testServer.Start(); err != nil {
		panic("failed to start test server: " + err.Error())
	}

	// Create test client
	testClient, err = client.NewClient(client.Config{
		BaseURL:       testServer.BaseURL(),
		APIKeyID:      testAPIKeyID,
		PrivateKeyHex: testAPIKeyHex,
		PollInterval:  100 * time.Millisecond,
		PollTimeout:   5 * time.Second,
	})
	if err != nil {
		testServer.Stop()
		panic("failed to create test client: " + err.Error())
	}

	// Run tests
	code := m.Run()

	// Cleanup
	testServer.Stop()

	os.Exit(code)
}

func TestHealthCheck(t *testing.T) {
	health, err := testClient.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ok", health.Status)
}

func TestPersonalSign(t *testing.T) {
	address := common.HexToAddress(testSignerAddress)
	signer := testClient.GetSigner(address, testChainID)

	message := "Hello, Remote Signer!"
	sig, err := signer.PersonalSign(message)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	// Signature should be 65 bytes (r, s, v)
	assert.Len(t, sig, 65)

	// Verify the signer address
	assert.Equal(t, address, signer.GetAddress())
}

func TestSignHash(t *testing.T) {
	address := common.HexToAddress(testSignerAddress)
	signer := testClient.GetSigner(address, testChainID)

	hash := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	sig, err := signer.SignHash(hash)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	// Signature should be 65 bytes
	assert.Len(t, sig, 65)
}

func TestSignRawMessage(t *testing.T) {
	address := common.HexToAddress(testSignerAddress)
	signer := testClient.GetSigner(address, testChainID)

	rawMessage := []byte("raw message bytes")
	sig, err := signer.SignRawMessage(rawMessage)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	assert.Len(t, sig, 65)
}

func TestSignEIP191Message(t *testing.T) {
	address := common.HexToAddress(testSignerAddress)
	signer := testClient.GetSigner(address, testChainID)

	// EIP-191 format: 0x19 + version byte + version-specific data
	// Version 0x45 is 'E' which is for Ethereum Signed Message (personal_sign)
	// The message must include the full EIP-191 format: "\x19Ethereum Signed Message:\n" + len + message
	// Since ethsig expects this format, we construct it properly
	rawMessage := "Hello, EIP-191!"
	// Format: 0x19 + "Ethereum Signed Message:\n" + len(message as string) + message
	eip191Message := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(rawMessage), rawMessage)

	sig, err := signer.SignEIP191Message(eip191Message)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	assert.Len(t, sig, 65)
}

func TestSignTypedData(t *testing.T) {
	address := common.HexToAddress(testSignerAddress)
	signer := testClient.GetSigner(address, testChainID)

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

func TestSignTransaction(t *testing.T) {
	address := common.HexToAddress(testSignerAddress)
	signer := testClient.GetSigner(address, testChainID)

	to := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(20000000000), // 20 gwei
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(1000000000000000000), // 1 ETH
		Data:     nil,
	})

	chainID := big.NewInt(1)
	signedTx, err := signer.SignTransactionWithChainID(tx, chainID)
	require.NoError(t, err)
	require.NotNil(t, signedTx)

	// Verify the transaction was signed
	v, r, s := signedTx.RawSignatureValues()
	assert.NotNil(t, v)
	assert.NotNil(t, r)
	assert.NotNil(t, s)
}

func TestSignEIP1559Transaction(t *testing.T) {
	address := common.HexToAddress(testSignerAddress)
	signer := testClient.GetSigner(address, testChainID)

	to := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	chainID := big.NewInt(1)

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     1,
		GasTipCap: big.NewInt(1000000000),  // 1 gwei
		GasFeeCap: big.NewInt(20000000000), // 20 gwei
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(500000000000000000), // 0.5 ETH
		Data:      nil,
	})

	signedTx, err := signer.SignTransactionWithChainID(tx, chainID)
	require.NoError(t, err)
	require.NotNil(t, signedTx)

	// Verify signature exists
	v, r, s := signedTx.RawSignatureValues()
	assert.NotNil(t, v)
	assert.NotNil(t, r)
	assert.NotNil(t, s)
}

func TestSignerNotFound(t *testing.T) {
	unknownAddress := common.HexToAddress("0x0000000000000000000000000000000000000001")
	signer := testClient.GetSigner(unknownAddress, testChainID)

	_, err := signer.PersonalSign("test message")
	require.Error(t, err)
}

func TestContextCancellation(t *testing.T) {
	address := common.HexToAddress(testSignerAddress)
	signer := testClient.GetSigner(address, testChainID)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := signer.PersonalSignWithContext(ctx, "test message")
	require.Error(t, err)
}

func TestMultipleSignRequests(t *testing.T) {
	address := common.HexToAddress(testSignerAddress)
	signer := testClient.GetSigner(address, testChainID)

	// Sign multiple messages sequentially
	// Note: Concurrent signing works with PostgreSQL but SQLite has locking issues
	messages := []string{
		"Message 1",
		"Message 2",
		"Message 3",
	}

	for _, msg := range messages {
		sig, err := signer.PersonalSign(msg)
		require.NoError(t, err)
		assert.Len(t, sig, 65)
	}
}

func TestDirectSignAPI(t *testing.T) {
	ctx := context.Background()

	// Test direct Sign API call
	resp, err := testClient.Sign(ctx, &client.SignRequest{
		ChainID:       testChainID,
		SignerAddress: testSignerAddress,
		SignType:      client.SignTypePersonal,
		Payload:       []byte(`{"message":"Direct API test"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Signature)
}
