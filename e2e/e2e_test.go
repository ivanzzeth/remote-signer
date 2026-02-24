//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ivanzzeth/ethsig/eip712"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
)

// Environment variables for external server mode:
//
// E2E_EXTERNAL_SERVER  - Set to "true" or "1" to use an external server instead of starting one
// E2E_BASE_URL         - Base URL of the external server (default: http://localhost:8548)
// E2E_SIGNER_ADDRESS   - Signer address to use for tests (default: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266)
// E2E_CHAIN_ID         - Chain ID to use for tests (default: 1)
//
// Admin API key (required for external server mode):
// E2E_API_KEY_ID       - Admin API key ID
// E2E_PRIVATE_KEY      - Admin Ed25519 private key (hex or base64, auto-detected)
//
// Non-admin API key (optional):
// E2E_NONADMIN_API_KEY_ID   - Non-admin API key ID
// E2E_NONADMIN_PRIVATE_KEY  - Non-admin Ed25519 private key (hex or base64, auto-detected)
//
// Example usage with external server:
//   E2E_EXTERNAL_SERVER=true \
//   E2E_BASE_URL=http://localhost:8548 \
//   E2E_API_KEY_ID=my-admin-key \
//   E2E_PRIVATE_KEY=<ed25519-private-key-hex-or-base64> \
//   go test -tags=e2e ./e2e/...

const (
	// Well-known test private key (Hardhat/Foundry first account)
	// Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
	testSignerPrivateKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	testSignerAddress    = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	testChainID          = "1"

	// Second signer (Hardhat account 2) — not in any whitelist; used for approval-guard e2e
	testSigner2PrivateKey = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
	testSigner2Address    = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

	// Default API port for e2e tests
	defaultAPIPort = 8548

	// Treasury address from example config (whitelisted in "Allow transfers to treasury" rule)
	treasuryAddress = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"

	// Burn address (blocked by "Block known malicious addresses" rule)
	burnAddress = "0x000000000000000000000000000000000000dEaD"
)

var (
	testServer *TestServer

	// Admin client (can manage rules, approve requests)
	adminClient    *client.Client
	adminAPIKeyID  string
	adminAPIKeyHex string

	// Non-admin client (can only submit sign requests)
	nonAdminClient    *client.Client
	nonAdminAPIKeyID  string
	nonAdminAPIKeyHex string

	// External server mode flag
	useExternalServer bool

	// Configurable test parameters
	signerAddress string
	chainID       string
	baseURL       string
)

func TestMain(m *testing.M) {
	// Check if using external server
	extServer := os.Getenv("E2E_EXTERNAL_SERVER")
	useExternalServer = extServer == "true" || extServer == "1"

	// Set default test parameters
	signerAddress = testSignerAddress
	chainID = testChainID

	// Override from environment if set
	if addr := os.Getenv("E2E_SIGNER_ADDRESS"); addr != "" {
		signerAddress = addr
	}
	if cid := os.Getenv("E2E_CHAIN_ID"); cid != "" {
		chainID = cid
	}

	var err error

	if useExternalServer {
		// External server mode: use environment variables for configuration
		baseURL = os.Getenv("E2E_BASE_URL")
		if baseURL == "" {
			baseURL = fmt.Sprintf("http://localhost:%d", defaultAPIPort)
		}

		// Admin API key from environment (required)
		adminAPIKeyID = os.Getenv("E2E_API_KEY_ID")
		adminPrivKey := os.Getenv("E2E_PRIVATE_KEY")
		if adminAPIKeyID == "" || adminPrivKey == "" {
			panic("E2E_API_KEY_ID and E2E_PRIVATE_KEY are required for external server mode")
		}

		// Convert admin private key to hex (supports both hex and base64)
		var convertErr error
		adminAPIKeyHex, convertErr = convertPrivateKeyToHex(adminPrivKey)
		if convertErr != nil {
			panic("failed to convert admin private key: " + convertErr.Error())
		}

		// Non-admin API key from environment (optional)
		nonAdminAPIKeyID = os.Getenv("E2E_NONADMIN_API_KEY_ID")
		nonAdminPrivKey := os.Getenv("E2E_NONADMIN_PRIVATE_KEY")
		if nonAdminPrivKey != "" {
			nonAdminAPIKeyHex, convertErr = convertPrivateKeyToHex(nonAdminPrivKey)
			if convertErr != nil {
				panic("failed to convert non-admin private key: " + convertErr.Error())
			}
		}

		fmt.Printf("E2E: Using external server at %s\n", baseURL)
		fmt.Printf("E2E: Signer address: %s, Chain ID: %s\n", signerAddress, chainID)
	} else {
		// Internal server mode: start test server with generated keys
		port := defaultAPIPort
		if portStr := os.Getenv("E2E_API_PORT"); portStr != "" {
			if p, err := strconv.Atoi(portStr); err == nil {
				port = p
			}
		}

		// Generate Ed25519 API key for admin
		adminPubKey, adminPrivKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic("failed to generate admin API key: " + err.Error())
		}
		adminAPIKeyID = "test-admin-key-e2e"
		adminAPIKeyHex = hex.EncodeToString(adminPrivKey)

		// Generate Ed25519 API key for non-admin
		nonAdminPubKey, nonAdminPrivKey, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic("failed to generate non-admin API key: " + err.Error())
		}
		nonAdminAPIKeyID = "test-nonadmin-key-e2e"
		nonAdminAPIKeyHex = hex.EncodeToString(nonAdminPrivKey)

		// Find config.e2e.yaml path
		configPath := "config.e2e.yaml"
		wd, err := os.Getwd()
		if err == nil {
			// Try to find project root
			for wd != "/" && wd != "" {
				testPath := filepath.Join(wd, configPath)
				if _, statErr := os.Stat(testPath); statErr == nil {
					configPath = testPath
					break
				}
				wd = filepath.Dir(wd)
			}
		}

		// Start test server with config.e2e.yaml
		testServer, err = NewTestServer(TestServerConfig{
			Port:                    port,
			SignerPrivateKey:        testSignerPrivateKey,
			SignerAddress:           testSignerAddress,
			APIKeyID:                adminAPIKeyID,
			APIKeyPublicKey:         adminPubKey,
			NonAdminAPIKeyID:        nonAdminAPIKeyID,
			NonAdminAPIKeyPublicKey: nonAdminPubKey,
			ConfigPath:              configPath,
		})
		if err != nil {
			panic("failed to create test server: " + err.Error())
		}

		if err := testServer.Start(); err != nil {
			panic("failed to start test server: " + err.Error())
		}

		baseURL = testServer.BaseURL()
	}

	// Set poll interval based on mode:
	// - Internal mode: 100ms for fast testing
	// - External mode: 1 second to avoid flooding the server
	pollInterval := 100 * time.Millisecond
	pollTimeout := 5 * time.Second
	if useExternalServer {
		pollInterval = 1 * time.Second
		pollTimeout = 30 * time.Second
	}

	// Create admin client
	adminClient, err = client.NewClient(client.Config{
		BaseURL:       baseURL,
		APIKeyID:      adminAPIKeyID,
		PrivateKeyHex: adminAPIKeyHex,
		PollInterval:  pollInterval,
		PollTimeout:   pollTimeout,
	})
	if err != nil {
		if testServer != nil {
			testServer.Stop()
		}
		panic("failed to create admin client: " + err.Error())
	}

	// Create non-admin client (only if credentials are provided)
	if nonAdminAPIKeyID != "" && nonAdminAPIKeyHex != "" {
		nonAdminClient, err = client.NewClient(client.Config{
			BaseURL:       baseURL,
			APIKeyID:      nonAdminAPIKeyID,
			PrivateKeyHex: nonAdminAPIKeyHex,
			PollInterval:  pollInterval,
			PollTimeout:   pollTimeout,
		})
		if err != nil {
			if testServer != nil {
				testServer.Stop()
			}
			panic("failed to create non-admin client: " + err.Error())
		}
	}

	// Run tests
	code := m.Run()

	// Cleanup (only if we started the server)
	if testServer != nil {
		testServer.Stop()
	}

	os.Exit(code)
}

// =============================================================================
// Health Check Tests
// =============================================================================

func TestHealthCheck(t *testing.T) {
	health, err := adminClient.Health(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ok", health.Status)
}

// =============================================================================
// Authentication Tests
// =============================================================================

func TestAuth_AdminCanAccessAdminEndpoints(t *testing.T) {
	ctx := context.Background()

	// Admin should be able to list rules
	rules, err := adminClient.ListRules(ctx, nil)
	require.NoError(t, err)
	assert.NotNil(t, rules)
}

func TestAuth_NonAdminCannotAccessAdminEndpoints(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	// Non-admin should NOT be able to list rules
	_, err := nonAdminClient.ListRules(ctx, nil)
	require.Error(t, err)

	// Should be a 403 Forbidden error
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode)
}

func TestAuth_NonAdminCanSubmitSignRequest(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	// Non-admin should be able to submit sign requests
	// With Example 8 (signer_restriction) and Example 9 (sign_type_restriction), personal_sign is auto-approved
	address := common.HexToAddress(signerAddress)
	signer := nonAdminClient.GetSigner(address, chainID)

	sig, err := signer.PersonalSign("Hello from non-admin!")
	require.NoError(t, err)
	assert.Len(t, sig, 65)
}

func TestAuth_AdminCanSubmitSignRequest(t *testing.T) {
	// Admin should also be able to submit sign requests
	// With Example 8 (signer_restriction) and Example 9 (sign_type_restriction), personal_sign is auto-approved
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	sig, err := signer.PersonalSign("Hello from admin!")
	require.NoError(t, err)
	assert.Len(t, sig, 65)
}

// =============================================================================
// Sign Request Tests (using admin client for simplicity)
// =============================================================================

func TestSign_PersonalSign(t *testing.T) {
	// With Example 8 (signer_restriction) and Example 9 (sign_type_restriction),
	// personal_sign is auto-approved for the test signer
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	message := "Hello, Remote Signer!"
	sig, err := signer.PersonalSign(message)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	// Signature should be 65 bytes (r, s, v)
	assert.Len(t, sig, 65)

	// Verify the signer address
	assert.Equal(t, address, signer.GetAddress())
}

func TestSign_Hash(t *testing.T) {
	// With Example 8 (signer_restriction) and Example 9 (sign_type_restriction),
	// hash signing is auto-approved for the test signer
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	hash := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	sig, err := signer.SignHash(hash)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	// Signature should be 65 bytes
	assert.Len(t, sig, 65)
}

func TestSign_RawMessage(t *testing.T) {
	// With Example 8 (signer_restriction) and Example 9 (sign_type_restriction),
	// raw_message signing is auto-approved for the test signer
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	rawMessage := []byte("raw message bytes")
	sig, err := signer.SignRawMessage(rawMessage)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	assert.Len(t, sig, 65)
}

func TestSign_EIP191Message(t *testing.T) {
	// With Example 8 (signer_restriction) and Example 9 (sign_type_restriction),
	// eip191 signing is auto-approved for the test signer
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	rawMessage := "Hello, EIP-191!"
	eip191Message := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(rawMessage), rawMessage)

	sig, err := signer.SignEIP191Message(eip191Message)
	require.NoError(t, err)
	require.NotEmpty(t, sig)

	assert.Len(t, sig, 65)
}

func TestSign_TypedData(t *testing.T) {
	// With Example 8 (signer_restriction) and Example 9 (sign_type_restriction),
	// typed_data signing is auto-approved for the test signer
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

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
	signer := adminClient.GetSigner(address, chainID)

	// Send to treasury address (whitelisted in example config "Allow transfers to treasury" rule)
	// with value <= 1 ETH (within "Max 1 ETH transfer with address check" rule)
	to := common.HexToAddress(treasuryAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0,
		GasPrice: big.NewInt(20000000000), // 20 gwei
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(500000000000000000), // 0.5 ETH (within 1 ETH limit)
		Data:     nil,
	})

	chainIDBig := big.NewInt(1)
	signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err)
	require.NotNil(t, signedTx)

	// Verify the transaction was signed
	v, r, s := signedTx.RawSignatureValues()
	assert.NotNil(t, v)
	assert.NotNil(t, r)
	assert.NotNil(t, s)
}

func TestSign_EIP1559Transaction(t *testing.T) {
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	// Send to treasury address (whitelisted in example config)
	to := common.HexToAddress(treasuryAddress)
	chainIDBig := big.NewInt(1)

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainIDBig,
		Nonce:     1,
		GasTipCap: big.NewInt(1000000000),  // 1 gwei
		GasFeeCap: big.NewInt(20000000000), // 20 gwei
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(500000000000000000), // 0.5 ETH (within limit)
		Data:      nil,
	})

	signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err)
	require.NotNil(t, signedTx)

	// Verify signature exists
	v, r, s := signedTx.RawSignatureValues()
	assert.NotNil(t, v)
	assert.NotNil(t, r)
	assert.NotNil(t, s)
}

func TestSign_SignerNotFound(t *testing.T) {
	unknownAddress := common.HexToAddress("0x0000000000000000000000000000000000000001")
	signer := adminClient.GetSigner(unknownAddress, testChainID)

	_, err := signer.PersonalSign("test message")
	require.Error(t, err)
}

func TestSign_ContextCancellation(t *testing.T) {
	// Test context cancellation behavior
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := signer.PersonalSignWithContext(ctx, "test message")
	require.Error(t, err)
}

func TestSign_MultipleRequests(t *testing.T) {
	// With Example 8 (signer_restriction) and Example 9 (sign_type_restriction),
	// personal_sign is auto-approved for the test signer
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	// Sign multiple messages sequentially
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

func TestSign_DirectSignAPI(t *testing.T) {
	// With Example 8 (signer_restriction) and Example 9 (sign_type_restriction),
	// personal_sign is auto-approved for the test signer
	ctx := context.Background()

	// Test direct Sign API call
	resp, err := adminClient.Sign(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      client.SignTypePersonal,
		Payload:       []byte(`{"message":"Direct API test"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.Signature)
}

// TestApprovalGuard_PauseAndResume verifies that after N consecutive "rejected" outcomes
// (rule-blocked or manual approval), the guard pauses sign requests, and admin resume restores service.
// Triggers via blocklist: 3 transactions to burn address (blocked by config.e2e rule) → guard fires.
func TestApprovalGuard_PauseAndResume(t *testing.T) {
	if useExternalServer {
		t.Skip("approval guard e2e uses internal server with config.e2e.yaml (guard + blocklist rule)")
	}

	ctx := context.Background()

	// Transaction payload to burn address — blocked by "Block known malicious addresses" rule in config.e2e
	burnTxPayload := []byte(`{"transaction":{"to":"0x000000000000000000000000000000000000dEaD","value":"0","gas":21000,"gasPrice":"1000000000","txType":"legacy","nonce":0}}`)

	// 1) Submit 3 sign requests that are blocked by rule → each counts as rejection (client may return err when status=rejected)
	for i := 0; i < 3; i++ {
		resp, err := adminClient.Sign(ctx, &client.SignRequest{
			ChainID:       chainID,
			SignerAddress: signerAddress,
			SignType:      client.SignTypeTransaction,
			Payload:       burnTxPayload,
		})
		if err != nil {
			assert.Contains(t, err.Error(), "rejected", "request %d should be blocked by rule", i+1)
			assert.Contains(t, err.Error(), "blocked", "message should mention blocked")
		} else {
			require.NotNil(t, resp)
			assert.Equal(t, "rejected", resp.Status)
			assert.Contains(t, resp.Message, "blocked")
		}
	}

	// 2) Next sign request must be rejected (guard paused)
	_, err := adminClient.Sign(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      client.SignTypePersonal,
		Payload:       []byte(`{"message":"e2e after trigger"}`),
	})
	require.Error(t, err)
	// Client may wrap as "API error 500: ..."; server message contains "paused"
	assert.True(t, strings.Contains(err.Error(), "paused") || strings.Contains(err.Error(), "500"),
		"expected error to indicate pause or 500, got: %s", err.Error())

	// 3) Admin resume
	err = adminClient.ResumeApprovalGuard(ctx)
	require.NoError(t, err)

	// 4) Next request should succeed again (e.g. personal sign auto-approved by sign_type_restriction)
	resp, err := adminClient.Sign(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      client.SignTypePersonal,
		Payload:       []byte(`{"message":"e2e after resume"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "completed", resp.Status)
}

// =============================================================================
// Rule Management Tests (Admin Only)
// =============================================================================

func TestRule_AdminCanCreateRule(t *testing.T) {
	ctx := context.Background()

	rule := &client.CreateRuleRequest{
		Name:    "Test Rule - Address Whitelist",
		Type:    "evm_address_list",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"addresses": []string{
				"0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
				"0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
			},
		},
	}

	created, err := adminClient.CreateRule(ctx, rule)
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.Equal(t, rule.Name, created.Name)
	assert.Equal(t, rule.Type, created.Type)
	assert.True(t, created.Enabled)

	// Cleanup
	err = adminClient.DeleteRule(ctx, created.ID)
	require.NoError(t, err)
}

func TestRule_AdminCanListRules(t *testing.T) {
	ctx := context.Background()

	resp, err := adminClient.ListRules(ctx, nil)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	// Should have at least the auto-approve rule created by test server
	assert.GreaterOrEqual(t, len(resp.Rules), 1)
}

func TestRule_AdminCanGetRule(t *testing.T) {
	ctx := context.Background()

	// First create a rule
	createReq := &client.CreateRuleRequest{
		Name:    "Test Rule - Get",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "1000000000000000000", // 1 ETH
		},
	}

	created, err := adminClient.CreateRule(ctx, createReq)
	require.NoError(t, err)

	// Get the rule
	rule, err := adminClient.GetRule(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, rule.ID)
	assert.Equal(t, created.Name, rule.Name)

	// Cleanup
	err = adminClient.DeleteRule(ctx, created.ID)
	require.NoError(t, err)
}

func TestRule_AdminCanUpdateRule(t *testing.T) {
	ctx := context.Background()

	// First create a rule
	createReq := &client.CreateRuleRequest{
		Name:    "Test Rule - Update Original",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "1000000000000000000",
		},
	}

	created, err := adminClient.CreateRule(ctx, createReq)
	require.NoError(t, err)

	// Update the rule
	updateReq := &client.UpdateRuleRequest{
		Name:    "Test Rule - Update Modified",
		Enabled: false, // Disable it
	}

	updated, err := adminClient.UpdateRule(ctx, created.ID, updateReq)
	require.NoError(t, err)
	assert.Equal(t, "Test Rule - Update Modified", updated.Name)
	assert.False(t, updated.Enabled)

	// Cleanup
	err = adminClient.DeleteRule(ctx, created.ID)
	require.NoError(t, err)
}

func TestRule_AdminCanDeleteRule(t *testing.T) {
	ctx := context.Background()

	// First create a rule
	createReq := &client.CreateRuleRequest{
		Name:    "Test Rule - Delete",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "1000000000000000000",
		},
	}

	created, err := adminClient.CreateRule(ctx, createReq)
	require.NoError(t, err)

	// Delete the rule
	err = adminClient.DeleteRule(ctx, created.ID)
	require.NoError(t, err)

	// Verify it's deleted
	_, err = adminClient.GetRule(ctx, created.ID)
	require.Error(t, err)
}

func TestRule_AdminCanDisableRule(t *testing.T) {
	ctx := context.Background()

	// First create an enabled rule
	createReq := &client.CreateRuleRequest{
		Name:    "Test Rule - Disable",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "1000000000000000000",
		},
	}

	created, err := adminClient.CreateRule(ctx, createReq)
	require.NoError(t, err)
	assert.True(t, created.Enabled)

	// Disable the rule
	updateReq := &client.UpdateRuleRequest{
		Enabled: false,
	}
	updated, err := adminClient.UpdateRule(ctx, created.ID, updateReq)
	require.NoError(t, err)
	assert.False(t, updated.Enabled)

	// Re-enable the rule
	updateReq.Enabled = true
	updated, err = adminClient.UpdateRule(ctx, created.ID, updateReq)
	require.NoError(t, err)
	assert.True(t, updated.Enabled)

	// Cleanup
	err = adminClient.DeleteRule(ctx, created.ID)
	require.NoError(t, err)
}

func TestRule_NonAdminCannotCreateRule(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	rule := &client.CreateRuleRequest{
		Name:    "Test Rule - Non-Admin Create",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "1000000000000000000",
		},
	}

	_, err := nonAdminClient.CreateRule(ctx, rule)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.Equal(t, 403, apiErr.StatusCode)
}

func TestRule_NonAdminCannotUpdateRule(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	// First create a rule as admin
	createReq := &client.CreateRuleRequest{
		Name:    "Test Rule - Non-Admin Update",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "1000000000000000000",
		},
	}

	created, err := adminClient.CreateRule(ctx, createReq)
	require.NoError(t, err)

	// Try to update as non-admin
	updateReq := &client.UpdateRuleRequest{
		Name: "Modified by non-admin",
	}
	_, err = nonAdminClient.UpdateRule(ctx, created.ID, updateReq)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.Equal(t, 403, apiErr.StatusCode)

	// Cleanup
	err = adminClient.DeleteRule(ctx, created.ID)
	require.NoError(t, err)
}

func TestRule_NonAdminCannotDeleteRule(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	// First create a rule as admin
	createReq := &client.CreateRuleRequest{
		Name:    "Test Rule - Non-Admin Delete",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "1000000000000000000",
		},
	}

	created, err := adminClient.CreateRule(ctx, createReq)
	require.NoError(t, err)

	// Try to delete as non-admin
	err = nonAdminClient.DeleteRule(ctx, created.ID)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.Equal(t, 403, apiErr.StatusCode)

	// Cleanup
	err = adminClient.DeleteRule(ctx, created.ID)
	require.NoError(t, err)
}

func TestRule_NonAdminCannotListRules(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	_, err := nonAdminClient.ListRules(ctx, nil)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok)
	assert.Equal(t, 403, apiErr.StatusCode)
}

// =============================================================================
// Rule Evaluation Tests (Sign requests with rules)
// =============================================================================

func TestRule_TransactionToTreasuryPasses(t *testing.T) {
	// Test that transactions to treasury address (whitelisted) pass
	// This verifies the "Allow transfers to treasury" rule in example config
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	to := common.HexToAddress(treasuryAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    100,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(100000000000000000), // 0.1 ETH (within limit)
		Data:     nil,
	})

	chainIDBig := big.NewInt(1)
	signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err, "Transaction to treasury address should pass whitelist rule")
	require.NotNil(t, signedTx)

	v, r, s := signedTx.RawSignatureValues()
	assert.NotNil(t, v)
	assert.NotNil(t, r)
	assert.NotNil(t, s)
}

func TestRule_TransactionToBurnAddressBlocked(t *testing.T) {
	// Test that transactions to burn address (0xdead) are blocked
	// This verifies the "Block known malicious addresses" blocklist rule in example config
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	to := common.HexToAddress(burnAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    101,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(100000000000000000), // 0.1 ETH
		Data:     nil,
	})

	chainIDBig := big.NewInt(1)
	_, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	// Should be blocked by the blocklist rule
	require.Error(t, err, "Transaction to burn address should be blocked by blocklist rule")
}

func TestRule_SignRequestMatchesWhitelistRule(t *testing.T) {
	// With Example 8 (signer_restriction) and Example 9 (sign_type_restriction),
	// personal_sign is auto-approved for the test signer
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	sig, err := signer.PersonalSign("This should match the whitelist rule")
	require.NoError(t, err)
	assert.Len(t, sig, 65)
}

func TestRule_ValueLimitRuleBlocks(t *testing.T) {
	ctx := context.Background()

	// Create a value limit rule that blocks high-value transactions
	createReq := &client.CreateRuleRequest{
		Name:    "Test Value Limit - Block High Value",
		Type:    "evm_value_limit",
		Mode:    "blocklist", // Blocklist mode - blocks if value exceeds limit
		Enabled: true,
		Config: map[string]interface{}{
			"max_value": "100000000000000000", // 0.1 ETH - block if value > 0.1 ETH
		},
	}

	created, err := adminClient.CreateRule(ctx, createReq)
	require.NoError(t, err)

	// Try to sign a transaction with value > 0.1 ETH to treasury (treasury is whitelisted)
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	to := common.HexToAddress(treasuryAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    10,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(1000000000000000000), // 1 ETH - exceeds our test blocklist limit
		Data:     nil,
	})

	chainIDBig := big.NewInt(1)
	_, err = signer.SignTransactionWithChainID(tx, chainIDBig)
	// The blocklist rule we created should block this (value > 0.1 ETH)
	// Note: blocklist rules are evaluated before whitelist rules
	require.Error(t, err, "Transaction exceeding value limit should be blocked")

	// Cleanup
	err = adminClient.DeleteRule(ctx, created.ID)
	require.NoError(t, err)
}

func TestRule_SignerRestrictionAllowsTestSigner(t *testing.T) {
	// Test that signer_restriction allows requests from whitelisted signer
	// This verifies the "Allow hot wallet signer" rule (Example 8)
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	// Personal sign should be allowed because:
	// - Internal mode: e2e-test-rule (signer_restriction) allows test signer
	// - External mode: "Allow hot wallet signer" rule allows test signer
	sig, err := signer.PersonalSign("Test signer restriction allows test signer")
	require.NoError(t, err, "Signer restriction should allow test signer")
	assert.Len(t, sig, 65)
}

func TestRule_SignerRestrictionBlocksUnknownSigner(t *testing.T) {
	// Test that requests from unknown signer are blocked/need approval
	// Note: This test uses an unknown signer address that doesn't exist
	unknownSigner := common.HexToAddress("0x0000000000000000000000000000000000000001")
	signer := adminClient.GetSigner(unknownSigner, chainID)

	// This should fail because the signer doesn't exist in the registry
	_, err := signer.PersonalSign("Test signer restriction blocks unknown signer")
	require.Error(t, err, "Unknown signer should be rejected")
}

func TestRule_SignTypeRestrictionAllowsPersonalSign(t *testing.T) {
	// Test that sign_type_restriction allows personal_sign
	// This verifies the "Allow personal and typed_data signing" rule (Example 9)
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	// Personal sign should be allowed because:
	// - Internal mode: e2e-sign-type-rule allows "personal" type
	// - External mode: "Allow personal and typed_data signing" allows "personal"
	sig, err := signer.PersonalSign("Test sign type restriction allows personal_sign")
	require.NoError(t, err, "Sign type restriction should allow personal_sign")
	assert.Len(t, sig, 65)
}

func TestRule_SignTypeRestrictionAllowsTransaction(t *testing.T) {
	// Test that sign_type_restriction allows transaction signing
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	to := common.HexToAddress(treasuryAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    102,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(100000000000000000), // 0.1 ETH
		Data:     nil,
	})

	chainIDBig := big.NewInt(1)
	signedTx, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err, "Sign type restriction should allow transaction signing")
	require.NotNil(t, signedTx)
}

func TestRule_SignTypeRestrictionAllowsHashSign(t *testing.T) {
	// Test that sign_type_restriction allows hash signing
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	hash := common.HexToHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	sig, err := signer.SignHash(hash)
	require.NoError(t, err, "Sign type restriction should allow hash signing")
	assert.Len(t, sig, 65)
}

func TestRule_CreateSignerRestrictionViaAPI(t *testing.T) {
	// Test creating a signer_restriction rule via API
	ctx := context.Background()

	// Create a signer restriction rule
	createReq := &client.CreateRuleRequest{
		Name:    "Test Signer Restriction via API",
		Type:    "signer_restriction",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"allowed_signers": []string{signerAddress},
		},
	}

	created, err := adminClient.CreateRule(ctx, createReq)
	require.NoError(t, err)
	assert.Equal(t, "signer_restriction", string(created.Type))
	assert.Equal(t, "whitelist", string(created.Mode))

	// Cleanup
	err = adminClient.DeleteRule(ctx, created.ID)
	require.NoError(t, err)
}

func TestRule_CreateSignTypeRestrictionViaAPI(t *testing.T) {
	// Test creating a sign_type_restriction rule via API
	ctx := context.Background()

	// Create a sign type restriction rule
	createReq := &client.CreateRuleRequest{
		Name:    "Test Sign Type Restriction via API",
		Type:    "sign_type_restriction",
		Mode:    "whitelist",
		Enabled: true,
		Config: map[string]interface{}{
			"allowed_sign_types": []string{"personal", "transaction"},
		},
	}

	created, err := adminClient.CreateRule(ctx, createReq)
	require.NoError(t, err)
	assert.Equal(t, "sign_type_restriction", string(created.Type))
	assert.Equal(t, "whitelist", string(created.Mode))

	// Cleanup
	err = adminClient.DeleteRule(ctx, created.ID)
	require.NoError(t, err)
}

func TestRule_SignTypeRestrictionBlocksDisallowedType(t *testing.T) {
	ctx := context.Background()

	// Create a sign type restriction rule that ONLY allows transaction
	// This simulates the "Transaction signing only" rule (Example 10)
	createReq := &client.CreateRuleRequest{
		Name:    "Test Sign Type Blocklist - Only Transaction",
		Type:    "sign_type_restriction",
		Mode:    "blocklist", // Blocklist mode: if sign type NOT in list, block
		Enabled: true,
		Config: map[string]interface{}{
			"allowed_sign_types": []string{"personal"}, // Block personal sign
		},
	}

	created, err := adminClient.CreateRule(ctx, createReq)
	require.NoError(t, err)

	// Cleanup with defer to ensure rule is deleted even if test fails
	defer func() {
		_ = adminClient.DeleteRule(ctx, created.ID)
	}()

	// Personal sign should be blocked by this blocklist rule
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	_, err = signer.PersonalSign("This should be blocked")
	// Should be blocked by blocklist rule
	require.Error(t, err, "Personal sign should be blocked by sign_type_restriction blocklist")
}

// =============================================================================
// Request List Tests
// =============================================================================

func TestRequest_ListRequests(t *testing.T) {
	ctx := context.Background()

	// First make a sign request (transaction to treasury to match whitelist)
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	to := common.HexToAddress(treasuryAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    200,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(100000000000000000), // 0.1 ETH
		Data:     nil,
	})

	chainIDBig := big.NewInt(1)
	_, err := signer.SignTransactionWithChainID(tx, chainIDBig)
	require.NoError(t, err)

	// List requests
	requests, err := adminClient.ListRequests(ctx, &client.ListRequestsFilter{
		Limit: 10,
	})
	require.NoError(t, err)
	assert.NotNil(t, requests)
	assert.GreaterOrEqual(t, len(requests.Requests), 1)
}

func TestRequest_GetRequest(t *testing.T) {
	// With Example 8 (signer_restriction) and Example 9 (sign_type_restriction),
	// personal_sign is auto-approved for the test signer
	ctx := context.Background()

	// Submit a sign request and get its ID
	resp, err := adminClient.Sign(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      client.SignTypePersonal,
		Payload:       []byte(`{"message":"Get request test"}`),
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.RequestID)

	// Get the request status
	status, err := adminClient.GetRequest(ctx, resp.RequestID)
	require.NoError(t, err)
	assert.Equal(t, resp.RequestID, status.ID)
	assert.Equal(t, "completed", status.Status)
}

// =============================================================================
// Audit Tests
// =============================================================================

func TestAudit_ListAuditRecords(t *testing.T) {
	ctx := context.Background()

	// Make some requests first (transaction to treasury to match whitelist)
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	to := common.HexToAddress(treasuryAddress)
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    201,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &to,
		Value:    big.NewInt(100000000000000000), // 0.1 ETH
		Data:     nil,
	})

	chainIDBig := big.NewInt(1)
	_, _ = signer.SignTransactionWithChainID(tx, chainIDBig)

	// List audit records
	resp, err := adminClient.ListAuditRecords(ctx, &client.ListAuditFilter{
		Limit: 10,
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// =============================================================================
// Pagination Tests
// =============================================================================

func TestPagination_RequestsCursorBased(t *testing.T) {
	ctx := context.Background()

	// Create multiple sign requests to test pagination
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	// Create at least 5 requests for pagination testing
	for i := 0; i < 5; i++ {
		msg := fmt.Sprintf("Pagination test message %d", i)
		_, err := signer.PersonalSign(msg)
		require.NoError(t, err)
		// Small delay to ensure different timestamps
		time.Sleep(10 * time.Millisecond)
	}

	// Test pagination with small limit (2 items per page)
	limit := 2

	// Fetch first page
	page1, err := adminClient.ListRequests(ctx, &client.ListRequestsFilter{
		Limit: limit,
	})
	require.NoError(t, err)
	require.NotNil(t, page1)
	assert.LessOrEqual(t, len(page1.Requests), limit)

	// If there are more items, test cursor-based pagination
	if page1.HasMore {
		assert.NotNil(t, page1.NextCursor, "NextCursor should be set when HasMore is true")
		assert.NotNil(t, page1.NextCursorID, "NextCursorID should be set when HasMore is true")

		// Fetch second page using cursor
		page2, err := adminClient.ListRequests(ctx, &client.ListRequestsFilter{
			Limit:    limit,
			Cursor:   page1.NextCursor,
			CursorID: page1.NextCursorID,
		})
		require.NoError(t, err)
		require.NotNil(t, page2)

		// Ensure page 2 has different items than page 1
		if len(page1.Requests) > 0 && len(page2.Requests) > 0 {
			assert.NotEqual(t, page1.Requests[0].ID, page2.Requests[0].ID,
				"Page 2 should have different items than page 1")
		}

		// If there's a third page, verify continued pagination
		if page2.HasMore && page2.NextCursor != nil {
			page3, err := adminClient.ListRequests(ctx, &client.ListRequestsFilter{
				Limit:    limit,
				Cursor:   page2.NextCursor,
				CursorID: page2.NextCursorID,
			})
			require.NoError(t, err)
			require.NotNil(t, page3)

			// Ensure page 3 has different items
			if len(page2.Requests) > 0 && len(page3.Requests) > 0 {
				assert.NotEqual(t, page2.Requests[0].ID, page3.Requests[0].ID,
					"Page 3 should have different items than page 2")
			}
		}
	}
}

func TestPagination_RequestsWithStatusFilter(t *testing.T) {
	ctx := context.Background()

	// Test pagination with status filter
	limit := 5
	page1, err := adminClient.ListRequests(ctx, &client.ListRequestsFilter{
		Status: "completed",
		Limit:  limit,
	})
	require.NoError(t, err)
	require.NotNil(t, page1)

	// All returned requests should have "completed" status
	for _, req := range page1.Requests {
		assert.Equal(t, "completed", req.Status)
	}

	// If there are more pages, verify filter is maintained
	if page1.HasMore && page1.NextCursor != nil {
		page2, err := adminClient.ListRequests(ctx, &client.ListRequestsFilter{
			Status:   "completed",
			Limit:    limit,
			Cursor:   page1.NextCursor,
			CursorID: page1.NextCursorID,
		})
		require.NoError(t, err)

		// All page 2 requests should also be "completed"
		for _, req := range page2.Requests {
			assert.Equal(t, "completed", req.Status)
		}
	}
}

func TestPagination_AuditCursorBased(t *testing.T) {
	ctx := context.Background()

	// Create some sign requests to generate audit records
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("Audit pagination test %d", i)
		_, _ = signer.PersonalSign(msg)
		time.Sleep(10 * time.Millisecond)
	}

	// Test pagination with small limit
	limit := 2

	// Fetch first page
	page1, err := adminClient.ListAuditRecords(ctx, &client.ListAuditFilter{
		Limit: limit,
	})
	require.NoError(t, err)
	require.NotNil(t, page1)
	assert.LessOrEqual(t, len(page1.Records), limit)

	// If there are more items, test cursor-based pagination
	if page1.HasMore {
		assert.NotNil(t, page1.NextCursor, "NextCursor should be set when HasMore is true")
		assert.NotNil(t, page1.NextCursorID, "NextCursorID should be set when HasMore is true")

		// Fetch second page using cursor
		page2, err := adminClient.ListAuditRecords(ctx, &client.ListAuditFilter{
			Limit:    limit,
			Cursor:   page1.NextCursor,
			CursorID: page1.NextCursorID,
		})
		require.NoError(t, err)
		require.NotNil(t, page2)

		// Ensure page 2 has different items than page 1
		if len(page1.Records) > 0 && len(page2.Records) > 0 {
			assert.NotEqual(t, page1.Records[0].ID, page2.Records[0].ID,
				"Page 2 should have different audit records than page 1")
		}
	}
}

func TestPagination_AuditWithEventTypeFilter(t *testing.T) {
	ctx := context.Background()

	// Test pagination with event type filter
	limit := 5
	page1, err := adminClient.ListAuditRecords(ctx, &client.ListAuditFilter{
		EventType: "sign_complete",
		Limit:     limit,
	})
	require.NoError(t, err)
	require.NotNil(t, page1)

	// All returned records should have the filtered event type
	for _, record := range page1.Records {
		assert.Equal(t, "sign_complete", record.EventType)
	}
}

func TestPagination_TotalCountConsistency(t *testing.T) {
	ctx := context.Background()

	// Get all requests in one large page
	largePage, err := adminClient.ListRequests(ctx, &client.ListRequestsFilter{
		Limit: 100,
	})
	require.NoError(t, err)

	// Get total from small page
	smallPage, err := adminClient.ListRequests(ctx, &client.ListRequestsFilter{
		Limit: 2,
	})
	require.NoError(t, err)

	// Total should be the same regardless of page size
	assert.Equal(t, largePage.Total, smallPage.Total,
		"Total count should be consistent across different page sizes")
}

func TestPagination_EmptyPage(t *testing.T) {
	ctx := context.Background()

	// Test with a filter that returns no results.
	// Use a valid signer_address that doesn't match any request.
	page, err := adminClient.ListRequests(ctx, &client.ListRequestsFilter{
		SignerAddress: "0x0000000000000000000000000000000000000000",
		Limit:         10,
	})
	require.NoError(t, err)
	require.NotNil(t, page)

	// Should have no results but not error
	assert.Empty(t, page.Requests)
	assert.False(t, page.HasMore)
	assert.Nil(t, page.NextCursor)
	assert.Nil(t, page.NextCursorID)
}

func TestPagination_CursorURLEncoding(t *testing.T) {
	ctx := context.Background()

	// Create requests to ensure we have data
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)

	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("URL encoding test %d", i)
		_, _ = signer.PersonalSign(msg)
		time.Sleep(10 * time.Millisecond)
	}

	// Get first page
	page1, err := adminClient.ListRequests(ctx, &client.ListRequestsFilter{
		Limit: 1,
	})
	require.NoError(t, err)

	if page1.HasMore && page1.NextCursor != nil {
		// The cursor value typically contains timestamp with ':' characters
		// This tests that URL encoding is working correctly
		cursor := *page1.NextCursor
		t.Logf("Cursor value: %s", cursor)

		// Using the cursor should work (URL encoding is handled by client)
		page2, err := adminClient.ListRequests(ctx, &client.ListRequestsFilter{
			Limit:    1,
			Cursor:   page1.NextCursor,
			CursorID: page1.NextCursorID,
		})
		require.NoError(t, err, "Cursor with special characters should work when URL-encoded")
		require.NotNil(t, page2)

		// Page 2 should have different data
		if len(page1.Requests) > 0 && len(page2.Requests) > 0 {
			assert.NotEqual(t, page1.Requests[0].ID, page2.Requests[0].ID,
				"URL-encoded cursor should fetch different page")
		}
	}
}

// =============================================================================
// Signer Management Tests
// =============================================================================

func TestSigner_ListSigners(t *testing.T) {
	ctx := context.Background()

	// List signers (should include the test signer)
	resp, err := adminClient.ListSigners(ctx, &client.ListSignersFilter{
		Limit: 10,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.GreaterOrEqual(t, resp.Total, 1, "Should have at least the test signer")

	// Verify the test signer is in the list
	found := false
	for _, signer := range resp.Signers {
		if signer.Address == signerAddress {
			found = true
			assert.True(t, signer.Enabled, "Test signer should be enabled")
			assert.Equal(t, "private_key", signer.Type)
			break
		}
	}
	assert.True(t, found, "Test signer should be in the list")
}

func TestSigner_ListSignersWithTypeFilter(t *testing.T) {
	ctx := context.Background()

	// Filter by private_key type
	resp, err := adminClient.ListSigners(ctx, &client.ListSignersFilter{
		Type:  "private_key",
		Limit: 10,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// All returned signers should be private_key type
	for _, signer := range resp.Signers {
		assert.Equal(t, "private_key", signer.Type)
	}

	// Filter by keystore type (should be empty initially)
	resp, err = adminClient.ListSigners(ctx, &client.ListSignersFilter{
		Type:  "keystore",
		Limit: 10,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	// May or may not have keystore signers depending on test order
}

func TestSigner_ListSignersPagination(t *testing.T) {
	ctx := context.Background()

	// Test pagination with small limit
	resp, err := adminClient.ListSigners(ctx, &client.ListSignersFilter{
		Limit: 1,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.LessOrEqual(t, len(resp.Signers), 1)

	// If there are more signers, HasMore should be true
	if resp.Total > 1 {
		assert.True(t, resp.HasMore, "HasMore should be true when more signers exist")

		// Get next page
		resp2, err := adminClient.ListSigners(ctx, &client.ListSignersFilter{
			Offset: 1,
			Limit:  1,
		})
		require.NoError(t, err)
		require.NotNil(t, resp2)

		// Should have different signers
		if len(resp.Signers) > 0 && len(resp2.Signers) > 0 {
			assert.NotEqual(t, resp.Signers[0].Address, resp2.Signers[0].Address,
				"Page 2 should have different signers than page 1")
		}
	}
}

func TestSigner_CreateKeystoreSigner(t *testing.T) {
	if useExternalServer {
		t.Skip("Skipping: keystore creation test not supported with external server")
	}

	ctx := context.Background()

	// Create a new keystore signer
	req := &client.CreateSignerRequest{
		Type: "keystore",
		Keystore: &client.CreateKeystoreParams{
			Password: "test-password-e2e-123",
		},
	}

	signer, err := adminClient.CreateSigner(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, signer)

	assert.NotEmpty(t, signer.Address, "Created signer should have an address")
	assert.Equal(t, "keystore", signer.Type)
	assert.True(t, signer.Enabled, "Created signer should be enabled")

	// Verify the new signer appears in the list
	resp, err := adminClient.ListSigners(ctx, &client.ListSignersFilter{
		Limit: 100,
	})
	require.NoError(t, err)

	found := false
	for _, s := range resp.Signers {
		if s.Address == signer.Address {
			found = true
			assert.Equal(t, "keystore", s.Type)
			break
		}
	}
	assert.True(t, found, "Newly created signer should appear in the list")
}

func TestSigner_CreateSignerValidationErrors(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		req         *client.CreateSignerRequest
		expectError bool
	}{
		{
			name:        "missing type",
			req:         &client.CreateSignerRequest{},
			expectError: true,
		},
		{
			name: "missing keystore params",
			req: &client.CreateSignerRequest{
				Type: "keystore",
			},
			expectError: true,
		},
		{
			name: "empty password",
			req: &client.CreateSignerRequest{
				Type: "keystore",
				Keystore: &client.CreateKeystoreParams{
					Password: "",
				},
			},
			expectError: true,
		},
		{
			name: "unsupported type",
			req: &client.CreateSignerRequest{
				Type: "aws_kms",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := adminClient.CreateSigner(ctx, tt.req)
			if tt.expectError {
				require.Error(t, err, "Expected error for %s", tt.name)
			} else {
				require.NoError(t, err, "Expected no error for %s", tt.name)
			}
		})
	}
}

func TestSigner_NonAdminCanListSigners(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	// Non-admin should be able to list signers (GET is public)
	resp, err := nonAdminClient.ListSigners(ctx, &client.ListSignersFilter{
		Limit: 10,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.GreaterOrEqual(t, resp.Total, 1)
}

func TestSigner_NonAdminCannotCreateSigner(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	// Non-admin should NOT be able to create signers
	req := &client.CreateSignerRequest{
		Type: "keystore",
		Keystore: &client.CreateKeystoreParams{
			Password: "test-password",
		},
	}

	_, err := nonAdminClient.CreateSigner(ctx, req)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode, "Non-admin should get 403 Forbidden")
}

// =============================================================================
// Template Management Tests
// =============================================================================

func TestTemplate_AdminCanCreateTemplate(t *testing.T) {
	ctx := context.Background()

	req := &client.CreateTemplateRequest{
		Name:        "Test Template - Address Whitelist",
		Description: "Template for whitelisting addresses with variables",
		Type:        "evm_address_list",
		Mode:        "whitelist",
		Variables: []client.TemplateVariable{
			{
				Name:        "allowed_address",
				Type:        "address",
				Description: "The address to whitelist",
				Required:    true,
			},
		},
		Config: map[string]interface{}{
			"addresses": []string{"${allowed_address}"},
		},
		Enabled: true,
	}

	created, err := adminClient.CreateTemplate(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.NotEmpty(t, created.ID)
	assert.Equal(t, req.Name, created.Name)
	assert.Equal(t, req.Description, created.Description)
	assert.Equal(t, req.Type, created.Type)
	assert.Equal(t, req.Mode, created.Mode)
	assert.True(t, created.Enabled)

	// Cleanup
	err = adminClient.DeleteTemplate(ctx, created.ID)
	require.NoError(t, err)
}

// TestTemplate_ConfigLoadedTemplatesAndInstanceRules verifies that the server loads
// templates from config and expands instance rules at startup (same flow as main.go).
// config.e2e.yaml defines one file template (E2E Minimal Template) and one instance
// rule; the expanded rule "E2E From Template Instance" must appear in the rules list.
func TestTemplate_ConfigLoadedTemplatesAndInstanceRules(t *testing.T) {
	ctx := context.Background()

	resp, err := adminClient.ListRules(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	var found bool
	for _, r := range resp.Rules {
		if r.Name == "E2E From Template Instance" {
			found = true
			assert.Equal(t, "evm_address_whitelist", string(r.Type))
			assert.True(t, r.Enabled)
			break
		}
	}
	assert.True(t, found, "rule 'E2E From Template Instance' (from config template instance) should be loaded at startup")
}

func TestTemplate_AdminCanListTemplates(t *testing.T) {
	ctx := context.Background()

	// Get initial count
	initialResp, err := adminClient.ListTemplates(ctx, nil)
	require.NoError(t, err)
	initialCount := initialResp.Total

	// Create a template
	req := &client.CreateTemplateRequest{
		Name:    "Test Template - List",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled: true,
	}

	created, err := adminClient.CreateTemplate(ctx, req)
	require.NoError(t, err)

	// List again and verify count increased
	resp, err := adminClient.ListTemplates(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, initialCount+1, resp.Total)

	// Cleanup
	err = adminClient.DeleteTemplate(ctx, created.ID)
	require.NoError(t, err)
}

func TestTemplate_AdminCanGetTemplate(t *testing.T) {
	ctx := context.Background()

	// Create a template
	req := &client.CreateTemplateRequest{
		Name:        "Test Template - Get",
		Description: "A template for get testing",
		Type:        "evm_value_limit",
		Mode:        "whitelist",
		Config:      map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled:     true,
	}

	created, err := adminClient.CreateTemplate(ctx, req)
	require.NoError(t, err)

	// Get the template by ID
	tmpl, err := adminClient.GetTemplate(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, tmpl.ID)
	assert.Equal(t, created.Name, tmpl.Name)
	assert.Equal(t, created.Description, tmpl.Description)
	assert.Equal(t, created.Type, tmpl.Type)
	assert.Equal(t, created.Mode, tmpl.Mode)
	assert.Equal(t, created.Enabled, tmpl.Enabled)

	// Cleanup
	err = adminClient.DeleteTemplate(ctx, created.ID)
	require.NoError(t, err)
}

func TestTemplate_AdminCanUpdateTemplate(t *testing.T) {
	ctx := context.Background()

	// Create a template
	req := &client.CreateTemplateRequest{
		Name:        "Test Template - Update Original",
		Description: "Original description",
		Type:        "evm_value_limit",
		Mode:        "whitelist",
		Config:      map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled:     true,
	}

	created, err := adminClient.CreateTemplate(ctx, req)
	require.NoError(t, err)

	// Update the template
	updateReq := &client.UpdateTemplateRequest{
		Name:        "Test Template - Update Modified",
		Description: "Modified description",
	}

	updated, err := adminClient.UpdateTemplate(ctx, created.ID, updateReq)
	require.NoError(t, err)
	assert.Equal(t, "Test Template - Update Modified", updated.Name)
	assert.Equal(t, "Modified description", updated.Description)

	// Cleanup
	err = adminClient.DeleteTemplate(ctx, created.ID)
	require.NoError(t, err)
}

func TestTemplate_AdminCanDeleteTemplate(t *testing.T) {
	ctx := context.Background()

	// Create a template
	req := &client.CreateTemplateRequest{
		Name:    "Test Template - Delete",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled: true,
	}

	created, err := adminClient.CreateTemplate(ctx, req)
	require.NoError(t, err)

	// Delete the template
	err = adminClient.DeleteTemplate(ctx, created.ID)
	require.NoError(t, err)

	// Verify it's deleted
	_, err = adminClient.GetTemplate(ctx, created.ID)
	require.Error(t, err)
}

func TestTemplate_AdminCanInstantiateTemplate(t *testing.T) {
	ctx := context.Background()

	// Create a template with a variable
	createReq := &client.CreateTemplateRequest{
		Name:        "Test Template - Instantiate",
		Description: "Address whitelist template for instantiation",
		Type:        "evm_address_list",
		Mode:        "whitelist",
		Variables: []client.TemplateVariable{
			{
				Name:        "allowed_address",
				Type:        "address",
				Description: "The address to whitelist",
				Required:    true,
			},
		},
		Config: map[string]interface{}{
			"addresses": []string{"${allowed_address}"},
		},
		Enabled: true,
	}

	created, err := adminClient.CreateTemplate(ctx, createReq)
	require.NoError(t, err)

	// Instantiate the template with concrete variable values
	instReq := &client.InstantiateTemplateRequest{
		Variables: map[string]string{
			"allowed_address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		},
	}

	instResp, err := adminClient.InstantiateTemplate(ctx, created.ID, instReq)
	require.NoError(t, err)
	require.NotNil(t, instResp)
	assert.NotNil(t, instResp.Rule, "Instantiate response should contain a rule")

	// Cleanup: delete template
	err = adminClient.DeleteTemplate(ctx, created.ID)
	require.NoError(t, err)
}

// TestTemplate_InstanceWithBudget_CreateAndSign verifies that an instance with budget
// can be created and that one matching sign request succeeds (budget is deducted).
// Full budget-exhaustion behavior is covered by unit tests (whitelist + BudgetChecker).
func TestTemplate_InstanceWithBudget_CreateAndSign(t *testing.T) {
	ctx := context.Background()

	createReq := &client.CreateTemplateRequest{
		Name:        "E2E Budget Template",
		Description: "Template with budget metering for e2e",
		Type:        "signer_restriction",
		Mode:        "whitelist",
		Variables: []client.TemplateVariable{
			{Name: "allowed_signer", Type: "address", Description: "Allowed signer", Required: true},
		},
		Config: map[string]interface{}{
			"allowed_signers": []string{"${allowed_signer}"},
		},
		BudgetMetering: map[string]interface{}{
			"method": "count_only",
			"unit":   "count",
		},
		Enabled: true,
	}

	created, err := adminClient.CreateTemplate(ctx, createReq)
	require.NoError(t, err)
	require.NotNil(t, created)
	defer func() { _ = adminClient.DeleteTemplate(ctx, created.ID) }()

	instReq := &client.InstantiateTemplateRequest{
		Variables: map[string]string{
			"allowed_signer": signerAddress,
		},
		Budget: &client.BudgetConfig{
			MaxTotal:   "10",
			MaxPerTx:   "1",
			MaxTxCount: 5,
			AlertPct:   80,
		},
	}

	instResp, err := adminClient.InstantiateTemplate(ctx, created.ID, instReq)
	require.NoError(t, err)
	require.NotNil(t, instResp)
	require.NotNil(t, instResp.Rule, "instantiate response should contain rule")
	require.NotNil(t, instResp.Budget, "instantiate response should contain budget when budget requested")

	// One matching sign request should succeed (budget deducted)
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)
	_, err = signer.PersonalSign("E2E budget instance sign")
	require.NoError(t, err, "first sign with budget instance should succeed")

	// Revoke instance so config is clean for other tests
	var ruleData struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(instResp.Rule, &ruleData))
	revokeResp, err := adminClient.RevokeInstance(ctx, ruleData.ID)
	require.NoError(t, err)
	require.Equal(t, "revoked", revokeResp.Status)
}

func TestTemplate_AdminCanRevokeInstance(t *testing.T) {
	ctx := context.Background()

	// Create a template with a variable
	createReq := &client.CreateTemplateRequest{
		Name:        "Test Template - Revoke Instance",
		Description: "Template for revoke testing",
		Type:        "evm_address_list",
		Mode:        "whitelist",
		Variables: []client.TemplateVariable{
			{
				Name:        "allowed_address",
				Type:        "address",
				Description: "The address to whitelist",
				Required:    true,
			},
		},
		Config: map[string]interface{}{
			"addresses": []string{"${allowed_address}"},
		},
		Enabled: true,
	}

	created, err := adminClient.CreateTemplate(ctx, createReq)
	require.NoError(t, err)

	// Instantiate the template
	instReq := &client.InstantiateTemplateRequest{
		Variables: map[string]string{
			"allowed_address": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
		},
	}

	instResp, err := adminClient.InstantiateTemplate(ctx, created.ID, instReq)
	require.NoError(t, err)
	require.NotNil(t, instResp)

	// Extract rule ID from the instantiate response
	var ruleData struct {
		ID string `json:"id"`
	}
	err = json.Unmarshal(instResp.Rule, &ruleData)
	require.NoError(t, err)
	require.NotEmpty(t, ruleData.ID)

	// Revoke the instance
	revokeResp, err := adminClient.RevokeInstance(ctx, ruleData.ID)
	require.NoError(t, err)
	require.NotNil(t, revokeResp)
	assert.Equal(t, "revoked", revokeResp.Status)
	assert.Equal(t, ruleData.ID, revokeResp.RuleID)

	// Cleanup: delete template
	err = adminClient.DeleteTemplate(ctx, created.ID)
	require.NoError(t, err)
}

func TestTemplate_NonAdminCannotCreateTemplate(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	req := &client.CreateTemplateRequest{
		Name:    "Test Template - Non-Admin Create",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled: true,
	}

	_, err := nonAdminClient.CreateTemplate(ctx, req)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode)
}

func TestTemplate_NonAdminCannotListTemplates(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	_, err := nonAdminClient.ListTemplates(ctx, nil)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode)
}

func TestTemplate_NonAdminCannotDeleteTemplate(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	// Create a template as admin
	createReq := &client.CreateTemplateRequest{
		Name:    "Test Template - Non-Admin Delete",
		Type:    "evm_value_limit",
		Mode:    "whitelist",
		Config:  map[string]interface{}{"max_value": "1000000000000000000"},
		Enabled: true,
	}

	created, err := adminClient.CreateTemplate(ctx, createReq)
	require.NoError(t, err)

	// Try to delete as non-admin
	err = nonAdminClient.DeleteTemplate(ctx, created.ID)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode)

	// Cleanup as admin
	err = adminClient.DeleteTemplate(ctx, created.ID)
	require.NoError(t, err)
}

// =============================================================================
// Helper Functions
// =============================================================================

// isHexKey determines if a key string is hex-encoded (vs base64)
func isHexKey(key string) bool {
	// Hex private key should be 128 characters (64 bytes)
	if len(key) == 128 {
		for _, c := range key {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
		return true
	}

	// Otherwise, try to decode as base64 to see if it's valid
	_, err := base64.StdEncoding.DecodeString(key)
	return err != nil // If base64 decode fails, assume hex
}

// convertPrivateKeyToHex converts a private key from hex or base64 to hex format
func convertPrivateKeyToHex(key string) (string, error) {
	if isHexKey(key) {
		return key, nil
	}

	// Try to decode as base64
	derBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 key: %w", err)
	}

	// Ed25519 DER private key is 48 bytes: 16-byte header + 32-byte key
	// Extract the last 32 bytes (the actual private key seed)
	if len(derBytes) < 32 {
		return "", fmt.Errorf("invalid key length: got %d bytes, need at least 32", len(derBytes))
	}

	// For Ed25519, the private key is 64 bytes (seed + public key)
	// The DER format contains the 32-byte seed, we need to expand it
	var privateKey ed25519.PrivateKey
	if len(derBytes) >= 48 {
		// PKCS#8 DER format: extract seed from header
		seed := derBytes[len(derBytes)-32:]
		privateKey = ed25519.NewKeyFromSeed(seed)
	} else if len(derBytes) == 32 {
		// Raw 32-byte seed
		privateKey = ed25519.NewKeyFromSeed(derBytes)
	} else {
		return "", fmt.Errorf("unexpected key format: %d bytes", len(derBytes))
	}

	return hex.EncodeToString(privateKey), nil
}

// =============================================================================
// JavaScript Client E2E Tests
// =============================================================================

// TestJavaScriptClientE2E runs the JavaScript client's e2e tests against the test server
func TestJavaScriptClientE2E(t *testing.T) {
	// Skip if running in external server mode (server not started by us)
	if useExternalServer {
		t.Skip("Skipping JavaScript client e2e tests in external server mode")
	}

	// Get the project root directory
	projectRoot, err := os.Getwd()
	require.NoError(t, err)
	// Go up from e2e/ to project root
	for !strings.HasSuffix(projectRoot, "remote-signer") && len(projectRoot) > 1 {
		projectRoot = filepath.Dir(projectRoot)
	}
	require.True(t, strings.HasSuffix(projectRoot, "remote-signer"), "Could not find project root")

	jsClientDir := filepath.Join(projectRoot, "pkg", "js-client")

	// Check if js-client directory exists
	if _, err := os.Stat(jsClientDir); os.IsNotExist(err) {
		t.Skipf("JavaScript client directory not found at %s, skipping test", jsClientDir)
	}

	// Check if node_modules exists (dependencies installed)
	nodeModulesPath := filepath.Join(jsClientDir, "node_modules")
	if _, err := os.Stat(nodeModulesPath); os.IsNotExist(err) {
		t.Skipf("JavaScript client dependencies not installed at %s, skipping test. Run 'npm install' in %s", nodeModulesPath, jsClientDir)
	}

	// Set up environment variables for JavaScript tests
	env := os.Environ()
	env = append(env, "E2E_EXTERNAL_SERVER=true")
	env = append(env, fmt.Sprintf("E2E_BASE_URL=%s", baseURL))
	env = append(env, fmt.Sprintf("E2E_API_KEY_ID=%s", adminAPIKeyID))
	env = append(env, fmt.Sprintf("E2E_PRIVATE_KEY=%s", adminAPIKeyHex))
	env = append(env, fmt.Sprintf("E2E_SIGNER_ADDRESS=%s", testSignerAddress))

	// Parse chain ID
	chainIDInt, err := strconv.Atoi(testChainID)
	if err != nil {
		chainIDInt = 1 // Default to 1
	}
	env = append(env, fmt.Sprintf("E2E_CHAIN_ID=%d", chainIDInt))

	// Run JavaScript e2e tests
	cmd := exec.Command("npm", "run", "test:e2e")
	cmd.Dir = jsClientDir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	t.Logf("Running JavaScript client e2e tests...")
	t.Logf("  Base URL: %s", baseURL)
	t.Logf("  API Key ID: %s", adminAPIKeyID)
	t.Logf("  Working directory: %s", jsClientDir)

	err = cmd.Run()
	require.NoError(t, err, "JavaScript client e2e tests failed")
}

// TestMetaMaskSnapE2E runs the MetaMask Snap's e2e tests against the test server
func TestMetaMaskSnapE2E(t *testing.T) {
	// Skip if running in external server mode (server not started by us)
	if useExternalServer {
		t.Skip("Skipping MetaMask Snap e2e tests in external server mode")
	}

	// Get the project root directory
	projectRoot, err := os.Getwd()
	require.NoError(t, err)
	// Go up from e2e/ to project root
	for !strings.HasSuffix(projectRoot, "remote-signer") && len(projectRoot) > 1 {
		projectRoot = filepath.Dir(projectRoot)
	}
	require.True(t, strings.HasSuffix(projectRoot, "remote-signer"), "Could not find project root")

	snapDir := filepath.Join(projectRoot, "app", "metamask-snap")

	// Check if snap directory exists
	if _, err := os.Stat(snapDir); os.IsNotExist(err) {
		t.Skipf("MetaMask Snap directory not found at %s, skipping test", snapDir)
	}

	// Check if node_modules exists (dependencies installed)
	nodeModulesPath := filepath.Join(snapDir, "node_modules")
	if _, err := os.Stat(nodeModulesPath); os.IsNotExist(err) {
		t.Skipf("MetaMask Snap dependencies not installed at %s, skipping test. Run 'npm install' in %s", nodeModulesPath, snapDir)
	}

	// Set up environment variables for Snap tests
	env := os.Environ()
	env = append(env, "E2E_EXTERNAL_SERVER=true")
	env = append(env, fmt.Sprintf("E2E_BASE_URL=%s", baseURL))
	env = append(env, fmt.Sprintf("E2E_API_KEY_ID=%s", adminAPIKeyID))
	env = append(env, fmt.Sprintf("E2E_PRIVATE_KEY=%s", adminAPIKeyHex))
	env = append(env, fmt.Sprintf("E2E_SIGNER_ADDRESS=%s", testSignerAddress))

	// Parse chain ID
	chainIDInt, err := strconv.Atoi(testChainID)
	if err != nil {
		chainIDInt = 1 // Default to 1
	}
	env = append(env, fmt.Sprintf("E2E_CHAIN_ID=%d", chainIDInt))

	// Run MetaMask Snap e2e tests
	cmd := exec.Command("npm", "run", "test:e2e")
	cmd.Dir = snapDir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	t.Logf("Running MetaMask Snap e2e tests...")
	t.Logf("  Base URL: %s", baseURL)
	t.Logf("  API Key ID: %s", adminAPIKeyID)
	t.Logf("  Working directory: %s", snapDir)

	err = cmd.Run()
	require.NoError(t, err, "MetaMask Snap e2e tests failed")
}
