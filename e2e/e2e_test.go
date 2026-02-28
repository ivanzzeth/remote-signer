//go:build e2e

package e2e

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

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

	// Default API port for e2e tests (use 18548 to avoid conflicts with production on 8548)
	defaultAPIPort = 18548

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
