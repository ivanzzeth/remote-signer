//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/blocklist"
	evmpkg "github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// Blocked address used in the dynamic blocklist tests.
// This is a well-known Tornado Cash address from the OFAC SDN list.
const blockedTestAddr = "0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b"

// TestDynamicBlocklist_BlocksSignToSanctionedAddress verifies that the dynamic blocklist
// blocks signing requests to addresses fetched from an external source at runtime.
func TestDynamicBlocklist_BlocksSignToSanctionedAddress(t *testing.T) {
	if useExternalServer {
		t.Skip("dynamic blocklist e2e requires internal server with mock HTTP source")
	}

	// 1. Start a mock HTTP server that serves a text blocklist.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# OFAC SDN ETH test addresses\n" + blockedTestAddr + "\n"))
	}))
	defer mockServer.Close()

	// 2. Create the dynamic blocklist with the mock source.
	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "blocklist_cache.json")

	bl, err := blocklist.NewDynamicBlocklist(blocklist.Config{
		Enabled:   true,
		FailMode:  "close",
		CacheFile: cacheFile,
		Sources: []blocklist.SourceConfig{
			{Name: "e2e-mock", Type: "url_text", URL: mockServer.URL},
		},
	}, testServerLogger())
	require.NoError(t, err)

	err = bl.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl.Stop()

	// Wait for first async sync to complete.
	require.Eventually(t, func() bool {
		return bl.AddressCount() > 0
	}, 5*time.Second, 100*time.Millisecond, "blocklist should have synced")

	// 3. Verify the address is blocked at the blocklist level.
	blocked, reason := bl.IsBlocked(blockedTestAddr)
	assert.True(t, blocked, "sanctioned address should be blocked")
	assert.Contains(t, reason, "dynamic blocklist")

	// Normal address should NOT be blocked.
	blocked, _ = bl.IsBlocked(treasuryAddress)
	assert.False(t, blocked, "treasury address should not be blocked")

	// 4. Verify cache file was created.
	_, err = os.Stat(cacheFile)
	assert.NoError(t, err, "cache file should exist after sync")
}

// TestDynamicBlocklist_CacheFileLoadsOnRestart verifies that the blocklist loads
// from the local cache file at startup without needing network access.
func TestDynamicBlocklist_CacheFileLoadsOnRestart(t *testing.T) {
	if useExternalServer {
		t.Skip("dynamic blocklist e2e requires internal server")
	}

	tmpDir := t.TempDir()
	cacheFile := filepath.Join(tmpDir, "blocklist_cache.json")

	// Write a cache file with a blocked address.
	cache := map[string]interface{}{
		"updated_at": time.Now().UTC().Format(time.RFC3339),
		"addresses":  []string{common.HexToAddress(blockedTestAddr).Hex()},
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cacheFile, data, 0o640))

	// Create blocklist with unreachable URL (should still work from cache).
	bl, err := blocklist.NewDynamicBlocklist(blocklist.Config{
		Enabled:   true,
		FailMode:  "open",
		CacheFile: cacheFile,
		Sources: []blocklist.SourceConfig{
			{Name: "unreachable", Type: "url_text", URL: "http://localhost:1/nonexistent"},
		},
	}, testServerLogger())
	require.NoError(t, err)

	err = bl.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl.Stop()

	// Should have loaded address from cache immediately (before any network).
	assert.Equal(t, 1, bl.AddressCount(), "should have loaded 1 address from cache")
	blocked, _ := bl.IsBlocked(blockedTestAddr)
	assert.True(t, blocked, "cached address should be blocked")
}

// TestDynamicBlocklist_JSONSource verifies the url_json source type.
func TestDynamicBlocklist_JSONSource(t *testing.T) {
	if useExternalServer {
		t.Skip("dynamic blocklist e2e requires internal server with mock HTTP source")
	}

	jsonData := map[string]interface{}{
		"sanctioned": map[string]interface{}{
			"eth_addresses": []string{blockedTestAddr},
		},
	}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jsonData)
	}))
	defer mockServer.Close()

	bl, err := blocklist.NewDynamicBlocklist(blocklist.Config{
		Enabled:  true,
		FailMode: "open",
		Sources: []blocklist.SourceConfig{
			{Name: "json-mock", Type: "url_json", URL: mockServer.URL, JSONPath: "sanctioned.eth_addresses"},
		},
	}, testServerLogger())
	require.NoError(t, err)

	err = bl.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl.Stop()

	require.Eventually(t, func() bool {
		return bl.AddressCount() > 0
	}, 5*time.Second, 100*time.Millisecond)

	blocked, _ := bl.IsBlocked(blockedTestAddr)
	assert.True(t, blocked)
}

// TestDynamicBlocklist_Evaluator_IntegrationWithEngine tests the evaluator
// through the full rule engine (create rule via API, sign, verify blocked).
func TestDynamicBlocklist_Evaluator_IntegrationWithEngine(t *testing.T) {
	if useExternalServer {
		t.Skip("dynamic blocklist e2e requires internal server with mock HTTP source")
	}

	// Create mock blocklist source.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(blockedTestAddr + "\n"))
	}))
	defer mockServer.Close()

	bl, err := blocklist.NewDynamicBlocklist(blocklist.Config{
		Enabled:  true,
		FailMode: "open",
		Sources:  []blocklist.SourceConfig{{Name: "e2e", Type: "url_text", URL: mockServer.URL}},
	}, testServerLogger())
	require.NoError(t, err)
	err = bl.Start(context.Background(), 1*time.Hour)
	require.NoError(t, err)
	defer bl.Stop()
	require.Eventually(t, func() bool { return bl.AddressCount() > 0 }, 5*time.Second, 100*time.Millisecond)

	// Register dynamic blocklist evaluator with the running engine.
	blEval, err := blocklist.NewEvaluator(bl)
	require.NoError(t, err)
	testServer.RegisterDynamicBlocklistEvaluator(blEval)

	// Create a blocklist rule via API.
	ctx := context.Background()
	chainType := "evm"
	ruleResp, err := adminClient.EVM.Rules.Create(ctx, &evmpkg.CreateRuleRequest{
		Name:      "E2E Dynamic Blocklist",
		Type:      "evm_dynamic_blocklist",
		Mode:      "blocklist",
		ChainType: &chainType,
		Config: map[string]interface{}{
			"check_recipient":          true,
			"check_verifying_contract": true,
		},
		Enabled: true,
	})
	require.NoError(t, err, "should create dynamic blocklist rule")
	defer func() { _ = adminClient.EVM.Rules.Delete(ctx, ruleResp.ID) }()

	// Try to sign a transaction to the blocked address → should be rejected.
	address := common.HexToAddress(signerAddress)
	signer := evmpkg.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	blockedTo := common.HexToAddress(blockedTestAddr)
	blockedTx := ethtypes.NewTx(&ethtypes.LegacyTx{
		Nonce:    200,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &blockedTo,
		Value:    big.NewInt(0),
	})
	_, err = signer.SignTransactionWithChainID(blockedTx, big.NewInt(1))
	require.Error(t, err, "signing to sanctioned address should be blocked")
	assert.Contains(t, err.Error(), "dynamic blocklist", "error should mention dynamic blocklist")

	// Sign a transaction to a non-blocked address → should pass.
	normalTo := common.HexToAddress(treasuryAddress)
	normalTx := ethtypes.NewTx(&ethtypes.LegacyTx{
		Nonce:    201,
		GasPrice: big.NewInt(20000000000),
		Gas:      21000,
		To:       &normalTo,
		Value:    big.NewInt(100000000000000000),
	})
	signedTx, err := signer.SignTransactionWithChainID(normalTx, big.NewInt(1))
	require.NoError(t, err, "signing to non-blocked address should pass")
	require.NotNil(t, signedTx)
}

func testServerLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}
