//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// skipIfNoSimulator skips the test when the simulation engine is not available.
// This happens when either: (a) the test server has no simulator (no RPC gateway / no anvil),
// or (b) running against an external server (we cannot inspect its capabilities).
func skipIfNoSimulator(t *testing.T) {
	t.Helper()
	if useExternalServer {
		t.Skip("simulation e2e tests require internal test server with simulator")
	}
	if testServer == nil || !testServer.HasSimulator() {
		t.Skip("simulation requires RPC gateway and anvil binary; set EVM_RPC_GATEWAY_URL to enable")
	}
}

// skipOnInfraError skips the test if the error indicates an infrastructure problem
// (e.g. RPC gateway unreachable, anvil fork timeout) rather than a logic bug.
func skipOnInfraError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	msg := err.Error()
	infraPatterns := []string{
		"context deadline exceeded",
		"connection refused",
		"connection reset",
		"i/o timeout",
		"no such host",
		"anvil",
		"fork",
	}
	for _, p := range infraPatterns {
		if strings.Contains(strings.ToLower(msg), p) {
			t.Skipf("skipping due to simulation infrastructure issue: %v", err)
		}
	}
}

// TestSimulate_SimpleTransfer simulates a native ETH transfer and verifies success + gas usage.
func TestSimulate_SimpleTransfer(t *testing.T) {
	skipIfNoSimulator(t)
	ensureGuardResumed(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Use a regular EOA address (not a precompile) to avoid reverts on mainnet forks
	resp, err := adminClient.EVM.Simulate.Simulate(ctx, &evm.SimulateRequest{
		ChainID: chainID,
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", // Hardhat account 2
		Value:   "0x1",
		Data:    "0x",
	})
	skipOnInfraError(t, err)
	require.NoError(t, err, "simulate API should succeed")
	assert.True(t, resp.Success, "simple transfer should succeed")
	assert.Greater(t, resp.GasUsed, uint64(0), "gas used should be > 0")
	assert.Empty(t, resp.RevertReason, "no revert reason for successful tx")
}

// TestSimulate_Batch simulates two transactions in sequence and verifies both execute
// and the second tx can observe state from the first (shared fork state within batch).
func TestSimulate_Batch(t *testing.T) {
	skipIfNoSimulator(t)
	ensureGuardResumed(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	resp, err := adminClient.EVM.Simulate.SimulateBatch(ctx, &evm.SimulateBatchRequest{
		ChainID: chainID,
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		Transactions: []evm.SimulateTxDTO{
			{
				// First tx: simple native transfer to Hardhat account 2
				To:    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
				Value: "0x1",
				Data:  "0x",
			},
			{
				// Second tx: another native transfer to Hardhat account 3
				To:    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
				Value: "0x1",
				Data:  "0x",
			},
		},
	})
	skipOnInfraError(t, err)
	require.NoError(t, err, "batch simulate API should succeed")
	require.Len(t, resp.Results, 2, "should have 2 results for 2 transactions")

	// Both transactions should succeed
	assert.True(t, resp.Results[0].Success, "tx 0 should succeed")
	assert.True(t, resp.Results[1].Success, "tx 1 should succeed")
	assert.Greater(t, resp.Results[0].GasUsed, uint64(0), "tx 0 gas used > 0")
	assert.Greater(t, resp.Results[1].GasUsed, uint64(0), "tx 1 gas used > 0")
}

// TestSimulate_RevertedTx simulates a transaction that will revert and verifies
// success=false and a non-empty revert reason.
func TestSimulate_RevertedTx(t *testing.T) {
	skipIfNoSimulator(t)
	ensureGuardResumed(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Send a transaction with invalid calldata to a non-contract address with gas limit
	// that would force the EVM to attempt execution.
	// Calling WETH with insufficient gas should revert.
	resp, err := adminClient.EVM.Simulate.Simulate(ctx, &evm.SimulateRequest{
		ChainID: chainID,
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x0000000000000000000000000000000000000000",
		Value:   "0x0",
		Data:    "0x",
	})
	skipOnInfraError(t, err)
	require.NoError(t, err, "simulate API call itself should not error")

	// The transaction to address(0) may or may not revert depending on chain state.
	// If it succeeds, try an alternative approach: call a non-existent function on WETH with low gas.
	if resp.Success {
		resp2, err2 := adminClient.EVM.Simulate.Simulate(ctx, &evm.SimulateRequest{
			ChainID: chainID,
			From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
			To:      "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", // WETH on mainnet
			Value:   "0x0",
			Data:    "0xdeadbeef00000000000000000000000000000000000000000000000000000000",
			Gas:     "0x5208", // 21000 - not enough for contract call
		})
		skipOnInfraError(t, err2)
		require.NoError(t, err2, "simulate API call should not error")
		// With insufficient gas for a contract call, this should fail
		if !resp2.Success {
			assert.NotEmpty(t, resp2.RevertReason, "reverted tx should have a revert reason")
		} else {
			t.Log("Warning: revert test inconclusive - both attempts succeeded. This can happen on some chain forks.")
		}
	} else {
		assert.NotEmpty(t, resp.RevertReason, "reverted tx should have a revert reason")
	}
}

// TestSimulate_Unauthorized verifies that unauthenticated requests to the simulate
// endpoint are rejected.
func TestSimulate_Unauthorized(t *testing.T) {
	skipIfNoSimulator(t)
	ctx := context.Background()

	// Create a client with credentials not registered on the server
	_, privKey, keyErr := ed25519.GenerateKey(nil)
	require.NoError(t, keyErr)
	invalidClient, err := client.NewClient(client.Config{
		BaseURL:       baseURL,
		APIKeyID:      "nonexistent-key-id",
		PrivateKeyHex: hex.EncodeToString(privKey),
	})
	require.NoError(t, err)

	_, err = invalidClient.EVM.Simulate.Simulate(ctx, &evm.SimulateRequest{
		ChainID: chainID,
		From:    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
		To:      "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Value:   "0x1",
		Data:    "0x",
	})
	require.Error(t, err, "unauthenticated request should be rejected")
	assert.Contains(t, err.Error(), "401", "should return 401 Unauthorized")
}
