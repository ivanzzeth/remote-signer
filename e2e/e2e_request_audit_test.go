//go:build e2e
package e2e

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/audit"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

func TestRequest_ListRequests(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	// First make a sign request (transaction to treasury to match whitelist)
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)

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
	requests, err := adminClient.EVM.Requests.List(ctx, &evm.ListRequestsFilter{
		Limit: 10,
	})
	require.NoError(t, err)
	assert.NotNil(t, requests)
	assert.GreaterOrEqual(t, len(requests.Requests), 1)
}

func TestRequest_GetRequest(t *testing.T) {
	ensureGuardResumed(t)
	// With Example 8 (signer_restriction) and Example 9 (sign_type_restriction),
	// personal_sign is auto-approved for the test signer
	ctx := context.Background()

	// Submit a sign request and get its ID
	resp, err := adminClient.EVM.Sign.Execute(ctx, &evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      evm.SignTypePersonal,
		Payload:       []byte(`{"message":"Get request test"}`),
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.RequestID)

	// Get the request status
	status, err := adminClient.EVM.Requests.Get(ctx, resp.RequestID)
	require.NoError(t, err)
	assert.Equal(t, resp.RequestID, status.ID)
	assert.Equal(t, "completed", status.Status)
}

// =============================================================================
// Audit Tests
// =============================================================================

func TestAudit_ListAuditRecords(t *testing.T) {
	ensureGuardResumed(t)
	ctx := context.Background()

	// Make some requests first (transaction to treasury to match whitelist)
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)

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
	resp, err := adminClient.Audit.List(ctx, &audit.ListFilter{
		Limit: 10,
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// =============================================================================
// Pagination Tests
// =============================================================================
