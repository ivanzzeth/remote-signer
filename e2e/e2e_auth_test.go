//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

func TestAuth_AdminCanAccessAdminEndpoints(t *testing.T) {
	ctx := context.Background()
	rules, err := adminClient.EVM.Rules.List(ctx, nil)
	require.NoError(t, err)
	assert.NotNil(t, rules)
}

func TestAuth_NonAdminCannotAccessAdminEndpoints(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}
	ctx := context.Background()
	// Agent can list rules (scoped to own), but cannot list API keys (admin-only)
	_, err := nonAdminClient.APIKeys.List(ctx, nil)
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode)
}

func TestAuth_NonAdminCanSubmitSignRequest(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(nonAdminClient.EVM.Sign, address, chainID)
	sig, err := signer.PersonalSign("Hello from non-admin!")
	require.NoError(t, err)
	assert.Len(t, sig, 65)
}

func TestAuth_AdminCanSubmitSignRequest(t *testing.T) {
	address := common.HexToAddress(signerAddress)
	signer := evm.NewRemoteSigner(adminClient.EVM.Sign, address, chainID)
	sig, err := signer.PersonalSign("Hello from admin!")
	require.NoError(t, err)
	assert.Len(t, sig, 65)
}
