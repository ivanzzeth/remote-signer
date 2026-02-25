//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
)

func TestAuth_AdminCanAccessAdminEndpoints(t *testing.T) {
	ctx := context.Background()
	rules, err := adminClient.ListRules(ctx, nil)
	require.NoError(t, err)
	assert.NotNil(t, rules)
}

func TestAuth_NonAdminCannotAccessAdminEndpoints(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}
	ctx := context.Background()
	_, err := nonAdminClient.ListRules(ctx, nil)
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
	signer := nonAdminClient.GetSigner(address, chainID)
	sig, err := signer.PersonalSign("Hello from non-admin!")
	require.NoError(t, err)
	assert.Len(t, sig, 65)
}

func TestAuth_AdminCanSubmitSignRequest(t *testing.T) {
	address := common.HexToAddress(signerAddress)
	signer := adminClient.GetSigner(address, chainID)
	sig, err := signer.PersonalSign("Hello from admin!")
	require.NoError(t, err)
	assert.Len(t, sig, 65)
}
