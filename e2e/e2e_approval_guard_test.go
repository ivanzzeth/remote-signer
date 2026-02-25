//go:build e2e

package e2e

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
)

// TestApprovalGuard_PauseAndResume verifies that after N consecutive "rejected" outcomes
// (rule-blocked or manual approval), the guard pauses sign requests, and admin resume restores service.
func TestApprovalGuard_PauseAndResume(t *testing.T) {
	if useExternalServer {
		t.Skip("approval guard e2e uses internal server with config.e2e.yaml (guard + blocklist rule)")
	}
	ctx := context.Background()
	burnTxPayload := []byte(`{"transaction":{"to":"0x000000000000000000000000000000000000dEaD","value":"0","gas":21000,"gasPrice":"1000000000","txType":"legacy","nonce":0}}`)

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

	_, err := adminClient.Sign(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      client.SignTypePersonal,
		Payload:       []byte(`{"message":"e2e after trigger"}`),
	})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "paused") || strings.Contains(err.Error(), "500"),
		"expected error to indicate pause or 500, got: %s", err.Error())

	err = adminClient.ResumeApprovalGuard(ctx)
	require.NoError(t, err)

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
