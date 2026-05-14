//go:build e2e

package e2e

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// TestZ_ApprovalGuard_PauseAndResume verifies that after N consecutive "rejected" outcomes
// (rule-blocked or manual approval), the guard pauses sign requests, and admin resume restores service.
// Named with Z_ prefix so it runs last (Go runs tests alphabetically); this test pauses the guard
// and would leave it paused if it failed before Resume(), breaking all later sign-request tests.
func TestZ_ApprovalGuard_PauseAndResume(t *testing.T) {
	if useExternalServer {
		t.Skip("approval guard e2e uses internal server with config.e2e.yaml (guard + blocklist rule)")
	}
	ctx := context.Background()

	// Resume guard and clear accumulated events from prior tests (sliding window may have stale rejections)
	_ = adminClient.EVM.Guard.Resume(ctx)

	burnTxPayload := []byte(`{"transaction":{"to":"0x000000000000000000000000000000000000dEaD","value":"0","gas":21000,"gasPrice":"1000000000","txType":"legacy","nonce":0}}`)

	for i := 0; i < 3; i++ {
		resp, err := adminClient.EVM.Sign.Execute(ctx, &evm.SignRequest{
			ChainID:       chainID,
			SignerAddress: signerAddress,
			SignType:      evm.SignTypeTransaction,
			Payload:       burnTxPayload,
		})
		if err != nil {
			errMsg := err.Error()
			// The last request may trigger the approval guard pause (sliding window),
			// so accept both "blocked" and "paused" as valid rejection outcomes.
			isBlocked := strings.Contains(errMsg, "rejected") || strings.Contains(errMsg, "blocked")
			isPaused := strings.Contains(errMsg, "paused")
			assert.True(t, isBlocked || isPaused,
				"request %d should be blocked by rule or paused by guard, got: %s", i+1, errMsg)
		} else {
			require.NotNil(t, resp)
			assert.Equal(t, "rejected", resp.Status)
			assert.Contains(t, resp.Message, "blocked")
		}
	}

	_, err := adminClient.EVM.Sign.Execute(ctx, &evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      evm.SignTypePersonal,
		Payload:       []byte(`{"message":"e2e after trigger"}`),
	})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "paused") || strings.Contains(err.Error(), "500"),
		"expected error to indicate pause or 500, got: %s", err.Error())

	err = adminClient.EVM.Guard.Resume(ctx)
	require.NoError(t, err)

	resp, err := adminClient.EVM.Sign.Execute(ctx, &evm.SignRequest{
		ChainID:       chainID,
		SignerAddress: signerAddress,
		SignType:      evm.SignTypePersonal,
		Payload:       []byte(`{"message":"e2e after resume"}`),
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "completed", resp.Status)
}
