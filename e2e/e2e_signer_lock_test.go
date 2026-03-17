//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

// =============================================================================
// Signer Lock/Unlock Tests
// =============================================================================

func TestSigner_LockAndUnlock_Keystore(t *testing.T) {
	snapshotRules(t)
	if useExternalServer {
		t.Skip("Skipping: keystore lock/unlock test not supported with external server")
	}

	ctx := context.Background()
	password := "test-lock-unlock-e2e-123"

	// Step 1: Create a keystore signer
	signer, err := adminClient.EVM.Signers.Create(ctx, &evm.CreateSignerRequest{
		Type: "keystore",
		Keystore: &evm.CreateKeystoreParams{
			Password: password,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, signer)
	assert.True(t, signer.Enabled)
	assert.False(t, signer.Locked)

	addr := signer.Address
	t.Logf("Created keystore signer: %s", addr)

	// Step 2: Verify it appears as unlocked in the list
	resp, err := adminClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{Limit: 100})
	require.NoError(t, err)
	found := findSigner(resp.Signers, addr)
	require.NotNil(t, found, "Signer should appear in list")
	assert.False(t, found.Locked, "Signer should be unlocked after creation")
	assert.True(t, found.Enabled, "Signer should be enabled after creation")

	// Step 3: Lock the signer
	lockResp, err := adminClient.EVM.Signers.Lock(ctx, addr)
	require.NoError(t, err)
	assert.Equal(t, addr, lockResp.Address)
	assert.True(t, lockResp.Locked, "Signer should be locked after lock")
	assert.False(t, lockResp.Enabled, "Signer should be disabled after lock")
	t.Log("Locked signer successfully")

	// Step 4: Verify it appears as locked in the list
	resp, err = adminClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{Limit: 100})
	require.NoError(t, err)
	found = findSigner(resp.Signers, addr)
	require.NotNil(t, found, "Locked signer should still appear in list")
	assert.True(t, found.Locked, "Signer should show as locked in list")

	// Step 5: Try to sign with locked signer — should fail with 403
	payload, err := json.Marshal(map[string]interface{}{"message": "should fail"})
	require.NoError(t, err)

	_, signErr := adminClient.EVM.Sign.Execute(ctx, &evm.SignRequest{
		ChainID:      chainID,
		SignerAddress: addr,
		SignType:      "personal",
		Payload:       payload,
	})
	require.Error(t, signErr, "Signing with locked signer should fail")
	apiErr, ok := signErr.(*client.APIError)
	if ok {
		assert.Equal(t, 403, apiErr.StatusCode, "Locked signer signing should return 403")
	}

	// Step 6: Unlock with wrong password — should fail
	_, err = adminClient.EVM.Signers.Unlock(ctx, addr, &evm.UnlockSignerRequest{
		Password: "wrong-password",
	})
	require.Error(t, err, "Unlock with wrong password should fail")

	// Step 7: Unlock with correct password
	unlockResp, err := adminClient.EVM.Signers.Unlock(ctx, addr, &evm.UnlockSignerRequest{
		Password: password,
	})
	require.NoError(t, err)
	assert.Equal(t, addr, unlockResp.Address)
	assert.False(t, unlockResp.Locked, "Signer should be unlocked after unlock")
	assert.True(t, unlockResp.Enabled, "Signer should be enabled after unlock")
	t.Log("Unlocked signer successfully")

	// Step 8: Verify it appears as unlocked in the list
	resp, err = adminClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{Limit: 100})
	require.NoError(t, err)
	found = findSigner(resp.Signers, addr)
	require.NotNil(t, found, "Signer should appear in list")
	assert.False(t, found.Locked, "Signer should be unlocked in list")
	assert.True(t, found.Enabled, "Signer should be enabled in list")
}

func TestSigner_LockAndUnlock_HDWallet(t *testing.T) {
	snapshotRules(t)
	if useExternalServer {
		t.Skip("Skipping: HD wallet lock/unlock test not supported with external server")
	}

	ctx := context.Background()
	password := "test-hdwallet-lock-e2e-123"

	// Step 1: Create an HD wallet
	createResp, err := adminClient.EVM.HDWallets.Create(ctx, &evm.CreateHDWalletRequest{
		Password:    password,
		EntropyBits: 128,
	})
	require.NoError(t, err)
	require.NotNil(t, createResp)

	primaryAddr := createResp.PrimaryAddress
	t.Logf("Created HD wallet with primary address: %s", primaryAddr)

	// Step 2: Verify it appears as unlocked in signers list
	resp, err := adminClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{
		Type:  "hd_wallet",
		Limit: 100,
	})
	require.NoError(t, err)
	found := findSigner(resp.Signers, primaryAddr)
	require.NotNil(t, found, "HD wallet primary signer should appear in list")
	assert.False(t, found.Locked)
	assert.True(t, found.Enabled)

	// Step 3: Lock the HD wallet signer
	lockResp, err := adminClient.EVM.Signers.Lock(ctx, primaryAddr)
	require.NoError(t, err)
	assert.True(t, lockResp.Locked)
	t.Log("Locked HD wallet signer successfully")

	// Step 4: Unlock with correct password
	unlockResp, err := adminClient.EVM.Signers.Unlock(ctx, primaryAddr, &evm.UnlockSignerRequest{
		Password: password,
	})
	require.NoError(t, err)
	assert.False(t, unlockResp.Locked)
	assert.True(t, unlockResp.Enabled)
	t.Log("Unlocked HD wallet signer successfully")
}

func TestSigner_UnlockAlreadyUnlocked(t *testing.T) {
	snapshotRules(t)
	if useExternalServer {
		t.Skip("Skipping: unlock test not supported with external server")
	}

	ctx := context.Background()

	// The test signer (private_key) is already unlocked — unlock should fail with 409
	_, err := adminClient.EVM.Signers.Unlock(ctx, signerAddress, &evm.UnlockSignerRequest{
		Password: "irrelevant",
	})
	require.Error(t, err, "Unlocking an already-unlocked signer should fail")
	apiErr, ok := err.(*client.APIError)
	if ok {
		assert.Equal(t, 409, apiErr.StatusCode, "Should return 409 Conflict")
	}
}

func TestSigner_LockNonExistent(t *testing.T) {
	snapshotRules(t)
	ctx := context.Background()

	_, err := adminClient.EVM.Signers.Lock(ctx, "0x0000000000000000000000000000000000000000")
	require.Error(t, err, "Locking a non-existent signer should fail")
	apiErr, ok := err.(*client.APIError)
	if ok {
		assert.Equal(t, 404, apiErr.StatusCode, "Should return 404 Not Found")
	}
}

func TestSigner_UnlockNonExistent(t *testing.T) {
	snapshotRules(t)
	ctx := context.Background()

	_, err := adminClient.EVM.Signers.Unlock(ctx, "0x0000000000000000000000000000000000000000", &evm.UnlockSignerRequest{
		Password: "irrelevant",
	})
	require.Error(t, err, "Unlocking a non-existent signer should fail")
	apiErr, ok := err.(*client.APIError)
	if ok {
		assert.Equal(t, 404, apiErr.StatusCode, "Should return 404 Not Found")
	}
}

func TestSigner_NonAdminCannotLockOrUnlock(t *testing.T) {
	snapshotRules(t)
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}
	if useExternalServer {
		t.Skip("Skipping: non-admin lock test not supported with external server")
	}

	ctx := context.Background()
	password := "test-nonadmin-lock-e2e-123"

	// Create a keystore signer first (as admin)
	signer, err := adminClient.EVM.Signers.Create(ctx, &evm.CreateSignerRequest{
		Type: "keystore",
		Keystore: &evm.CreateKeystoreParams{
			Password: password,
		},
	})
	require.NoError(t, err)
	addr := signer.Address

	// Non-admin: try to lock — should fail with 403
	_, err = nonAdminClient.EVM.Signers.Lock(ctx, addr)
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	if ok {
		assert.Equal(t, 403, apiErr.StatusCode, "Non-admin lock should return 403")
	}

	// Lock as admin first, then non-admin tries to unlock — should fail with 403
	_, err = adminClient.EVM.Signers.Lock(ctx, addr)
	require.NoError(t, err)

	_, err = nonAdminClient.EVM.Signers.Unlock(ctx, addr, &evm.UnlockSignerRequest{
		Password: password,
	})
	require.Error(t, err)
	apiErr, ok = err.(*client.APIError)
	if ok {
		assert.Equal(t, 403, apiErr.StatusCode, "Non-admin unlock should return 403")
	}

	// Cleanup: unlock as admin
	_, err = adminClient.EVM.Signers.Unlock(ctx, addr, &evm.UnlockSignerRequest{
		Password: password,
	})
	require.NoError(t, err)
}

// findSigner finds a signer by address in a list.
func findSigner(signers []evm.Signer, address string) *evm.Signer {
	for i := range signers {
		if signers[i].Address == address {
			return &signers[i]
		}
	}
	return nil
}
