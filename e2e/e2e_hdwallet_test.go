//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
)

// =============================================================================
// HD Wallet Management Tests
// =============================================================================

func TestHDWallet_CreateAndList(t *testing.T) {
	if useExternalServer {
		t.Skip("Skipping: HD wallet creation test not supported with external server")
	}

	ctx := context.Background()

	// Create a new HD wallet
	resp, err := adminClient.CreateHDWallet(ctx, &client.CreateHDWalletRequest{
		Password:    "test-hd-wallet-password-e2e",
		EntropyBits: 128,
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.NotEmpty(t, resp.PrimaryAddress, "HD wallet should have a primary address")
	assert.NotEmpty(t, resp.BasePath, "HD wallet should have a base path")
	assert.GreaterOrEqual(t, resp.DerivedCount, 1, "Should have at least the primary address derived")

	// List HD wallets
	listResp, err := adminClient.ListHDWallets(ctx)
	require.NoError(t, err)
	require.NotNil(t, listResp)
	assert.GreaterOrEqual(t, len(listResp.Wallets), 1, "Should have at least one HD wallet")

	// Verify the newly created wallet is in the list
	found := false
	for _, w := range listResp.Wallets {
		if w.PrimaryAddress == resp.PrimaryAddress {
			found = true
			assert.Equal(t, resp.BasePath, w.BasePath)
			break
		}
	}
	assert.True(t, found, "Newly created HD wallet should appear in the list")

	// Verify the primary address appears in signers list
	signersResp, err := adminClient.ListSigners(ctx, &client.ListSignersFilter{
		Type:  "hd_wallet",
		Limit: 100,
	})
	require.NoError(t, err)

	foundSigner := false
	for _, s := range signersResp.Signers {
		if s.Address == resp.PrimaryAddress {
			foundSigner = true
			assert.Equal(t, "hd_wallet", s.Type)
			assert.True(t, s.Enabled)
			break
		}
	}
	assert.True(t, foundSigner, "Primary address should appear in signers list")
}

func TestHDWallet_DeriveAddresses(t *testing.T) {
	if useExternalServer {
		t.Skip("Skipping: HD wallet derive test not supported with external server")
	}

	ctx := context.Background()

	// Create a new HD wallet for this test
	createResp, err := adminClient.CreateHDWallet(ctx, &client.CreateHDWalletRequest{
		Password:    "test-derive-password-e2e",
		EntropyBits: 128,
	})
	require.NoError(t, err)
	primaryAddr := createResp.PrimaryAddress

	// Derive a single address at index 1
	idx := uint32(1)
	deriveResp, err := adminClient.DeriveAddress(ctx, primaryAddr, &client.DeriveAddressRequest{
		Index: &idx,
	})
	require.NoError(t, err)
	require.NotNil(t, deriveResp)
	assert.Len(t, deriveResp.Derived, 1, "Should derive exactly 1 address")
	assert.NotEqual(t, primaryAddr, deriveResp.Derived[0].Address, "Derived address should differ from primary")
	assert.Equal(t, "hd_wallet", deriveResp.Derived[0].Type)

	// Derive a batch of addresses (indices 2-4)
	start := uint32(2)
	count := uint32(3)
	batchResp, err := adminClient.DeriveAddress(ctx, primaryAddr, &client.DeriveAddressRequest{
		Start: &start,
		Count: &count,
	})
	require.NoError(t, err)
	require.NotNil(t, batchResp)
	assert.Len(t, batchResp.Derived, 3, "Should derive exactly 3 addresses")

	// All derived addresses should be unique
	addrSet := map[string]bool{primaryAddr: true, deriveResp.Derived[0].Address: true}
	for _, d := range batchResp.Derived {
		assert.False(t, addrSet[d.Address], "Derived address should be unique: %s", d.Address)
		addrSet[d.Address] = true
	}

	// List derived addresses
	listResp, err := adminClient.ListDerivedAddresses(ctx, primaryAddr)
	require.NoError(t, err)
	require.NotNil(t, listResp)
	assert.GreaterOrEqual(t, len(listResp.Derived), 5, "Should have at least 5 derived addresses (0-4)")
}

func TestHDWallet_DerivedAddressCanSign(t *testing.T) {
	if useExternalServer {
		t.Skip("Skipping: HD wallet signing test not supported with external server")
	}

	ctx := context.Background()

	// Create HD wallet
	createResp, err := adminClient.CreateHDWallet(ctx, &client.CreateHDWalletRequest{
		Password:    "test-sign-password-e2e",
		EntropyBits: 128,
	})
	require.NoError(t, err)
	primaryAddr := createResp.PrimaryAddress

	// First, create a signer restriction whitelist rule for this address
	_, err = adminClient.CreateRule(ctx, &client.CreateRuleRequest{
		Name: "E2E HD wallet signer allow",
		Type: "signer_restriction",
		Mode: "whitelist",
		Config: map[string]interface{}{
			"allowed_signers": []string{primaryAddr},
		},
		Enabled: true,
	})
	require.NoError(t, err)

	// Sign a personal message with the primary address
	payload, err := json.Marshal(map[string]interface{}{"message": "Hello from HD wallet"})
	require.NoError(t, err)

	signResp, err := adminClient.Sign(ctx, &client.SignRequest{
		ChainID:       chainID,
		SignerAddress:  primaryAddr,
		SignType:       "personal",
		Payload:        payload,
	})
	require.NoError(t, err)
	require.NotNil(t, signResp)
	assert.Equal(t, "completed", signResp.Status)
	assert.NotEmpty(t, signResp.Signature)
}

func TestHDWallet_NonAdminCannotCreate(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	// Non-admin should NOT be able to create HD wallets
	_, err := nonAdminClient.CreateHDWallet(ctx, &client.CreateHDWalletRequest{
		Password: "should-fail",
	})
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode, "Non-admin should get 403 Forbidden")
}

func TestHDWallet_NonAdminCannotList(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}

	ctx := context.Background()

	// Non-admin should NOT be able to list HD wallets (admin-only route)
	_, err := nonAdminClient.ListHDWallets(ctx)
	require.Error(t, err)

	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode, "Non-admin should get 403 Forbidden")
}

func TestHDWallet_ValidationErrors(t *testing.T) {
	if useExternalServer {
		t.Skip("Skipping: HD wallet validation test not supported with external server")
	}

	ctx := context.Background()

	// Missing password
	_, err := adminClient.CreateHDWallet(ctx, &client.CreateHDWalletRequest{
		Password: "",
	})
	require.Error(t, err)

	// Derive from non-existent wallet
	idx := uint32(0)
	_, err = adminClient.DeriveAddress(ctx, "0x0000000000000000000000000000000000000000", &client.DeriveAddressRequest{
		Index: &idx,
	})
	require.Error(t, err)
}
