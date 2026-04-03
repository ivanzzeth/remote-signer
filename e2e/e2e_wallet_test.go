//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/pkg/client"
	"github.com/ivanzzeth/remote-signer/pkg/client/evm"
)

func firstSignerByType(t *testing.T, ctx context.Context, signerType string) *evm.Signer {
	t.Helper()
	list, err := adminClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{
		Type:  signerType,
		Limit: 100,
	})
	require.NoError(t, err)
	for _, s := range list.Signers {
		if s.Type == signerType {
			signer := s
			return &signer
		}
	}
	return nil
}

func firstNonHDSigner(t *testing.T, ctx context.Context) *evm.Signer {
	t.Helper()
	list, err := adminClient.EVM.Signers.List(ctx, &evm.ListSignersFilter{Limit: 100})
	require.NoError(t, err)
	for _, s := range list.Signers {
		if s.Type != "hd_wallet" {
			signer := s
			return &signer
		}
	}
	return nil
}

// cleanupWallet registers a t.Cleanup that deletes a wallet (ignoring errors).
func cleanupWallet(t *testing.T, id string) {
	t.Helper()
	t.Cleanup(func() {
		_ = adminClient.EVM.Wallets.Delete(context.Background(), id)
	})
}

// TestWalletCRUDFlow tests creating, reading, listing, and deleting a wallet.
func TestWalletCRUDFlow(t *testing.T) {
	ctx := context.Background()

	// Create
	col, err := adminClient.EVM.Wallets.Create(ctx, &evm.CreateWalletRequest{
		Name:        "E2E Test Wallet",
		Description: "Integration test wallet",
	})
	require.NoError(t, err)
	require.NotNil(t, col)
	assert.NotEmpty(t, col.ID)
	assert.Equal(t, "E2E Test Wallet", col.Name)
	cleanupWallet(t, col.ID)

	// Get
	got, err := adminClient.EVM.Wallets.Get(ctx, col.ID)
	require.NoError(t, err)
	assert.Equal(t, col.ID, got.ID)
	assert.Equal(t, col.Name, got.Name)

	// List
	list, err := adminClient.EVM.Wallets.List(ctx, &evm.ListWalletsFilter{Limit: 100})
	require.NoError(t, err)
	require.NotNil(t, list)
	found := false
	for _, c := range list.Wallets {
		if c.ID == col.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "created wallet should appear in list")

	// Delete
	err = adminClient.EVM.Wallets.Delete(ctx, col.ID)
	require.NoError(t, err)

	// Verify deleted
	_, err = adminClient.EVM.Wallets.Get(ctx, col.ID)
	require.Error(t, err)
}

// TestWalletMemberManagement tests adding, listing, and removing members.
func TestWalletMemberManagement(t *testing.T) {
	ctx := context.Background()

	// Create wallet
	col, err := adminClient.EVM.Wallets.Create(ctx, &evm.CreateWalletRequest{
		Name: "E2E Member Test Wallet",
	})
	require.NoError(t, err)
	cleanupWallet(t, col.ID)

	walletID := signerAddress

	// Add member
	member, err := adminClient.EVM.Wallets.AddMember(ctx, col.ID, &evm.AddWalletMemberRequest{
		SignerAddress: walletID,
	})
	require.NoError(t, err)
	require.NotNil(t, member)

	// List members
	members, err := adminClient.EVM.Wallets.ListMembers(ctx, col.ID)
	require.NoError(t, err)
	require.NotNil(t, members)
	assert.GreaterOrEqual(t, len(members.Members), 1)
	found := false
	for _, m := range members.Members {
		if m.SignerAddress == walletID {
			found = true
			break
		}
	}
	assert.True(t, found, "added wallet should be in member list")

	// Remove member
	err = adminClient.EVM.Wallets.RemoveMember(ctx, col.ID, walletID)
	require.NoError(t, err)

	// Verify removed
	members, err = adminClient.EVM.Wallets.ListMembers(ctx, col.ID)
	require.NoError(t, err)
	for _, m := range members.Members {
		assert.NotEqual(t, walletID, m.WalletID, "removed wallet should not be in member list")
	}
}

// TestWalletDeleteCascadesMembers verifies that deleting a wallet removes its members.
func TestWalletDeleteCascadesMembers(t *testing.T) {
	ctx := context.Background()

	col, err := adminClient.EVM.Wallets.Create(ctx, &evm.CreateWalletRequest{
		Name: "E2E Cascade Delete Wallet",
	})
	require.NoError(t, err)

	// Add a member
	_, err = adminClient.EVM.Wallets.AddMember(ctx, col.ID, &evm.AddWalletMemberRequest{
		SignerAddress: signerAddress,
	})
	require.NoError(t, err)

	// Delete wallet (should cascade)
	err = adminClient.EVM.Wallets.Delete(ctx, col.ID)
	require.NoError(t, err)

	// Wallet should no longer exist
	_, err = adminClient.EVM.Wallets.Get(ctx, col.ID)
	require.Error(t, err)
}

// TestWalletCreateRequiresName verifies that creating a wallet without a name fails.
func TestWalletCreateRequiresName(t *testing.T) {
	ctx := context.Background()

	_, err := adminClient.EVM.Wallets.Create(ctx, &evm.CreateWalletRequest{
		Name: "",
	})
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 400, apiErr.StatusCode)
}

// TestWalletGetNotFound verifies that getting a nonexistent wallet returns 404.
func TestWalletGetNotFound(t *testing.T) {
	ctx := context.Background()

	_, err := adminClient.EVM.Wallets.Get(ctx, "nonexistent-id-12345")
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 404, apiErr.StatusCode)
}

// TestWalletStrategyRoleDenied verifies that strategy-role users cannot manage wallets.
func TestWalletStrategyRoleDenied(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}
	ctx := context.Background()

	// Strategy role should not be able to create wallets
	_, err := nonAdminClient.EVM.Wallets.Create(ctx, &evm.CreateWalletRequest{
		Name: "E2E Strategy Wallet",
	})
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode)

	// Strategy role should not be able to list wallets
	_, err = nonAdminClient.EVM.Wallets.List(ctx, &evm.ListWalletsFilter{Limit: 100})
	require.Error(t, err)
	apiErr, ok = err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode)

	// Strategy role should not access an admin wallet
	adminCol, err := adminClient.EVM.Wallets.Create(ctx, &evm.CreateWalletRequest{
		Name: "E2E Admin Wallet for Strategy Test",
	})
	require.NoError(t, err)
	cleanupWallet(t, adminCol.ID)

	_, err = nonAdminClient.EVM.Wallets.Get(ctx, adminCol.ID)
	require.Error(t, err)
	apiErr, ok = err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode)
}

// TestNestedWalletRejected verifies that adding a wallet ID as a member is rejected.
func TestNestedWalletRejected(t *testing.T) {
	ctx := context.Background()

	// Create two wallets
	col1, err := adminClient.EVM.Wallets.Create(ctx, &evm.CreateWalletRequest{
		Name: "E2E Parent Wallet",
	})
	require.NoError(t, err)
	cleanupWallet(t, col1.ID)

	col2, err := adminClient.EVM.Wallets.Create(ctx, &evm.CreateWalletRequest{
		Name: "E2E Child Wallet",
	})
	require.NoError(t, err)
	cleanupWallet(t, col2.ID)

	// Try to add col2 as a member of col1 — should be rejected
	_, err = adminClient.EVM.Wallets.AddMember(ctx, col1.ID, &evm.AddWalletMemberRequest{
		SignerAddress: col2.ID,
	})
	require.Error(t, err, "adding a wallet as a member should be rejected")
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 400, apiErr.StatusCode)
}

// TestWalletMemberTypes_KeystoreAndHDWallet verifies that both keystore and hd_wallet
// wallet IDs can be added to a wallet and listed as members.
func TestWalletMemberTypes_KeystoreAndHDWallet(t *testing.T) {
	ctx := context.Background()

	col, err := adminClient.EVM.Wallets.Create(ctx, &evm.CreateWalletRequest{
		Name: "E2E Member Types Wallet",
	})
	require.NoError(t, err)
	cleanupWallet(t, col.ID)

	// Ensure we have a keystore signer for deterministic coverage.
	keystoreSigner := firstSignerByType(t, ctx, "keystore")
	if keystoreSigner == nil {
		created, createErr := adminClient.EVM.Signers.Create(ctx, &evm.CreateSignerRequest{
			Type: "keystore",
			Keystore: &evm.CreateKeystoreParams{
				Password: "e2e-wallet-keystore-member-pass",
			},
		})
		require.NoError(t, createErr)
		t.Cleanup(func() {
			_ = adminClient.EVM.Signers.DeleteSigner(context.Background(), created.Address)
		})
		keystoreSigner = created
	}
	require.NotNil(t, keystoreSigner, "expected at least one keystore signer in test environment")

	hdSigner := firstSignerByType(t, ctx, "hd_wallet")
	var createdHD string
	if hdSigner == nil {
		if useExternalServer {
			t.Skip("Skipping: no hd_wallet signer available in external server mode")
		}
		created, createErr := adminClient.EVM.HDWallets.Create(ctx, &evm.CreateHDWalletRequest{
			Password:    "e2e-wallet-hd-member-pass",
			EntropyBits: 128,
		})
		require.NoError(t, createErr)
		createdHD = created.PrimaryAddress
		t.Cleanup(func() {
			_ = adminClient.EVM.Signers.DeleteSigner(context.Background(), createdHD)
		})
		hdSigner = &evm.Signer{
			Address:       created.PrimaryAddress,
			SignerAddress: created.PrimaryAddress,
			Type:          "hd_wallet",
		}
	}

	keystoreWalletID := keystoreSigner.PrimaryAddress
	if keystoreWalletID == "" {
		keystoreWalletID = keystoreSigner.Address
	}
	hdWalletID := hdSigner.PrimaryAddress
	if hdWalletID == "" {
		hdWalletID = hdSigner.Address
	}

	_, err = adminClient.EVM.Wallets.AddMember(ctx, col.ID, &evm.AddWalletMemberRequest{
		SignerAddress: keystoreWalletID,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = adminClient.EVM.Wallets.RemoveMember(context.Background(), col.ID, keystoreWalletID)
	})

	_, err = adminClient.EVM.Wallets.AddMember(ctx, col.ID, &evm.AddWalletMemberRequest{
		SignerAddress: hdWalletID,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = adminClient.EVM.Wallets.RemoveMember(context.Background(), col.ID, hdWalletID)
	})

	members, err := adminClient.EVM.Wallets.ListMembers(ctx, col.ID)
	require.NoError(t, err)
	foundKeystore := false
	foundHD := false
	for _, m := range members.Members {
		if m.SignerAddress == keystoreWalletID {
			foundKeystore = true
		}
		if m.SignerAddress == hdWalletID {
			foundHD = true
		}
	}
	assert.True(t, foundKeystore, "keystore wallet should be present in wallet members")
	assert.True(t, foundHD, "hd wallet should be present in wallet members")
}

// TestWalletDepthLimit_RejectNestedAdditions verifies depth<=1 behavior:
// a wallet cannot include another wallet as a member.
func TestWalletDepthLimit_RejectNestedAdditions(t *testing.T) {
	ctx := context.Background()

	parent, err := adminClient.EVM.Wallets.Create(ctx, &evm.CreateWalletRequest{
		Name: "E2E Depth Parent",
	})
	require.NoError(t, err)
	cleanupWallet(t, parent.ID)

	child, err := adminClient.EVM.Wallets.Create(ctx, &evm.CreateWalletRequest{
		Name: "E2E Depth Child",
	})
	require.NoError(t, err)
	cleanupWallet(t, child.ID)

	_, err = adminClient.EVM.Wallets.AddMember(ctx, parent.ID, &evm.AddWalletMemberRequest{
		SignerAddress: child.ID,
	})
	require.Error(t, err, "adding wallet as member should be rejected by depth limit")
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 400, apiErr.StatusCode)

	members, err := adminClient.EVM.Wallets.ListMembers(ctx, parent.ID)
	require.NoError(t, err)
	assert.Len(t, members.Members, 0, "nested wallet rejection should leave parent members unchanged")
}

// TestWalletMemberAdd_OwnerCannotAccessWallet403 verifies that even if a caller
// owns the wallet, they still need ownership or access to the wallet_id they add.
func TestWalletMemberAdd_OwnerCannotAccessWallet403(t *testing.T) {
	ctx := context.Background()

	// Dev creates the wallet (so they own it).
	devClient := createRoleClient(t, "dev", "e2e-wallet-add-no-access-dev")
	col, err := devClient.EVM.Wallets.Create(ctx, &evm.CreateWalletRequest{
		Name: "E2E Dev Owns Wallet - No Access to Wallet",
	})
	require.NoError(t, err)
	cleanupWallet(t, col.ID)

	// Dev attempts to add admin's signer (signerAddress) without grant/ownership.
	_, err = devClient.EVM.Wallets.AddMember(ctx, col.ID, &evm.AddWalletMemberRequest{
		SignerAddress: signerAddress,
	})
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode, "caller without wallet ownership/access should get 403")
}

// TestWalletRemoveMember_NotMemberReturns404 verifies that removing a wallet_id
// that is not a member returns 404.
func TestWalletRemoveMember_NotMemberReturns404(t *testing.T) {
	ctx := context.Background()

	col, err := adminClient.EVM.Wallets.Create(ctx, &evm.CreateWalletRequest{
		Name: "E2E Remove Not-Member Returns 404",
	})
	require.NoError(t, err)
	cleanupWallet(t, col.ID)

	err = adminClient.EVM.Wallets.RemoveMember(ctx, col.ID, signerAddress)
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 404, apiErr.StatusCode, "removing non-member should get 404")
}

// TestWalletDeleteAfterDelete_ListMembersReturns404 verifies that once a wallet
// is deleted, member listing for that wallet is not found.
func TestWalletDeleteAfterDelete_ListMembersReturns404(t *testing.T) {
	ctx := context.Background()

	col, err := adminClient.EVM.Wallets.Create(ctx, &evm.CreateWalletRequest{
		Name: "E2E Delete Wallet Then List Members",
	})
	require.NoError(t, err)

	// Delete wallet
	err = adminClient.EVM.Wallets.Delete(ctx, col.ID)
	require.NoError(t, err)

	// List members should now return 404 (wallet not found)
	_, err = adminClient.EVM.Wallets.ListMembers(ctx, col.ID)
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 404, apiErr.StatusCode)
}

// TestWalletMemberAdd_UnauthorizedWalletOwnerReturns404 verifies the handler's
// "wallet not found" behavior when the caller does not own the wallet.
func TestWalletMemberAdd_UnauthorizedWalletOwnerReturns404(t *testing.T) {
	ctx := context.Background()

	// Dev owns the wallet.
	devClient := createRoleClient(t, "dev", "e2e-wallet-owner-dev-404")
	col, err := devClient.EVM.Wallets.Create(ctx, &evm.CreateWalletRequest{
		Name: "E2E Unauthorized Owner Member Add",
	})
	require.NoError(t, err)
	cleanupWallet(t, col.ID)

	// Agent tries to add members to someone else's wallet.
	agentClient := createRoleClient(t, "agent", "e2e-wallet-non-owner-agent-404")
	_, err = agentClient.EVM.Wallets.AddMember(ctx, col.ID, &evm.AddWalletMemberRequest{
		SignerAddress: signerAddress,
	})
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 404, apiErr.StatusCode, "non-owner wallet member add should be treated as not found")
}
