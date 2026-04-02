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

// cleanupCollection registers a t.Cleanup that deletes a collection (ignoring errors).
func cleanupCollection(t *testing.T, id string) {
	t.Helper()
	t.Cleanup(func() {
		_ = adminClient.EVM.Collections.Delete(context.Background(), id)
	})
}

// TestCollectionCRUDFlow tests creating, reading, listing, and deleting a collection.
func TestCollectionCRUDFlow(t *testing.T) {
	ctx := context.Background()

	// Create
	col, err := adminClient.EVM.Collections.Create(ctx, &evm.CreateCollectionRequest{
		Name:        "E2E Test Collection",
		Description: "Integration test collection",
	})
	require.NoError(t, err)
	require.NotNil(t, col)
	assert.NotEmpty(t, col.ID)
	assert.Equal(t, "E2E Test Collection", col.Name)
	cleanupCollection(t, col.ID)

	// Get
	got, err := adminClient.EVM.Collections.Get(ctx, col.ID)
	require.NoError(t, err)
	assert.Equal(t, col.ID, got.ID)
	assert.Equal(t, col.Name, got.Name)

	// List
	list, err := adminClient.EVM.Collections.List(ctx, &evm.ListCollectionsFilter{Limit: 100})
	require.NoError(t, err)
	require.NotNil(t, list)
	found := false
	for _, c := range list.Collections {
		if c.ID == col.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "created collection should appear in list")

	// Delete
	err = adminClient.EVM.Collections.Delete(ctx, col.ID)
	require.NoError(t, err)

	// Verify deleted
	_, err = adminClient.EVM.Collections.Get(ctx, col.ID)
	require.Error(t, err)
}

// TestCollectionMemberManagement tests adding, listing, and removing members.
func TestCollectionMemberManagement(t *testing.T) {
	ctx := context.Background()

	// Create collection
	col, err := adminClient.EVM.Collections.Create(ctx, &evm.CreateCollectionRequest{
		Name: "E2E Member Test Collection",
	})
	require.NoError(t, err)
	cleanupCollection(t, col.ID)

	walletID := signerAddress

	// Add member
	member, err := adminClient.EVM.Collections.AddMember(ctx, col.ID, &evm.AddCollectionMemberRequest{
		WalletID: walletID,
	})
	require.NoError(t, err)
	require.NotNil(t, member)

	// List members
	members, err := adminClient.EVM.Collections.ListMembers(ctx, col.ID)
	require.NoError(t, err)
	require.NotNil(t, members)
	assert.GreaterOrEqual(t, len(members.Members), 1)
	found := false
	for _, m := range members.Members {
		if m.WalletID == walletID {
			found = true
			break
		}
	}
	assert.True(t, found, "added wallet should be in member list")

	// Remove member
	err = adminClient.EVM.Collections.RemoveMember(ctx, col.ID, walletID)
	require.NoError(t, err)

	// Verify removed
	members, err = adminClient.EVM.Collections.ListMembers(ctx, col.ID)
	require.NoError(t, err)
	for _, m := range members.Members {
		assert.NotEqual(t, walletID, m.WalletID, "removed wallet should not be in member list")
	}
}

// TestCollectionDeleteCascadesMembers verifies that deleting a collection removes its members.
func TestCollectionDeleteCascadesMembers(t *testing.T) {
	ctx := context.Background()

	col, err := adminClient.EVM.Collections.Create(ctx, &evm.CreateCollectionRequest{
		Name: "E2E Cascade Delete Collection",
	})
	require.NoError(t, err)

	// Add a member
	_, err = adminClient.EVM.Collections.AddMember(ctx, col.ID, &evm.AddCollectionMemberRequest{
		WalletID: signerAddress,
	})
	require.NoError(t, err)

	// Delete collection (should cascade)
	err = adminClient.EVM.Collections.Delete(ctx, col.ID)
	require.NoError(t, err)

	// Collection should no longer exist
	_, err = adminClient.EVM.Collections.Get(ctx, col.ID)
	require.Error(t, err)
}

// TestCollectionCreateRequiresName verifies that creating a collection without a name fails.
func TestCollectionCreateRequiresName(t *testing.T) {
	ctx := context.Background()

	_, err := adminClient.EVM.Collections.Create(ctx, &evm.CreateCollectionRequest{
		Name: "",
	})
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 400, apiErr.StatusCode)
}

// TestCollectionGetNotFound verifies that getting a nonexistent collection returns 404.
func TestCollectionGetNotFound(t *testing.T) {
	ctx := context.Background()

	_, err := adminClient.EVM.Collections.Get(ctx, "nonexistent-id-12345")
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 404, apiErr.StatusCode)
}

// TestCollectionStrategyRoleDenied verifies that strategy-role users cannot manage collections.
func TestCollectionStrategyRoleDenied(t *testing.T) {
	if nonAdminClient == nil {
		t.Skip("Skipping: non-admin client not configured")
	}
	ctx := context.Background()

	// Strategy role should not be able to create collections
	_, err := nonAdminClient.EVM.Collections.Create(ctx, &evm.CreateCollectionRequest{
		Name: "E2E Strategy Collection",
	})
	require.Error(t, err)
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode)

	// Strategy role should not be able to list collections
	_, err = nonAdminClient.EVM.Collections.List(ctx, &evm.ListCollectionsFilter{Limit: 100})
	require.Error(t, err)
	apiErr, ok = err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode)

	// Strategy role should not access an admin collection
	adminCol, err := adminClient.EVM.Collections.Create(ctx, &evm.CreateCollectionRequest{
		Name: "E2E Admin Collection for Strategy Test",
	})
	require.NoError(t, err)
	cleanupCollection(t, adminCol.ID)

	_, err = nonAdminClient.EVM.Collections.Get(ctx, adminCol.ID)
	require.Error(t, err)
	apiErr, ok = err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 403, apiErr.StatusCode)
}

// TestNestedCollectionRejected verifies that adding a collection ID as a member is rejected.
func TestNestedCollectionRejected(t *testing.T) {
	ctx := context.Background()

	// Create two collections
	col1, err := adminClient.EVM.Collections.Create(ctx, &evm.CreateCollectionRequest{
		Name: "E2E Parent Collection",
	})
	require.NoError(t, err)
	cleanupCollection(t, col1.ID)

	col2, err := adminClient.EVM.Collections.Create(ctx, &evm.CreateCollectionRequest{
		Name: "E2E Child Collection",
	})
	require.NoError(t, err)
	cleanupCollection(t, col2.ID)

	// Try to add col2 as a member of col1 — should be rejected
	_, err = adminClient.EVM.Collections.AddMember(ctx, col1.ID, &evm.AddCollectionMemberRequest{
		WalletID: col2.ID,
	})
	require.Error(t, err, "adding a collection as a member should be rejected")
	apiErr, ok := err.(*client.APIError)
	require.True(t, ok, "expected APIError, got %T", err)
	assert.Equal(t, 400, apiErr.StatusCode)
}
