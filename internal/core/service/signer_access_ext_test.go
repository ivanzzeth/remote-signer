//go:build integration

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
	"github.com/ivanzzeth/remote-signer/internal/storage"
)

// ---------------------------------------------------------------------------
// TestPatchSignerLabels
// ---------------------------------------------------------------------------

func TestPatchSignerLabels(t *testing.T) {
	db := setupTestDB(t)
	svc, ownershipRepo, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")

	// Set owner
	require.NoError(t, svc.SetOwner(ctx, "0xAAAA", "owner-1", types.SignerOwnershipActive))

	t.Run("no_fields_to_update", func(t *testing.T) {
		err := svc.PatchSignerLabels(ctx, "owner-1", "0xAAAA", types.SignerLabelPatch{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no fields to update")
	})

	t.Run("update_display_name", func(t *testing.T) {
		name := "My Signer"
		err := svc.PatchSignerLabels(ctx, "owner-1", "0xAAAA", types.SignerLabelPatch{
			DisplayName: &name,
		})
		require.NoError(t, err)

		o, err := ownershipRepo.Get(ctx, "0xAAAA")
		require.NoError(t, err)
		assert.Equal(t, "My Signer", o.DisplayName)
	})

	t.Run("update_tags", func(t *testing.T) {
		tags := []string{"production", "critical"}
		err := svc.PatchSignerLabels(ctx, "owner-1", "0xAAAA", types.SignerLabelPatch{
			Tags: &tags,
		})
		require.NoError(t, err)

		o, err := ownershipRepo.Get(ctx, "0xAAAA")
		require.NoError(t, err)
		parsed := types.ParseSignerTagsJSON(o.TagsJSON)
		assert.ElementsMatch(t, []string{"production", "critical"}, parsed)
	})

	t.Run("non_owner_cannot_patch", func(t *testing.T) {
		createTestAPIKey(t, apiKeyRepo, "non-owner", "dev")
		name := "Hacker"
		err := svc.PatchSignerLabels(ctx, "non-owner", "0xAAAA", types.SignerLabelPatch{
			DisplayName: &name,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not the owner")
	})

	t.Run("nonexistent_signer_returns_error", func(t *testing.T) {
		name := "Ghost"
		err := svc.PatchSignerLabels(ctx, "owner-1", "0xNONEXISTENT", types.SignerLabelPatch{
			DisplayName: &name,
		})
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// TestGetOwnership
// ---------------------------------------------------------------------------

func TestGetOwnership(t *testing.T) {
	db := setupTestDB(t)
	svc, ownershipRepo, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")

	t.Run("returns_ownership_when_exists", func(t *testing.T) {
		require.NoError(t, svc.SetOwner(ctx, "0xBBBB", "owner-1", types.SignerOwnershipActive))

		o, err := svc.GetOwnership(ctx, "0xBBBB")
		require.NoError(t, err)
		require.NotNil(t, o)
		assert.Equal(t, "0xBBBB", o.SignerAddress)
		assert.Equal(t, "owner-1", o.OwnerID)
	})

	t.Run("returns_not_found_when_missing", func(t *testing.T) {
		_, err := svc.GetOwnership(ctx, "0xMISSING")
		require.Error(t, err)
		assert.True(t, types.IsNotFound(err))
	})

	// Test GetOwnership also calls through ownershipRepo.Get directly
	t.Run("existing_via_ownership_repo_get", func(t *testing.T) {
		o, err := ownershipRepo.Get(ctx, "0xBBBB")
		require.NoError(t, err)
		assert.Equal(t, "owner-1", o.OwnerID)
	})
}

// ---------------------------------------------------------------------------
// TestCountOwnedHDWallets
// ---------------------------------------------------------------------------

func TestCountOwnedHDWallets(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")

	t.Run("zero_count_when_no_hd_wallets", func(t *testing.T) {
		require.NoError(t, svc.SetOwner(ctx, "0xCCCC", "owner-1", types.SignerOwnershipActive))

		count, err := svc.CountOwnedHDWallets(ctx, "owner-1")
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})

	t.Run("counts_hd_wallets_by_type", func(t *testing.T) {
		// Create HD wallets using SetOwnerWithType
		require.NoError(t, svc.SetOwnerWithType(ctx, "0xHD1", "owner-1", types.SignerOwnershipActive, types.SignerTypeHDWallet))
		require.NoError(t, svc.SetOwnerWithType(ctx, "0xHD2", "owner-1", types.SignerOwnershipActive, types.SignerTypeHDWallet))

		count, err := svc.CountOwnedHDWallets(ctx, "owner-1")
		require.NoError(t, err)
		assert.Equal(t, int64(2), count)
	})

	t.Run("non_existent_owner_returns_zero", func(t *testing.T) {
		count, err := svc.CountOwnedHDWallets(ctx, "nobody")
		require.NoError(t, err)
		assert.Equal(t, int64(0), count)
	})
}

// ---------------------------------------------------------------------------
// TestSetOwnerWithType
// ---------------------------------------------------------------------------

func TestSetOwnerWithType(t *testing.T) {
	db := setupTestDB(t)
	svc, ownershipRepo, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")

	err := svc.SetOwnerWithType(ctx, "0xWALLET1", "owner-1", types.SignerOwnershipActive, types.SignerTypeHDWallet)
	require.NoError(t, err)

	o, err := ownershipRepo.Get(ctx, "0xWALLET1")
	require.NoError(t, err)
	assert.Equal(t, types.SignerTypeHDWallet, o.SignerType)
	assert.Equal(t, "owner-1", o.OwnerID)

	// Verify SetOwner defaults to keystore type
	require.NoError(t, svc.SetOwner(ctx, "0xKEY1", "owner-1", types.SignerOwnershipActive))
	o, err = ownershipRepo.Get(ctx, "0xKEY1")
	require.NoError(t, err)
	assert.Equal(t, types.SignerTypeKeystore, o.SignerType)
}

// ---------------------------------------------------------------------------
// TestNewSignerAccessService_MissingLogger
// ---------------------------------------------------------------------------

func TestNewSignerAccessService_MissingLogger(t *testing.T) {
	db := setupTestDB(t)
	ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	accessRepo, err := storage.NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	apiKeyRepo, err := storage.NewGormAPIKeyRepository(db)
	require.NoError(t, err)

	_, err = NewSignerAccessService(ownershipRepo, accessRepo, apiKeyRepo, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

// ---------------------------------------------------------------------------
// TestNewSignerAccessService_AllValidations
// ---------------------------------------------------------------------------

func TestNewSignerAccessService_AllValidations(t *testing.T) {
	db := setupTestDB(t)

	t.Run("nil_ownership_repo", func(t *testing.T) {
		_, err := NewSignerAccessService(nil, nil, nil, nil, txServiceLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ownership repository is required")
	})

	t.Run("nil_access_repo", func(t *testing.T) {
		ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
		require.NoError(t, err)
		_, err = NewSignerAccessService(ownershipRepo, nil, nil, nil, txServiceLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access repository is required")
	})

	t.Run("nil_api_key_repo", func(t *testing.T) {
		ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
		require.NoError(t, err)
		accessRepo, err := storage.NewGormSignerAccessRepository(db)
		require.NoError(t, err)
		_, err = NewSignerAccessService(ownershipRepo, accessRepo, nil, nil, txServiceLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "API key repository is required")
	})
}

// ---------------------------------------------------------------------------
// TestSignerAccessService_ConstructionValidation
// ---------------------------------------------------------------------------

func TestSignerAccessService_ConstructionValidation(t *testing.T) {
	db := setupTestDB(t)

	t.Run("nil_ownership_repo", func(t *testing.T) {
		_, err := NewSignerAccessService(nil, nil, nil, nil, txServiceLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ownership repository is required")
	})

	t.Run("nil_access_repo", func(t *testing.T) {
		ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
		require.NoError(t, err)
		_, err = NewSignerAccessService(ownershipRepo, nil, nil, nil, txServiceLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access repository is required")
	})

	t.Run("nil_api_key_repo", func(t *testing.T) {
		ownershipRepo, err := storage.NewGormSignerOwnershipRepository(db)
		require.NoError(t, err)
		accessRepo, err := storage.NewGormSignerAccessRepository(db)
		require.NoError(t, err)
		_, err = NewSignerAccessService(ownershipRepo, accessRepo, nil, nil, txServiceLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "API key repository is required")
	})
}

// ---------------------------------------------------------------------------
// TestSetRuleRepo
// ---------------------------------------------------------------------------

func TestSetRuleRepo(t *testing.T) {
	db := setupTestDB(t)
	ruleRepo, err := storage.NewGormRuleRepository(db)
	require.NoError(t, err)
	svc, _, _, _ := setupAccessService(t, db)
	// Should not panic
	svc.SetRuleRepo(ruleRepo)
}

// ---------------------------------------------------------------------------
// TestGrantAccess_NonExistentGrantee
// ---------------------------------------------------------------------------

func TestGrantAccess_NonExistentGrantee(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")
	require.NoError(t, svc.SetOwner(ctx, "0xEEEE", "owner-1", types.SignerOwnershipActive))

	err := svc.GrantAccess(ctx, "owner-1", "0xEEEE", "nonexistent-grantee")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ---------------------------------------------------------------------------
// TestRevokeAccess_NonOwner
// ---------------------------------------------------------------------------

func TestRevokeAccess_NonOwner(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")
	createTestAPIKey(t, apiKeyRepo, "non-owner", "dev")
	require.NoError(t, svc.SetOwner(ctx, "0xFFFF", "owner-1", types.SignerOwnershipActive))

	err := svc.RevokeAccess(ctx, "non-owner", "0xFFFF", "someone")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not the owner")
}

// ---------------------------------------------------------------------------
// TestListAccess_NonOwner
// ---------------------------------------------------------------------------

func TestListAccess_NonOwner(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")
	createTestAPIKey(t, apiKeyRepo, "non-owner", "dev")
	require.NoError(t, svc.SetOwner(ctx, "0xABCD", "owner-1", types.SignerOwnershipActive))

	_, err := svc.ListAccess(ctx, "non-owner", "0xABCD")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not the owner")
}

// ---------------------------------------------------------------------------
// TestDeleteSigner_NonOwner
// ---------------------------------------------------------------------------

func TestDeleteSigner_NonOwner(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")
	createTestAPIKey(t, apiKeyRepo, "non-owner", "dev")
	require.NoError(t, svc.SetOwner(ctx, "0xDEAD", "owner-1", types.SignerOwnershipActive))

	err := svc.DeleteSigner(ctx, "non-owner", "0xDEAD")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not the owner")
}

// ---------------------------------------------------------------------------
// TestTransferOwnership_NonExistentNewOwner
// ---------------------------------------------------------------------------

func TestTransferOwnership_NonExistentNewOwner(t *testing.T) {
	db := setupTestDB(t)
	svc, _, _, apiKeyRepo := setupAccessService(t, db)
	ctx := context.Background()

	createTestAPIKey(t, apiKeyRepo, "owner-1", "admin")
	require.NoError(t, svc.SetOwner(ctx, "0xBEEF", "owner-1", types.SignerOwnershipActive))

	err := svc.TransferOwnership(ctx, "owner-1", "0xBEEF", "nonexistent-owner")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
