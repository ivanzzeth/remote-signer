package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

// newIntegrationDB creates an isolated in-memory SQLite DB with all models
// auto-migrated. Each test gets its own DB via t.Name() so parallel tests
// don't share state.
func newIntegrationDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&types.Signer{},
		&types.SignerOwnership{},
		&types.SignerAccess{},
		&types.RulePreset{},
		&types.Transaction{},
		&types.Rule{},
		&types.RuleTemplate{},
		&types.RuleBudget{},
		&types.AuditRecord{},
		&types.RequestSimulation{},
		&types.SignRequest{},
	))
	return db
}

// ---------------------------------------------------------------------------
// Signer repository tests
// ---------------------------------------------------------------------------

func TestGormSignerRepo_New_NilDB(t *testing.T) {
	repo, err := NewGormSignerRepository(nil)
	assert.Nil(t, repo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection is required")
}

func TestGormSignerRepo_UpsertAndGet(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	idx := uint32(0)
	signer := &types.Signer{
		Address:           "0x1111111111111111111111111111111111111111",
		Type:              types.SignerTypeHDWallet,
		PrimaryAddress:    "0x1111111111111111111111111111111111111111",
		HDDerivationIndex: &idx,
		Enabled:           true,
		Locked:            false,
		MaterialStatus:    types.SignerMaterialStatusPresent,
	}

	require.NoError(t, repo.Upsert(ctx, signer))

	got, err := repo.Get(ctx, "0x1111111111111111111111111111111111111111")
	require.NoError(t, err)
	assert.Equal(t, "0x1111111111111111111111111111111111111111", got.Address)
	assert.Equal(t, types.SignerTypeHDWallet, got.Type)
	assert.True(t, got.Enabled)
}

func TestGormSignerRepo_Upsert_UpdatesExisting(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	idx := uint32(0)
	signer := &types.Signer{
		Address:           "0x2222222222222222222222222222222222222222",
		Type:              types.SignerTypePrivateKey,
		PrimaryAddress:    "0x2222222222222222222222222222222222222222",
		HDDerivationIndex: &idx,
		Enabled:           true,
		MaterialStatus:    types.SignerMaterialStatusPresent,
	}
	require.NoError(t, repo.Upsert(ctx, signer))

	// Update fields via Upsert (ON CONFLICT DO UPDATE)
	idx2 := uint32(1)
	signer.HDDerivationIndex = &idx2
	signer.Locked = true
	require.NoError(t, repo.Upsert(ctx, signer))

	got, err := repo.Get(ctx, "0x2222222222222222222222222222222222222222")
	require.NoError(t, err)
	assert.Equal(t, uint32(1), *got.HDDerivationIndex)
	assert.True(t, got.Locked)
}

func TestGormSignerRepo_Get_NotFound(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerRepository(db)
	require.NoError(t, err)

	_, err = repo.Get(context.Background(), "0x0000000000000000000000000000000000000000")
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormSignerRepo_List_WithTypeFilter(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		addr := fmt.Sprintf("0x%040x", i+1)
		signerType := types.SignerTypePrivateKey
		if i >= 3 {
			signerType = types.SignerTypeKeystore
		}
		require.NoError(t, repo.Upsert(ctx, &types.Signer{
			Address:        addr,
			Type:           signerType,
			PrimaryAddress: addr,
			Enabled:        true,
			MaterialStatus: types.SignerMaterialStatusPresent,
		}))
	}

	pkType := types.SignerTypePrivateKey
	signers, total, err := repo.List(ctx, SignerListFilter{Type: &pkType})
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Len(t, signers, 3)
}

func TestGormSignerRepo_List_DefaultLimit(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	for i := 0; i < 60; i++ {
		addr := fmt.Sprintf("0x%040x", i+1)
		require.NoError(t, repo.Upsert(ctx, &types.Signer{
			Address:        addr,
			Type:           types.SignerTypePrivateKey,
			PrimaryAddress: addr,
			Enabled:        true,
			MaterialStatus: types.SignerMaterialStatusPresent,
		}))
	}

	signers, total, err := repo.List(ctx, SignerListFilter{})
	require.NoError(t, err)
	assert.Equal(t, 60, total)
	assert.Len(t, signers, 50) // default limit
}

func TestGormSignerRepo_Delete(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, repo.Upsert(ctx, &types.Signer{
		Address:        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Type:           types.SignerTypePrivateKey,
		PrimaryAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Enabled:        true,
		MaterialStatus: types.SignerMaterialStatusPresent,
	}))

	require.NoError(t, repo.Delete(ctx, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))

	_, err = repo.Get(ctx, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormSignerRepo_Delete_NotFound(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerRepository(db)
	require.NoError(t, err)

	err = repo.Delete(context.Background(), "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormSignerRepo_UpdateMaterialStatus(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, repo.Upsert(ctx, &types.Signer{
		Address:        "0xcccccccccccccccccccccccccccccccccccccccc",
		Type:           types.SignerTypeKeystore,
		PrimaryAddress: "0xcccccccccccccccccccccccccccccccccccccccc",
		Enabled:        true,
		MaterialStatus: types.SignerMaterialStatusPresent,
	}))

	now := time.Now().UTC()
	missingAt := now.Add(-1 * time.Hour)
	require.NoError(t, repo.UpdateMaterialStatus(ctx,
		"0xcccccccccccccccccccccccccccccccccccccccc",
		types.SignerMaterialStatusMissing, now, &missingAt, "file not found"))

	got, err := repo.Get(ctx, "0xcccccccccccccccccccccccccccccccccccccccc")
	require.NoError(t, err)
	assert.Equal(t, types.SignerMaterialStatusMissing, got.MaterialStatus)
	assert.Equal(t, "file not found", got.MaterialError)
}

func TestGormSignerRepo_UpdateMaterialStatus_NotFound(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerRepository(db)
	require.NoError(t, err)

	err = repo.UpdateMaterialStatus(context.Background(),
		"0xdddddddddddddddddddddddddddddddddddddddd",
		types.SignerMaterialStatusPresent, time.Now(), nil, "")
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormSignerRepo_Upsert_NilSigner(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerRepository(db)
	require.NoError(t, err)

	err = repo.Upsert(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signer cannot be nil")
}

// ---------------------------------------------------------------------------
// Signer ownership repository tests
// ---------------------------------------------------------------------------

func TestGormSignerOwnershipRepo_New_NilDB(t *testing.T) {
	repo, err := NewGormSignerOwnershipRepository(nil)
	assert.Nil(t, repo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection is required")
}

func TestGormSignerOwnershipRepo_UpsertAndGet(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	ownership := &types.SignerOwnership{
		SignerAddress: "0x1111111111111111111111111111111111111111",
		OwnerID:       "key-owner-1",
		SignerType:    types.SignerTypeHDWallet,
		Status:        types.SignerOwnershipActive,
		DisplayName:   "test-signer",
		TagsJSON:      types.FormatSignerTagsJSON([]string{"tag1", "tag2"}),
	}
	require.NoError(t, repo.Upsert(ctx, ownership))

	got, err := repo.Get(ctx, "0x1111111111111111111111111111111111111111")
	require.NoError(t, err)
	assert.Equal(t, "key-owner-1", got.OwnerID)
	assert.Equal(t, []string{"tag1", "tag2"}, got.Tags())
}

func TestGormSignerOwnershipRepo_Get_NotFound(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)

	_, err = repo.Get(context.Background(), "0x0000000000000000000000000000000000000000")
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormSignerOwnershipRepo_GetBoth(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, repo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		OwnerID:       "key-a",
		SignerType:    types.SignerTypePrivateKey,
		Status:        types.SignerOwnershipActive,
	}))
	require.NoError(t, repo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		OwnerID:       "key-b",
		SignerType:    types.SignerTypePrivateKey,
		Status:        types.SignerOwnershipActive,
	}))

	sender, recipient, err := repo.GetBoth(ctx,
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	require.NoError(t, err)
	require.NotNil(t, sender)
	require.NotNil(t, recipient)
	assert.Equal(t, "key-a", sender.OwnerID)
	assert.Equal(t, "key-b", recipient.OwnerID)
}

func TestGormSignerOwnershipRepo_GetBoth_PartialMissing(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, repo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		OwnerID:       "key-a",
		SignerType:    types.SignerTypePrivateKey,
		Status:        types.SignerOwnershipActive,
	}))

	// Recipient does not exist — sender should still be returned
	sender, recipient, err := repo.GetBoth(ctx,
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	require.NoError(t, err)
	require.NotNil(t, sender)
	assert.Nil(t, recipient)
}

func TestGormSignerOwnershipRepo_GetByOwner(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("0x%040x", i+100)
		require.NoError(t, repo.Upsert(ctx, &types.SignerOwnership{
			SignerAddress: addr,
			OwnerID:       "shared-owner",
			SignerType:    types.SignerTypePrivateKey,
			Status:        types.SignerOwnershipActive,
		}))
	}

	results, err := repo.GetByOwner(ctx, "shared-owner")
	require.NoError(t, err)
	assert.Len(t, results, 3)
}

func TestGormSignerOwnershipRepo_Delete(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, repo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: "0xdddddddddddddddddddddddddddddddddddddddd",
		OwnerID:       "key-del",
		SignerType:    types.SignerTypePrivateKey,
		Status:        types.SignerOwnershipActive,
	}))

	require.NoError(t, repo.Delete(ctx, "0xdddddddddddddddddddddddddddddddddddddddd"))

	_, err = repo.Get(ctx, "0xdddddddddddddddddddddddddddddddddddddddd")
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormSignerOwnershipRepo_Delete_NotFound(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)

	err = repo.Delete(context.Background(), "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormSignerOwnershipRepo_UpdateOwner(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, repo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: "0xffffffffffffffffffffffffffffffffffffffff",
		OwnerID:       "old-owner",
		SignerType:    types.SignerTypePrivateKey,
		Status:        types.SignerOwnershipActive,
	}))

	require.NoError(t, repo.UpdateOwner(ctx, "0xffffffffffffffffffffffffffffffffffffffff", "new-owner"))

	got, err := repo.Get(ctx, "0xffffffffffffffffffffffffffffffffffffffff")
	require.NoError(t, err)
	assert.Equal(t, "new-owner", got.OwnerID)
}

func TestGormSignerOwnershipRepo_UpdateOwner_NotFound(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)

	err = repo.UpdateOwner(context.Background(), "0x0000000000000000000000000000000000000000", "any-owner")
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormSignerOwnershipRepo_CountByOwner(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("0x%040x", i+200)
		require.NoError(t, repo.Upsert(ctx, &types.SignerOwnership{
			SignerAddress: addr,
			OwnerID:       "count-owner",
			SignerType:    types.SignerTypePrivateKey,
			Status:        types.SignerOwnershipActive,
		}))
	}

	count, err := repo.CountByOwner(ctx, "count-owner")
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestGormSignerOwnershipRepo_CountByOwnerAndType(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("0x%040x", i+300)
		require.NoError(t, repo.Upsert(ctx, &types.SignerOwnership{
			SignerAddress: addr,
			OwnerID:       "ct-owner",
			SignerType:    types.SignerTypeHDWallet,
			Status:        types.SignerOwnershipActive,
		}))
	}
	// Add one more of a different type
	require.NoError(t, repo.Upsert(ctx, &types.SignerOwnership{
		SignerAddress: "0x3333333333333333333333333333333333333333",
		OwnerID:       "ct-owner",
		SignerType:    types.SignerTypePrivateKey,
		Status:        types.SignerOwnershipActive,
	}))

	count, err := repo.CountByOwnerAndType(ctx, "ct-owner", types.SignerTypeHDWallet)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestGormSignerOwnershipRepo_RunInTransaction(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerOwnershipRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	err = repo.RunInTransaction(ctx, func(txOwnership SignerOwnershipRepository, txAccess SignerAccessRepository) error {
		require.NoError(t, txOwnership.Upsert(ctx, &types.SignerOwnership{
			SignerAddress: "0x4444444444444444444444444444444444444444",
			OwnerID:       "tx-owner",
			SignerType:    types.SignerTypePrivateKey,
			Status:        types.SignerOwnershipActive,
		}))
		require.NoError(t, txAccess.Grant(ctx, &types.SignerAccess{
			SignerAddress: "0x4444444444444444444444444444444444444444",
			APIKeyID:      "tx-key",
			GrantedBy:     "tx-owner",
		}))
		return nil
	})
	require.NoError(t, err)

	// Verify both were persisted
	got, err := repo.Get(ctx, "0x4444444444444444444444444444444444444444")
	require.NoError(t, err)
	assert.Equal(t, "tx-owner", got.OwnerID)

	accessRepo, err := NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	has, err := accessRepo.HasAccess(ctx, "0x4444444444444444444444444444444444444444", "tx-key")
	require.NoError(t, err)
	assert.True(t, has)
}

// ---------------------------------------------------------------------------
// Signer access repository tests
// ---------------------------------------------------------------------------

func TestGormSignerAccessRepo_Revoke(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, repo.Grant(ctx, &types.SignerAccess{
		SignerAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		APIKeyID:      "key-a",
		GrantedBy:     "admin",
	}))

	require.NoError(t, repo.Revoke(ctx, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "key-a"))

	has, err := repo.HasAccess(ctx, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "key-a")
	require.NoError(t, err)
	assert.False(t, has)
}

func TestGormSignerAccessRepo_Revoke_NotFound(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	err = repo.Revoke(context.Background(), "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "no-such-key")
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormSignerAccessRepo_List(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		apiKeyID := fmt.Sprintf("key-list-%d", i)
		require.NoError(t, repo.Grant(ctx, &types.SignerAccess{
			SignerAddress: "0xcccccccccccccccccccccccccccccccccccccccc",
			APIKeyID:      apiKeyID,
			GrantedBy:     "admin",
		}))
	}

	accesses, err := repo.List(ctx, "0xcccccccccccccccccccccccccccccccccccccccc")
	require.NoError(t, err)
	assert.Len(t, accesses, 3)
}

func TestGormSignerAccessRepo_HasAccess(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, repo.Grant(ctx, &types.SignerAccess{
		SignerAddress: "0xdddddddddddddddddddddddddddddddddddddddd",
		APIKeyID:      "key-has",
		GrantedBy:     "admin",
	}))

	has, err := repo.HasAccess(ctx, "0xdddddddddddddddddddddddddddddddddddddddd", "key-has")
	require.NoError(t, err)
	assert.True(t, has)

	has, err = repo.HasAccess(ctx, "0xdddddddddddddddddddddddddddddddddddddddd", "other-key")
	require.NoError(t, err)
	assert.False(t, has)
}

func TestGormSignerAccessRepo_HasAccessViaWallet(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, repo.Grant(ctx, &types.SignerAccess{
		SignerAddress: "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		APIKeyID:      "key-wallet",
		GrantedBy:     "admin",
		WalletID:      "wallet-1",
	}))

	has, err := repo.HasAccessViaWallet(ctx, "key-wallet", "wallet-1")
	require.NoError(t, err)
	assert.True(t, has)

	has, err = repo.HasAccessViaWallet(ctx, "key-wallet", "wallet-other")
	require.NoError(t, err)
	assert.False(t, has)
}

func TestGormSignerAccessRepo_DeleteBySigner(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, repo.Grant(ctx, &types.SignerAccess{
		SignerAddress: "0xffffffffffffffffffffffffffffffffffffffff",
		APIKeyID:      "key-ds",
		GrantedBy:     "admin",
	}))

	require.NoError(t, repo.DeleteBySigner(ctx, "0xffffffffffffffffffffffffffffffffffffffff"))

	accesses, err := repo.List(ctx, "0xffffffffffffffffffffffffffffffffffffffff")
	require.NoError(t, err)
	assert.Empty(t, accesses)
}

func TestGormSignerAccessRepo_DeleteByAPIKey(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("0x%040x", i+500)
		require.NoError(t, repo.Grant(ctx, &types.SignerAccess{
			SignerAddress: addr,
			APIKeyID:      "key-to-delete",
			GrantedBy:     "admin",
		}))
	}

	require.NoError(t, repo.DeleteByAPIKey(ctx, "key-to-delete"))

	// All access rows for the deleted API key should be gone
	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("0x%040x", i+500)
		has, err := repo.HasAccess(ctx, addr, "key-to-delete")
		require.NoError(t, err)
		assert.False(t, has)
	}
}

func TestGormSignerAccessRepo_ListAccessibleAddresses(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormSignerAccessRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		addr := fmt.Sprintf("0x%040x", i+600)
		require.NoError(t, repo.Grant(ctx, &types.SignerAccess{
			SignerAddress: addr,
			APIKeyID:      "key-list-addr",
			GrantedBy:     "admin",
		}))
	}

	addrs, err := repo.ListAccessibleAddresses(ctx, "key-list-addr")
	require.NoError(t, err)
	assert.Len(t, addrs, 3)
}

// ---------------------------------------------------------------------------
// Preset repository tests
// ---------------------------------------------------------------------------

func TestGormPresetRepo_New_NilDB(t *testing.T) {
	repo, err := NewGormPresetRepository(nil)
	assert.Nil(t, repo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection is required")
}

func TestGormPresetRepo_CreateAndGet(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormPresetRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	preset := &types.RulePreset{
		ID:      "preset-1",
		Name:    "Test Preset",
		Enabled: true,
		Source:  types.RuleSourceFile,
	}
	require.NoError(t, repo.Create(ctx, preset))

	got, err := repo.Get(ctx, "preset-1")
	require.NoError(t, err)
	assert.Equal(t, "Test Preset", got.Name)
	assert.Equal(t, types.RuleSourceFile, got.Source)
}

func TestGormPresetRepo_Get_NotFound(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormPresetRepository(db)
	require.NoError(t, err)

	_, err = repo.Get(context.Background(), "no-such-preset")
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormPresetRepo_Update(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormPresetRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.RulePreset{
		ID:      "preset-update",
		Name:    "Original",
		Source:  types.RuleSourceAPI,
		Enabled: true,
	}))

	require.NoError(t, repo.Update(ctx, &types.RulePreset{
		ID:      "preset-update",
		Name:    "Updated",
		Source:  types.RuleSourceAPI,
		Enabled: false,
	}))

	got, err := repo.Get(ctx, "preset-update")
	require.NoError(t, err)
	assert.Equal(t, "Updated", got.Name)
	assert.False(t, got.Enabled)
}

func TestGormPresetRepo_Delete(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormPresetRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.RulePreset{
		ID:      "preset-del",
		Name:    "Delete me",
		Source:  types.RuleSourceConfig,
		Enabled: true,
	}))

	require.NoError(t, repo.Delete(ctx, "preset-del"))

	_, err = repo.Get(ctx, "preset-del")
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormPresetRepo_Delete_NotFound(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormPresetRepository(db)
	require.NoError(t, err)

	err = repo.Delete(context.Background(), "no-such-preset")
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormPresetRepo_ListAndCount(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormPresetRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	evm := types.ChainTypeEVM
	for i := 0; i < 5; i++ {
		require.NoError(t, repo.Create(ctx, &types.RulePreset{
			ID:        fmt.Sprintf("preset-list-%d", i),
			Name:      fmt.Sprintf("Preset %d", i),
			ChainType: evm,
			Source:    types.RuleSourceFile,
			Enabled:   true,
		}))
	}

	allPresets, err := repo.List(ctx, PresetFilter{})
	require.NoError(t, err)
	assert.Len(t, allPresets, 5)

	ct := types.ChainTypeEVM
	filtered, err := repo.List(ctx, PresetFilter{ChainType: &ct})
	require.NoError(t, err)
	assert.Len(t, filtered, 5)

	count, err := repo.Count(ctx, PresetFilter{ChainType: &ct})
	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestGormPresetRepo_Upsert_New(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormPresetRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	changed, err := repo.Upsert(ctx, &types.RulePreset{
		ID:          "preset-upsert-new",
		Name:        "New Preset",
		Source:      types.RuleSourceFile,
		Enabled:     true,
		ContentHash: "abc123",
	})
	require.NoError(t, err)
	assert.True(t, changed)
}

func TestGormPresetRepo_Upsert_ExistingSameHash(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormPresetRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.RulePreset{
		ID:          "preset-upsert-same",
		Name:        "Existing",
		Source:      types.RuleSourceFile,
		Enabled:     true,
		ContentHash: "samehash",
	}))

	changed, err := repo.Upsert(ctx, &types.RulePreset{
		ID:          "preset-upsert-same",
		Name:        "Existing",
		Source:      types.RuleSourceFile,
		Enabled:     true,
		ContentHash: "samehash",
	})
	require.NoError(t, err)
	assert.False(t, changed)
}

func TestGormPresetRepo_Upsert_ExistingDifferentHash(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormPresetRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.RulePreset{
		ID:          "preset-upsert-diff",
		Name:        "Old",
		Source:      types.RuleSourceFile,
		Enabled:     true,
		ContentHash: "oldhash",
	}))

	changed, err := repo.Upsert(ctx, &types.RulePreset{
		ID:          "preset-upsert-diff",
		Name:        "Updated",
		Source:      types.RuleSourceFile,
		Enabled:     true,
		ContentHash: "newhash",
	})
	require.NoError(t, err)
	assert.True(t, changed)

	got, err := repo.Get(ctx, "preset-upsert-diff")
	require.NoError(t, err)
	assert.Equal(t, "Updated", got.Name)
}

func TestGormPresetRepo_Upsert_Nil(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormPresetRepository(db)
	require.NoError(t, err)

	_, err = repo.Upsert(context.Background(), nil)
	require.Error(t, err)
}

func TestGormPresetRepo_Upsert_EmptyID(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormPresetRepository(db)
	require.NoError(t, err)

	_, err = repo.Upsert(context.Background(), &types.RulePreset{Name: "No ID"})
	require.Error(t, err)
}

func TestGormPresetRepo_ListIDsBySource(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormPresetRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		require.NoError(t, repo.Create(ctx, &types.RulePreset{
			ID:      fmt.Sprintf("preset-src-%d", i),
			Name:    fmt.Sprintf("Source %d", i),
			Source:  types.RuleSourceFile,
			Enabled: true,
		}))
	}

	ids, err := repo.ListIDsBySource(ctx, types.RuleSourceFile)
	require.NoError(t, err)
	assert.Len(t, ids, 3)
}

func TestGormPresetRepo_DeleteMany(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormPresetRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		require.NoError(t, repo.Create(ctx, &types.RulePreset{
			ID:      fmt.Sprintf("preset-dm-%d", i),
			Name:    fmt.Sprintf("DM %d", i),
			Source:  types.RuleSourceConfig,
			Enabled: true,
		}))
	}

	require.NoError(t, repo.DeleteMany(ctx, []string{"preset-dm-0", "preset-dm-1"}))

	_, err = repo.Get(ctx, "preset-dm-0")
	require.ErrorIs(t, err, types.ErrNotFound)
	_, err = repo.Get(ctx, "preset-dm-1")
	require.ErrorIs(t, err, types.ErrNotFound)

	// The third one should still exist
	got, err := repo.Get(ctx, "preset-dm-2")
	require.NoError(t, err)
	assert.Equal(t, "DM 2", got.Name)
}

func TestGormPresetRepo_DeleteMany_Empty(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormPresetRepository(db)
	require.NoError(t, err)

	// Should not error
	require.NoError(t, repo.DeleteMany(context.Background(), nil))
	require.NoError(t, repo.DeleteMany(context.Background(), []string{}))
}

// ---------------------------------------------------------------------------
// Transaction repository tests
// ---------------------------------------------------------------------------

func TestGormTransactionRepo_New_NilDB(t *testing.T) {
	repo, err := NewGormTransactionRepository(nil)
	assert.Nil(t, repo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection is required")
}

func TestGormTransactionRepo_Get(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormTransactionRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	tx := &types.Transaction{
		ID:            "tx-1",
		ChainID:       "1",
		TxHash:        "0xabc",
		FromAddress:   "0x1111111111111111111111111111111111111111",
		Status:        types.TxStatusBroadcasted,
		BroadcastedAt: time.Now(),
	}
	require.NoError(t, repo.Create(ctx, tx))

	got, err := repo.Get(ctx, "tx-1")
	require.NoError(t, err)
	assert.Equal(t, "0xabc", got.TxHash)
}

func TestGormTransactionRepo_Get_NotFound(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormTransactionRepository(db)
	require.NoError(t, err)

	_, err = repo.Get(context.Background(), "no-such-tx")
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormTransactionRepo_Count(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormTransactionRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	broadcasted := types.TxStatusBroadcasted
	for i := 0; i < 3; i++ {
		require.NoError(t, repo.Create(ctx, &types.Transaction{
			ID:            fmt.Sprintf("tx-cnt-%d", i),
			ChainID:       "1",
			TxHash:        fmt.Sprintf("0x%x", i+100),
			FromAddress:   "0x1111111111111111111111111111111111111111",
			Status:        types.TxStatusBroadcasted,
			BroadcastedAt: time.Now(),
		}))
	}

	count, err := repo.Count(ctx, types.TransactionFilter{})
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	// Filter by status
	count, err = repo.Count(ctx, types.TransactionFilter{Status: &broadcasted})
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	// Filter by chain ID
	count, err = repo.Count(ctx, types.TransactionFilter{ChainID: "1"})
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	// Non-matching filter
	mined := types.TxStatusMined
	count, err = repo.Count(ctx, types.TransactionFilter{Status: &mined})
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestGormTransactionRepo_Update(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormTransactionRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	blockNum := uint64(42)
	tx := &types.Transaction{
		ID:            "tx-upd",
		ChainID:       "137",
		TxHash:        "0xdeadbeef",
		FromAddress:   "0x2222222222222222222222222222222222222222",
		Status:        types.TxStatusBroadcasted,
		BroadcastedAt: time.Now(),
	}
	require.NoError(t, repo.Create(ctx, tx))

	now := time.Now()
	tx.Status = types.TxStatusMined
	tx.BlockNumber = &blockNum
	tx.MinedAt = &now
	require.NoError(t, repo.Update(ctx, tx))

	got, err := repo.Get(ctx, "tx-upd")
	require.NoError(t, err)
	assert.Equal(t, types.TxStatusMined, got.Status)
	require.NotNil(t, got.BlockNumber)
	assert.Equal(t, uint64(42), *got.BlockNumber)
}

func TestGormTransactionRepo_Update_Nil(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormTransactionRepository(db)
	require.NoError(t, err)

	err = repo.Update(context.Background(), nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// Request repository tests
// ---------------------------------------------------------------------------

func TestGormRequestRepo_UpdateLastNoMatchReason(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormRequestRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	req := &types.SignRequest{
		ID:        "req-nomatch-1",
		APIKeyID:  "key-1",
		ChainType: types.ChainTypeEVM,
		ChainID:   "1",
		Status:    types.StatusPending,
	}
	require.NoError(t, repo.Create(ctx, req))

	require.NoError(t, repo.UpdateLastNoMatchReason(ctx, "req-nomatch-1", "no rule matched: all rules skipped"))

	got, err := repo.Get(ctx, "req-nomatch-1")
	require.NoError(t, err)
	assert.Equal(t, "no rule matched: all rules skipped", got.LastNoMatchReason)
}

func TestGormRequestRepo_LookupBySignedData_Found(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormRequestRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	signedData := []byte("signed-tx-bytes-123")
	req := &types.SignRequest{
		ID:         "req-lookup-1",
		APIKeyID:   "key-lookup",
		ChainType:  types.ChainTypeEVM,
		ChainID:    "1",
		Status:     types.StatusCompleted,
		SignedData: signedData,
		CompletedAt: func() *time.Time { t := time.Now(); return &t }(),
	}
	require.NoError(t, repo.Create(ctx, req))

	got, err := repo.LookupBySignedData(ctx, signedData)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "req-lookup-1", string(got.ID))
}

func TestGormRequestRepo_LookupBySignedData_NotFound(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormRequestRepository(db)
	require.NoError(t, err)

	_, err = repo.LookupBySignedData(context.Background(), []byte("no-such-data"))
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormRequestRepo_LookupBySignedData_EmptyBytes(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormRequestRepository(db)
	require.NoError(t, err)

	_, err = repo.LookupBySignedData(context.Background(), []byte{})
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestGormRequestRepo_SetTransactionID(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormRequestRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	req := &types.SignRequest{
		ID:        "req-set-tx-1",
		APIKeyID:  "key-1",
		ChainType: types.ChainTypeEVM,
		ChainID:   "1",
		Status:    types.StatusCompleted,
	}
	require.NoError(t, repo.Create(ctx, req))

	require.NoError(t, repo.SetTransactionID(ctx, "req-set-tx-1", "tx-abc-123"))

	got, err := repo.Get(ctx, "req-set-tx-1")
	require.NoError(t, err)
	require.NotNil(t, got.TransactionID)
	assert.Equal(t, "tx-abc-123", *got.TransactionID)
}

func TestGormRequestRepo_SetTransactionID_NotFound(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormRequestRepository(db)
	require.NoError(t, err)

	err = repo.SetTransactionID(context.Background(), "no-such-req", "tx-any")
	require.ErrorIs(t, err, types.ErrNotFound)
}

// ---------------------------------------------------------------------------
// Budget repository tests
// ---------------------------------------------------------------------------

func TestGormBudgetRepo_CreateOrGet_CreatesNew(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormBudgetRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	budget := &types.RuleBudget{
		ID:       types.BudgetID("rule-1", "eth"),
		RuleID:   "rule-1",
		Unit:     "eth",
		MaxTotal: "1000",
		MaxPerTx: "100",
		Spent:    "0",
	}

	got, created, err := repo.CreateOrGet(ctx, budget)
	require.NoError(t, err)
	assert.True(t, created)
	assert.Equal(t, "1000", got.MaxTotal)
}

func TestGormBudgetRepo_CreateOrGet_ReturnsExisting(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormBudgetRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	budget := &types.RuleBudget{
		ID:       types.BudgetID("rule-2", "usdc"),
		RuleID:   "rule-2",
		Unit:     "usdc",
		MaxTotal: "5000",
		MaxPerTx: "500",
		Spent:    "0",
	}
	require.NoError(t, repo.Create(ctx, budget))

	// Try CreateOrGet again — should return existing
	got, created, err := repo.CreateOrGet(ctx, budget)
	require.NoError(t, err)
	assert.False(t, created)
	assert.Equal(t, "5000", got.MaxTotal)
}

func TestGormBudgetRepo_CreateOrGet_NilBudget(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormBudgetRepository(db)
	require.NoError(t, err)

	_, _, err = repo.CreateOrGet(context.Background(), nil)
	require.Error(t, err)
}

func TestGormBudgetRepo_CountByRuleID(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormBudgetRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	for _, unit := range []string{"eth", "usdc", "dai"} {
		require.NoError(t, repo.Create(ctx, &types.RuleBudget{
			ID:     types.BudgetID("rule-bgt", unit),
			RuleID: "rule-bgt",
			Unit:   unit,
		}))
	}

	count, err := repo.CountByRuleID(ctx, "rule-bgt")
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestGormBudgetRepo_CountByRuleID_Empty(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormBudgetRepository(db)
	require.NoError(t, err)

	count, err := repo.CountByRuleID(context.Background(), "no-such-rule")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// ---------------------------------------------------------------------------
// Audit repository tests
// ---------------------------------------------------------------------------

func TestGormAuditRepo_DeleteOlderThan(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormAuditRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	now := time.Now()
	// Old records
	for i := 0; i < 3; i++ {
		require.NoError(t, repo.Log(ctx, &types.AuditRecord{
			ID:        types.AuditID(fmt.Sprintf("audit-old-%d", i)),
			EventType: types.AuditEventTypeSignRequest,
			Severity:  types.AuditSeverityInfo,
			Timestamp: now.Add(-2 * time.Hour),
			APIKeyID:  "key-1",
		}))
	}
	// Recent record
	require.NoError(t, repo.Log(ctx, &types.AuditRecord{
		ID:        "audit-recent",
		EventType: types.AuditEventTypeSignRequest,
		Severity:  types.AuditSeverityInfo,
		Timestamp: now,
		APIKeyID:  "key-1",
	}))

	deleted, err := repo.DeleteOlderThan(ctx, now.Add(-1*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(3), deleted)

	// Verify only the recent one remains
	records, err := repo.Query(ctx, AuditFilter{})
	require.NoError(t, err)
	assert.Len(t, records, 1)
}

func TestGormAuditRepo_DeleteOlderThan_NoneToDelete(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormAuditRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, repo.Log(ctx, &types.AuditRecord{
		ID:        "audit-future",
		EventType: types.AuditEventTypeSignRequest,
		Severity:  types.AuditSeverityInfo,
		Timestamp: time.Now(),
		APIKeyID:  "key-1",
	}))

	deleted, err := repo.DeleteOlderThan(ctx, time.Now().Add(-24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted)
}

// ---------------------------------------------------------------------------
// Rule repository tests
// ---------------------------------------------------------------------------

func TestGormRuleRepo_RunInTransaction_Success(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormRuleRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	err = repo.RunInTransaction(ctx, func(txRepo RuleRepository) error {
		require.NoError(t, txRepo.Create(ctx, &types.Rule{
			ID:   "rule-tx-1",
			Type: types.RuleTypeSignerRestriction,
			Name: "tx rule 1",
		}))
		require.NoError(t, txRepo.Create(ctx, &types.Rule{
			ID:   "rule-tx-2",
			Type: types.RuleTypeSignerRestriction,
			Name: "tx rule 2",
		}))
		return nil
	})
	require.NoError(t, err)

	// Verify both rules were created
	rules, err := repo.List(ctx, RuleFilter{})
	require.NoError(t, err)
	assert.Len(t, rules, 2)
}

func TestGormRuleRepo_RunInTransaction_Rollback(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormRuleRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	err = repo.RunInTransaction(ctx, func(txRepo RuleRepository) error {
		require.NoError(t, txRepo.Create(ctx, &types.Rule{
			ID:   "rule-rollback-1",
			Type: types.RuleTypeSignerRestriction,
			Name: "will be rolled back",
		}))
		// Return an error to trigger rollback
		return fmt.Errorf("something went wrong")
	})
	require.Error(t, err)

	// No rules should have been created
	rules, err := repo.List(ctx, RuleFilter{})
	require.NoError(t, err)
	assert.Empty(t, rules)
}

// ---------------------------------------------------------------------------
// Template repository tests
// ---------------------------------------------------------------------------

func TestGormTemplateRepo_ListIDsBySource(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormTemplateRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		require.NoError(t, repo.Create(ctx, &types.RuleTemplate{
			ID:     fmt.Sprintf("tmpl-src-%d", i),
			Name:   fmt.Sprintf("Template %d", i),
			Type:   types.RuleTypeMessagePattern,
			Mode:   types.RuleModeWhitelist,
			Source: types.RuleSourceFile,
		}))
	}

	// Add one with a different source
	require.NoError(t, repo.Create(ctx, &types.RuleTemplate{
		ID:     "tmpl-api",
		Name:   "API Template",
		Type:   types.RuleTypeMessagePattern,
		Mode:   types.RuleModeWhitelist,
		Source: types.RuleSourceAPI,
	}))

	ids, err := repo.ListIDsBySource(ctx, types.RuleSourceFile)
	require.NoError(t, err)
	assert.Len(t, ids, 3)

	apiIDs, err := repo.ListIDsBySource(ctx, types.RuleSourceAPI)
	require.NoError(t, err)
	assert.Len(t, apiIDs, 1)
	assert.Equal(t, "tmpl-api", apiIDs[0])
}

func TestGormTemplateRepo_DeleteMany(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormTemplateRepository(db)
	require.NoError(t, err)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		require.NoError(t, repo.Create(ctx, &types.RuleTemplate{
			ID:     fmt.Sprintf("tmpl-dm-%d", i),
			Name:   fmt.Sprintf("DM Template %d", i),
			Type:   types.RuleTypeSignerRestriction,
			Mode:   types.RuleModeWhitelist,
			Source: types.RuleSourceFile,
		}))
	}

	require.NoError(t, repo.DeleteMany(ctx, []string{"tmpl-dm-0", "tmpl-dm-2"}))

	_, err = repo.Get(ctx, "tmpl-dm-0")
	require.ErrorIs(t, err, types.ErrNotFound)

	// tmpl-dm-1 should still exist
	got, err := repo.Get(ctx, "tmpl-dm-1")
	require.NoError(t, err)
	assert.Equal(t, "DM Template 1", got.Name)

	// Verify count after deletion
	count, err := repo.Count(ctx, TemplateFilter{})
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestGormTemplateRepo_DeleteMany_Empty(t *testing.T) {
	db := newIntegrationDB(t)
	repo, err := NewGormTemplateRepository(db)
	require.NoError(t, err)

	require.NoError(t, repo.DeleteMany(context.Background(), nil))
	require.NoError(t, repo.DeleteMany(context.Background(), []string{}))
}

// ---------------------------------------------------------------------------
// RequestSimulation repository tests — nil DB gap
// ---------------------------------------------------------------------------

func TestGormRequestSimulationRepo_New_NilDB(t *testing.T) {
	repo, err := NewGormRequestSimulationRepository(nil)
	assert.Nil(t, repo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection is required")
}
