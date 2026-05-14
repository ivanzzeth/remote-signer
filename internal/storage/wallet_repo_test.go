package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func setupWalletTestDB(t *testing.T) (*gorm.DB, *GormWalletRepository) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&types.Wallet{},
		&types.WalletMember{},
		&types.SignerAccess{},
	))
	repo, err := NewGormWalletRepository(db)
	require.NoError(t, err)
	return db, repo
}

func TestWalletRepo_CreateAndGet(t *testing.T) {
	_, repo := setupWalletTestDB(t)
	ctx := context.Background()

	coll := &types.Wallet{
		Name:        "Test Collection",
		Description: "A test collection",
		OwnerID:     "key-1",
	}
	err := repo.Create(ctx, coll)
	require.NoError(t, err)
	assert.NotEmpty(t, coll.ID)

	got, err := repo.Get(ctx, coll.ID)
	require.NoError(t, err)
	assert.Equal(t, "Test Collection", got.Name)
	assert.Equal(t, "A test collection", got.Description)
	assert.Equal(t, "key-1", got.OwnerID)
}

func TestWalletRepo_Get_NotFound(t *testing.T) {
	_, repo := setupWalletTestDB(t)
	ctx := context.Background()

	_, err := repo.Get(ctx, "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestWalletRepo_Update(t *testing.T) {
	_, repo := setupWalletTestDB(t)
	ctx := context.Background()

	coll := &types.Wallet{
		Name:    "Original",
		OwnerID: "key-1",
	}
	require.NoError(t, repo.Create(ctx, coll))

	coll.Name = "Updated"
	coll.Description = "Updated desc"
	err := repo.Update(ctx, coll)
	require.NoError(t, err)

	got, err := repo.Get(ctx, coll.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated", got.Name)
	assert.Equal(t, "Updated desc", got.Description)
}

func TestWalletRepo_Update_NotFound(t *testing.T) {
	_, repo := setupWalletTestDB(t)
	ctx := context.Background()

	coll := &types.Wallet{ID: "nonexistent", Name: "x"}
	err := repo.Update(ctx, coll)
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestWalletRepo_Delete(t *testing.T) {
	_, repo := setupWalletTestDB(t)
	ctx := context.Background()

	coll := &types.Wallet{Name: "To Delete", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll))

	err := repo.Delete(ctx, coll.ID)
	require.NoError(t, err)

	_, err = repo.Get(ctx, coll.ID)
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestWalletRepo_Delete_CascadeMembers(t *testing.T) {
	db, repo := setupWalletTestDB(t)
	ctx := context.Background()

	coll := &types.Wallet{Name: "With Members", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll))

	// Add two members
	require.NoError(t, repo.AddMember(ctx, &types.WalletMember{
		WalletID: coll.ID,
		SignerAddress:     "0xWallet1",
	}))
	require.NoError(t, repo.AddMember(ctx, &types.WalletMember{
		WalletID: coll.ID,
		SignerAddress:     "0xWallet2",
	}))

	// Verify members exist
	members, err := repo.ListMembers(ctx, coll.ID)
	require.NoError(t, err)
	assert.Len(t, members, 2)

	// Delete collection
	require.NoError(t, repo.Delete(ctx, coll.ID))

	// Verify collection is gone
	_, err = repo.Get(ctx, coll.ID)
	assert.ErrorIs(t, err, types.ErrNotFound)

	// Verify members are also gone (CASCADE)
	var count int64
	require.NoError(t, db.Model(&types.WalletMember{}).Where("wallet_id = ?", coll.ID).Count(&count).Error)
	assert.Equal(t, int64(0), count, "collection members should be deleted on cascade")
}

func TestWalletRepo_Delete_CleansUpSignerAccess(t *testing.T) {
	db, repo := setupWalletTestDB(t)
	ctx := context.Background()

	coll := &types.Wallet{Name: "With Access Grants", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll))

	// Create signer_access entries that reference this collection via wallet_id
	accessRepo, err := NewGormSignerAccessRepository(db)
	require.NoError(t, err)

	require.NoError(t, accessRepo.Grant(ctx, &types.SignerAccess{
		SignerAddress: "0xSigner1",
		APIKeyID:      "grantee-1",
		GrantedBy:     "key-1",
		WalletID:      coll.ID, // points to the collection
	}))
	require.NoError(t, accessRepo.Grant(ctx, &types.SignerAccess{
		SignerAddress: "0xSigner2",
		APIKeyID:      "grantee-2",
		GrantedBy:     "key-1",
		WalletID:      coll.ID, // points to the collection
	}))

	// Also create an access entry NOT tied to this collection (should survive)
	require.NoError(t, accessRepo.Grant(ctx, &types.SignerAccess{
		SignerAddress: "0xOtherSigner",
		APIKeyID:      "grantee-3",
		GrantedBy:     "key-1",
		WalletID:      "some-other-id",
	}))

	// Delete the collection
	require.NoError(t, repo.Delete(ctx, coll.ID))

	// Verify signer_access entries referencing the collection are gone
	var count int64
	require.NoError(t, db.Model(&types.SignerAccess{}).Where("wallet_id = ?", coll.ID).Count(&count).Error)
	assert.Equal(t, int64(0), count, "signer_access referencing deleted collection should be cleaned up")

	// Verify unrelated signer_access is still there
	require.NoError(t, db.Model(&types.SignerAccess{}).Where("wallet_id = ?", "some-other-id").Count(&count).Error)
	assert.Equal(t, int64(1), count, "unrelated signer_access should not be deleted")
}

func TestWalletRepo_Delete_NotFound(t *testing.T) {
	_, repo := setupWalletTestDB(t)
	ctx := context.Background()

	err := repo.Delete(ctx, "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestWalletRepo_List(t *testing.T) {
	_, repo := setupWalletTestDB(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, repo.Create(ctx, &types.Wallet{
			Name:    "Collection",
			OwnerID: "key-1",
		}))
	}
	require.NoError(t, repo.Create(ctx, &types.Wallet{
		Name:    "Other Owner",
		OwnerID: "key-2",
	}))

	// List for key-1
	result, err := repo.List(ctx, types.WalletFilter{OwnerID: "key-1"})
	require.NoError(t, err)
	assert.Equal(t, 5, result.Total)
	assert.Len(t, result.Wallets, 5)
	assert.False(t, result.HasMore)

	// List for key-2
	result, err = repo.List(ctx, types.WalletFilter{OwnerID: "key-2"})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Total)

	// List all (empty owner)
	result, err = repo.List(ctx, types.WalletFilter{})
	require.NoError(t, err)
	assert.Equal(t, 6, result.Total)
}

func TestWalletRepo_List_Pagination(t *testing.T) {
	_, repo := setupWalletTestDB(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, repo.Create(ctx, &types.Wallet{
			Name:    "Collection",
			OwnerID: "key-1",
		}))
	}

	result, err := repo.List(ctx, types.WalletFilter{OwnerID: "key-1", Limit: 3})
	require.NoError(t, err)
	assert.Len(t, result.Wallets, 3)
	assert.True(t, result.HasMore)
	assert.Equal(t, 5, result.Total)

	result, err = repo.List(ctx, types.WalletFilter{OwnerID: "key-1", Limit: 3, Offset: 3})
	require.NoError(t, err)
	assert.Len(t, result.Wallets, 2)
	assert.False(t, result.HasMore)
}

func TestWalletRepo_AddMember(t *testing.T) {
	_, repo := setupWalletTestDB(t)
	ctx := context.Background()

	coll := &types.Wallet{Name: "Test", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll))

	member := &types.WalletMember{
		WalletID: coll.ID,
		SignerAddress:     "0x1234567890abcdef1234567890abcdef12345678",
	}
	err := repo.AddMember(ctx, member)
	require.NoError(t, err)

	members, err := repo.ListMembers(ctx, coll.ID)
	require.NoError(t, err)
	assert.Len(t, members, 1)
	assert.Equal(t, "0x1234567890abcdef1234567890abcdef12345678", members[0].SignerAddress)
}

func TestWalletRepo_AddMember_NestedCollectionDenied(t *testing.T) {
	_, repo := setupWalletTestDB(t)
	ctx := context.Background()

	coll1 := &types.Wallet{Name: "Collection 1", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll1))

	coll2 := &types.Wallet{Name: "Collection 2", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll2))

	// Try to add coll2 as a member of coll1 (should fail)
	member := &types.WalletMember{
		WalletID: coll1.ID,
		SignerAddress:     coll2.ID,
	}
	err := repo.AddMember(ctx, member)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nested wallets are not allowed")
}

func TestWalletRepo_RemoveMember(t *testing.T) {
	_, repo := setupWalletTestDB(t)
	ctx := context.Background()

	coll := &types.Wallet{Name: "Test", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll))

	walletID := "0x1234567890abcdef1234567890abcdef12345678"
	require.NoError(t, repo.AddMember(ctx, &types.WalletMember{
		WalletID: coll.ID,
		SignerAddress:     walletID,
	}))

	err := repo.RemoveMember(ctx, coll.ID, walletID)
	require.NoError(t, err)

	members, err := repo.ListMembers(ctx, coll.ID)
	require.NoError(t, err)
	assert.Len(t, members, 0)
}

func TestWalletRepo_RemoveMember_NotFound(t *testing.T) {
	_, repo := setupWalletTestDB(t)
	ctx := context.Background()

	err := repo.RemoveMember(ctx, "nonexistent", "0xabc")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestWalletRepo_IsMember(t *testing.T) {
	_, repo := setupWalletTestDB(t)
	ctx := context.Background()

	coll := &types.Wallet{Name: "Test", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll))

	walletID := "0x1234567890abcdef1234567890abcdef12345678"
	require.NoError(t, repo.AddMember(ctx, &types.WalletMember{
		WalletID: coll.ID,
		SignerAddress:     walletID,
	}))

	isMember, err := repo.IsMember(ctx, coll.ID, walletID)
	require.NoError(t, err)
	assert.True(t, isMember)

	isMember, err = repo.IsMember(ctx, coll.ID, "0xNonexistent")
	require.NoError(t, err)
	assert.False(t, isMember)
}

func TestWalletRepo_GetCollectionsForWallet(t *testing.T) {
	_, repo := setupWalletTestDB(t)
	ctx := context.Background()

	coll1 := &types.Wallet{Name: "Coll 1", OwnerID: "key-1"}
	coll2 := &types.Wallet{Name: "Coll 2", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll1))
	require.NoError(t, repo.Create(ctx, coll2))

	walletID := "0xWallet"
	require.NoError(t, repo.AddMember(ctx, &types.WalletMember{
		WalletID: coll1.ID,
		SignerAddress:     walletID,
	}))
	require.NoError(t, repo.AddMember(ctx, &types.WalletMember{
		WalletID: coll2.ID,
		SignerAddress:     walletID,
	}))

	collections, err := repo.GetWalletsForSigner(ctx, walletID)
	require.NoError(t, err)
	assert.Len(t, collections, 2)
}

func TestNewGormWalletRepository_NilDB(t *testing.T) {
	_, err := NewGormWalletRepository(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database connection is required")
}
