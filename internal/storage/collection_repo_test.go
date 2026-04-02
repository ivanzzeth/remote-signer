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

func setupCollectionTestDB(t *testing.T) (*gorm.DB, *GormCollectionRepository) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&types.WalletCollection{},
		&types.CollectionMember{},
	))
	repo, err := NewGormCollectionRepository(db)
	require.NoError(t, err)
	return db, repo
}

func TestCollectionRepo_CreateAndGet(t *testing.T) {
	_, repo := setupCollectionTestDB(t)
	ctx := context.Background()

	coll := &types.WalletCollection{
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

func TestCollectionRepo_Get_NotFound(t *testing.T) {
	_, repo := setupCollectionTestDB(t)
	ctx := context.Background()

	_, err := repo.Get(ctx, "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestCollectionRepo_Update(t *testing.T) {
	_, repo := setupCollectionTestDB(t)
	ctx := context.Background()

	coll := &types.WalletCollection{
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

func TestCollectionRepo_Update_NotFound(t *testing.T) {
	_, repo := setupCollectionTestDB(t)
	ctx := context.Background()

	coll := &types.WalletCollection{ID: "nonexistent", Name: "x"}
	err := repo.Update(ctx, coll)
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestCollectionRepo_Delete(t *testing.T) {
	_, repo := setupCollectionTestDB(t)
	ctx := context.Background()

	coll := &types.WalletCollection{Name: "To Delete", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll))

	err := repo.Delete(ctx, coll.ID)
	require.NoError(t, err)

	_, err = repo.Get(ctx, coll.ID)
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestCollectionRepo_Delete_NotFound(t *testing.T) {
	_, repo := setupCollectionTestDB(t)
	ctx := context.Background()

	err := repo.Delete(ctx, "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestCollectionRepo_List(t *testing.T) {
	_, repo := setupCollectionTestDB(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, repo.Create(ctx, &types.WalletCollection{
			Name:    "Collection",
			OwnerID: "key-1",
		}))
	}
	require.NoError(t, repo.Create(ctx, &types.WalletCollection{
		Name:    "Other Owner",
		OwnerID: "key-2",
	}))

	// List for key-1
	result, err := repo.List(ctx, types.CollectionFilter{OwnerID: "key-1"})
	require.NoError(t, err)
	assert.Equal(t, 5, result.Total)
	assert.Len(t, result.Collections, 5)
	assert.False(t, result.HasMore)

	// List for key-2
	result, err = repo.List(ctx, types.CollectionFilter{OwnerID: "key-2"})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Total)

	// List all (empty owner)
	result, err = repo.List(ctx, types.CollectionFilter{})
	require.NoError(t, err)
	assert.Equal(t, 6, result.Total)
}

func TestCollectionRepo_List_Pagination(t *testing.T) {
	_, repo := setupCollectionTestDB(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, repo.Create(ctx, &types.WalletCollection{
			Name:    "Collection",
			OwnerID: "key-1",
		}))
	}

	result, err := repo.List(ctx, types.CollectionFilter{OwnerID: "key-1", Limit: 3})
	require.NoError(t, err)
	assert.Len(t, result.Collections, 3)
	assert.True(t, result.HasMore)
	assert.Equal(t, 5, result.Total)

	result, err = repo.List(ctx, types.CollectionFilter{OwnerID: "key-1", Limit: 3, Offset: 3})
	require.NoError(t, err)
	assert.Len(t, result.Collections, 2)
	assert.False(t, result.HasMore)
}

func TestCollectionRepo_AddMember(t *testing.T) {
	_, repo := setupCollectionTestDB(t)
	ctx := context.Background()

	coll := &types.WalletCollection{Name: "Test", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll))

	member := &types.CollectionMember{
		CollectionID: coll.ID,
		WalletID:     "0x1234567890abcdef1234567890abcdef12345678",
	}
	err := repo.AddMember(ctx, member)
	require.NoError(t, err)

	members, err := repo.ListMembers(ctx, coll.ID)
	require.NoError(t, err)
	assert.Len(t, members, 1)
	assert.Equal(t, "0x1234567890abcdef1234567890abcdef12345678", members[0].WalletID)
}

func TestCollectionRepo_AddMember_NestedCollectionDenied(t *testing.T) {
	_, repo := setupCollectionTestDB(t)
	ctx := context.Background()

	coll1 := &types.WalletCollection{Name: "Collection 1", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll1))

	coll2 := &types.WalletCollection{Name: "Collection 2", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll2))

	// Try to add coll2 as a member of coll1 (should fail)
	member := &types.CollectionMember{
		CollectionID: coll1.ID,
		WalletID:     coll2.ID,
	}
	err := repo.AddMember(ctx, member)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nested collections are not allowed")
}

func TestCollectionRepo_RemoveMember(t *testing.T) {
	_, repo := setupCollectionTestDB(t)
	ctx := context.Background()

	coll := &types.WalletCollection{Name: "Test", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll))

	walletID := "0x1234567890abcdef1234567890abcdef12345678"
	require.NoError(t, repo.AddMember(ctx, &types.CollectionMember{
		CollectionID: coll.ID,
		WalletID:     walletID,
	}))

	err := repo.RemoveMember(ctx, coll.ID, walletID)
	require.NoError(t, err)

	members, err := repo.ListMembers(ctx, coll.ID)
	require.NoError(t, err)
	assert.Len(t, members, 0)
}

func TestCollectionRepo_RemoveMember_NotFound(t *testing.T) {
	_, repo := setupCollectionTestDB(t)
	ctx := context.Background()

	err := repo.RemoveMember(ctx, "nonexistent", "0xabc")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestCollectionRepo_IsMember(t *testing.T) {
	_, repo := setupCollectionTestDB(t)
	ctx := context.Background()

	coll := &types.WalletCollection{Name: "Test", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll))

	walletID := "0x1234567890abcdef1234567890abcdef12345678"
	require.NoError(t, repo.AddMember(ctx, &types.CollectionMember{
		CollectionID: coll.ID,
		WalletID:     walletID,
	}))

	isMember, err := repo.IsMember(ctx, coll.ID, walletID)
	require.NoError(t, err)
	assert.True(t, isMember)

	isMember, err = repo.IsMember(ctx, coll.ID, "0xNonexistent")
	require.NoError(t, err)
	assert.False(t, isMember)
}

func TestCollectionRepo_GetCollectionsForWallet(t *testing.T) {
	_, repo := setupCollectionTestDB(t)
	ctx := context.Background()

	coll1 := &types.WalletCollection{Name: "Coll 1", OwnerID: "key-1"}
	coll2 := &types.WalletCollection{Name: "Coll 2", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll1))
	require.NoError(t, repo.Create(ctx, coll2))

	walletID := "0xWallet"
	require.NoError(t, repo.AddMember(ctx, &types.CollectionMember{
		CollectionID: coll1.ID,
		WalletID:     walletID,
	}))
	require.NoError(t, repo.AddMember(ctx, &types.CollectionMember{
		CollectionID: coll2.ID,
		WalletID:     walletID,
	}))

	collections, err := repo.GetCollectionsForWallet(ctx, walletID)
	require.NoError(t, err)
	assert.Len(t, collections, 2)
}

func TestCollectionRepo_IsCollection(t *testing.T) {
	_, repo := setupCollectionTestDB(t)
	ctx := context.Background()

	coll := &types.WalletCollection{Name: "Test", OwnerID: "key-1"}
	require.NoError(t, repo.Create(ctx, coll))

	is, err := repo.IsCollection(ctx, coll.ID)
	require.NoError(t, err)
	assert.True(t, is)

	is, err = repo.IsCollection(ctx, "nonexistent")
	require.NoError(t, err)
	assert.False(t, is)
}

func TestNewGormCollectionRepository_NilDB(t *testing.T) {
	_, err := NewGormCollectionRepository(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "database connection is required")
}
