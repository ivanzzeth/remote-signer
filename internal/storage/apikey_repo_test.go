package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/ivanzzeth/remote-signer/internal/core/types"
)

func setupAPIKeyRepoTestDB(t *testing.T) (*gorm.DB, *GormAPIKeyRepository) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.APIKey{}))
	repo, err := NewGormAPIKeyRepository(db)
	require.NoError(t, err)
	return db, repo
}

func TestAPIKeyRepo_NewGormAPIKeyRepository_NilDB(t *testing.T) {
	repo, err := NewGormAPIKeyRepository(nil)
	assert.Nil(t, repo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection is required")
}

func TestAPIKeyRepo_Create(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	key := &types.APIKey{
		ID:       "key-1",
		Name:     "Test Key",
		Enabled:  true,
		Admin:    false,
	}
	err := repo.Create(ctx, key)
	require.NoError(t, err)

	got, err := repo.Get(ctx, "key-1")
	require.NoError(t, err)
	assert.Equal(t, "key-1", got.ID)
	assert.Equal(t, "Test Key", got.Name)
	assert.True(t, got.Enabled)
}

func TestAPIKeyRepo_Create_Nil(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	err := repo.Create(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API key cannot be nil")
}

func TestAPIKeyRepo_Get_NotFound(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	_, err := repo.Get(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestAPIKeyRepo_Update(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	key := &types.APIKey{
		ID:      "key-upd-1",
		Name:    "Original",
		Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, key))

	key.Name = "Updated"
	key.Enabled = false
	err := repo.Update(ctx, key)
	require.NoError(t, err)

	got, _ := repo.Get(ctx, "key-upd-1")
	assert.Equal(t, "Updated", got.Name)
	assert.False(t, got.Enabled)
}

func TestAPIKeyRepo_Update_Nil(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	err := repo.Update(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API key cannot be nil")
}

func TestAPIKeyRepo_Delete(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	key := &types.APIKey{
		ID:      "key-del-1",
		Name:    "To Delete",
		Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, key))

	err := repo.Delete(ctx, "key-del-1")
	require.NoError(t, err)

	_, err = repo.Get(ctx, "key-del-1")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestAPIKeyRepo_Delete_NotFound(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	err := repo.Delete(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestAPIKeyRepo_List(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "key-l1", Name: "K1", Enabled: true}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "key-l2", Name: "K2", Enabled: false}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "key-l3", Name: "K3", Enabled: true}))

	// All keys
	list, err := repo.List(ctx, APIKeyFilter{})
	require.NoError(t, err)
	assert.Len(t, list, 3)
}

func TestAPIKeyRepo_List_EnabledOnly(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	// Create enabled key
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "key-eo1", Name: "Enabled", Enabled: true}))
	// Create key and then disable it via Update (because GORM default:true means
	// Create with Enabled=false doesn't reliably store false as it's the zero value)
	disabledKey := &types.APIKey{ID: "key-eo2", Name: "Disabled", Enabled: true}
	require.NoError(t, repo.Create(ctx, disabledKey))
	disabledKey.Enabled = false
	require.NoError(t, repo.Update(ctx, disabledKey))

	list, err := repo.List(ctx, APIKeyFilter{EnabledOnly: true})
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "key-eo1", list[0].ID)
}

func TestAPIKeyRepo_List_ExcludesExpiredKeys(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	expiredAt := time.Now().Add(-1 * time.Hour)
	validAt := time.Now().Add(24 * time.Hour)

	require.NoError(t, repo.Create(ctx, &types.APIKey{
		ID: "key-exp1", Name: "Expired", Enabled: true, ExpiresAt: &expiredAt,
	}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{
		ID: "key-exp2", Name: "Valid", Enabled: true, ExpiresAt: &validAt,
	}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{
		ID: "key-exp3", Name: "No Expiry", Enabled: true, ExpiresAt: nil,
	}))

	list, err := repo.List(ctx, APIKeyFilter{EnabledOnly: true})
	require.NoError(t, err)
	assert.Len(t, list, 2, "expired key should be excluded when EnabledOnly=true")

	ids := make(map[string]struct{})
	for _, k := range list {
		ids[k.ID] = struct{}{}
	}
	assert.Contains(t, ids, "key-exp2")
	assert.Contains(t, ids, "key-exp3")
	assert.NotContains(t, ids, "key-exp1")
}

func TestAPIKeyRepo_List_Pagination(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, repo.Create(ctx, &types.APIKey{
			ID: "key-pg-" + string(rune('a'+i)), Name: "K", Enabled: true,
		}))
	}

	list, err := repo.List(ctx, APIKeyFilter{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, list, 2)

	list, err = repo.List(ctx, APIKeyFilter{Limit: 10, Offset: 3})
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestAPIKeyRepo_UpdateLastUsed(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	key := &types.APIKey{
		ID:      "key-lu-1",
		Name:    "Test",
		Enabled: true,
	}
	require.NoError(t, repo.Create(ctx, key))

	before := time.Now()
	err := repo.UpdateLastUsed(ctx, "key-lu-1")
	require.NoError(t, err)
	after := time.Now()

	got, _ := repo.Get(ctx, "key-lu-1")
	require.NotNil(t, got.LastUsedAt)
	assert.False(t, got.LastUsedAt.Before(before))
	assert.False(t, got.LastUsedAt.After(after))
}

func TestAPIKeyRepo_UpdateLastUsed_NotFound(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	err := repo.UpdateLastUsed(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}
