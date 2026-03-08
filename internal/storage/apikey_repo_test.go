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

// ===========================================================================
// Count
// ===========================================================================

func TestAPIKeyRepo_Count(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	// Empty DB
	count, err := repo.Count(ctx, APIKeyFilter{})
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	// Add keys
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "c1", Name: "K1", Enabled: true}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "c2", Name: "K2", Enabled: true}))
	disabledKey := &types.APIKey{ID: "c3", Name: "K3", Enabled: true}
	require.NoError(t, repo.Create(ctx, disabledKey))
	disabledKey.Enabled = false
	require.NoError(t, repo.Update(ctx, disabledKey))

	// All keys
	count, err = repo.Count(ctx, APIKeyFilter{})
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	// Enabled only
	count, err = repo.Count(ctx, APIKeyFilter{EnabledOnly: true})
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestAPIKeyRepo_Count_WithSource(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "cs1", Name: "Config1", Enabled: true, Source: "config"}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "cs2", Name: "Config2", Enabled: true, Source: "config"}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "cs3", Name: "API1", Enabled: true, Source: "api"}))

	count, err := repo.Count(ctx, APIKeyFilter{Source: "config"})
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	count, err = repo.Count(ctx, APIKeyFilter{Source: "api"})
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	count, err = repo.Count(ctx, APIKeyFilter{Source: "nonexistent"})
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// ===========================================================================
// DeleteBySourceExcluding
// ===========================================================================

func TestAPIKeyRepo_DeleteBySourceExcluding(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "d1", Name: "Config1", Enabled: true, Source: "config"}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "d2", Name: "Config2", Enabled: true, Source: "config"}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "d3", Name: "Config3", Enabled: true, Source: "config"}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "d4", Name: "API1", Enabled: true, Source: "api"}))

	// Delete config keys excluding d1
	deleted, err := repo.DeleteBySourceExcluding(ctx, "config", []string{"d1"})
	require.NoError(t, err)
	assert.Equal(t, int64(2), deleted)

	// d1 should still exist
	_, err = repo.Get(ctx, "d1")
	assert.NoError(t, err)

	// d2 and d3 should be deleted
	_, err = repo.Get(ctx, "d2")
	assert.ErrorIs(t, err, types.ErrNotFound)
	_, err = repo.Get(ctx, "d3")
	assert.ErrorIs(t, err, types.ErrNotFound)

	// d4 (api source) should be preserved
	_, err = repo.Get(ctx, "d4")
	assert.NoError(t, err)
}

func TestAPIKeyRepo_DeleteBySourceExcluding_PreservesExcluded(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "e1", Name: "C1", Enabled: true, Source: "config"}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "e2", Name: "C2", Enabled: true, Source: "config"}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "e3", Name: "C3", Enabled: true, Source: "config"}))

	// Exclude all three - nothing should be deleted
	deleted, err := repo.DeleteBySourceExcluding(ctx, "config", []string{"e1", "e2", "e3"})
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted)

	// All should still exist
	for _, id := range []string{"e1", "e2", "e3"} {
		_, err = repo.Get(ctx, id)
		assert.NoError(t, err, "key %s should still exist", id)
	}
}

func TestAPIKeyRepo_DeleteBySourceExcluding_EmptyExclude(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "f1", Name: "C1", Enabled: true, Source: "config"}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "f2", Name: "C2", Enabled: true, Source: "config"}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "f3", Name: "API1", Enabled: true, Source: "api"}))

	// Empty exclude list - deletes all config keys
	deleted, err := repo.DeleteBySourceExcluding(ctx, "config", nil)
	require.NoError(t, err)
	assert.Equal(t, int64(2), deleted)

	// Config keys gone
	_, err = repo.Get(ctx, "f1")
	assert.ErrorIs(t, err, types.ErrNotFound)
	_, err = repo.Get(ctx, "f2")
	assert.ErrorIs(t, err, types.ErrNotFound)

	// API key preserved
	_, err = repo.Get(ctx, "f3")
	assert.NoError(t, err)
}

// ===========================================================================
// BackfillSource
// ===========================================================================

func TestAPIKeyRepo_BackfillSource(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	// Create keys with empty source (simulating legacy data).
	// SQLite stores the GORM default 'config', so we need to manually clear it.
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "bf1", Name: "Legacy1", Enabled: true}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "bf2", Name: "Legacy2", Enabled: true}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "bf3", Name: "HasSource", Enabled: true, Source: "api"}))

	// Manually set source to empty for the legacy keys
	repo.db.Model(&types.APIKey{}).Where("id IN ?", []string{"bf1", "bf2"}).Update("source", "")

	count, err := repo.BackfillSource(ctx, "config")
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	// Verify backfilled keys
	k1, err := repo.Get(ctx, "bf1")
	require.NoError(t, err)
	assert.Equal(t, "config", k1.Source)

	k2, err := repo.Get(ctx, "bf2")
	require.NoError(t, err)
	assert.Equal(t, "config", k2.Source)

	// API key should be unchanged
	k3, err := repo.Get(ctx, "bf3")
	require.NoError(t, err)
	assert.Equal(t, "api", k3.Source)
}

func TestAPIKeyRepo_BackfillSource_NoEmptyKeys(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	// All keys already have source set
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "bf-ne1", Name: "K1", Enabled: true, Source: "config"}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "bf-ne2", Name: "K2", Enabled: true, Source: "api"}))

	count, err := repo.BackfillSource(ctx, "config")
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

// ===========================================================================
// List with Source filter
// ===========================================================================

func TestAPIKeyRepo_List_WithSourceFilter(t *testing.T) {
	_, repo := setupAPIKeyRepoTestDB(t)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "ls1", Name: "Config1", Enabled: true, Source: "config"}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "ls2", Name: "Config2", Enabled: true, Source: "config"}))
	require.NoError(t, repo.Create(ctx, &types.APIKey{ID: "ls3", Name: "API1", Enabled: true, Source: "api"}))

	// Filter by config source
	list, err := repo.List(ctx, APIKeyFilter{Source: "config"})
	require.NoError(t, err)
	assert.Len(t, list, 2)
	for _, k := range list {
		assert.Equal(t, "config", k.Source)
	}

	// Filter by api source
	list, err = repo.List(ctx, APIKeyFilter{Source: "api"})
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, "ls3", list[0].ID)

	// No filter - all keys
	list, err = repo.List(ctx, APIKeyFilter{})
	require.NoError(t, err)
	assert.Len(t, list, 3)
}
