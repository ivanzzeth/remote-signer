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

func setupRequestRepoTestDB(t *testing.T) (*gorm.DB, *GormRequestRepository) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.SignRequest{}))
	repo, err := NewGormRequestRepository(db)
	require.NoError(t, err)
	return db, repo
}

func TestRequestRepo_NewGormRequestRepository_NilDB(t *testing.T) {
	repo, err := NewGormRequestRepository(nil)
	assert.Nil(t, repo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database connection is required")
}

func TestRequestRepo_Create(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	ctx := context.Background()

	req := &types.SignRequest{
		ID:            "req-1",
		APIKeyID:      "key-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xAAA",
		SignType:      "transaction",
		Status:        types.StatusPending,
	}
	err := repo.Create(ctx, req)
	require.NoError(t, err)

	got, err := repo.Get(ctx, "req-1")
	require.NoError(t, err)
	assert.Equal(t, types.SignRequestID("req-1"), got.ID)
	assert.Equal(t, "key-1", got.APIKeyID)
	assert.Equal(t, types.ChainTypeEVM, got.ChainType)
}

func TestRequestRepo_Create_Nil(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	err := repo.Create(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request cannot be nil")
}

func TestRequestRepo_Get_NotFound(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	_, err := repo.Get(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestRequestRepo_Update(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	ctx := context.Background()

	req := &types.SignRequest{
		ID:            "req-upd-1",
		APIKeyID:      "key-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xAAA",
		Status:        types.StatusPending,
	}
	require.NoError(t, repo.Create(ctx, req))

	req.Status = types.StatusCompleted
	err := repo.Update(ctx, req)
	require.NoError(t, err)

	got, _ := repo.Get(ctx, "req-upd-1")
	assert.Equal(t, types.StatusCompleted, got.Status)
}

func TestRequestRepo_Update_Nil(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	err := repo.Update(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request cannot be nil")
}

func TestRequestRepo_CompareAndUpdate_Success(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	ctx := context.Background()

	req := &types.SignRequest{
		ID:            "req-cas-1",
		APIKeyID:      "key-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xAAA",
		Status:        types.StatusPending,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	require.NoError(t, repo.Create(ctx, req))

	// Update from pending to authorizing
	now := time.Now()
	req.Status = types.StatusAuthorizing
	req.UpdatedAt = now
	err := repo.CompareAndUpdate(ctx, req, types.StatusPending)
	require.NoError(t, err)

	got, _ := repo.Get(ctx, "req-cas-1")
	assert.Equal(t, types.StatusAuthorizing, got.Status)
}

func TestRequestRepo_CompareAndUpdate_Conflict(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	ctx := context.Background()

	req := &types.SignRequest{
		ID:            "req-cas-2",
		APIKeyID:      "key-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xAAA",
		Status:        types.StatusPending,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	require.NoError(t, repo.Create(ctx, req))

	// Try to update from "authorizing" but it's actually "pending" => conflict
	req.Status = types.StatusCompleted
	req.UpdatedAt = time.Now()
	err := repo.CompareAndUpdate(ctx, req, types.StatusAuthorizing)
	assert.ErrorIs(t, err, ErrStateConflict)

	// Original status should be unchanged
	got, _ := repo.Get(ctx, "req-cas-2")
	assert.Equal(t, types.StatusPending, got.Status)
}

func TestRequestRepo_CompareAndUpdate_Nil(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	err := repo.CompareAndUpdate(context.Background(), nil, types.StatusPending)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request cannot be nil")
}

func TestRequestRepo_UpdateStatus(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	ctx := context.Background()

	req := &types.SignRequest{
		ID:            "req-st-1",
		APIKeyID:      "key-1",
		ChainType:     types.ChainTypeEVM,
		ChainID:       "1",
		SignerAddress: "0xAAA",
		Status:        types.StatusPending,
	}
	require.NoError(t, repo.Create(ctx, req))

	err := repo.UpdateStatus(ctx, "req-st-1", types.StatusRejected)
	require.NoError(t, err)

	got, _ := repo.Get(ctx, "req-st-1")
	assert.Equal(t, types.StatusRejected, got.Status)
}

func TestRequestRepo_UpdateStatus_NotFound(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	err := repo.UpdateStatus(context.Background(), "nonexistent", types.StatusRejected)
	assert.ErrorIs(t, err, types.ErrNotFound)
}

func TestRequestRepo_List(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	ctx := context.Background()

	now := time.Now()
	for i := 0; i < 5; i++ {
		require.NoError(t, repo.Create(ctx, &types.SignRequest{
			ID:            types.SignRequestID("req-list-" + string(rune('a'+i))),
			APIKeyID:      "key-1",
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xAAA",
			Status:        types.StatusPending,
			CreatedAt:     now.Add(time.Duration(i) * time.Second),
		}))
	}

	list, err := repo.List(ctx, RequestFilter{Limit: 3})
	require.NoError(t, err)
	assert.Len(t, list, 3)
}

func TestRequestRepo_List_WithFilters(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	ctx := context.Background()

	apiKeyID := "key-filter"
	signerAddr := "0xBBB"
	evm := types.ChainTypeEVM
	chainID := "137"

	req1 := &types.SignRequest{
		ID: "req-filt-1", APIKeyID: apiKeyID, ChainType: types.ChainTypeEVM,
		ChainID: "137", SignerAddress: signerAddr, Status: types.StatusPending,
		CreatedAt: time.Now(),
	}
	req2 := &types.SignRequest{
		ID: "req-filt-2", APIKeyID: "other-key", ChainType: types.ChainTypeEVM,
		ChainID: "1", SignerAddress: "0xCCC", Status: types.StatusCompleted,
		CreatedAt: time.Now(),
	}
	require.NoError(t, repo.Create(ctx, req1))
	require.NoError(t, repo.Create(ctx, req2))

	list, err := repo.List(ctx, RequestFilter{
		APIKeyID:      &apiKeyID,
		SignerAddress: &signerAddr,
		ChainType:     &evm,
		ChainID:       &chainID,
		Status:        []types.SignRequestStatus{types.StatusPending},
	})
	require.NoError(t, err)
	assert.Len(t, list, 1)
	assert.Equal(t, types.SignRequestID("req-filt-1"), list[0].ID)
}

func TestRequestRepo_List_CursorPagination(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	ctx := context.Background()

	now := time.Now()
	for i := 0; i < 5; i++ {
		require.NoError(t, repo.Create(ctx, &types.SignRequest{
			ID:            types.SignRequestID("req-cur-" + string(rune('a'+i))),
			APIKeyID:      "key-1",
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xAAA",
			Status:        types.StatusPending,
			CreatedAt:     now.Add(time.Duration(i) * time.Second),
		}))
	}

	// First page
	list, err := repo.List(ctx, RequestFilter{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, list, 2)

	// Cursor-based second page
	cursor := list[len(list)-1].CreatedAt
	cursorID := list[len(list)-1].ID
	list2, err := repo.List(ctx, RequestFilter{
		Limit:    2,
		Cursor:   &cursor,
		CursorID: &cursorID,
	})
	require.NoError(t, err)
	assert.Len(t, list2, 2)

	// Verify no overlap
	for _, r1 := range list {
		for _, r2 := range list2 {
			assert.NotEqual(t, r1.ID, r2.ID, "pages should not overlap")
		}
	}
}

func TestRequestRepo_List_CursorWithoutID(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	ctx := context.Background()

	now := time.Now()
	for i := 0; i < 3; i++ {
		require.NoError(t, repo.Create(ctx, &types.SignRequest{
			ID:            types.SignRequestID("req-cnid-" + string(rune('a'+i))),
			APIKeyID:      "key-1",
			ChainType:     types.ChainTypeEVM,
			ChainID:       "1",
			SignerAddress: "0xAAA",
			Status:        types.StatusPending,
			CreatedAt:     now.Add(time.Duration(i) * time.Second),
		}))
	}

	// Cursor without CursorID
	cursor := now.Add(1 * time.Second)
	list, err := repo.List(ctx, RequestFilter{
		Limit:  10,
		Cursor: &cursor,
	})
	require.NoError(t, err)
	assert.Len(t, list, 1) // only the one with createdAt before cursor
}

func TestRequestRepo_Count(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	ctx := context.Background()

	require.NoError(t, repo.Create(ctx, &types.SignRequest{
		ID: "req-cnt-1", APIKeyID: "key-1", ChainType: types.ChainTypeEVM,
		ChainID: "1", SignerAddress: "0xAAA", Status: types.StatusPending,
	}))
	require.NoError(t, repo.Create(ctx, &types.SignRequest{
		ID: "req-cnt-2", APIKeyID: "key-1", ChainType: types.ChainTypeEVM,
		ChainID: "1", SignerAddress: "0xAAA", Status: types.StatusCompleted,
	}))

	count, err := repo.Count(ctx, RequestFilter{})
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	// Count with status filter
	count, err = repo.Count(ctx, RequestFilter{
		Status: []types.SignRequestStatus{types.StatusPending},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestRequestRepo_List_DefaultLimit(t *testing.T) {
	_, repo := setupRequestRepoTestDB(t)
	ctx := context.Background()

	// Create a few requests, then list with no limit
	require.NoError(t, repo.Create(ctx, &types.SignRequest{
		ID: "req-dl-1", APIKeyID: "key-1", ChainType: types.ChainTypeEVM,
		ChainID: "1", SignerAddress: "0xAAA", Status: types.StatusPending,
	}))

	list, err := repo.List(ctx, RequestFilter{})
	require.NoError(t, err)
	assert.Len(t, list, 1)
}
