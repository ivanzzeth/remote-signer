//go:build integration

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

func newSimTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&types.RequestSimulation{}))
	return db
}

func TestRequestSimulationRepo_UpsertReplacesExisting(t *testing.T) {
	// Each tick of the simulation pipeline rewrites the row (the
	// table is 1:1 with sign requests by design — we want "latest
	// known outcome" semantics, not an append log). Pin that
	// Upsert overwrites rather than inserting a duplicate row.
	repo, err := NewGormRequestSimulationRepository(newSimTestDB(t))
	require.NoError(t, err)
	ctx := context.Background()

	first := &types.RequestSimulation{
		SignRequestID: "req-1",
		ChainID:       "1",
		Decision:      "no_match",
		Reason:        "no decision yet",
		Success:       true,
		GasUsed:       50_000,
		SimulatedAt:   time.Now(),
		UpdatedAt:     time.Now(),
	}
	require.NoError(t, repo.Upsert(ctx, first))

	// Same id, different decision + richer fields.
	second := &types.RequestSimulation{
		SignRequestID:  "req-1",
		ChainID:        "1",
		Decision:       "allow",
		Reason:         "",
		Success:        true,
		GasUsed:        287_453,
		BalanceChanges: types.JSONBytes(`[{"token":"native","amount":"-100"}]`),
		Events:         types.JSONBytes(`[{"address":"0xabc","event":"Transfer"}]`),
		Contracts:      types.JSONBytes(`["0xabc","0xdef"]`),
		SimulatedAt:    time.Now().Add(time.Second),
		UpdatedAt:      time.Now().Add(time.Second),
	}
	require.NoError(t, repo.Upsert(ctx, second))

	got, err := repo.GetByRequestID(ctx, "req-1")
	require.NoError(t, err)
	assert.Equal(t, "allow", got.Decision)
	assert.Equal(t, uint64(287_453), got.GasUsed)
	// JSON columns came back intact.
	assert.JSONEq(t, `[{"token":"native","amount":"-100"}]`, string(got.BalanceChanges))
	assert.JSONEq(t, `["0xabc","0xdef"]`, string(got.Contracts))
}

func TestRequestSimulationRepo_GetMissingReturnsNotFound(t *testing.T) {
	// The handler maps ErrNotFound → HTTP 404 so the UI can show
	// "simulation evaluating" instead of a hard error while the
	// pipeline is still in flight on a fresh request.
	repo, err := NewGormRequestSimulationRepository(newSimTestDB(t))
	require.NoError(t, err)

	_, err = repo.GetByRequestID(context.Background(), "no-such-req")
	require.ErrorIs(t, err, types.ErrNotFound)
}

func TestRequestSimulationRepo_UpsertRejectsEmptyID(t *testing.T) {
	// Defence in depth — the model says PK is non-empty; a caller
	// that forgot to populate sign_request_id should fail loudly
	// here rather than orphaning a row with empty PK.
	repo, err := NewGormRequestSimulationRepository(newSimTestDB(t))
	require.NoError(t, err)

	err = repo.Upsert(context.Background(), &types.RequestSimulation{ChainID: "1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sign_request_id")
}
